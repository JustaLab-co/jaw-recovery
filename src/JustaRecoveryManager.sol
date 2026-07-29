// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import { MultiOwnable } from "justanaccount/MultiOwnable.sol";

import { EIP712 } from "solady/utils/EIP712.sol";
import { ReentrancyGuard } from "solady/utils/ReentrancyGuard.sol";

import { IRecoveryManager } from "./interfaces/IRecoveryManager.sol";
import { IRecoveryProvider } from "./interfaces/IRecoveryProvider.sol";
import { SignatureProofLib } from "./libraries/SignatureProofLib.sol";

/**
 * @title JustaRecoveryManager
 *
 * @notice Recovery coordinator for JustanAccount: registered as an owner of each opted-in account, it
 *         holds the per-account recovery registry and time-locks the registration of a new owner (WebAuthn
 *         passkey or EOA) behind a threshold of recovery approvals.
 *
 * @dev The unit of recovery is a "recovery": a `(provider, commitment)` pair plus a time-lock `delay`,
 *      keyed by `recoveryId = keccak256(abi.encode(account, provider, commitment))`. The same provider may
 *      back several recoveries for one account.
 * @dev The manager owns all state — recoveries & commitments, the approval threshold, the per-recovery
 *      delays, and the per-account used-salt registry — and treats providers as stateless verifiers: on
 *      each approval it calls `provider.verify(account, subject, salt, expiry, commitment, proof)`, which
 *      reverts on an invalid proof. Provider trust is therefore equivalent to provider correctness.
 * @dev Recovery administration has TWO authorization doors over one shared implementation: the
 *      `onlyAccount` externals (the single-chain door — a plain call/userop from the account itself) and
 *      `executeRecoveryAdmin` (the multichain door — a batch authorized by a current owner's chain-agnostic
 *      EIP-712 signature, submittable by anyone on every chain). Both dispatch into the same internal
 *      functions, so every invariant holds identically regardless of the door used.
 * @dev Non-ownable, non-upgradeable, deployed once per chain at a deterministic address.
 *
 * @author JustaLab
 */
contract JustaRecoveryManager is IRecoveryManager, ReentrancyGuard, EIP712 {

    using EnumerableSet for EnumerableSet.Bytes32Set;

    ////////////////////////////////////////////////////////////////////////
    // CONSTANTS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice EIP-712 typehash for one admin operation inside a `RecoveryAdmin` batch.
     */
    bytes32 public constant ADMIN_OP_TYPEHASH = keccak256("AdminOp(uint8 opType,bytes data)");

    /**
     * @notice EIP-712 typehash for a signed admin batch.
     * @dev The owner signs the ordered ops array together with the batch's single-use `salt` and `expiry`;
     *      the digest omits chainId, so one signature is valid on every chain (consumed independently per
     *      chain via the salt).
     */
    bytes32 public constant RECOVERY_ADMIN_TYPEHASH = keccak256(
        "RecoveryAdmin(address account,AdminOp[] ops,bytes32 salt,uint256 expiry)AdminOp(uint8 opType,bytes data)"
    );

    ////////////////////////////////////////////////////////////////////////
    // STORAGE
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Per-account set of registered recovery ids (`keccak256(abi.encode(account, provider, commitment))`).
     */
    mapping(address account => EnumerableSet.Bytes32Set recoveryIds) internal _recoveryIds;

    /**
     * @notice Per-account recovery data, keyed by recovery id.
     */
    mapping(address account => mapping(bytes32 recoveryId => Recovery recovery)) internal _recoveries;

    /**
     * @notice Per-account approval threshold. `0` means "use the default of 1".
     */
    mapping(address account => uint256 threshold) internal _recoveryThreshold;

    /**
     * @notice Per-account registry of consumed ceremony salts.
     * @dev A salt is bound into every proof and consumed on a successful request, which makes the
     *      ceremony's proofs single-use on this chain while the same proofs stay submittable on chains that
     *      have not consumed the salt. Also seeds the deterministic `requestId`.
     */
    mapping(address account => mapping(bytes32 salt => bool used)) internal _usedSalts;

    /**
     * @notice Pending recovery requests keyed by `requestId`.
     */
    mapping(bytes32 requestId => RecoveryRequest request) internal _recoveryRequests;

    ////////////////////////////////////////////////////////////////////////
    // MODIFIERS
    ////////////////////////////////////////////////////////////////////////

    modifier onlyAccount(address account) {
        if (msg.sender != account) {
            revert JustaRecoveryManager_NotAccount(msg.sender, account);
        }
        _;
    }

    ////////////////////////////////////////////////////////////////////////
    // RECOVERY ADMIN
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Register a recovery for an account.
     * @dev Callable only by the account, which must have opted in by registering this manager as an owner
     *      (`addOwnerAddress(address(this))`) before recoveries can be added.
     * @dev The same `provider` may be registered with different `commitment`s. Reverts if the
     *      `(provider, commitment)` recovery already exists.
     * @dev To change a recovery's `delay`, remove it and add it again.
     * @param account The smart account.
     * @param provider The recovery provider (a stateless verifier); must be a contract.
     * @param commitment Provider-specific commitment bytes (e.g. `abi.encode(eoa)`, an email hash).
     * @param delay The per-recovery time-lock in seconds (`0` = instant; bounded only by `uint32`).
     * @return recoveryId The registered recovery's id.
     */
    function addRecovery(
        address account,
        address provider,
        bytes calldata commitment,
        uint32 delay
    )
        external
        onlyAccount(account)
        returns (bytes32 recoveryId)
    {
        return _addRecovery(account, provider, commitment, delay);
    }

    /**
     * @notice Unregister a recovery for an account.
     * @dev Callable only by the account. Rejected if it would drop the recovery count below the threshold,
     *      unless it removes the last recovery (a full opt-out to zero).
     * @dev Intentionally callable without the manager being an owner of `account`, so an account that opted
     *      out (or was never fully opted in) can still clean up its stale registrations.
     * @param account The smart account.
     * @param recoveryId The recovery id to remove.
     */
    function removeRecovery(address account, bytes32 recoveryId) external onlyAccount(account) {
        _removeRecovery(account, recoveryId);
    }

    /**
     * @notice Set the per-account approval threshold.
     * @dev Callable only by the account. Must be within `[1, recoveryCount]` so a recovery is always
     *      achievable.
     * @dev Intentionally callable without the manager being an owner of `account`: `removeRecovery` refuses
     *      to drop the count below the threshold, so lowering the threshold must stay possible even for an
     *      account that opted out, or its stale recoveries could never be cleaned up.
     * @param account The smart account.
     * @param threshold The number of distinct recoveries required to approve a request.
     */
    function setRecoveryThreshold(address account, uint256 threshold) external onlyAccount(account) {
        _setRecoveryThreshold(account, threshold);
    }

    /**
     * @notice Execute a batch of admin operations authorized by a chain-agnostic signature from a current
     *         owner of `account` — the multichain door over the same logic as the `onlyAccount` functions
     *         above.
     * @dev Unrestricted caller; the owner signature carries authorization, so a relayer can fan the same
     *      bytes out to every chain.
     * @dev Check order: non-empty batch, expiry, salt unused (shared registry with recovery ceremonies —
     *      single-use per chain, reusable across chains), signer is a CURRENT owner (a removed owner's
     *      signatures die automatically), proof verifies over the chain-agnostic digest.
     * @dev The salt is then consumed and the ops applied in signed order, atomically: any failing op
     *      reverts the whole batch on this chain.
     * @dev Per-op events fire from the shared internals; `RecoveryAdminExecuted` is the batch envelope.
     * @param account The smart account whose recovery configuration is administered.
     * @param ops The ordered admin operations (see {IRecoveryManager.AdminOp} for `data` encodings).
     * @param salt The batch's single-use salt (random 32 bytes chosen off-chain).
     * @param expiry The signature's expiry timestamp; bounds how long the unsubmitted batch stays usable.
     * @param ownerBytes The authorizing owner in canonical MultiOwnable owner-bytes form: 32-byte
     *        `abi.encode(address)` (EOA) or 64-byte `abi.encode(x, y)` (raw passkey public key).
     * @param proof A 64/65-byte ECDSA signature or an ABI-encoded WebAuthn assertion over the digest.
     */
    function executeRecoveryAdmin(
        address account,
        AdminOp[] calldata ops,
        bytes32 salt,
        uint256 expiry,
        bytes calldata ownerBytes,
        bytes calldata proof
    )
        external
        nonReentrant
    {
        if (ops.length == 0) {
            revert JustaRecoveryManager_EmptyAdminOps();
        }

        // Expiry bounds how long an unsubmitted signed batch stays usable; the salt makes it single-use
        // per chain while the same signature stays submittable on chains that have not consumed it.
        if (block.timestamp > expiry) {
            revert JustaRecoveryManager_ProofsExpired(expiry);
        }
        if (_usedSalts[account][salt]) {
            revert JustaRecoveryManager_SaltAlreadyUsed(account, salt);
        }

        // The signer must be a CURRENT owner, checked at submission time on this chain. A contract owner
        // passes here but can never produce a valid proof below (strict ecrecover cannot recover a
        // contract address), so smart-account owners must use the account door.
        if (!MultiOwnable(account).isOwnerBytes(ownerBytes)) {
            revert JustaRecoveryManager_SignerNotAccountOwner(account, ownerBytes);
        }

        // Verify the owner's signature over the chain-agnostic batch digest.
        if (!SignatureProofLib.isValidProof(_recoveryAdminDigest(account, ops, salt, expiry), ownerBytes, proof)) {
            revert JustaRecoveryManager_InvalidOwnerProof();
        }

        _usedSalts[account][salt] = true;

        // Apply in signed order, atomically: one failing op reverts the whole batch, so it can never land
        // half-applied (per-chain all-or-nothing keeps chains in sync).
        for (uint256 i = 0; i < ops.length; ++i) {
            uint8 opType = ops[i].opType;
            bytes calldata data = ops[i].data;

            if (opType == uint8(AdminOpType.ADD_RECOVERY)) {
                (address provider, bytes memory commitment, uint32 delay) = abi.decode(data, (address, bytes, uint32));
                _addRecovery(account, provider, commitment, delay);
            } else if (opType == uint8(AdminOpType.REMOVE_RECOVERY)) {
                _removeRecovery(account, abi.decode(data, (bytes32)));
            } else if (opType == uint8(AdminOpType.SET_THRESHOLD)) {
                _setRecoveryThreshold(account, abi.decode(data, (uint256)));
            } else if (opType == uint8(AdminOpType.CANCEL_REQUEST)) {
                _cancelRecoveryRequest(account, abi.decode(data, (bytes32)));
            } else {
                revert JustaRecoveryManager_InvalidAdminOp(opType);
            }
        }

        emit RecoveryAdminExecuted(account, salt, ops.length);
    }

    ////////////////////////////////////////////////////////////////////////
    // EXECUTION
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Queue a recovery request once the threshold of distinct recoveries have approved the same
     *         new owner.
     * @dev Unrestricted caller; the proofs carry authorization. Requires exactly
     *      `recoveryThreshold(account)` distinct, registered recoveries, each verifying a proof over the
     *      same `(subject, salt, expiry)` ceremony.
     * @dev `subject` must be a 32-byte EOA owner or a 64-byte passkey owner.
     * @dev `salt` must be unused for the account on this chain and is consumed on success, making the
     *      proofs single-use per chain; the same ceremony stays submittable on other chains.
     * @dev Reverts once `expiry` has passed.
     * @param account The smart account to recover.
     * @param subject ABI-encoded new owner: `abi.encode(address)` (32B) or `abi.encode(bytes32 x, bytes32 y)` (64B).
     * @param salt The ceremony's single-use salt (random 32 bytes chosen off-chain).
     * @param expiry The ceremony's expiry timestamp; bounds how long unused proofs stay usable.
     * @param approvals One approval per required recovery: the `(provider, commitment)` recovery plus its proof.
     * @return requestId A deterministic id for the queued recovery request
     *         (`keccak256(abi.encode(account, subject, salt))` — identical on every chain).
     */
    function requestRecovery(
        address account,
        bytes calldata subject,
        bytes32 salt,
        uint256 expiry,
        Approval[] calldata approvals
    )
        external
        nonReentrant
        returns (bytes32 requestId)
    {
        uint256 required = _effectiveThreshold(account);
        if (approvals.length != required) {
            revert JustaRecoveryManager_InvalidApprovalCount(approvals.length, required);
        }

        // Expiry bounds how long unused guardian proofs stay usable; it has no effect after queueing.
        if (block.timestamp > expiry) {
            revert JustaRecoveryManager_ProofsExpired(expiry);
        }

        _validateSubject(subject);

        // Single-use per chain: a consumed salt can never queue again here. Other chains consume the same
        // ceremony's salt independently, which is what makes one signing ceremony multichain.
        if (_usedSalts[account][salt]) {
            revert JustaRecoveryManager_SaltAlreadyUsed(account, salt);
        }

        // Fail fast if the new owner is already registered (would revert at execute). Best-effort only:
        // the owner set can still change during the delay.
        if (MultiOwnable(account).isOwnerBytes(subject)) {
            revert JustaRecoveryManager_SubjectAlreadyOwner(subject);
        }

        // Fail fast if the manager was removed as an owner after setup, so guardians do not burn
        // single-use proofs on a request that can never execute.
        if (!MultiOwnable(account).isOwnerAddress(address(this))) {
            revert JustaRecoveryManager_ManagerNotAccountOwner(account);
        }

        uint256 maxDelay;
        bytes32[] memory recoveryIds = new bytes32[](approvals.length);
        for (uint256 i = 0; i < approvals.length; ++i) {
            bytes32 recoveryId = approvals[i].recoveryId;

            // Must be a registered recovery for this account.
            if (!_recoveryIds[account].contains(recoveryId)) {
                revert JustaRecoveryManager_RecoveryNotRegistered(account, recoveryId);
            }

            // Must be distinct from every earlier approval.
            for (uint256 j = 0; j < i; ++j) {
                if (recoveryIds[j] == recoveryId) {
                    revert JustaRecoveryManager_DuplicateRecovery(recoveryId);
                }
            }
            recoveryIds[i] = recoveryId;

            // Its `(provider, commitment)` are trusted (set at add time, proven registered above), so
            // verification cannot be steered by caller-supplied data.
            Recovery storage recovery = _recoveries[account][recoveryId];

            // The queued delay is the largest among the approving recoveries.
            if (recovery.delay > maxDelay) {
                maxDelay = recovery.delay;
            }

            // Delegate verification; the provider reverts on an invalid proof.
            IRecoveryProvider(recovery.provider)
                .verify(account, subject, salt, expiry, recovery.commitment, approvals[i].proof);
        }

        requestId = keccak256(abi.encode(account, subject, salt));
        _usedSalts[account][salt] = true;

        // Safe: `block.timestamp` plus a `uint32` delay cannot exceed `uint64`.
        uint64 executeAt = uint64(block.timestamp + maxDelay);
        _recoveryRequests[requestId] = RecoveryRequest({ account: account, executeAt: executeAt, subject: subject });

        emit RecoveryRequested(account, requestId, recoveryIds, subject, executeAt);
    }

    /**
     * @notice Finalize a queued recovery request whose delay has elapsed.
     * @dev Unrestricted caller. Registers the new owner from `subject` — a 64-byte passkey via
     *      `addOwnerPublicKey`, or a 32-byte EOA via `addOwnerAddress`.
     * @dev Requires the manager to be a registered owner of the account (set during opt-in).
     * @dev The pending entry is deleted before the external call (CEI); a reverting owner-add rolls the
     *      delete back, so the request stays executable rather than being lost.
     * @param requestId The id returned from `requestRecovery`.
     */
    function executeRecoveryRequest(bytes32 requestId) external nonReentrant {
        RecoveryRequest storage request = _recoveryRequests[requestId];

        // Confirm the request exists.
        if (request.account == address(0)) {
            revert JustaRecoveryManager_RequestNotPending(requestId);
        }

        // Confirm the delay has elapsed.
        if (block.timestamp < request.executeAt) {
            revert JustaRecoveryManager_RequestNotReady(requestId, request.executeAt);
        }

        // Snapshot fields to memory before deletion.
        address account = request.account;
        bytes memory subject = request.subject;

        // The owner-add calls below return nothing, so Solidity emits no code-existence check: against a
        // codeless account they would succeed vacuously, burning the request while adding no owner.
        // Reachable only if a 7702 delegation was revoked during the time-lock.
        if (account.code.length == 0) {
            revert JustaRecoveryManager_AccountHasNoCode(account);
        }

        // Delete the pending entry first (CEI).
        delete _recoveryRequests[requestId];

        // `subject` length selects the owner type (validated at request):
        //   64 bytes => WebAuthn passkey (bytes32 x, bytes32 y); 32 bytes => EOA address.
        if (subject.length == 64) {
            (bytes32 x, bytes32 y) = abi.decode(subject, (bytes32, bytes32));
            MultiOwnable(account).addOwnerPublicKey(x, y);
        } else if (subject.length == 32) {
            address owner = abi.decode(subject, (address));
            MultiOwnable(account).addOwnerAddress(owner);
        } else {
            revert JustaRecoveryManager_InvalidSubjectLength(subject.length);
        }

        emit RecoveryRequestExecuted(account, requestId, subject);
    }

    /**
     * @notice Cancel a queued recovery request before it executes.
     * @dev Callable only by the account named in the request (msg.sender == request.account).
     * @param requestId The id of the pending recovery request to cancel.
     */
    function cancelRecoveryRequest(bytes32 requestId) external {
        _cancelRecoveryRequest(msg.sender, requestId);
    }

    ////////////////////////////////////////////////////////////////////////
    // VIEW FUNCTIONS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice The deterministic id for an account's `(provider, commitment)` recovery.
     */
    function computeRecoveryId(
        address account,
        address provider,
        bytes calldata commitment
    )
        external
        pure
        returns (bytes32)
    {
        return _computeRecoveryId(account, provider, commitment);
    }

    /**
     * @notice Whether a recovery id is registered for an account.
     */
    function hasRecovery(address account, bytes32 recoveryId) external view returns (bool) {
        return _recoveryIds[account].contains(recoveryId);
    }

    /**
     * @notice The recoveries registered for an account.
     */
    function getRecoveries(address account) external view returns (Recovery[] memory recoveries) {
        bytes32[] memory ids = _recoveryIds[account].values();
        recoveries = new Recovery[](ids.length);
        for (uint256 i = 0; i < ids.length; ++i) {
            recoveries[i] = _recoveries[account][ids[i]];
        }
    }

    /**
     * @notice A single registered recovery by id.
     * @dev Returns a zeroed `Recovery` (`provider == address(0)`) if the id is not registered for the
     *      account; pair with `hasRecovery` when the distinction matters.
     */
    function getRecovery(address account, bytes32 recoveryId) external view returns (Recovery memory) {
        return _recoveries[account][recoveryId];
    }

    /**
     * @notice The number of recoveries registered for an account.
     */
    function recoveryCount(address account) external view returns (uint256) {
        return _recoveryIds[account].length();
    }

    /**
     * @notice The account's effective approval threshold (1 if never set).
     */
    function recoveryThreshold(address account) external view returns (uint256) {
        return _effectiveThreshold(account);
    }

    /**
     * @notice Whether `salt` has been consumed for `account` on this chain.
     */
    function isSaltUsed(address account, bytes32 salt) external view returns (bool) {
        return _usedSalts[account][salt];
    }

    /**
     * @notice Compute the chain-agnostic EIP-712 digest an owner must sign to authorize an admin batch.
     * @dev EOA owners sign this digest directly; passkey owners produce a WebAuthn assertion with
     *      `challenge = abi.encode(digest)`. Identical on every chain (the domain omits chainId and the
     *      manager deploys at the same deterministic address everywhere).
     * @param account The smart account whose recovery configuration is administered.
     * @param ops The ordered admin operations.
     * @param salt The batch's single-use salt.
     * @param expiry The signature's expiry timestamp.
     * @return The EIP-712 digest to sign.
     */
    function recoveryAdminDigest(
        address account,
        AdminOp[] calldata ops,
        bytes32 salt,
        uint256 expiry
    )
        external
        view
        returns (bytes32)
    {
        return _recoveryAdminDigest(account, ops, salt, expiry);
    }

    /**
     * @notice The details of a pending recovery request (a zeroed `RecoveryRequest` if not pending).
     * @param requestId The recovery request id.
     * @return The pending request: `account`, `executeAt`, and the new-owner `subject`.
     */
    function recoveryRequest(bytes32 requestId) external view returns (RecoveryRequest memory) {
        return _recoveryRequests[requestId];
    }

    ////////////////////////////////////////////////////////////////////////
    // INTERNAL HELPERS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @dev Effective approval threshold for an account (`0` stored => default `1`).
     */
    function _effectiveThreshold(address account) internal view returns (uint256) {
        uint256 threshold = _recoveryThreshold[account];
        return threshold == 0 ? 1 : threshold;
    }

    /**
     * @dev Deterministic id for an account's `(provider, commitment)` recovery. Takes `memory` so both
     *      doors can call it (the admin door decodes commitments out of the signed ops).
     */
    function _computeRecoveryId(
        address account,
        address provider,
        bytes memory commitment
    )
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(account, provider, commitment));
    }

    /**
     * @dev Shared implementation of `addRecovery`, reached from both doors (`onlyAccount` wrapper and
     *      `executeRecoveryAdmin`).
     * @dev All checks and events live here so the invariants hold identically regardless of the
     *      authorization path.
     */
    function _addRecovery(
        address account,
        address provider,
        bytes memory commitment,
        uint32 delay
    )
        internal
        returns (bytes32 recoveryId)
    {
        if (provider == address(0)) {
            revert JustaRecoveryManager_ZeroProvider();
        }
        if (provider.code.length == 0) {
            revert JustaRecoveryManager_ProviderNotContract(provider);
        }
        if (commitment.length == 0) {
            revert JustaRecoveryManager_EmptyCommitment();
        }
        if (!MultiOwnable(account).isOwnerAddress(address(this))) {
            revert JustaRecoveryManager_ManagerNotAccountOwner(account);
        }

        recoveryId = _computeRecoveryId(account, provider, commitment);
        if (!_recoveryIds[account].add(recoveryId)) {
            revert JustaRecoveryManager_RecoveryAlreadyAdded(account, recoveryId);
        }

        _recoveries[account][recoveryId] = Recovery({ provider: provider, commitment: commitment, delay: delay });

        emit RecoveryAdded(account, delay, recoveryId);
    }

    /**
     * @dev Shared implementation of `removeRecovery`, reached from both doors.
     */
    function _removeRecovery(address account, bytes32 recoveryId) internal {
        // Remove first, then validate the resulting count; a failed check reverts the tx and undoes the
        // removal, so reading the post-removal length directly is safe and avoids `length - 1` math.
        if (!_recoveryIds[account].remove(recoveryId)) {
            revert JustaRecoveryManager_RecoveryNotRegistered(account, recoveryId);
        }

        // Disallow dropping below the threshold (except a full opt-out to zero). With the setter's
        // `threshold <= count` bound, this keeps the invariant `count == 0 || count >= threshold`.
        uint256 newCount = _recoveryIds[account].length();
        if (newCount != 0 && newCount < _effectiveThreshold(account)) {
            revert JustaRecoveryManager_RemovalBelowThreshold(newCount, _effectiveThreshold(account));
        }

        delete _recoveries[account][recoveryId];

        emit RecoveryRemoved(account, recoveryId);
    }

    /**
     * @dev Shared implementation of `setRecoveryThreshold`, reached from both doors.
     */
    function _setRecoveryThreshold(address account, uint256 threshold) internal {
        uint256 count = _recoveryIds[account].length();
        if (threshold < 1 || threshold > count) {
            revert JustaRecoveryManager_InvalidThreshold(threshold, count);
        }

        uint256 oldThreshold = _effectiveThreshold(account);
        _recoveryThreshold[account] = threshold;

        emit RecoveryThresholdChanged(account, oldThreshold, threshold);
    }

    /**
     * @dev Shared implementation of `cancelRecoveryRequest`, reached from both doors. `account` is the
     *      authorized canceller: `msg.sender` on the account door, the digest-bound account on the admin
     *      door.
     * @dev Reverts (rather than no-ops) on a non-pending request so an admin cancel that raced an
     *      in-flight attack leaves its salt unconsumed — the signed cancel stays alive until it actually
     *      cancels.
     */
    function _cancelRecoveryRequest(address account, bytes32 requestId) internal {
        RecoveryRequest storage request = _recoveryRequests[requestId];

        // Confirm the request exists.
        if (request.account == address(0)) {
            revert JustaRecoveryManager_RequestNotPending(requestId);
        }

        // Only the account that the request is for may cancel it.
        if (account != request.account) {
            revert JustaRecoveryManager_NotAccount(account, request.account);
        }

        delete _recoveryRequests[requestId];

        emit RecoveryRequestCancelled(account, requestId);
    }

    /**
     * @dev Build the chain-agnostic EIP-712 digest for an admin batch: hash each op per EIP-712
     *      (`keccak256(abi.encode(ADMIN_OP_TYPEHASH, opType, keccak256(data)))`), hash the ops array as
     *      the concatenation of those hashes, then bind `(account, opsHash, salt, expiry)` under the
     *      sans-chainId domain.
     */
    function _recoveryAdminDigest(
        address account,
        AdminOp[] calldata ops,
        bytes32 salt,
        uint256 expiry
    )
        internal
        view
        returns (bytes32)
    {
        bytes32[] memory opHashes = new bytes32[](ops.length);
        for (uint256 i = 0; i < ops.length; ++i) {
            opHashes[i] = keccak256(abi.encode(ADMIN_OP_TYPEHASH, ops[i].opType, keccak256(ops[i].data)));
        }

        bytes32 structHash = keccak256(
            abi.encode(RECOVERY_ADMIN_TYPEHASH, account, keccak256(abi.encodePacked(opHashes)), salt, expiry)
        );
        return _hashTypedDataSansChainId(structHash);
    }

    /**
     * @dev EIP-712 domain name and version, consumed by Solady's EIP712 base.
     * @dev The domain binds `{name, version, verifyingContract}` — chainId is deliberately absent, and the
     *      deterministic same-address deployment makes admin digests byte-identical on every chain.
     */
    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "JustaRecoveryManager";
        version = "1";
    }

    /**
     * @dev Validate a subject at request time so `executeRecoveryRequest` cannot revert on it after the
     *      delay.
     * @dev A 32-byte subject must fit in an `address` (clean upper bits) so the execute-time
     *      `abi.decode(subject, (address))` succeeds; mirrors `MultiOwnable._initializeOwners`.
     * @dev A 64-byte subject needs no content check — any `(x, y)` decodes and registers without reverting.
     */
    function _validateSubject(bytes calldata subject) internal pure {
        if (subject.length == 64) {
            return;
        }
        if (subject.length == 32) {
            if (uint256(abi.decode(subject, (bytes32))) > type(uint160).max) {
                revert JustaRecoveryManager_InvalidSubject(subject);
            }
            return;
        }
        revert JustaRecoveryManager_InvalidSubjectLength(subject.length);
    }

}
