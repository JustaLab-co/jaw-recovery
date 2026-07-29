// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @title IRecoveryManager
 *
 * @notice Recovery coordinator serving all JustanAccount instances, so every account-scoped function
 *         takes an explicit `account`.
 *
 * @dev The unit of recovery is a "recovery": a `(provider, commitment)` pair plus a per-recovery
 *      time-lock `delay`. The same provider may back several recoveries for one account, each with its
 *      own delay. The manager owns the recoveries, the per-account used-salt registry, and the approval
 *      threshold; providers are stateless verifiers (see {IRecoveryProvider}).
 * @dev Recovery is a two-step time-locked flow: `requestRecovery` verifies one proof per recovery for the
 *      account's threshold of distinct recoveries and queues a request at `block.timestamp + maxDelay`
 *      (the largest delay among the approving recoveries), then `executeRecoveryRequest` registers the new
 *      owner once that delay elapses. The account may `cancelRecoveryRequest` during the window.
 *
 * @author JustaLab
 */
interface IRecoveryManager {

    ////////////////////////////////////////////////////////////////////////
    // ERRORS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Thrown when the provider address is zero.
     */
    error JustaRecoveryManager_ZeroProvider();

    /**
     * @notice Thrown when the provider address has no contract code (e.g. an EOA or a typo).
     * @dev Checked at registration so the failure surfaces while the account can still fix it, rather
     *      than at recovery time when the account is locked out.
     * @param provider The offending provider address.
     */
    error JustaRecoveryManager_ProviderNotContract(address provider);

    /**
     * @notice Thrown when the commitment is empty.
     */
    error JustaRecoveryManager_EmptyCommitment();

    /**
     * @notice Thrown when the recovery manager is not registered as an owner of `account`.
     * @dev Either the account never opted in (never called `addOwnerAddress(address(manager))`), or the
     *      manager was later removed as an owner.
     * @param account The smart account.
     */
    error JustaRecoveryManager_ManagerNotAccountOwner(address account);

    /**
     * @notice Thrown when adding a recovery that is already registered for the account.
     * @param account The smart account.
     * @param recoveryId The recovery id (`keccak256(abi.encode(account, provider, commitment))`).
     */
    error JustaRecoveryManager_RecoveryAlreadyAdded(address account, bytes32 recoveryId);

    /**
     * @notice Thrown when the recovery is not registered for the account.
     * @param account The smart account.
     * @param recoveryId The recovery id.
     */
    error JustaRecoveryManager_RecoveryNotRegistered(address account, bytes32 recoveryId);

    /**
     * @notice Thrown when the same recovery appears more than once in `requestRecovery`.
     * @param recoveryId The duplicated recovery id.
     */
    error JustaRecoveryManager_DuplicateRecovery(bytes32 recoveryId);

    /**
     * @notice Thrown when the caller is not the account named in the call.
     * @param caller The actual caller.
     * @param account The expected account.
     */
    error JustaRecoveryManager_NotAccount(address caller, address account);

    /**
     * @notice Thrown when a threshold is outside `[1, recoveryCount]`.
     * @param requested The requested threshold.
     * @param recoveryCount The account's current number of registered recoveries.
     */
    error JustaRecoveryManager_InvalidThreshold(uint256 requested, uint256 recoveryCount);

    /**
     * @notice Thrown when removing a recovery would drop the count below the account's threshold.
     * @param newCount The recovery count that would remain after removal.
     * @param threshold The account's current effective threshold.
     */
    error JustaRecoveryManager_RemovalBelowThreshold(uint256 newCount, uint256 threshold);

    /**
     * @notice Thrown when the number of submitted approvals does not equal the account's threshold.
     * @param submitted The number of approvals submitted.
     * @param required The account's effective threshold.
     */
    error JustaRecoveryManager_InvalidApprovalCount(uint256 submitted, uint256 required);

    /**
     * @notice Thrown when the ceremony's `expiry` has passed at request time.
     * @dev Expiry bounds how long unused guardian proofs stay usable; it has no effect on a request once
     *      queued.
     * @param expiry The expired ceremony deadline.
     */
    error JustaRecoveryManager_ProofsExpired(uint256 expiry);

    /**
     * @notice Thrown when `subject` is not 32 bytes (EOA owner) or 64 bytes (passkey owner).
     * @param length The length of the supplied subject.
     */
    error JustaRecoveryManager_InvalidSubjectLength(uint256 length);

    /**
     * @notice Thrown when a 32-byte `subject` does not fit in an `address` (dirty upper bits).
     * @dev Validated at request so `executeRecoveryRequest`'s `abi.decode(subject, (address))` cannot
     *      revert after the delay has elapsed.
     * @param subject The offending subject.
     */
    error JustaRecoveryManager_InvalidSubject(bytes subject);

    /**
     * @notice Thrown when the ceremony's `salt` was already consumed for `account` on this chain.
     * @dev Consumption makes a ceremony's proofs single-use per chain; other chains consume the same salt
     *      independently.
     * @param account The smart account.
     * @param salt The already-consumed salt.
     */
    error JustaRecoveryManager_SaltAlreadyUsed(address account, bytes32 salt);

    /**
     * @notice Thrown when `subject` is already an owner of the account at request time.
     * @dev A best-effort fail-fast: the owner set can change during the delay, so this does not guarantee
     *      `executeRecoveryRequest` won't later revert with `MultiOwnable_AlreadyOwner`.
     * @param subject The new-owner payload that is already registered.
     */
    error JustaRecoveryManager_SubjectAlreadyOwner(bytes subject);

    /**
     * @notice Thrown when a request id does not correspond to a pending recovery request.
     * @param requestId The recovery request id.
     */
    error JustaRecoveryManager_RequestNotPending(bytes32 requestId);

    /**
     * @notice Thrown when `executeRecoveryRequest` is called before the request's `executeAt` timestamp.
     * @param requestId The recovery request id.
     * @param executeAt The timestamp at which the request becomes executable.
     */
    error JustaRecoveryManager_RequestNotReady(bytes32 requestId, uint64 executeAt);

    /**
     * @notice Thrown when `executeRecoveryRequest` targets an account with no code.
     * @dev The owner-add calls return nothing, so Solidity emits no code-existence check; without this
     *      guard they would succeed vacuously against a codeless address, deleting the request and
     *      emitting success while registering no owner.
     * @dev Unreachable for CREATE2 accounts (code never disappears); reachable for an EIP-7702 account
     *      whose key holder revoked the delegation during the time-lock.
     * @param account The codeless account.
     */
    error JustaRecoveryManager_AccountHasNoCode(address account);

    /**
     * @notice Thrown when `executeRecoveryAdmin` is called with an empty ops array.
     */
    error JustaRecoveryManager_EmptyAdminOps();

    /**
     * @notice Thrown when an admin op's `opType` is not a member of {AdminOpType}.
     * @dev Reverts the whole batch (ops are applied atomically).
     * @param opType The unknown op type.
     */
    error JustaRecoveryManager_InvalidAdminOp(uint8 opType);

    /**
     * @notice Thrown when the admin signer identified by `ownerBytes` is not a current owner of the account.
     * @dev Checked at submission time on each chain, so signatures from a since-removed owner die
     *      automatically.
     * @param account The smart account.
     * @param ownerBytes The rejected signer, in canonical MultiOwnable owner-bytes form.
     */
    error JustaRecoveryManager_SignerNotAccountOwner(address account, bytes ownerBytes);

    /**
     * @notice Thrown when the admin proof does not verify against `ownerBytes` over the batch digest.
     */
    error JustaRecoveryManager_InvalidOwnerProof();

    ////////////////////////////////////////////////////////////////////////
    // TYPES
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice The admin operations executable through `executeRecoveryAdmin`.
     */
    enum AdminOpType {
        ADD_RECOVERY,
        REMOVE_RECOVERY,
        SET_THRESHOLD,
        CANCEL_REQUEST
    }

    /**
     * @notice One admin operation inside a signed `RecoveryAdmin` batch.
     * @dev `opType` is a `uint8` rather than the enum so the struct matches the signed EIP-712 type exactly
     *      (EIP-712 has no enum type) and an out-of-range value reaches the manager's own `InvalidAdminOp`
     *      revert instead of an ABI-decoding panic.
     * @dev `data` encodings by op type:
     *        ADD_RECOVERY    => `abi.encode(address provider, bytes commitment, uint32 delay)`
     *        REMOVE_RECOVERY => `abi.encode(bytes32 recoveryId)`
     *        SET_THRESHOLD   => `abi.encode(uint256 threshold)`
     *        CANCEL_REQUEST  => `abi.encode(bytes32 requestId)`
     */
    struct AdminOp {
        uint8 opType;
        bytes data;
    }

    /**
     * @notice A registered recovery: a provider, the commitment it verifies against, and the time-lock
     *         delay applied when this recovery participates in a request.
     */
    struct Recovery {
        address provider;
        bytes commitment;
        uint32 delay;
    }

    /**
     * @notice One recovery's approval submitted to `requestRecovery`.
     * @dev `recoveryId` must identify a registered recovery for the account; the manager looks up its
     *      stored `(provider, commitment)` and verifies `proof` against them.
     */
    struct Approval {
        bytes32 recoveryId;
        bytes proof;
    }

    /**
     * @notice A queued recovery request awaiting execution.
     * @dev `account == address(0)` is the sentinel for "not present": a request is only written for an
     *      account that registered a recovery, and registration requires `msg.sender == account`, so
     *      `address(0)` can never be the subject of a request.
     * @dev The implementation packs `account` (20 bytes) and `executeAt` (8 bytes) into one storage slot.
     */
    struct RecoveryRequest {
        address account;
        uint64 executeAt;
        bytes subject;
    }

    ////////////////////////////////////////////////////////////////////////
    // EVENTS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @dev Events reference recoveries by `recoveryId` only, which is not reversible on-chain; resolve it
     *      via `getRecoveries(account)`. Callers that need the preimage of a removed recovery must retain
     *      it off-chain at `addRecovery` time.
     */
    event RecoveryAdded(address indexed account, uint32 delay, bytes32 indexed recoveryId);
    event RecoveryRemoved(address indexed account, bytes32 indexed recoveryId);
    event RecoveryThresholdChanged(address indexed account, uint256 oldThreshold, uint256 newThreshold);
    event RecoveryRequested(
        address indexed account, bytes32 indexed requestId, bytes32[] recoveryIds, bytes subject, uint64 executeAt
    );
    event RecoveryRequestExecuted(address indexed account, bytes32 indexed requestId, bytes subject);
    event RecoveryRequestCancelled(address indexed account, bytes32 indexed requestId);
    /// @dev Envelope event for a signed admin batch (per-op events still fire individually). `salt`
    ///      identifies the batch across chains for indexers, mirroring `requestId` for ceremonies.
    event RecoveryAdminExecuted(address indexed account, bytes32 salt, uint256 opsCount);

    ////////////////////////////////////////////////////////////////////////
    // RECOVERY ADMIN
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Register a recovery for an account.
     * @dev Callable only by the account.
     * @dev The same `provider` may be registered with different `commitment`s. Reverts if the
     *      `(provider, commitment)` recovery already exists.
     * @dev To change a recovery's `delay`, remove it and add it again.
     * @param account The smart account.
     * @param provider The recovery provider (a stateless verifier); must be a contract.
     * @param commitment Provider-specific commitment bytes (e.g. `abi.encode(eoa)`, an email hash).
     * @param delay The per-recovery time-lock in seconds applied when this recovery approves a request
     *        (`0` = instant; no upper bound beyond the `uint32` type).
     * @return recoveryId The registered recovery's id (`keccak256(abi.encode(account, provider, commitment))`).
     */
    function addRecovery(
        address account,
        address provider,
        bytes calldata commitment,
        uint32 delay
    )
        external
        returns (bytes32 recoveryId);

    /**
     * @notice Unregister a recovery for an account.
     * @dev Callable only by the account.
     * @dev Rejected if it would drop the recovery count below the threshold, unless it removes the last
     *      recovery (a full opt-out to zero).
     * @param account The smart account.
     * @param recoveryId The recovery id to remove (`keccak256(abi.encode(account, provider, commitment))`).
     */
    function removeRecovery(address account, bytes32 recoveryId) external;

    /**
     * @notice Set the per-account approval threshold (how many recoveries must approve a request).
     * @dev Callable only by the account. Must be within `[1, recoveryCount(account)]`.
     * @param account The smart account.
     * @param threshold The number of distinct recoveries required to approve a request.
     */
    function setRecoveryThreshold(address account, uint256 threshold) external;

    /**
     * @notice Execute a batch of admin operations authorized by a chain-agnostic signature from a current
     *         owner of `account` — the multichain door.
     * @dev Unrestricted caller; the owner signature carries authorization, so a relayer can fan the same
     *      bytes out to every chain. The `onlyAccount` functions above remain the single-chain door; both
     *      apply the identical internal logic.
     * @dev The signed digest omits `chainId` (the manager deploys at the same deterministic address on
     *      every chain) and binds `(account, ops, salt, expiry)`; see `recoveryAdminDigest`.
     * @dev `salt` shares the ceremony registry: single-use per chain, reusable across chains until `expiry`.
     * @dev The signer must be a CURRENT owner of `account` in canonical owner-bytes form — 32-byte
     *      `abi.encode(address)` (EOA, strict ecrecover) or 64-byte `abi.encode(x, y)` (raw passkey,
     *      direct WebAuthn). A smart-account owner cannot sign chain-agnostically (its ERC-1271 door binds
     *      chainId) and must use the account door instead.
     * @dev Ops are applied in order, atomically: any failing op (including an unknown `opType`) reverts the
     *      whole batch on this chain.
     * @param account The smart account whose recovery configuration is administered.
     * @param ops The ordered admin operations (see {AdminOp} for per-type `data` encodings).
     * @param salt The batch's single-use salt (random 32 bytes chosen off-chain).
     * @param expiry The signature's expiry timestamp; bounds how long the unsubmitted batch stays usable.
     * @param ownerBytes The authorizing owner in canonical MultiOwnable owner-bytes form.
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
        external;

    ////////////////////////////////////////////////////////////////////////
    // EXECUTION
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Queue a recovery request once the threshold of distinct recoveries have approved the same
     *         new owner.
     * @dev Unrestricted caller; the proofs carry authorization. Requires exactly
     *      `recoveryThreshold(account)` distinct, registered recoveries, each verifying a proof over the
     *      same `(subject, salt, expiry)` ceremony.
     * @dev `salt` must be unused for the account on this chain and is consumed on success, making the
     *      proofs single-use per chain; the same ceremony stays submittable on other chains.
     * @dev Reverts once `expiry` has passed. The queued `executeAt` uses the largest delay among the
     *      approving recoveries.
     * @param account The smart account to recover.
     * @param subject ABI-encoded new owner: `abi.encode(address)` (32B) or `abi.encode(bytes32 x, bytes32 y)` (64B).
     * @param salt The ceremony's single-use salt (random 32 bytes chosen off-chain).
     * @param expiry The ceremony's expiry timestamp; requests revert after it.
     * @param approvals One approval per required recovery: the recovery's id plus its proof.
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
        returns (bytes32 requestId);

    /**
     * @notice Finalize a queued recovery request whose delay has elapsed.
     * @dev Unrestricted caller. Registers the new owner from `subject` — a 64-byte passkey via
     *      `addOwnerPublicKey`, or a 32-byte EOA via `addOwnerAddress`.
     * @dev Reverts if the request is not pending or its `executeAt` has not yet been reached.
     * @param requestId The id returned from `requestRecovery`.
     */
    function executeRecoveryRequest(bytes32 requestId) external;

    /**
     * @notice Cancel a queued recovery request before it executes.
     * @dev Callable only by the account that the request is for (msg.sender == request.account).
     * @param requestId The id of the pending recovery request to cancel.
     */
    function cancelRecoveryRequest(bytes32 requestId) external;

    ////////////////////////////////////////////////////////////////////////
    // VIEW FUNCTIONS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice The deterministic id for an account's `(provider, commitment)` recovery.
     * @return The recovery id (`keccak256(abi.encode(account, provider, commitment))`).
     */
    function computeRecoveryId(
        address account,
        address provider,
        bytes calldata commitment
    )
        external
        pure
        returns (bytes32);

    /**
     * @notice Whether a recovery id is registered for an account.
     */
    function hasRecovery(address account, bytes32 recoveryId) external view returns (bool);

    /**
     * @notice The recoveries registered for an account.
     */
    function getRecoveries(address account) external view returns (Recovery[] memory);

    /**
     * @notice A single registered recovery by id.
     * @dev Returns a zeroed `Recovery` (`provider == address(0)`) if the id is not registered for the
     *      account; pair with `hasRecovery` when the distinction matters.
     * @param account The smart account.
     * @param recoveryId The recovery id.
     * @return The registered recovery (`provider`, `commitment`, `delay`).
     */
    function getRecovery(address account, bytes32 recoveryId) external view returns (Recovery memory);

    /**
     * @notice The number of recoveries registered for an account.
     */
    function recoveryCount(address account) external view returns (uint256);

    /**
     * @notice The account's effective approval threshold (1 if never set).
     */
    function recoveryThreshold(address account) external view returns (uint256);

    /**
     * @notice Whether `salt` has been consumed for `account` on this chain.
     * @dev A salt is consumed by a successful `requestRecovery` and can never queue again here; the same
     *      ceremony stays submittable on chains that have not consumed it.
     */
    function isSaltUsed(address account, bytes32 salt) external view returns (bool);

    /**
     * @notice Compute the chain-agnostic EIP-712 digest an owner must sign to authorize an admin batch.
     * @dev EOA owners sign this digest directly; passkey owners produce a WebAuthn assertion with
     *      `challenge = abi.encode(digest)`.
     * @dev Identical on every chain (the domain omits chainId and the manager deploys at the same
     *      deterministic address everywhere).
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
        returns (bytes32);

    /**
     * @notice The details of a pending recovery request (a zeroed `RecoveryRequest` if not pending).
     * @param requestId The recovery request id.
     * @return The pending request: `account`, `executeAt`, and the new-owner `subject`.
     */
    function recoveryRequest(bytes32 requestId) external view returns (RecoveryRequest memory);

}
