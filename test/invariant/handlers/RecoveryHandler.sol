// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { Test, console2 } from "forge-std/Test.sol";

import { JustanAccount } from "justanaccount/JustanAccount.sol";

import { PrepareRecovery } from "../../../script/PrepareRecovery.s.sol";
import { JustaRecoveryManager } from "../../../src/JustaRecoveryManager.sol";
import { IRecoveryManager } from "../../../src/interfaces/IRecoveryManager.sol";
import { SignatureRecoveryProvider } from "../../../src/providers/SignatureRecoveryProvider.sol";

/**
 * @title RecoveryHandler
 *
 * @notice The only contract the invariant campaign calls. It wraps `JustaRecoveryManager` so every fuzzed
 *         call is a meaningful one — a correctly signed ceremony, a well-formed admin batch, a deliberate
 *         attack — instead of random bytes that would revert at the first check.
 *
 * @dev Three jobs, following the Foundry handler pattern:
 *        1. Constrain inputs. Raw fuzz values are folded into valid ranges with `bound`, and a call that
 *           has nothing to act on returns early instead of reverting.
 *        2. Keep a MODEL of what the manager must hold (ghost state): the guardian set, threshold, pending
 *           requests and consumed salts for each account. Before each legitimate call the handler predicts
 *           from the model whether it must succeed, then compares that with what the manager actually did.
 *        3. Attack. The `attack*` functions each present something that lacks a required authorization and
 *           must therefore fail on every path.
 * @dev A mismatch or a successful attack is recorded in `violation` rather than asserted here, so the
 *      result does not depend on how the campaign treats handler reverts. The handler itself is written to
 *      never revert; the suite runs with `fail_on_revert = true` so a revert that does happen is surfaced.
 * @dev Two accounts share one manager, one provider and the same guardian keys, so anything that leaked
 *      between accounts would show up as a model mismatch on the other one.
 */
contract RecoveryHandler is Test, PrepareRecovery {

    ////////////////////////////////////////////////////////////////////////
    // TYPES
    ////////////////////////////////////////////////////////////////////////

    /// @dev What the manager must hold for one account.
    struct Model {
        bool[5] registered;
        uint32[5] delay;
        uint256 count;
        uint256 threshold;
    }

    enum RequestState {
        NONE,
        PENDING,
        EXECUTED,
        CANCELLED
    }

    struct Request {
        address account;
        bytes32 id;
        bytes subject;
        uint64 executeAt;
        RequestState state;
    }

    struct SaltUse {
        address account;
        bytes32 salt;
    }

    ////////////////////////////////////////////////////////////////////////
    // CONSTANTS
    ////////////////////////////////////////////////////////////////////////

    uint256 public constant GUARDIANS = 5;

    /// @dev Guardians 0..3 are EOAs; guardian 4 is a raw passkey, so both provider branches are exercised.
    uint256 internal constant PASSKEY_GUARDIAN = 4;
    uint256 internal constant GUARDIAN_PK_BASE = 0x6A0000;
    uint256 internal constant GUARDIAN_PASSKEY_PK = 0x6A55C0DE;

    /// @dev A key that is neither an owner nor a guardian of anything.
    uint256 internal constant STRANGER_PK = 0xBADBAD;

    /// @dev Kept below `MAX_WARP` so that queued requests regularly become executable within a run.
    uint32 internal constant MAX_DELAY = 3 days;
    uint256 internal constant MAX_WARP = 4 days;
    uint256 internal constant ADMIN_WINDOW = 15 minutes;
    uint256 internal constant CEREMONY_WINDOW = 7 days;

    ////////////////////////////////////////////////////////////////////////
    // SYSTEM UNDER TEST
    ////////////////////////////////////////////////////////////////////////

    JustaRecoveryManager public immutable manager;
    SignatureRecoveryProvider public immutable provider;

    address[] public accounts;
    mapping(address account => uint256 pk) internal _ownerPk;

    /// @dev Unprivileged callers: every permissionless function is submitted by one of these.
    address[] public actors;

    bytes[5] internal _commitments;

    ////////////////////////////////////////////////////////////////////////
    // GHOST STATE
    ////////////////////////////////////////////////////////////////////////

    mapping(address account => Model model) internal _model;

    /// @notice Recoveries executed per account: the only way the owner set may grow.
    mapping(address account => uint256 executed) public ghost_executed;

    Request[] internal _requests;
    SaltUse[] internal _ceremonySalts;
    SaltUse[] internal _adminSalts;

    /// @notice First broken expectation or successful attack; empty while everything behaves.
    string public violation;

    /// @notice How often each handler function was called, and how often its main action went through.
    mapping(bytes4 selector => uint256 count) public calls;
    mapping(bytes4 selector => uint256 count) public successes;

    /// @dev The most recent successful ceremony and admin batch, kept to replay them.
    bytes internal _lastCeremony;
    uint256[] internal _lastCeremonyGuardians;
    bytes internal _lastAdminBatch;

    uint256 internal _nonce;

    ////////////////////////////////////////////////////////////////////////
    // SETUP
    ////////////////////////////////////////////////////////////////////////

    constructor(
        JustaRecoveryManager manager_,
        SignatureRecoveryProvider provider_,
        address[] memory accounts_,
        uint256[] memory ownerPks_
    ) {
        manager = manager_;
        provider = provider_;

        for (uint256 i = 0; i < accounts_.length; ++i) {
            accounts.push(accounts_[i]);
            _ownerPk[accounts_[i]] = ownerPks_[i];
            _model[accounts_[i]].threshold = 1; // the manager's default
        }

        for (uint256 i = 0; i < 5; ++i) {
            actors.push(makeAddr(string.concat("actor", vm.toString(i))));
        }

        for (uint256 g = 0; g < PASSKEY_GUARDIAN; ++g) {
            _commitments[g] = encodeEoaCommitment(vm.addr(GUARDIAN_PK_BASE + g));
        }
        (uint256 x, uint256 y) = vm.publicKeyP256(GUARDIAN_PASSKEY_PK);
        _commitments[PASSKEY_GUARDIAN] = encodePasskeyCommitment(bytes32(x), bytes32(y));
    }

    modifier countCall(bytes4 selector) {
        calls[selector]++;
        _;
    }

    ////////////////////////////////////////////////////////////////////////
    // LEGITIMATE ACTIONS — GUARDIAN ADMINISTRATION (both doors)
    ////////////////////////////////////////////////////////////////////////

    function addRecovery(
        uint256 accountSeed,
        uint256 guardian,
        uint32 delay,
        bool viaAdminDoor,
        bool passkeySigner,
        uint256 actorSeed
    )
        external
        countCall(this.addRecovery.selector)
    {
        address account = _account(accountSeed);
        guardian = bound(guardian, 0, GUARDIANS - 1);
        delay = uint32(bound(delay, 0, MAX_DELAY));

        Model memory m = _model[account];
        bool expected = _modelAdd(m, guardian, delay);

        bool ok;
        bytes memory commitment = _commitments[guardian];
        if (viaAdminDoor) {
            ok = _adminBatch(
                account,
                _one(encodeAddRecoveryOp(address(provider), commitment, delay)),
                passkeySigner,
                _actor(actorSeed)
            );
        } else {
            bytes32 expectedId = _recoveryId(account, guardian);
            vm.prank(account);
            try manager.addRecovery(account, address(provider), commitment, delay) returns (bytes32 id) {
                ok = true;
                if (id != expectedId) {
                    _violate("addRecovery returned the wrong id");
                }
            } catch { }
        }

        _settle(account, m, ok, expected, this.addRecovery.selector, "addRecovery");
    }

    function removeRecovery(
        uint256 accountSeed,
        uint256 guardian,
        bool viaAdminDoor,
        bool passkeySigner,
        uint256 actorSeed
    )
        external
        countCall(this.removeRecovery.selector)
    {
        address account = _account(accountSeed);
        guardian = bound(guardian, 0, GUARDIANS - 1);

        Model memory m = _model[account];
        bool expected = _modelRemove(m, guardian);

        bool ok;
        bytes32 id = _recoveryId(account, guardian);
        if (viaAdminDoor) {
            ok = _adminBatch(account, _one(encodeRemoveRecoveryOp(id)), passkeySigner, _actor(actorSeed));
        } else {
            vm.prank(account);
            try manager.removeRecovery(account, id) {
                ok = true;
            } catch { }
        }

        _settle(account, m, ok, expected, this.removeRecovery.selector, "removeRecovery");
    }

    function setRecoveryThreshold(
        uint256 accountSeed,
        uint256 threshold,
        bool viaAdminDoor,
        bool passkeySigner,
        uint256 actorSeed
    )
        external
        countCall(this.setRecoveryThreshold.selector)
    {
        address account = _account(accountSeed);
        Model memory m = _model[account];
        threshold = bound(threshold, 0, m.count + 1); // the valid range plus the invalid 0 and count + 1
        bool expected = _modelSetThreshold(m, threshold);

        bool ok;
        if (viaAdminDoor) {
            ok = _adminBatch(account, _one(encodeSetThresholdOp(threshold)), passkeySigner, _actor(actorSeed));
        } else {
            vm.prank(account);
            try manager.setRecoveryThreshold(account, threshold) {
                ok = true;
            } catch { }
        }

        _settle(account, m, ok, expected, this.setRecoveryThreshold.selector, "setRecoveryThreshold");
    }

    /**
     * @notice A signed batch of two or three mixed operations. It must apply entirely or not at all: the
     *         model applies the ops in order and expects success only if every one of them is valid.
     */
    function adminBatch(
        uint256 accountSeed,
        uint256[3] calldata opSeeds,
        uint256 opCount,
        bool passkeySigner,
        uint256 actorSeed
    )
        external
        countCall(this.adminBatch.selector)
    {
        address account = _account(accountSeed);
        opCount = bound(opCount, 2, 3);

        Model memory m = _model[account];
        bool expected = true;
        IRecoveryManager.AdminOp[] memory ops = new IRecoveryManager.AdminOp[](opCount);

        for (uint256 i = 0; i < opCount; ++i) {
            uint256 seed = opSeeds[i];
            uint256 kind = seed % 3;
            uint256 guardian = (seed >> 8) % GUARDIANS;
            // Three ops in four are steered toward validity so whole batches regularly apply; the fourth
            // is left raw so batches that must revert as a whole are exercised too.
            bool steer = (seed >> 4) % 4 != 0;

            if (kind == 0) {
                if (steer) {
                    guardian = _pickGuardian(m, guardian, false);
                }
                uint32 delay = uint32((seed >> 16) % (uint256(MAX_DELAY) + 1));
                ops[i] = encodeAddRecoveryOp(address(provider), _commitments[guardian], delay);
                if (expected) {
                    expected = _modelAdd(m, guardian, delay);
                }
            } else if (kind == 1) {
                if (steer) {
                    guardian = _pickGuardian(m, guardian, true);
                }
                ops[i] = encodeRemoveRecoveryOp(_recoveryId(account, guardian));
                if (expected) {
                    expected = _modelRemove(m, guardian);
                }
            } else {
                uint256 threshold = steer && m.count != 0 ? 1 + (seed >> 16) % m.count : (seed >> 16) % (GUARDIANS + 2);
                ops[i] = encodeSetThresholdOp(threshold);
                if (expected) {
                    expected = _modelSetThreshold(m, threshold);
                }
            }
        }

        bool ok = _adminBatch(account, ops, passkeySigner, _actor(actorSeed));
        _settle(account, m, ok, expected, this.adminBatch.selector, "adminBatch");
    }

    ////////////////////////////////////////////////////////////////////////
    // LEGITIMATE ACTIONS — RECOVERY LIFECYCLE
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice A correctly signed ceremony from exactly the threshold number of registered guardians. It
     *         must always queue, with the largest delay among the guardians that signed.
     */
    function requestRecovery(
        uint256 accountSeed,
        uint256 subsetSeed,
        bool passkeySubject,
        uint256 actorSeed
    )
        external
        countCall(this.requestRecovery.selector)
    {
        address account = _account(accountSeed);
        Model memory m = _model[account];
        if (m.count == 0) {
            return;
        }

        bytes memory subject = _freshSubject(passkeySubject);
        bytes32 salt = _freshSalt();
        uint256 expiry = block.timestamp + CEREMONY_WINDOW;

        (IRecoveryManager.Approval[] memory approvals, uint256[] memory guardians, uint256 maxDelay) =
            _signCeremony(account, m, subsetSeed, address(manager), account, subject, salt, expiry);

        vm.prank(_actor(actorSeed));
        try manager.requestRecovery(account, subject, salt, expiry, approvals) returns (bytes32 id) {
            successes[this.requestRecovery.selector]++;

            if (id != keccak256(abi.encode(account, subject, salt))) {
                _violate("requestRecovery returned the wrong id");
            }
            uint64 executeAt = manager.recoveryRequest(id).executeAt;
            if (executeAt != block.timestamp + maxDelay) {
                _violate("request queued with the wrong time-lock");
            }

            _requests.push(
                Request({
                    account: account, id: id, subject: subject, executeAt: executeAt, state: RequestState.PENDING
                })
            );
            _ceremonySalts.push(SaltUse(account, salt));

            _lastCeremony = abi.encode(account, subject, salt, expiry, approvals);
            _lastCeremonyGuardians = guardians;
        } catch {
            _violate("a legitimate ceremony was rejected");
        }
    }

    /**
     * @notice Anyone, at any time. Must succeed exactly when the request is pending and its delay is over.
     * @dev With `seekReady` the handler looks for a request that is ready, so executions happen regularly;
     *      without it the request is arbitrary, so early, repeated and post-cancel executions are tried too.
     */
    function executeRecoveryRequest(
        uint256 requestSeed,
        bool seekReady,
        uint256 actorSeed
    )
        external
        countCall(this.executeRecoveryRequest.selector)
    {
        if (_requests.length == 0) {
            return;
        }
        uint256 index = bound(requestSeed, 0, _requests.length - 1);
        if (seekReady) {
            for (uint256 i = 0; i < _requests.length; ++i) {
                uint256 candidate = (index + i) % _requests.length;
                if (
                    _requests[candidate].state == RequestState.PENDING
                        && block.timestamp >= _requests[candidate].executeAt
                ) {
                    index = candidate;
                    break;
                }
            }
        }
        Request storage request = _requests[index];
        bool expected = request.state == RequestState.PENDING && block.timestamp >= request.executeAt;

        bool ok;
        vm.prank(_actor(actorSeed));
        try manager.executeRecoveryRequest(request.id) {
            ok = true;
        } catch { }

        if (ok != expected) {
            _violate(ok ? "a request executed when it must not" : "a ready request failed to execute");
        }
        if (ok) {
            successes[this.executeRecoveryRequest.selector]++;
            request.state = RequestState.EXECUTED;
            ghost_executed[request.account]++;
            if (!JustanAccount(payable(request.account)).isOwnerBytes(request.subject)) {
                _violate("an executed request did not register its owner");
            }
        }
    }

    /// @notice The account cancels through either door. Must succeed exactly when the request is pending.
    function cancelRecoveryRequest(
        uint256 requestSeed,
        bool viaAdminDoor,
        bool passkeySigner,
        uint256 actorSeed
    )
        external
        countCall(this.cancelRecoveryRequest.selector)
    {
        if (_requests.length == 0) {
            return;
        }
        Request storage request = _requests[bound(requestSeed, 0, _requests.length - 1)];
        bool expected = request.state == RequestState.PENDING;

        bool ok;
        if (viaAdminDoor) {
            ok = _adminBatch(request.account, _one(encodeCancelRequestOp(request.id)), passkeySigner, _actor(actorSeed));
        } else {
            vm.prank(request.account);
            try manager.cancelRecoveryRequest(request.id) {
                ok = true;
            } catch { }
        }

        if (ok != expected) {
            _violate(ok ? "a non-pending request was cancelled" : "the account could not cancel its pending request");
        }
        if (ok) {
            successes[this.cancelRecoveryRequest.selector]++;
            request.state = RequestState.CANCELLED;
        }
    }

    /// @notice Lets time-locks elapse.
    function warp(uint256 secondsForward) external countCall(this.warp.selector) {
        vm.warp(block.timestamp + bound(secondsForward, 1, MAX_WARP));
        successes[this.warp.selector]++;
    }

    ////////////////////////////////////////////////////////////////////////
    // ATTACKS — every path here must fail
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice A ceremony in which exactly one approval is wrong in exactly one way. The other approvals are
     *         genuine, so a pass would mean that one missing property is not actually enforced.
     */
    function attackForgedApproval(
        uint256 accountSeed,
        uint256 subsetSeed,
        uint256 variant,
        bytes calldata junk,
        uint256 actorSeed
    )
        external
        countCall(this.attackForgedApproval.selector)
    {
        address account = _account(accountSeed);
        Model memory m = _model[account];
        if (m.count == 0) {
            return;
        }

        bytes memory subject = _freshSubject(false);
        bytes32 salt = _freshSalt();
        uint256 expiry = block.timestamp + CEREMONY_WINDOW;

        (IRecoveryManager.Approval[] memory approvals, uint256[] memory guardians,) =
            _signCeremony(account, m, subsetSeed, address(manager), account, subject, salt, expiry);

        uint256 slot = bound(subsetSeed, 0, approvals.length - 1);
        uint256 guardian = guardians[slot];
        variant = bound(variant, 0, 7);

        bytes memory forged;
        if (variant == 0) {
            forged = junk; // arbitrary bytes
        } else if (variant == 1) {
            // signed by a key that is not this guardian (an EOA key in an EOA slot, likewise for the passkey)
            forged = guardian == PASSKEY_GUARDIAN
                ? signWebAuthnProof(
                    provider.recoverDigest(address(manager), account, subject, salt, expiry), STRANGER_PK
                )
                : signRecoverProof(provider, address(manager), account, subject, salt, expiry, STRANGER_PK);
        } else if (variant == 2) {
            forged = _proof(guardian, address(manager), account, _freshSubject(false), salt, expiry); // other owner
        } else if (variant == 3) {
            forged = _proof(guardian, address(manager), account, subject, _freshSalt(), expiry); // other salt
        } else if (variant == 4) {
            forged = _proof(guardian, address(manager), account, subject, salt, expiry + 1); // other expiry
        } else if (variant == 5) {
            forged = _proof(guardian, address(this), account, subject, salt, expiry); // other manager
        } else if (variant == 6) {
            forged = _proof(guardian, address(manager), _otherAccount(account), subject, salt, expiry); // other account
        } else {
            // a different guardian's genuine signature placed in this guardian's slot
            forged = _proof((guardian + 1) % GUARDIANS, address(manager), account, subject, salt, expiry);
        }
        approvals[slot].proof = forged;

        _expectCeremonyRejected(account, subject, salt, expiry, approvals, actorSeed, "a forged approval was accepted");
    }

    /// @notice Genuine signatures, wrong quantity: one too few, one too many, or one guardian counted twice.
    function attackThresholdBypass(
        uint256 accountSeed,
        uint256 subsetSeed,
        uint256 mode,
        uint256 actorSeed
    )
        external
        countCall(this.attackThresholdBypass.selector)
    {
        address account = _account(accountSeed);
        Model memory m = _model[account];
        if (m.count == 0) {
            return;
        }

        bytes memory subject = _freshSubject(false);
        bytes32 salt = _freshSalt();
        uint256 expiry = block.timestamp + CEREMONY_WINDOW;
        mode = bound(mode, 0, 2);

        IRecoveryManager.Approval[] memory approvals;
        if (mode == 0) {
            // one approval short of the threshold
            if (m.threshold < 2) {
                return;
            }
            m.threshold -= 1;
            (approvals,,) = _signCeremony(account, m, subsetSeed, address(manager), account, subject, salt, expiry);
        } else if (mode == 1) {
            // one approval more than the threshold
            if (m.count <= m.threshold) {
                return;
            }
            m.threshold += 1;
            (approvals,,) = _signCeremony(account, m, subsetSeed, address(manager), account, subject, salt, expiry);
        } else {
            // the threshold number of approvals, all from the same guardian
            if (m.threshold < 2) {
                return;
            }
            (approvals,,) = _signCeremony(account, m, subsetSeed, address(manager), account, subject, salt, expiry);
            for (uint256 i = 1; i < approvals.length; ++i) {
                approvals[i] = approvals[0];
            }
        }

        _expectCeremonyRejected(
            account,
            subject,
            salt,
            expiry,
            approvals,
            actorSeed,
            "a ceremony with the wrong number of guardians was accepted"
        );
    }

    /// @notice A genuine ceremony or admin batch whose expiry has passed.
    function attackExpired(
        uint256 accountSeed,
        uint256 subsetSeed,
        bool passkeySigner,
        uint256 actorSeed
    )
        external
        countCall(this.attackExpired.selector)
    {
        address account = _account(accountSeed);
        Model memory m = _model[account];
        uint256 expiry = block.timestamp - 1;

        if (m.count != 0) {
            bytes memory subject = _freshSubject(false);
            bytes32 salt = _freshSalt();
            (IRecoveryManager.Approval[] memory approvals,,) =
                _signCeremony(account, m, subsetSeed, address(manager), account, subject, salt, expiry);
            _expectCeremonyRejected(
                account, subject, salt, expiry, approvals, actorSeed, "an expired ceremony was accepted"
            );
        }

        IRecoveryManager.AdminOp[] memory ops = _one(encodeSetThresholdOp(1));
        bytes32 adminSalt = _freshSalt();
        (bytes memory ownerBytes, bytes memory proof) = _ownerProof(account, ops, adminSalt, expiry, passkeySigner);
        _expectAdminRejected(
            account, ops, adminSalt, expiry, ownerBytes, proof, actorSeed, "an expired admin batch was applied"
        );
    }

    /**
     * @notice An admin batch that is not authorized by a current owner of the account: signed by the wrong
     *         key, or genuinely signed and then altered, or genuinely signed for the other account.
     */
    function attackUnauthorizedAdmin(
        uint256 accountSeed,
        uint256 guardian,
        uint256 variant,
        bool passkeySigner,
        uint256 actorSeed
    )
        external
        countCall(this.attackUnauthorizedAdmin.selector)
    {
        address account = _account(accountSeed);
        address other = _otherAccount(account);
        guardian = bound(guardian, 0, PASSKEY_GUARDIAN - 1);
        variant = bound(variant, 0, 6);

        // A batch that would be valid if authorized, whatever the current state: add an absent guardian or
        // set the threshold to 1 (a threshold of 1 is only invalid while no guardian is registered).
        IRecoveryManager.AdminOp[] memory ops = _model[account].registered[guardian]
            ? _one(encodeSetThresholdOp(1))
            : _one(encodeAddRecoveryOp(address(provider), _commitments[guardian], 0));
        bytes32 salt = _freshSalt();
        uint256 expiry = block.timestamp + ADMIN_WINDOW;

        bytes memory ownerBytes = abi.encode(vm.addr(_ownerPk[account]));
        bytes memory proof;
        address target = account;

        if (variant == 0) {
            // a stranger signs, claiming to be the owner
            proof = signAdminProof(manager, account, ops, salt, expiry, STRANGER_PK);
        } else if (variant == 1) {
            // a stranger signs as themselves
            ownerBytes = abi.encode(vm.addr(STRANGER_PK));
            proof = signAdminProof(manager, account, ops, salt, expiry, STRANGER_PK);
        } else if (variant == 2) {
            // a guardian signs, claiming to be the owner
            proof = signAdminProof(manager, account, ops, salt, expiry, GUARDIAN_PK_BASE + guardian);
        } else if (variant == 3) {
            // the OTHER account's owner signs this account's batch
            ownerBytes = abi.encode(vm.addr(_ownerPk[other]));
            proof = signAdminProof(manager, account, ops, salt, expiry, _ownerPk[other]);
        } else {
            // the real owner signs, then one signed field is changed before submission
            (ownerBytes, proof) = _ownerProof(account, ops, salt, expiry, passkeySigner);
            if (variant == 4) {
                salt = _freshSalt();
            } else if (variant == 5) {
                expiry += 1;
            } else {
                ops = _one(encodeAddRecoveryOp(address(provider), abi.encode(vm.addr(STRANGER_PK)), 0));
            }
        }

        _expectAdminRejected(
            target, ops, salt, expiry, ownerBytes, proof, actorSeed, "an unauthorized admin batch was applied"
        );
    }

    /// @notice A caller that is not the account uses the account door, including the other account.
    function attackAccountDoor(
        uint256 accountSeed,
        uint256 guardian,
        uint256 requestSeed,
        bool fromOtherAccount,
        uint256 actorSeed
    )
        external
        countCall(this.attackAccountDoor.selector)
    {
        address account = _account(accountSeed);
        address caller = fromOtherAccount ? _otherAccount(account) : _actor(actorSeed);
        guardian = bound(guardian, 0, GUARDIANS - 1);
        bytes memory commitment = _commitments[guardian];
        bytes32 id = _recoveryId(account, guardian);

        vm.prank(caller);
        try manager.addRecovery(account, address(provider), commitment, 0) {
            _violate("a stranger added a guardian through the account door");
        } catch { }

        vm.prank(caller);
        try manager.removeRecovery(account, id) {
            _violate("a stranger removed a guardian through the account door");
        } catch { }

        vm.prank(caller);
        try manager.setRecoveryThreshold(account, 1) {
            _violate("a stranger set the threshold through the account door");
        } catch { }

        if (_requests.length == 0) {
            return;
        }
        Request storage request = _requests[bound(requestSeed, 0, _requests.length - 1)];
        if (caller == request.account) {
            return;
        }
        vm.prank(caller);
        try manager.cancelRecoveryRequest(request.id) {
            _violate("a stranger cancelled a recovery request");
        } catch { }
    }

    /**
     * @notice Re-submit the last ceremony and the last admin batch that succeeded: on the same account (the
     *         salt is spent) and on the other account (the signatures name a different account).
     */
    function attackReplay(uint256 actorSeed) external countCall(this.attackReplay.selector) {
        if (_lastCeremony.length != 0) {
            (
                address account,
                bytes memory subject,
                bytes32 salt,
                uint256 expiry,
                IRecoveryManager.Approval[] memory approvals
            ) = abi.decode(_lastCeremony, (address, bytes, bytes32, uint256, IRecoveryManager.Approval[]));

            vm.prank(_actor(actorSeed));
            try manager.requestRecovery(account, subject, salt, expiry, approvals) {
                _violate("a spent ceremony was replayed");
            } catch { }

            // Same signatures, pointed at the other account's registrations of the same guardians.
            address other = _otherAccount(account);
            for (uint256 i = 0; i < approvals.length; ++i) {
                approvals[i].recoveryId = _recoveryId(other, _lastCeremonyGuardians[i]);
            }
            _expectCeremonyRejected(
                other, subject, salt, expiry, approvals, actorSeed, "a ceremony was replayed on another account"
            );
        }

        if (_lastAdminBatch.length != 0) {
            (
                address account,
                IRecoveryManager.AdminOp[] memory ops,
                bytes32 salt,
                uint256 expiry,
                bytes memory ownerBytes,
                bytes memory proof
            ) = abi.decode(_lastAdminBatch, (address, IRecoveryManager.AdminOp[], bytes32, uint256, bytes, bytes));

            vm.prank(_actor(actorSeed));
            try manager.executeRecoveryAdmin(account, ops, salt, expiry, ownerBytes, proof) {
                _violate("a spent admin batch was replayed");
            } catch { }

            _expectAdminRejected(
                _otherAccount(account),
                ops,
                salt,
                expiry,
                ownerBytes,
                proof,
                actorSeed,
                "an admin batch was replayed on another account"
            );
        }
    }

    ////////////////////////////////////////////////////////////////////////
    // VIEWS FOR THE INVARIANTS
    ////////////////////////////////////////////////////////////////////////

    function accountCount() external view returns (uint256) {
        return accounts.length;
    }

    function model(address account) external view returns (Model memory) {
        return _model[account];
    }

    function commitmentOf(uint256 guardian) external view returns (bytes memory) {
        return _commitments[guardian];
    }

    function recoveryIdOf(address account, uint256 guardian) external view returns (bytes32) {
        return _recoveryId(account, guardian);
    }

    function requestCount() external view returns (uint256) {
        return _requests.length;
    }

    function requestAt(uint256 index) external view returns (Request memory) {
        return _requests[index];
    }

    function ceremonySaltCount() external view returns (uint256) {
        return _ceremonySalts.length;
    }

    function ceremonySaltAt(uint256 index) external view returns (SaltUse memory) {
        return _ceremonySalts[index];
    }

    function adminSaltCount() external view returns (uint256) {
        return _adminSalts.length;
    }

    function adminSaltAt(uint256 index) external view returns (SaltUse memory) {
        return _adminSalts[index];
    }

    /// @notice Logs how often each action ran and went through, to confirm a campaign is not vacuous.
    function callSummary() external view {
        console2.log("--- call summary (calls / successes) ---");
        _logCalls("addRecovery", this.addRecovery.selector);
        _logCalls("removeRecovery", this.removeRecovery.selector);
        _logCalls("setRecoveryThreshold", this.setRecoveryThreshold.selector);
        _logCalls("adminBatch", this.adminBatch.selector);
        _logCalls("requestRecovery", this.requestRecovery.selector);
        _logCalls("executeRecoveryRequest", this.executeRecoveryRequest.selector);
        _logCalls("cancelRecoveryRequest", this.cancelRecoveryRequest.selector);
        _logCalls("warp", this.warp.selector);
        console2.log("--- attacks (attempts) ---");
        console2.log("attackForgedApproval", calls[this.attackForgedApproval.selector]);
        console2.log("attackThresholdBypass", calls[this.attackThresholdBypass.selector]);
        console2.log("attackExpired", calls[this.attackExpired.selector]);
        console2.log("attackUnauthorizedAdmin", calls[this.attackUnauthorizedAdmin.selector]);
        console2.log("attackAccountDoor", calls[this.attackAccountDoor.selector]);
        console2.log("attackReplay", calls[this.attackReplay.selector]);
    }

    ////////////////////////////////////////////////////////////////////////
    // MODEL — the manager's rules, restated independently
    ////////////////////////////////////////////////////////////////////////

    function _modelAdd(Model memory m, uint256 guardian, uint32 delay) internal pure returns (bool) {
        if (m.registered[guardian]) {
            return false;
        }
        m.registered[guardian] = true;
        m.delay[guardian] = delay;
        m.count += 1;
        return true;
    }

    function _modelRemove(Model memory m, uint256 guardian) internal pure returns (bool) {
        if (!m.registered[guardian]) {
            return false;
        }
        uint256 remaining = m.count - 1;
        if (remaining != 0 && remaining < m.threshold) {
            return false;
        }
        m.registered[guardian] = false;
        m.delay[guardian] = 0;
        m.count = remaining;
        return true;
    }

    function _modelSetThreshold(Model memory m, uint256 threshold) internal pure returns (bool) {
        if (threshold < 1 || threshold > m.count) {
            return false;
        }
        m.threshold = threshold;
        return true;
    }

    ////////////////////////////////////////////////////////////////////////
    // INTERNAL HELPERS
    ////////////////////////////////////////////////////////////////////////

    function _account(uint256 seed) internal view returns (address) {
        return accounts[bound(seed, 0, accounts.length - 1)];
    }

    function _otherAccount(address account) internal view returns (address) {
        return account == accounts[0] ? accounts[1] : accounts[0];
    }

    function _actor(uint256 seed) internal view returns (address) {
        return actors[bound(seed, 0, actors.length - 1)];
    }

    function _recoveryId(address account, uint256 guardian) internal view returns (bytes32) {
        return keccak256(abi.encode(account, address(provider), _commitments[guardian]));
    }

    /// @dev The first guardian at or after `start` whose registration matches `registered`; `start` if none.
    function _pickGuardian(Model memory m, uint256 start, bool registered) internal pure returns (uint256) {
        for (uint256 i = 0; i < GUARDIANS; ++i) {
            uint256 g = (start + i) % GUARDIANS;
            if (m.registered[g] == registered) {
                return g;
            }
        }
        return start;
    }

    function _freshSalt() internal returns (bytes32) {
        return keccak256(abi.encode("salt", ++_nonce));
    }

    function _freshSubject(bool passkey) internal returns (bytes memory) {
        uint256 n = ++_nonce;
        if (passkey) {
            return encodePasskeySubject(keccak256(abi.encode("x", n)), keccak256(abi.encode("y", n)));
        }
        return encodeEoaSubject(address(uint160(uint256(keccak256(abi.encode("owner", n))))));
    }

    function _one(IRecoveryManager.AdminOp memory op) internal pure returns (IRecoveryManager.AdminOp[] memory ops) {
        ops = new IRecoveryManager.AdminOp[](1);
        ops[0] = op;
    }

    function _violate(string memory what) internal {
        if (bytes(violation).length == 0) {
            violation = what;
        }
    }

    function _logCalls(string memory name, bytes4 selector) internal view {
        console2.log(name, calls[selector], successes[selector]);
    }

    /// @dev Compare the manager's answer with the model's prediction, and commit the model on success.
    function _settle(
        address account,
        Model memory m,
        bool ok,
        bool expected,
        bytes4 selector,
        string memory name
    )
        internal
    {
        if (ok != expected) {
            _violate(
                string.concat(
                    name,
                    ok ? " succeeded when the model says it must fail" : " failed when the model says it must succeed"
                )
            );
        }
        if (ok) {
            _model[account] = m;
            successes[selector]++;
        }
    }

    /// @dev One guardian's genuine proof over the given ceremony fields.
    function _proof(
        uint256 guardian,
        address forManager,
        address forAccount,
        bytes memory subject,
        bytes32 salt,
        uint256 expiry
    )
        internal
        view
        returns (bytes memory)
    {
        if (guardian == PASSKEY_GUARDIAN) {
            return signWebAuthnProof(
                provider.recoverDigest(forManager, forAccount, subject, salt, expiry), GUARDIAN_PASSKEY_PK
            );
        }
        return signRecoverProof(provider, forManager, forAccount, subject, salt, expiry, GUARDIAN_PK_BASE + guardian);
    }

    /**
     * @dev Genuine approvals from `m.threshold` distinct registered guardians of `account`, starting at a
     *      seed-chosen position in the registered set. Returns the guardians used and their largest delay.
     */
    function _signCeremony(
        address account,
        Model memory m,
        uint256 subsetSeed,
        address forManager,
        address forAccount,
        bytes memory subject,
        bytes32 salt,
        uint256 expiry
    )
        internal
        view
        returns (IRecoveryManager.Approval[] memory approvals, uint256[] memory guardians, uint256 maxDelay)
    {
        uint256[] memory registered = new uint256[](m.count);
        uint256 n;
        for (uint256 g = 0; g < GUARDIANS; ++g) {
            if (m.registered[g]) {
                registered[n++] = g;
            }
        }

        uint256 start = bound(subsetSeed, 0, n - 1);
        approvals = new IRecoveryManager.Approval[](m.threshold);
        guardians = new uint256[](m.threshold);
        for (uint256 k = 0; k < m.threshold; ++k) {
            uint256 g = registered[(start + k) % n];
            guardians[k] = g;
            approvals[k] =
                createApproval(_recoveryId(account, g), _proof(g, forManager, forAccount, subject, salt, expiry));
            if (m.delay[g] > maxDelay) {
                maxDelay = m.delay[g];
            }
        }
    }

    /// @dev The real owner's proof over an admin batch: the EOA owner, or the passkey owner.
    function _ownerProof(
        address account,
        IRecoveryManager.AdminOp[] memory ops,
        bytes32 salt,
        uint256 expiry,
        bool passkeySigner
    )
        internal
        view
        returns (bytes memory ownerBytes, bytes memory proof)
    {
        if (passkeySigner) {
            (uint256 x, uint256 y) = vm.publicKeyP256(PASSKEY_PK);
            ownerBytes = abi.encode(x, y);
            proof = signAdminProofPasskey(manager, account, ops, salt, expiry, PASSKEY_PK);
        } else {
            ownerBytes = abi.encode(vm.addr(_ownerPk[account]));
            proof = signAdminProof(manager, account, ops, salt, expiry, _ownerPk[account]);
        }
    }

    /// @dev Submit a genuinely owner-signed batch through the admin door and record its salt on success.
    function _adminBatch(
        address account,
        IRecoveryManager.AdminOp[] memory ops,
        bool passkeySigner,
        address actor
    )
        internal
        returns (bool ok)
    {
        bytes32 salt = _freshSalt();
        uint256 expiry = block.timestamp + ADMIN_WINDOW;
        (bytes memory ownerBytes, bytes memory proof) = _ownerProof(account, ops, salt, expiry, passkeySigner);

        vm.prank(actor);
        try manager.executeRecoveryAdmin(account, ops, salt, expiry, ownerBytes, proof) {
            ok = true;
            _adminSalts.push(SaltUse(account, salt));
            _lastAdminBatch = abi.encode(account, ops, salt, expiry, ownerBytes, proof);
        } catch {
            if (manager.isAdminSaltUsed(account, salt)) {
                _violate("a reverted admin batch consumed its salt");
            }
        }
    }

    function _expectCeremonyRejected(
        address account,
        bytes memory subject,
        bytes32 salt,
        uint256 expiry,
        IRecoveryManager.Approval[] memory approvals,
        uint256 actorSeed,
        string memory what
    )
        internal
    {
        bool usedBefore = manager.isSaltUsed(account, salt);
        vm.prank(_actor(actorSeed));
        try manager.requestRecovery(account, subject, salt, expiry, approvals) {
            _violate(what);
        } catch {
            if (!usedBefore && manager.isSaltUsed(account, salt)) {
                _violate("a rejected ceremony consumed its salt");
            }
        }
    }

    function _expectAdminRejected(
        address account,
        IRecoveryManager.AdminOp[] memory ops,
        bytes32 salt,
        uint256 expiry,
        bytes memory ownerBytes,
        bytes memory proof,
        uint256 actorSeed,
        string memory what
    )
        internal
    {
        bool usedBefore = manager.isAdminSaltUsed(account, salt);
        vm.prank(_actor(actorSeed));
        try manager.executeRecoveryAdmin(account, ops, salt, expiry, ownerBytes, proof) {
            _violate(what);
        } catch {
            if (!usedBefore && manager.isAdminSaltUsed(account, salt)) {
                _violate("a rejected admin batch consumed its salt");
            }
        }
    }

}
