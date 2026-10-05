# JustaRecoveryManager

> **🚧 Active development — not audited, not deployed.** This module is under active design and review. Interfaces, storage layout, and behavior may change without notice. Do not deploy to production or integrate against it until it has completed a security audit and a versioned release is tagged.

## Overview

`JustaRecoveryManager` is a Solidity smart contract that provides M-of-N, time-locked account recovery for [JustanAccount](https://github.com/justaname-id/justanaccount) smart accounts. An account opts in by registering the manager as one of its owners; if its keys are later lost, a pre-configured set of recovery factors can — after a per-factor time-lock — register a new owner (a WebAuthn passkey or an EOA) on the account.

The manager is a non-ownable, non-upgradeable singleton (one deployment serves every account on a chain). It owns all per-account recovery state and treats recovery providers as **stateless verifiers**: on each approval it calls `provider.verify(...)`, which reverts on an invalid proof. Provider trust is therefore equivalent to provider correctness.

Recovery is **multichain by design**: guardians sign one chain-agnostic ceremony, and the same proof bytes queue the recovery on every chain the account enrolled on (each chain consumes the ceremony's single-use salt independently, and the `requestId` is identical everywhere). This repository ships the canonical provider, `SignatureRecoveryProvider`, which verifies EOA guardians (strict ECDSA) and raw-pubkey passkey guardians (direct WebAuthn) against a chain-free EIP-712 digest.

## Features

- **M-of-N Threshold**: Require any `M` of an account's `N` registered recoveries to approve, defaulting to 1. Counted by distinct recovery, not by provider.
- **Per-Recovery Time-Lock**: Each recovery carries its own delay (in seconds), set at registration. A queued request uses the **largest** delay among the approving recoveries, so a request is only as fast as its most-cautious factor.
- **Owner-Type Agnostic**: A recovery can install a new WebAuthn passkey (64-byte `subject`) or a new EOA (32-byte `subject`); the manager dispatches on length at execution.
- **Stateless, Pluggable Providers**: Any contract implementing `IRecoveryProvider` can serve as a factor. The manager owns the commitments, the used-salt registry, and the expiry check and passes everything in on every call, so one provider deployment backs any number of factors for any number of accounts.
- **Sign-Once Multichain Ceremonies**: A ceremony is `(subject, salt, expiry)` signed once by each guardian over a chain-agnostic digest. Each chain's manager consumes the salt independently — single-use per chain, reusable across chains — and derives the same `requestId` everywhere.
- **Single-Use, Expiring Proofs**: The ceremony's random salt makes proofs single-use per chain; the ceremony's `expiry` (enforced by the manager at request time) bounds how long unused, leaked proofs stay usable.
- **Two-Step Flow with Veto**: `requestRecovery` queues a request; after the delay, anyone may `executeRecoveryRequest`. During the window the account itself may `cancelRecoveryRequest` to abort.
- **Permissionless Initiation/Execution**: The proofs carry authorization, so a relayer can request and execute on behalf of a locked-out user.
- **Lockout Prevention**: A threshold can never exceed the registered count, and a recovery cannot be removed below the threshold (except a full opt-out to zero).
- **Fail-Fast Subject Validation**: A new-owner `subject` is validated at request time (canonical address, and rejected if it is already an owner) so a request cannot silently queue and then revert at execution.
- **Reentrancy Protection**: State-changing recovery functions are guarded by a contract-wide reentrancy lock.

## Architecture

The system consists of a coordinator, a provider interface, and one concrete provider.

### JustaRecoveryManager (Main Contract)

The singleton coordinator that owns all per-account state (registered recoveries, approval threshold, used-salt registry) and queued recovery requests. It inherits from:

- `IRecoveryManager` (the manager's interface — errors, events, types, and function signatures)
- `ReentrancyGuard` (Solady's reentrancy protection)

#### Key Libraries Used

- `EnumerableSet` (OpenZeppelin) — per-account set of registered recovery ids
- `MultiOwnable` (JustanAccount) — owner registration on the target account (`addOwnerAddress` / `addOwnerPublicKey` / `isOwnerBytes`)

### IRecoveryProvider (Interface)

The stateless verifier standard every provider implements:

```solidity
interface IRecoveryProvider {
    function verify(
        address account,
        bytes calldata subject,
        bytes32 salt,
        uint256 expiry,
        bytes calldata commitment,
        bytes calldata proof
    ) external;
}
```

All implementations MUST revert on an invalid proof, bind the proof to all of `(account, subject, salt, expiry)`, and verify against exactly one `commitment` (so one proof cannot satisfy several recoveries of the same provider). Providers shipped in this repository MUST additionally be **multichain**: derive the proven message exclusively from that chain-agnostic tuple (never `block.chainid`), never route verification through a chain-binding intermediary (e.g. a third-party ERC-1271 door), and deploy deterministically at the same address on every chain. Third-party providers MAY be chain-bound; their factors are then valid on a single chain only.

### SignatureRecoveryProvider (Canonical Provider)

A stateless, chain-agnostic signature verifier serving two guardian classes, dispatched on commitment length:

- **32-byte commitment** (`abi.encode(eoa)`) — an EOA guardian. Proof = a 64/65-byte ECDSA signature over the digest, verified with **strict `ecrecover` only** (deliberately no ERC-1271/6492 fallback, so a chain-bound smart-account envelope can never re-enter; smart accounts cannot be guardians on this provider).
- **64-byte commitment** (`abi.encode(x, y)`) — a raw P-256 passkey public key. Proof = an ABI-encoded WebAuthn assertion whose challenge is the digest, verified directly in the provider, byte-for-byte the convention JustanAccount uses for its own passkey owners. Undeployed passkey guardians work natively — no ERC-6492 infrastructure.

The EIP-712 domain omits `chainId` (Solady `_hashTypedDataSansChainId`); with the deterministic same-address deployment the digest is byte-identical on every chain. It inherits from:

- `IRecoveryProvider`
- `EIP712` (Solady) — the sans-chainId domain binds proofs to this provider deployment (same address everywhere)

#### Key Libraries Used

- `ECDSA` (Solady) — strict signature recovery for EOA guardians
- `WebAuthn` + `P256` (Solady) — direct passkey assertion verification (requires the RIP-7212 precompile or the canonical P256 verifier per chain — the same dependency JustanAccount itself has)

## Data Structures

### Recovery

A registered recovery factor:

```solidity
struct Recovery {
    address provider;     // the verifier contract
    bytes commitment;     // provider-specific identity (e.g. abi.encode(eoa))
    uint32 delay;         // per-recovery time-lock in seconds
}
```

### Approval

One recovery's approval submitted to `requestRecovery`:

```solidity
struct Approval {
    bytes32 recoveryId;   // identifies a registered recovery for the account
    bytes proof;          // provider-specific proof (verified against the stored commitment)
}
```

### RecoveryRequest

A queued recovery awaiting execution (`account == address(0)` means "not present"):

```solidity
struct RecoveryRequest {
    address account;      // the account being recovered
    uint64 executeAt;     // timestamp the request becomes executable
    bytes subject;        // the new owner: abi.encode(address) (32B) or abi.encode(x, y) (64B)
}
```

## Identifiers

- **`recoveryId`** = `keccak256(abi.encode(account, provider, commitment))` — identifies a registered recovery. Account-scoped, so the same factor under two accounts yields different ids.
- **`requestId`** = `keccak256(abi.encode(account, subject, salt))` — identifies a queued request; deterministic, single-use (the salt is consumed), and **identical on every chain** for one ceremony.
- **`SignatureRecoveryProvider.RECOVER_TYPEHASH`** = `keccak256("Recover(address account,bytes subject,bytes32 salt,uint256 expiry)")`.

## Key Functions

### Account Owner Functions

Callable only by the account (`msg.sender == account`):

- `addRecovery(address account, address provider, bytes commitment, uint32 delay)`: Register a recovery and return its `recoveryId`. The provider must be a contract; the commitment must be non-empty.
- `removeRecovery(address account, bytes32 recoveryId)`: Unregister a recovery. Rejected if it would drop the count below the threshold, unless it removes the last one (full opt-out).
- `setRecoveryThreshold(address account, uint256 threshold)`: Set the approval threshold, bounded to `[1, recoveryCount(account)]`.

### Execution Functions

- `requestRecovery(address account, bytes subject, bytes32 salt, uint256 expiry, Approval[] approvals)`: Queue a request. Unrestricted caller; the proofs carry authorization. Requires exactly `recoveryThreshold(account)` distinct, registered recoveries, each verifying a proof over the same `(subject, salt, expiry)` ceremony; the salt must be unused on this chain (it is consumed on success) and `expiry` must not have passed. `subject` must be a canonical 32-byte EOA or 64-byte passkey and not already an owner. Returns `requestId`.
- `executeRecoveryRequest(bytes32 requestId)`: After the delay elapses, register the new owner on the account. Unrestricted caller.
- `cancelRecoveryRequest(bytes32 requestId)`: Abort a queued request. Callable only by the account the request is for.

### View Functions

- `computeRecoveryId(address account, address provider, bytes commitment)`: The deterministic recovery id.
- `hasRecovery(address account, bytes32 recoveryId)`: Whether a recovery id is registered.
- `getRecovery(address account, bytes32 recoveryId)`: A single registered recovery (zeroed if absent).
- `getRecoveries(address account)`: All registered recoveries.
- `recoveryCount(address account)`: Number of registered recoveries.
- `recoveryThreshold(address account)`: The effective approval threshold (1 if never set).
- `isSaltUsed(address account, bytes32 salt)`: Whether a ceremony's salt has been consumed on this chain.
- `recoveryRequest(bytes32 requestId)`: The pending request (zeroed if not pending).

## Security Model

### Two-Step Time-Lock

Recovery is intentionally a queue-then-execute flow with a delay, giving the legitimate owner a window to notice and `cancelRecoveryRequest` a malicious request. The pending entry is deleted before the external owner-add call (checks-effects-interactions).

### Replay Protection & Expiry

Each ceremony's random salt is bound into every proof and consumed by a successful request, making proofs single-use **per chain** — the same ceremony stays submittable on chains that have not consumed it, which is exactly the sign-once multichain semantics. The ceremony's `expiry` (checked by the manager at request time only) bounds how long unused, leaked proofs stay usable; it has no effect on a request once queued — the veto window is the protection during the time-lock. Cancelling a request permanently spends its salt on that chain; a retry is a fresh salt with re-signed proofs for the same subject. Signature malleability is accepted by design: a malleated ECDSA twin proves the same digest, consumes the same salt, and yields the same request — no state keys off raw proof bytes. The provider's sans-chainId domain still binds proofs to the specific provider deployment, so a signature cannot be reused on a different provider.

### Same-Subject, Atomic Approval

Every approval in a request verifies the **same** `subject`, so all `M` approvals authorize the same new owner. Verification is atomic: one invalid proof reverts the whole request, with no partial state and no salt consumed.

### Distinctness & Canonical Commitments

Distinctness is enforced by `recoveryId`. To keep one factor from counting twice, the canonical provider requires exact commitment lengths — 32 bytes (EOA) or 64 bytes (passkey pubkey), nothing else (otherwise `abi.decode` would accept trailing bytes and let one guardian appear under several ids). Every provider must enforce a one-to-one mapping between a commitment's bytes and its underlying identity. Note the consequences of length dispatch: a smart-account address enrolled as a 32-byte commitment, or an invalid pubkey as a 64-byte one, registers as a dead factor that never verifies — enrollment UIs must validate guardian types.

### Lockout Prevention

`setRecoveryThreshold` cannot exceed the registered count, and `removeRecovery` cannot drop the count below the threshold (except a full opt-out to zero). Together these maintain the invariant `count == 0 || count >= threshold`.

### Open Provider Model

Any contract may be a provider and any account may register any provider (gated only by `msg.sender == account`). The manager does not whitelist providers; trust equals provider correctness, curated by audits and UI guidance. Consequences to keep in mind:

- **M-of-N counts distinct registered recoveries, not distinct real-world identities.** Registering the same underlying identity under two provider deployments (or, for a provider that did not enforce canonical commitments, under two encodings) lets one key satisfy two factors. Use one canonical provider deployment per chain and let the UI curate what gets registered.
- A registered provider that is not a contract is rejected at registration; commitment-format validity is each provider's responsibility (enforced in its `verify`).

### Pending Requests Are Not Auto-Cancelled

Changing recovery configuration — `removeRecovery`, `setRecoveryThreshold` — does **not** cancel already-queued requests. A queued `RecoveryRequest` keeps its `executeAt` and still executes after its delay. To stop a pending request, call `cancelRecoveryRequest(requestId)` (the dedicated veto, callable by the account at any point in the window). Removing a compromised factor prevents *future* requests from it but does not stop one already in flight.

## Storage Layout

```solidity
// Per-account set of registered recovery ids
mapping(address account => EnumerableSet.Bytes32Set recoveryIds) internal _recoveryIds;

// Per-account recovery data, keyed by recovery id
mapping(address account => mapping(bytes32 recoveryId => Recovery recovery)) internal _recoveries;

// Per-account approval threshold (0 => default of 1)
mapping(address account => uint256 threshold) internal _recoveryThreshold;

// Per-account registry of consumed ceremony salts
mapping(address account => mapping(bytes32 salt => bool used)) internal _usedSalts;

// Pending recovery requests, keyed by request id
mapping(bytes32 requestId => RecoveryRequest request) internal _recoveryRequests;
```

## Events

```solidity
event RecoveryAdded(address indexed account, uint32 delay, bytes32 indexed recoveryId);
event RecoveryRemoved(address indexed account, bytes32 indexed recoveryId);
event RecoveryThresholdChanged(address indexed account, uint256 oldThreshold, uint256 newThreshold);
event RecoveryRequested(
    address indexed account, bytes32 indexed requestId, bytes32[] recoveryIds, bytes subject, uint64 executeAt
);
event RecoveryRequestExecuted(address indexed account, bytes32 indexed requestId, bytes subject);
event RecoveryRequestCancelled(address indexed account, bytes32 indexed requestId);
```

Events reference recoveries by `recoveryId` only; resolve an id to its `(provider, commitment)` via `getRecoveries(account)`.

## Integration with JustanAccount

JustaRecoveryManager acts as an owner of JustanAccount instances:

1. Deploy (or use) a JustanAccount instance.
2. Add JustaRecoveryManager as an owner via `addOwnerAddress(manager)`.
3. Register one or more recoveries via `addRecovery(account, provider, commitment, delay)` (a backup EOA or a guardian's raw passkey pubkey on the canonical provider). Repeat per chain — enrollment, like all account-authenticated operations, is per-chain.
4. Optionally raise the threshold via `setRecoveryThreshold(account, m)`.
5. On key loss, guardians sign ONE ceremony `(subject, salt, expiry)`; a relayer calls `requestRecovery(account, subject, salt, expiry, approvals)` with the same proof bytes on every enrolled chain.
6. After each chain's delay, anyone calls `executeRecoveryRequest(requestId)` to register the new owner there; during the delay the account may `cancelRecoveryRequest(requestId)` (per chain).

## Influences & Acknowledgments

This implementation was influenced by and builds upon:

- **[JustanAccount](https://github.com/justaname-id/justanaccount)**: The target smart account whose owners JustaRecoveryManager manages.
- **[Solady](https://github.com/Vectorized/solady)**: Optimized utilities — `ECDSA`, `EIP712`, `WebAuthn`, `P256`, and `ReentrancyGuard`.
- **[OpenZeppelin Contracts](https://github.com/OpenZeppelin/openzeppelin-contracts)**: `EnumerableSet`.
- **[Safe Singleton Deployer](https://github.com/wilsoncusack/safe-singleton-deployer-sol)**: Deterministic cross-chain deployment.