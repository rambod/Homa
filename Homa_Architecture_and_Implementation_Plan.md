# Homa (HMA) - Architecture and Implementation Plan
**Version:** 1.0.0
**Author:** Rambod (@RambodDev)
**Network Focus:** Pure Layer-1 Currency | Instant Finality | Zero Inflation | Hybrid PoS + Client PoW

## 1. Executive Summary & Tech Stack

Homa is designed to be a highly resilient, single-purpose Layer-1 cryptocurrency. By rejecting smart contracts and virtual machines, the network achieves extreme throughput and zero-bloat state management. It utilizes a hybrid consensus model: **Proof of Stake (PoS)** secures the network and validates blocks, while a lightweight **Proof of Work (PoW)** is computed on the client-side wallet to prevent network spam, allowing financial transaction fees to remain practically zero.

**Maximum Supply:** 36,000,000 HMA (Zero Inflation)
**Base Unit:** 1 HMA = 100,000,000 micro-homas ($\mu$HMA)

### Core Rust Dependencies
- **Async Runtime:** `tokio` (Multi-threaded event loop)
- **Networking:** `rust-libp2p` (Gossipsub for pub/sub broadcast, Kademlia for DHT peer discovery)
- **Cryptography:** `ed25519-dalek` (Signatures), `blake3` (Extremely fast hashing for PoW & block hashes)
- **Database:** `redb` or `sled` (Embedded key-value store for local state)
- **Serialization:** `serde`, `bincode` (Compact binary format for network transmission)

---

## 2. Phase 1: Cryptography & Data Structures

For a pure, high-speed currency, Homa will use an **Account-based model** (similar to Nano or Solana) rather than UTXO. This makes tracking staked balances for PoS much simpler and keeps the state footprint small.

### Task List
- [x] Initialize Rust workspace: `cargo new homa --bin` and configure `Cargo.toml`.
- [x] Implement Ed25519 keypair generation in `src/crypto/keys.rs`.
- [x] **Expansion:** Add typed crypto error handling (`CryptoError`) and signature verification API for strict wallet/node boundary checks.
- [x] Create address derivation logic (Public Key -> Blake3 Hash -> Base58 encoded string like `HMA...`).
- [x] **Expansion:** Add network/version prefixing and checksum validation rules for addresses to prevent cross-network replay/confusion.
- [x] Define the `Transaction` struct in `src/core/transaction.rs`. It must include a `pow_nonce` field.
- [x] **Expansion:** Add canonical transaction signing/serialization bytes and strict stateless validation (`TransactionError`) for mempool prechecks.
- [x] Define the `Block` and `BlockHeader` structs in `src/core/block.rs`.
- [x] **Expansion:** Add deterministic transaction-root commitment, block hashing, and typed block validation errors (`BlockError`).

**Structural Example:**
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub sender: String,
    pub receiver: String,
    pub amount: u64,       // In micro-homas
    pub fee: u64,          // Dynamic, practically zero
    pub nonce: u64,        // Account transaction counter to prevent replay attacks
    pub pow_nonce: u64,    // The result of the client-side PoW puzzle
    pub signature: Vec<u8>, 
}
```

---

## 3. Phase 2: Hybrid Consensus Engine

This is the core logic. PoW prevents spam; PoS secures the ledger.



### Task List
- [x] **Client PoW Logic:** Write the algorithm (`src/consensus/pow.rs`) that requires the `blake3` hash of the `Transaction` bytes + `pow_nonce` to start with a certain number of leading zeros.
- [x] **Expansion:** Add bounded nonce-search API, typed `PowError`, deterministic leading-zero-bit difficulty checks, and verification helpers.
- [x] **PoW Verification:** Add logic in the node's mempool ingestion pipeline to reject any transaction that does not have a valid `pow_nonce`.
- [x] **Expansion:** Introduce `src/core/mempool.rs` with typed admission errors, network-aware address checks, duplicate sender-nonce guards, and configurable `PoW` thresholds.
- [x] **Stake Tracking:** Create `src/consensus/stake.rs` to maintain an in-memory map of Validator addresses to their staked HMA amounts.
- [x] **Expansion:** Add overflow-safe stake accounting (`StakeLedger`), deterministic top-validator ordering, and typed staking errors (`StakeError`).
- [x] **Leader Election:** Implement a stake-weighted round-robin or Verifiable Random Function (VRF) so the protocol knows *which* validator is allowed to mint the next block based on block time (e.g., 1-second ticks).
- [x] **Expansion:** Add deterministic slot scheduler (`src/consensus/leader.rs`) with typed election errors and cycle-fairness tests.
- [x] **Fee Distribution:** Write the logic inside block finalization that sums all `fee` fields from included transactions and credits them to the block-producing validator's account. **Ensure total supply is hard-capped at 36,000,000.**
- [x] **Expansion:** Add `src/core/state.rs` (`ChainState`) for block application, nonce enforcement, balance checks, and max-supply-capped genesis allocation.

---

## 4. Phase 3: Anti-Fragile Networking Layer

The network must survive even if initial infrastructure goes offline.



### Task List
- [x] **Libp2p Setup:** Configure a `Swarm` in `src/network/p2p.rs` using TCP and QUIC transports.
- [x] **Gossipsub Integration:** Create topics for `transactions` and `blocks`. Configure the node to subscribe and propagate messages instantly to connected peers.
- [x] **Kademlia DHT:** Implement peer discovery. When a node connects to one peer, it should query the DHT to map out the rest of the network automatically.
- [x] **DNS Seed Resolver:** Write a fallback mechanism in the bootstrapping logic.
    - *Logic:* Query `seed1.homanetwork.io` via standard DNS TXT records. Parse the returned IP addresses.
    - *Fallback:* If DNS fails, fall back to hardcoded IPs. If IPs fail, listen for incoming Kademlia pings.
- [x] **Expansion:** Added typed `NetworkError`, deterministic address parsing helpers, Kademlia bootstrap helper, and unit tests for DNS-token parsing/fallback address resolution.

---

## 5. Phase 4: Mempool & State Sync

When a new node joins, it needs to catch up perfectly and fast.

### Task List
- [x] **Mempool Data Structure:** Implement a `BTreeMap` or `PriorityQueue` in `src/core/mempool.rs` to hold pending transactions.
- [x] **Fee/PoW Priority Sorting:** Sort the mempool first by fee (if the network is congested) and then by PoW difficulty (rewarding users who computed a harder PoW with faster inclusion).
- [x] **Dynamic Ledger Sync:** Implement a "Fast Sync" protocol.
    - Instead of downloading every historical block, nodes download a compressed snapshot of the Account State tree from trusted peers.
    - Cryptographically verify the state root hash against the latest finalized PoS block.
- [x] **Expansion:** Added deterministic snapshot export/import (`src/core/sync.rs`) and state-root generation (`ChainState::state_root`) for root-matched fast-sync validation.

---

## 6. Phase 5: CLI & Wallet Integration

The user experience needs to be seamless.

### Task List
- [x] Create `src/wallet/cli.rs` using the `clap` crate for terminal commands.
- [x] Implement `homa-cli keys generate` to create and save encrypted keypairs locally.
- [x] Implement `homa-cli tx send <address> <amount>`.
- [x] **Crucial Integration:** Wire the `send` command to the client-side PoW engine. The CLI must pause, calculate the `pow_nonce` using the local CPU for ~1-2 seconds, sign the transaction, and broadcast it to the network.
- [x] **Expansion:** Added encrypted wallet file format (Argon2id + ChaCha20Poly1305), local nonce state tracking, and best-effort gossipsub broadcast with DNS/fallback bootstrap inputs.

---

## 7. Phase 6: Security, Auditing & Testing

Ensure the network is bulletproof before deploying the genesis block.

### Task List
- [x] **Double-Spend Prevention:** Write unit tests ensuring the `nonce` (account transaction counter) strictly increments, rejecting older or duplicate nonces.
- [x] **Fuzzing the Mempool:** Use `cargo-fuzz` to throw malformed bytes at the Gossipsub network layer to ensure the node does not panic or crash.
- [x] **Sybil Mitigation Test:** Simulate spinning up 1,000 fake nodes with 0 staked HMA to verify they are unable to influence leader election or block production.
- [x] **Genesis Block Forging:** Hardcode the genesis block in `src/core/genesis.rs`, pre-allocating the 36,000,000 HMA to initial validator addresses to bootstrap the network.
- [x] **Expansion:** Added deterministic genesis allocations and forged block/state-root validation tests (`src/core/genesis.rs`).
- [x] **Expansion:** Added hardened transaction gossip decode boundary (`decode_transaction_gossip_payload`), a `cargo-fuzz` target (`fuzz/fuzz_targets/gossipsub_tx_payload.rs`), and a 1,000-node zero-stake Sybil resistance election test (`src/consensus/leader.rs`).

---

## 8. Phase 7: Resilience & Operational Hardening

Prepare the protocol for adverse network conditions and production node operations.

### Task List
- [x] **Network Partition Handling:** Add fork-choice tie-breaker rules and partition-rejoin reconciliation tests to ensure deterministic convergence.
- [x] **Node Crash Recovery:** Introduce atomic state commit/recovery flow (write-ahead snapshot strategy) so nodes recover cleanly after abrupt shutdowns.
- [x] **Mempool Rate Limiting:** Add per-peer/per-sender admission throttling and backpressure controls to reduce spam-amplification risk.
- [x] **Replay Hardening:** Add explicit chain-domain separation in signed transaction payloads to prevent cross-network replay at signature level.
- [x] **Observability:** Add structured metrics/events for consensus slot misses, gossip propagation failures, and sync lag.
- [x] **Chaos Integration Tests:** Add multi-node integration tests covering delayed links, temporary partitions, and re-sync correctness.
- [x] **Expansion:** Added `src/core/fork_choice.rs` with deterministic branch weighting (height -> cumulative fees -> tip hash), strict branch-link validation, typed reconciliation errors, and partition rejoin convergence/tamper tests.
- [x] **Expansion:** Added `src/core/recovery.rs` with WAL-first atomic snapshot commits (`commit_state_snapshot_atomic`), restart reconciliation (`recover_chain_state`), stale WAL cleanup/promotion logic, and tamper/empty-storage recovery tests.
- [x] **Expansion:** Added sliding-window mempool throttling in `src/core/mempool.rs` (`RateLimitPolicy`, per-sender/per-peer windows via `insert_from_peer`) and soft-limit priority backpressure rejection (`BackpressureRejected`) with targeted spam/backpressure tests.
- [x] **Expansion:** Added explicit transaction signature-domain envelope in `src/core/transaction.rs` (`HOMA_TX_SIG_V1` + network byte), `signing_bytes_for_network(...)` enforcement, wallet-side network-bound signing, and replay-resistance tests proving signatures fail across network domains.
- [x] **Expansion:** Added `src/observability/mod.rs` collector (structured counters + bounded event history), leader slot-miss instrumentation (`record_slot_observation`), gossip-failure instrumentation in `broadcast_transaction_bytes_with_observability`, and sync-lag reporting helpers/tests.
- [x] **Expansion:** Added `tests/chaos_integration.rs` with a deterministic `SimNode` harness and adversarial scenarios for delayed links and temporary 3-node partitions, including reconciliation checks for state-root convergence and sync-lag recovery after heal.

---

## 9. Phase 8: Performance & Runtime Hardening (Expansion V2)

Advance from functional correctness toward sustained adversarial runtime performance and cryptographic enforcement.

### Task List
- [x] **Mempool TTL & Stale Pruning:** Add configurable transaction retention TTL with lazy/prioritized pruning to prevent stale transaction buildup and reclaim capacity under delayed/partitioned network conditions.
- [x] **Signature-Authority Binding:** Bind sender authority to verifiable public-key material at transaction-validation time (address-to-key proof + mandatory signature verification at admission/finalization).
- [x] **Zero-Copy Gossip Decode Path:** Introduce a zero-copy decode path for gossiped transaction payloads to reduce allocation pressure under high-throughput bursts.
- [x] **Signed Sync Checkpoints:** Add optional validator-signed state snapshot checkpoints for fast-sync trust minimization.
- [x] **Partition Chaos Fuzzer:** Add randomized chaos simulation (delay/loss/reorder) with deterministic seed replay for regression stability.
- [x] **Expansion:** Implemented in `src/core/mempool.rs`: `transaction_ttl_ms` policy in `MempoolConfig`, `prune_expired` maintenance API, insertion-time lazy eviction, and TTL-focused tests (`ttl_pruning_reclaims_capacity_before_full_check`, `explicit_prune_removes_only_expired_transactions`, `ttl_can_be_disabled`).
- [x] **Expansion:** Implemented sender-authority enforcement in `src/core/transaction.rs` (`sender_public_key`, `validate_sender_authority_for_network`), wired mandatory authority checks into mempool admission (`MempoolError::TransactionAuthority`) and block finalization, updated wallet send-path to embed sender key material before PoW/signing, and added targeted authority tests across transaction/mempool/state plus signed branch-chaos fixtures.
- [x] **Expansion:** Added zero-copy borrowed transaction decoding (`Transaction::decode_borrowed`, `BorrowedTransaction<'_>`) and a dedicated gossip boundary API (`decode_transaction_gossip_payload_zero_copy`) in `src/network/p2p.rs`, with tests proving borrowed field pointers alias the original payload buffer and can be materialized to owned transactions when needed.
- [x] **Expansion:** Added optional validator-signed sync checkpoints in `src/core/sync.rs` (`SnapshotCheckpoint`, `SnapshotCheckpointSignature`, `CheckpointVerificationPolicy`, `sign_snapshot_checkpoint`, `verify_snapshot_checkpoint`, `import_verified_snapshot_with_checkpoint`) with network-domain-separated checkpoint signing bytes, trusted-validator threshold enforcement, duplicate/untrusted signer rejection, key-address binding checks, and tamper/insufficient-signature tests.
- [x] **Expansion:** Added `tests/partition_chaos_fuzzer.rs` with a deterministic seed-replay fuzz harness (`ChaosEnv`) that injects randomized delay/loss/reorder delivery, measures sync lag under partition pressure, and enforces post-heal convergence on branch height and state root across a multi-seed regression matrix.

---

## 10. Phase 9: Sync Integrity & Anti-Rollback Hardening (Expansion V3)

Close remaining fast-sync trust and availability gaps for adversarial peers and long-running nodes.

### Task List
- [x] **Snapshot Payload Rehash Verification:** Recompute state root from snapshot account payload and reject any payload whose computed root does not match its declared root before import.
- [x] **Snapshot Admission Guardrails:** Enforce bounded snapshot account-count/byte-size policies to reduce memory-amplification risk during fast sync from untrusted peers.
- [x] **Snapshot Chunk Streaming:** Define deterministic chunked snapshot transfer with per-chunk hashing for resume/retry under unreliable links.
- [x] **Anti-Rollback Import Rule:** Reject importing snapshots older than local finalized height unless explicitly running in bootstrap/recovery mode.
- [x] **Expansion:** Hardened `src/core/sync.rs` by adding canonical snapshot-account order enforcement, computed-vs-declared payload root validation (`SnapshotPayloadRootMismatch`), and targeted tamper/order regression tests (`rejects_snapshot_payload_root_mismatch`, `rejects_snapshot_with_non_canonical_account_order`).
- [x] **Expansion:** Added configurable snapshot-admission controls in `src/core/sync.rs` (`SnapshotAdmissionPolicy`, `DEFAULT_MAX_SNAPSHOT_BYTES`, `DEFAULT_MAX_SNAPSHOT_ACCOUNTS`, `StateSnapshot::decode_with_policy`, `import_verified_snapshot_with_policy`, `import_verified_snapshot_with_checkpoint_and_policy`) with strict invalid-policy handling and byte/account budget enforcement tests.
- [x] **Expansion:** Added rollback-safe import context in `src/core/sync.rs` (`SnapshotImportMode`, `SnapshotRollbackRejected`) and made snapshot import APIs explicit about bootstrap/recovery vs steady-state operation, with tests proving steady-state rollback rejection and bootstrap-mode allowance.
- [x] **Expansion:** Added deterministic resumable chunk streaming in `src/core/sync.rs` (`SnapshotChunk`, `split_snapshot_into_chunks`, `SnapshotChunkAssembler`) with domain-separated per-chunk integrity hashes (`SNAPSHOT_CHUNK_DOMAIN_SEPARATOR`), mixed-stream/duplicate/conflict detection, missing-chunk reporting for retry, and out-of-order reassembly/tamper tests.

---

## 11. Phase 10: Sync Network Protocol & Transport Wiring (Expansion V4)

Connect fast-sync chunking primitives to explicit P2P wire protocol boundaries and runtime transport topics.

### Task List
- [x] **Snapshot Sync Wire Codec:** Add typed snapshot chunk request/response wire messages with bounded encode/decode and strict malformed/oversized payload rejection.
- [x] **Chunk Request/Serve Engine:** Add node-side async request scheduler and chunk-serving handler (rate-limited, per-peer quotas, timeout/retry budget).
- [x] **Chunk Stream Session State:** Track per-peer/per-session in-flight chunk windows, duplicate suppression, and deterministic backoff under packet loss.
- [x] **Checkpoint-Aware Sync Handshake:** Require advertised checkpoint metadata before chunk stream acceptance when running in strict fast-sync mode.
- [x] **Expansion:** Updated `src/network/p2p.rs` with new sync gossip topics (`sync-requests`, `sync-chunks`), typed wire envelopes (`SnapshotChunkRequest`, `SnapshotChunkResponse`, `SyncWireMessage`), hardened sync codec helpers (`encode/decode_*`), and focused tests for request/response roundtrip, wrong-variant rejection, and malformed/oversized payload handling.
- [x] **Expansion:** Added `src/network/sync_engine.rs` with retry-aware outbound scheduler (`ChunkRequestScheduler`), per-peer serve quota limiter (`ChunkServeLimiter`), and validated `serve_chunk_request(...)` path enforcing metadata consistency and chunk-index bounds, covered by deterministic timeout/quota/mismatch tests.
- [x] **Expansion:** Extended `src/network/sync_engine.rs` with per-peer/per-session window manager (`ChunkSessionManager`) and explicit session policy (`ChunkSessionPolicy`) enforcing duplicate suppression, session/peer in-flight caps, and deterministic exponential backoff/cooldown under packet loss, with tests for window limits, defer-until-retry behavior, and ack-based loss-streak reset.
- [x] **Expansion:** Added strict sync handshake verification in `src/network/sync_engine.rs` (`SnapshotHandshakeAdvertisement`, `SyncHandshakeMode`, `OwnedCheckpointPolicy`, `validate_snapshot_handshake`) to bind chunk-stream acceptance to advertised snapshot metadata hash/root/height and optional mandatory validator checkpoint verification, with permissive/strict/tamper tests.

---

## 12. Phase 11: Runtime Abuse Resistance & Peer Reputation (Expansion V5)

Harden long-running sync and gossip behavior against abusive peers, unstable links, and repeated malformed traffic.

### Task List
- [x] **Peer Reputation Ledger:** Introduce weighted peer scoring (malformed payloads, timeout bursts, invalid checkpoints) with configurable decay and ban thresholds.
- [x] **Adaptive Dial/Serve Penalties:** Apply temporary dial cooldown and serve throttling to low-score peers to reduce repeated attack amplification.
- [x] **Sync Session Persistence Hooks:** Persist critical sync session checkpoints (in-flight windows + retry cursors) so node restarts can resume without full restart from genesis snapshot.
- [x] **Checkpoint Gossip Rotation:** Add rotating trusted-checkpoint set update mechanism with deterministic validation and rollback-safe activation.
- [x] **Expansion:** Added `src/network/reputation.rs` with a policy-driven `PeerReputationLedger` (weighted events, bounded score clamps, time decay toward zero, temporary ban thresholding/expiry) and tests for ban triggering/expiration, decay behavior, and score bounds.
- [x] **Expansion:** Added adaptive penalty controls in `src/network/reputation.rs` (`AdaptivePenaltyPolicy`, `AdaptivePenaltyManager`) with score-band-based dial cooldown escalation, serve-quota throttling, typed dial/banned errors, and deterministic tests for cooldown recovery/escalation and ban-driven quota denial.
- [x] **Expansion:** Completed crash-safe sync-session persistence in `src/network/sync_engine.rs` with deterministic checkpoint payloads (`SyncSessionCheckpoint`), scheduler/session export-import hooks (`checkpoint`/`from_checkpoint`), atomic file commit/recovery helpers (`persist_sync_*`, `recover_sync_*`), and strict restore consistency checks for request-id integrity, duplicate state entries, and peer in-flight counter mismatches; covered by new roundtrip/tamper/missing-file tests.
- [x] **Expansion:** Added `src/network/checkpoint_rotation.rs` and wired it in `src/network/mod.rs` with signed trusted-set rotation updates (`CheckpointSetRotationUpdate`), deterministic payload-hash tie-break staging, finalized-height-delayed activation (`CheckpointRotationManager`), canonical validator-set/network validation, and threshold signature verification from the active trusted set; covered by codec, activation, early-activation rejection, untrusted-signer rejection, tie-break, and finalized-height regression tests.

---

## 13. Phase 12: Runtime Policy Orchestration (Expansion V6)

Bind previously isolated reputation, sync-serving, and checkpoint-trust primitives into one runtime-facing control plane.

### Task List
- [x] **Unified Sync Runtime Policy Controller:** Introduce a single network runtime controller that composes adaptive peer reputation penalties, sync serve quota gates, and checkpoint trust policy selection.
- [x] **Reputation-Driven Serve Quota Enforcement:** Apply dynamic per-peer serve quotas (derived from score bands) at sync request admission time without relaxing existing rolling-window anti-amplification controls.
- [x] **Rotating Trust-Aware Handshake Validation:** Route sync handshake validation through the currently active checkpoint trust set so trust rotation activation immediately affects strict sync admission.
- [x] **Rotation Runtime Hooks:** Expose runtime APIs to ingest signed checkpoint-rotation updates and advance finalized height for deterministic staged activation.
- [x] **Expansion:** Added `src/network/runtime_policy.rs` with `SyncRuntimePolicyController` and typed `RuntimePolicyError`, wiring together `AdaptivePenaltyManager`, `ChunkServeLimiter`, and `CheckpointRotationManager` with explicit APIs for dial enforcement, serve admission, strict handshake validation, and trust-rotation lifecycle handling.
- [x] **Expansion:** Extended `src/network/sync_engine.rs` with `ChunkServeLimiter::admit_with_quota(...)` to support dynamic per-peer quota overrides while preserving existing rolling-window accounting and typed quota-exceeded errors.
- [x] **Expansion:** Exported runtime orchestration module from `src/network/mod.rs` and added deterministic tests for score-driven serve throttling, banned-peer serve denial, pre/post-rotation handshake trust behavior, and reputation dial cooldown surfacing.

---

## 14. Phase 13: Inbound Gossip Policy Wiring (Expansion V7)

Move from policy primitives to a concrete inbound network message handling path with enforced runtime gates.

### Task List
- [x] **Inbound Runtime Handler:** Add a topic-aware inbound gossip handler that maps raw `(topic, payload, peer, now)` tuples into typed actions for transaction, block, sync, and checkpoint-rotation traffic.
- [x] **Serve-Quota Gate on Sync Requests:** Enforce runtime policy admission (`SyncRuntimePolicyController`) before accepting inbound snapshot chunk requests.
- [x] **Checkpoint-Rotation Gossip Topic:** Add a dedicated checkpoint rotation gossip topic and subscribe nodes to it during swarm construction.
- [x] **Rotation Message Ingest Wiring:** Decode checkpoint-rotation gossip payloads and route them through runtime trust-rotation ingest APIs.
- [x] **Expansion:** Added `src/network/runtime_loop.rs` with `handle_inbound_gossip_message(...)`, `InboundGossipAction`, and typed `RuntimeLoopError`, wiring inbound topics to decode + runtime policy gates (including sync request quota/ban checks and checkpoint-rotation ingest flow).
- [x] **Expansion:** Updated `src/network/p2p.rs` with `CHECKPOINT_ROTATIONS_TOPIC`, `checkpoint_rotations_topic()`, and swarm subscription wiring so checkpoint trust-set updates have a first-class gossip channel.
- [x] **Expansion:** Exported runtime-loop module via `src/network/mod.rs` and added deterministic tests for transaction decoding, block payload passthrough, score-throttled sync request handling, banned-peer sync denial, checkpoint-rotation gossip ingest, and unknown-topic rejection.

---

## 15. Phase 14: Inbound Abuse Feedback & Payload Guardrails (Expansion V8)

Close the loop between inbound gossip validation failures and peer reputation so repeated malformed/protocol-violating traffic is penalized automatically at runtime.

### Task List
- [x] **Inbound Abuse Feedback Loop:** Add a runtime handler path that auto-maps inbound failures into peer reputation penalties (malformed payloads, protocol-violation classes).
- [x] **Block Gossip Payload Guardrail:** Enforce strict max-size checks on inbound block gossip payloads before forwarding to block-processing pipelines.
- [x] **Runtime Reputation Introspection Hooks:** Expose runtime-policy accessors for peer score/ban state to support deterministic abuse-feedback tests and future observability wiring.
- [x] **Flaky Sync Checkpoint Test Stabilization:** Make sync-engine temp-directory test fixtures collision-safe under parallel test execution.
- [x] **Expansion:** Updated `src/network/runtime_loop.rs` with `handle_inbound_gossip_message_with_feedback(...)`, deterministic error-to-`ReputationEvent` classification, block payload bound enforcement on `blocks` topic, and tests for malformed transaction penalties, unknown-topic penalties, and no double-penalty behavior for already banned peers.
- [x] **Expansion:** Updated `src/network/p2p.rs` with `MAX_BLOCK_GOSSIP_BYTES`, `NetworkError::BlockPayloadTooLarge`, and `validate_block_gossip_payload_bounds(...)` plus unit tests for accepted/rejected block payload sizes.
- [x] **Expansion:** Updated `src/network/runtime_policy.rs` with `peer_score(...)` and `is_peer_banned(...)` runtime accessors.
- [x] **Expansion:** Updated `src/network/sync_engine.rs` tests to use an atomic unique temp-directory suffix, eliminating intermittent parallel test collisions in checkpoint malformed-bytes coverage.

---

## 16. Phase 15: Outbound Sync Runtime Wiring (Expansion V9)

Wire outbound sync request/session state into real inbound `sync-chunks` processing so ack/loss/retry behavior is deterministic under hostile links.

### Task List
- [x] **Sync Runtime Coordinator:** Add a runtime coordinator that composes outbound request scheduler + per-session window state with explicit request-to-session tracking.
- [x] **Retry Activation Path:** Add deterministic retry activation APIs that enforce session backoff before retransmit dispatch of timed-out in-flight requests.
- [x] **Inbound Sync-Chunk Ack Wiring:** Route decoded inbound `sync-chunks` responses through runtime coordinator validation and ack hooks so successful responses clear scheduler/session in-flight state.
- [x] **Wrong-Peer Response Rejection:** Reject inbound sync responses from unexpected peers and penalize sender as protocol violation without clearing tracked in-flight request state.
- [x] **Timeout Loss Feedback Loop:** On timeout polling, feed loss signals into session backoff state and emit typed retry/exhausted feedback with deterministic `retry_at_ms`.
- [x] **Expansion:** Added `src/network/sync_runtime.rs` with `SyncRuntimeCoordinator`, typed schedule/activation/timeout outcomes, strict response metadata + peer validation, and targeted tests for ack success, wrong-peer rejection, retry backoff activation, and exhausted-request reschedule cooldown.
- [x] **Expansion:** Extended `src/network/sync_engine.rs` with `ChunkRequestScheduler::in_flight_request_context(...)` so runtime orchestration can validate inbound responses against active request/peer metadata without mutating scheduler state.
- [x] **Expansion:** Updated `src/network/runtime_loop.rs` with `handle_inbound_gossip_message_with_feedback_and_sync_runtime(...)` and `RuntimeLoopError::SyncRuntime`, wiring real inbound `sync-chunks` gossip into coordinator ack flow and automatic protocol-violation penalties on runtime rejection.
- [x] **Expansion:** Exported new runtime coordinator module in `src/network/mod.rs` (`pub mod sync_runtime`) and expanded runtime-loop integration tests to cover sync-chunk runtime ack and wrong-peer rejection/penalty behavior.

---

## 17. Phase 16: Snapshot Assembly Runtime Finalization (Expansion V10)

Complete the inbound sync runtime path by assembling accepted chunk streams into finalized snapshots with explicit completion signaling and queue-based consumption.

### Task List
- [x] **Assembler State Integration:** Integrate `SnapshotChunkAssembler` into sync runtime coordinator state and key assembly streams deterministically by `(height, state_root, snapshot_hash, total_chunks)`.
- [x] **Ingest-Before-Ack Safety:** Validate and ingest inbound chunk payloads before scheduler/session ack removal so malformed chunks do not clear retryable in-flight state.
- [x] **Completion Queue:** Add a completed-snapshot queue with explicit drain API for downstream import pipeline consumption.
- [x] **Assembly Policy Validation:** Add runtime assembly policy validation (chunk size and snapshot admission bounds) with a strict constructor surface.
- [x] **Runtime Loop Completion Wiring:** Ensure inbound `sync-chunks` runtime-loop path drives assembly to completion and preserves protocol-violation penalties on runtime rejection.
- [x] **Expansion:** Updated `src/network/sync_runtime.rs` with `SnapshotStreamKey`, `AssemblyIngestOutcome`, `CompletedSnapshot`, validated `with_assembly_policy(...)`, assembler map + completed queue state, chunk ingest/finalization flow, and runtime accessors (`active_assembly_stream_count`, `completed_snapshot_count`, `drain_completed_snapshots`).
- [x] **Expansion:** Hardened `handle_inbound_chunk_response(...)` in `src/network/sync_runtime.rs` to perform assembly validation before ack and keep in-flight tracking on chunk-hash failure.
- [x] **Expansion:** Added sync runtime tests for multi-chunk out-of-order stream completion/finalization, tampered chunk rejection without ack state loss, and invalid assembly policy rejection.
- [x] **Expansion:** Extended `src/network/runtime_loop.rs` tests with end-to-end multi-chunk `sync-chunks` handling that confirms completed snapshot queue emission through the runtime-loop wiring path.

---

## 18. Phase 17: Completed Snapshot Verified Import Orchestration (Expansion V11)

Consume completed assembled snapshots through verified import/apply runtime paths with explicit rollback-mode controls and optional checkpoint trust enforcement.

### Task List
- [x] **Completed Queue Import API:** Add runtime APIs to import the next completed snapshot into `ChainState` and consume queue entries only after successful verification/import.
- [x] **Rollback-Mode Runtime Control:** Thread `SnapshotImportMode` through runtime import orchestration so steady-state nodes enforce anti-rollback rules and bootstrap/recovery can opt in to older snapshots.
- [x] **Checkpoint-Gated Runtime Import:** Add a checkpoint-verified import path for completed snapshots using `CheckpointVerificationPolicy` and validator-signed snapshot checkpoints.
- [x] **Import-Failure Queue Safety:** Ensure failed verification/import leaves completed snapshot entries queued for deterministic operator retry/inspection.
- [x] **Expansion:** Updated `src/network/sync_runtime.rs` with `ImportedSnapshot`, `SyncRuntimeError::SnapshotImport`, and runtime queue-consumption APIs (`import_next_completed_snapshot`, `import_next_completed_snapshot_with_checkpoint`) that call `import_verified_snapshot_with_policy(...)` / `import_verified_snapshot_with_checkpoint_and_policy(...)` with coordinator admission policy.
- [x] **Expansion:** Added runtime import tests in `src/network/sync_runtime.rs` covering bootstrap-mode successful import, steady-state rollback rejection with queue retention, checkpoint-verified successful import, and empty-queue no-op import behavior.

---

## 19. Phase 18: Snapshot Import Quarantine & Head-of-Line Recovery (Expansion V12)

Prevent repeated invalid completed snapshots from permanently blocking downstream import progress.

### Task List
- [x] **Import Failure Budget Policy:** Add explicit runtime policy for maximum consecutive failed imports before quarantining a completed snapshot.
- [x] **Quarantine Queue & Inspection API:** Add typed quarantine records and drain/count APIs so operators can inspect isolated failed snapshots without dropping runtime state.
- [x] **Head-of-Line Unblock Path:** Ensure the runtime removes quarantined snapshots from the completed queue so later valid snapshots can still import.
- [x] **Policy Validation Guardrail:** Reject zero-threshold import failure policy configuration at construction time.
- [x] **Expansion:** Updated `src/network/sync_runtime.rs` with `SnapshotImportFailurePolicy`, `QuarantinedSnapshot`, internal failed-attempt tracking, `SyncRuntimeError::{InvalidImportFailurePolicy, SnapshotImportQuarantined}`, and runtime accessors (`quarantined_snapshot_count`, `drain_quarantined_snapshots`).
- [x] **Expansion:** Added runtime import hardening tests in `src/network/sync_runtime.rs` for repeated-failure quarantine transitions, queue-head unblocking into next-snapshot import, and invalid import-failure policy rejection.

---

## 20. Phase 19: Import Batch Orchestration & Snapshot Import Observability (Expansion V13)

Promote snapshot import from single-step APIs to runtime batch orchestration with first-class operational telemetry.

### Task List
- [x] **Batch Import Driver:** Add runtime batch APIs that process completed snapshots until queue drain, while preserving deterministic stop behavior on retryable blocking errors.
- [x] **Quarantine-Progress Continuation:** Ensure batch processing continues after quarantine events so head-of-line invalid snapshots do not block subsequent valid imports.
- [x] **Typed Import Error Metadata:** Extend snapshot import runtime errors with height/root/failure-count metadata for operator diagnostics and telemetry mapping.
- [x] **Snapshot Import Metrics/Events:** Add structured observability counters + events for snapshot import success, failure, and quarantine outcomes.
- [x] **Expansion:** Updated `src/network/sync_runtime.rs` with `SnapshotImportBatchOutcome`, batch import APIs (`import_completed_snapshot_batch`, `import_completed_snapshot_batch_with_checkpoint`), import-outcome observability wiring, and enriched `SyncRuntimeError::{SnapshotImport, SnapshotImportQuarantined}` metadata.
- [x] **Expansion:** Updated `src/observability/mod.rs` with new counters (`snapshot_import_success_total`, `snapshot_import_failure_total`, `snapshot_quarantine_total`), `SnapshotImportOutcome`, and `ObservabilityEventKind::SnapshotImport`.
- [x] **Expansion:** Added tests in `src/network/sync_runtime.rs` for batch progression after quarantine and batch stop behavior on retryable failures, plus new observability lifecycle coverage in `src/observability/mod.rs`.

---

## 21. Phase 20: Node Daemon Skeleton & Runtime Event Loop Wiring (Expansion V14)

Establish a long-running node daemon surface that composes networking, inbound runtime policy enforcement, sync maintenance, and state/mempool orchestration.

### Task List
- [x] **Node Runtime Module:** Add a dedicated node daemon module to host long-running runtime orchestration logic.
- [x] **Inbound Gossip-to-State Wiring:** Route inbound gossip tuples through runtime-loop policy gates and wire accepted transactions into mempool admission with peer-penalty feedback on rejection.
- [x] **Block Payload Queue Guardrail:** Decode/validate inbound block payloads and queue them into a bounded pending-block queue for downstream consensus processing.
- [x] **Sync Maintenance Tick:** Add deterministic maintenance tick API that applies timeout->reputation feedback and drives completed snapshot batch import with observability emission.
- [x] **Swarm Event Loop Skeleton:** Add bounded async swarm event-loop runner that interleaves inbound message handling and maintenance ticks.
- [x] **Bootstrap/Listen Wiring:** Add daemon helpers to attach/build swarm, open default listen sockets, and dial DNS/fallback bootstrap peers.
- [x] **Expansion:** Added `src/node/daemon.rs` and `src/node/mod.rs` with `NodeDaemon`, `NodeDaemonConfig`, typed daemon/runtime reports/errors, genesis bootstrap helpers (`from_genesis`, `trusted_checkpoint_set_from_genesis`), inbound action mapping, and bounded pending-block/mempool/snapshot orchestration.
- [x] **Expansion:** Exported daemon module via `src/lib.rs` (`pub mod node`) and added focused daemon tests for genesis bootstrap, transaction admission path, completed-snapshot maintenance import path, and missing-swarm event-loop guard behavior.

---

## 22. Phase 21: Executable Node Lifecycle & Security Regression Hardening (Expansion V15)

Close the gap between daemon library primitives and an executable operator-facing node process with regression security checks.

### Task List
- [x] **Node Binary Target:** Add a dedicated `homa-node` Cargo binary target and executable entrypoint.
- [x] **Node Run CLI Surface:** Add node runtime CLI (`run`) with network selection, bootstrap/listen controls, bounded smoke-step mode, and runtime policy knobs.
- [x] **Ctrl+C Lifecycle Loop:** Add daemon lifecycle API for continuous swarm loop execution until explicit OS signal shutdown.
- [x] **Config-Bootstrap Constructor:** Add config-aware genesis bootstrap constructor to instantiate daemon from explicit runtime policy values.
- [x] **Daemon Security Regression Tests:** Add daemon-level adversarial tests for malformed transaction payloads, unknown topics, and oversized block gossip payload handling with expected peer penalties.
- [x] **Fuzz Pentest Verification:** Run decode-boundary fuzz target on nightly toolchain (`gossipsub_tx_payload`) and verify no crash/panic findings in short bounded run.
- [x] **Operational Error Transparency:** Ensure operator-facing node failures include chained root-cause context (not generic top-level errors) for faster incident triage.
- [x] **Expansion:** Updated `Cargo.toml` with `homa-node` bin target and `tokio` signal feature, added `src/bin/homa-node.rs` and `src/node/cli.rs`, and wired node CLI execution from the shared library.
- [x] **Expansion:** Extended `src/node/daemon.rs` with `from_genesis_with_config(...)`, `run_until_ctrl_c(...)`, peer reputation introspection helpers, and report aggregation utilities.
- [x] **Expansion:** Updated `README.md` with node daemon usage (`homa-node run`) and nightly fuzz invocation guidance.
- [x] **Expansion:** Updated `NodeCliError` and `NodeDaemonError` display strings to include source error chains, and added a CLI regression test to prevent diagnostic regressions.

---

## 23. Phase 22: Production Security & Release Gates (Expansion V16)

Move from pre-alpha feature wiring toward repeatable production-readiness checks with explicit release gates and shutdown persistence safeguards.

### Task List
- [x] **Supply-Chain Security Gates:** Add `cargo-audit` + `cargo-deny` checks and enforce them in CI.
- [x] **Additional Fuzz Targets:** Add fuzz targets for block gossip decode path and sync chunk decode path.
- [x] **Long-Run Soak Test with SLOs:** Add deterministic multi-seed partition-chaos soak coverage with explicit convergence and delivery SLO assertions.
- [x] **Persistent Runtime Config File:** Add typed `node.toml` runtime config loading/validation with CLI override composition.
- [x] **Graceful Shutdown Persistence Check:** Flush chain snapshot + sync-session checkpoint to disk on shutdown path when state directory is configured.
- [x] **One-Command Release Gate:** Add a release gate script that runs format/lint/tests/security checks and fuzz smoke runs.
- [x] **Expansion:** Added `.github/workflows/release-gates.yml`, `deny.toml`, `scripts/release_gate.sh`, `node.toml.example`, `src/node/config.rs`, and new config/daemon/soak/fuzz test coverage.

---

## 24. Phase 23: Pending Block Finalization Pipeline (Expansion V17)

Close the runtime execution gap by moving queued inbound blocks through deterministic state transition and finalized-tip advancement.

### Task List
- [x] **Maintenance-Tick Block Finalization:** Execute queued pending blocks during maintenance ticks with deterministic parent/height admission checks against the current finalized tip.
- [x] **State-Root Enforcement:** Apply candidate blocks on a cloned `ChainState` and reject any block whose computed post-state root does not equal `header.state_root`.
- [x] **Out-of-Order Queue Safety:** Retain future-height blocks until parents arrive, while dropping stale and parent-mismatch blocks so invalid queue heads cannot stall progression.
- [x] **Mempool Inclusion Eviction:** Remove transactions included in finalized blocks from mempool to prevent stale duplicate nonce/fee contention.
- [x] **Runtime Reporting Expansion:** Extend daemon runtime stats and event-loop/CLI reporting with finalized/rejected block counters.
- [x] **Expansion:** Updated `src/node/daemon.rs` with pending-block processing (`process_pending_blocks`, `try_finalize_pending_block`, queue-drop helpers), new counters (`blocks_finalized_total`, `block_rejected_total`), and maintenance/event-loop report fields for finalized/rejected block totals.
- [x] **Expansion:** Updated `src/node/cli.rs` report output to include finalized/rejected block maintenance counters and cumulative block execution stats.
- [x] **Expansion:** Added daemon regression tests for valid finalization, state-root mismatch rejection, out-of-order future-block retention/unblocking, and mempool eviction for finalized block transactions.

---

## 25. Phase 24: Block Production & Local Finality (Expansion V18)

Add deterministic proposer-driven block minting to the node runtime so elected validators can build, sign, finalize, and gossip blocks.

### Task List
- [x] **Slot Scheduler:** Add maintenance-tick slot scheduling with deterministic slot index derivation and one-production-per-slot guard.
- [x] **Leader Gate:** Run stake-weighted leader election per slot and produce only when local validator is the elected leader.
- [x] **Block Builder:** Build block candidates from prioritized mempool transactions under a per-block transaction cap, with state-transition prechecks on projected state.
- [x] **Proposer Signing:** Sign produced block headers with local Ed25519 validator key and attach proposer signature bytes.
- [x] **Self-Finalization Path:** Apply produced blocks locally through finalized-tip state transition checks and mempool inclusion eviction.
- [x] **Block Gossip Broadcast:** Add best-effort block publish attempts over `blocks` topic with structured gossip-failure observability and failure counters.
- [x] **Runtime Config/CLI Surface:** Extend `node.toml` + CLI with slot duration, max block transactions, and optional local producer secret key configuration.
- [x] **Expansion:** Added normalized genesis stake-ledger bootstrap (`stake_ledger_from_genesis`) so leader rotation remains operational with large genesis balances while preserving proportional validator weights.
- [x] **Expansion:** Updated `src/node/daemon.rs` with local producer wiring, production metrics (`blocks_produced_total`, `block_publish_failure_total`), and production-aware maintenance/event-loop reporting.
- [x] **Expansion:** Updated `src/node/config.rs`, `src/node/cli.rs`, `node.toml.example`, and `README.md` for producer runtime configuration and operator-facing controls.
- [x] **Expansion:** Added regression tests for leader-slot local production, duplicate-slot no-double-produce guard, and mempool-draining local production path.

---

## 26. Phase 25: Inbound Block Consensus Admission Hardening (Expansion V19)

Harden inbound block handling so decoded gossip payloads are consensus-screened before entering the pending-finalization queue.

### Task List
- [x] **Leader/Slot Admission Gate:** Enforce deterministic slot-leader match on inbound blocks (proposer must equal elected leader for block timestamp slot).
- [x] **Timestamp Drift Bounds:** Reject inbound blocks that are too far ahead of local wall-clock or stale beyond finalized-tip historical tolerance.
- [x] **Timestamp Regression Guard:** Reject non-finalized-height inbound blocks whose timestamp regresses below the finalized tip timestamp.
- [x] **Same-Slot Equivocation Detection:** Track bounded slot commitments and reject conflicting same-slot block hashes.
- [x] **Duplicate Block Dedupe:** Ignore duplicate same-slot blocks with identical hash to prevent queue growth amplification.
- [x] **Abuse Feedback Integration:** Penalize peers for consensus-invalid inbound blocks via runtime reputation protocol-violation path.
- [x] **Runtime Metrics Expansion:** Add inbound consensus-rejection and duplicate-ignore counters to daemon runtime stats and CLI reporting.
- [x] **Expansion:** Updated `src/node/daemon.rs` with typed inbound block admission errors, bounded slot commitment tracking, and consensus validation helpers wired into block gossip ingestion.
- [x] **Expansion:** Updated `src/node/cli.rs` runtime report output with inbound consensus rejection/duplicate counters.
- [x] **Expansion:** Added daemon regression tests for unexpected proposer rejection, future timestamp rejection, same-slot equivocation rejection, and duplicate block dedupe behavior.
- [x] **Expansion:** Upgraded lockfile dependency `rustls-webpki` to `0.103.12` for newly disclosed URI/wildcard constraint advisories and adjusted `cargo-deny` yanked policy to warning while upstream `libp2p` transitive `core2` yanked dependency remains unresolved.

---

## 27. Phase 26: Proposer Identity Binding & Signature Enforcement (Expansion V20)

Bind proposer identity cryptographically so block acceptance requires a valid proposer signature and address derivation match, not only slot-schedule eligibility.

### Task List
- [x] **Block Proposer Public Key Field:** Extend block wire model with proposer public key bytes alongside proposer signature bytes.
- [x] **Proposer Proof Validation API:** Add block-level proposer proof validation that verifies signature, enforces key/signature length, and derives proposer address for network-domain match.
- [x] **Non-Genesis Signature Requirement:** Enforce proposer signature + proposer public key presence for non-genesis blocks.
- [x] **Inbound Admission Proof Gate:** Apply proposer proof validation before leader/timestamp admission checks when ingesting block gossip.
- [x] **Finalization Boundary Proof Gate:** Re-validate proposer proof at finalized-block application boundary to defend against non-gossip call paths.
- [x] **Local Block Production Proof Completion:** Attach proposer public key with signature for locally produced blocks.
- [x] **Expansion:** Updated `src/core/block.rs` with `proposer_public_key`, `with_proposer_proof(...)`, and `validate_proposer_proof_for_network(...)` plus new `BlockError` variants for typed proof failures.
- [x] **Expansion:** Updated `src/node/daemon.rs` to enforce proposer proof validation in inbound admission and finalized-block application paths, and to emit proof-complete locally produced blocks.
- [x] **Expansion:** Added regression coverage for valid proposer proof acceptance, address mismatch rejection, signature tamper rejection, missing-signature rejection, and daemon production/finalization proposer-proof assertions.

---

## 28. Phase 27: Inbound Replay & Parent-Continuity Guardrails (Expansion V21)

Reduce inbound block queue abuse surface by rejecting stale/replayed heights and finalized-boundary parent mismatches before queue admission.

### Task List
- [x] **Stale Height Replay Rejection:** Reject inbound blocks at or below finalized tip height before queueing.
- [x] **Finalized-Boundary Parent Check:** For next-height inbound blocks (`finalized_height + 1`), enforce exact parent hash match to finalized tip.
- [x] **Typed Admission Errors:** Extend inbound admission error surface with stale-height and parent-mismatch variants for operator observability.
- [x] **Peer Penalty Wiring:** Route stale-height replay and parent-mismatch rejections through protocol-violation reputation penalties.
- [x] **Expansion:** Updated `src/node/daemon.rs` admission pipeline with `validate_inbound_block_height(...)` and typed `InboundBlockAdmissionError::{StaleHeight, FinalizedBlockHash, ParentMismatch}`.
- [x] **Expansion:** Added daemon regression tests for stale-height replay rejection after local finalization and finalized-boundary parent mismatch rejection.

---

## 29. Phase 28: Crash-Restart Determinism & Startup Recovery (Expansion V22)

Close daemon restart gaps by persisting finalized-block metadata and restoring runtime chain head deterministically from disk.

### Task List
- [x] **Finalized-Block Checkpoint Persistence:** Persist finalized block metadata alongside chain snapshot + sync checkpoint during graceful shutdown flush.
- [x] **Startup Recovery Constructor:** Add daemon constructor path that restores from persisted state/checkpoints and only falls back to genesis when no persisted state exists.
- [x] **Recovery Consistency Gate:** Reject startup when recovered state snapshot metadata and finalized-block checkpoint metadata disagree.
- [x] **Checkpoint Corruption Surface:** Add typed daemon errors for finalized-block checkpoint missing/read/decode/write failures.
- [x] **CLI Recovery Wiring:** Update node CLI startup to use persisted recovery automatically whenever `state_directory` is configured.
- [x] **Expansion:** Updated `src/node/daemon.rs` with `FINALIZED_BLOCK_CHECKPOINT_FILE_NAME`, `from_persisted(...)`, `from_persisted_or_genesis(...)`, finalized-block checkpoint persistence/recovery helpers, extended `NodePersistenceReport`, and new finalized-checkpoint error variants.
- [x] **Expansion:** Updated `src/node/cli.rs` daemon initialization path to recover from persisted state directory and expanded persistence flush output with finalized-checkpoint byte metrics.
- [x] **Expansion:** Added daemon regression tests for persisted restart state restoration, empty-directory genesis fallback, and missing finalized-checkpoint rejection.

---

## 30. Phase 29: Sync Transport Restart Sanitization (Expansion V23)

Eliminate restart fragility caused by persisted in-flight sync transport state that depends on volatile runtime-only request-session bindings.

### Task List
- [x] **Scheduler Restart Sanitization API:** Add typed scheduler API to abandon recovered in-flight request transport state during process restart.
- [x] **Session Restart Sanitization API:** Add typed session-manager API to drop recovered in-flight chunk windows and reset peer transport counters while preserving retry-history entries.
- [x] **Daemon Recovery Hardening:** Update daemon persisted-startup sync recovery path to sanitize recovered in-flight transport state instead of hard-failing startup.
- [x] **Post-Restart Operability Test:** Add daemon regression proving startup recovery succeeds with persisted in-flight sync state and that new outbound scheduling remains operational after sanitization.
- [x] **Transport Sanitization Unit Tests:** Add sync-engine unit coverage for scheduler/session restart sanitization behavior and counter reset guarantees.
- [x] **Expansion:** Updated `src/network/sync_engine.rs` with `abandon_in_flight_for_restart(...)` APIs on `ChunkRequestScheduler` and `ChunkSessionManager` plus targeted tests.
- [x] **Expansion:** Updated `src/node/daemon.rs` recovered-sync path to sanitize recovered in-flight transport state and continue deterministic startup recovery.
- [x] **Expansion:** Replaced the previous startup-rejection regression with restart-sanitization coverage in daemon tests.

---

## 31. Phase 30: Durable Mempool Persistence (Expansion V24)

Add durable mempool checkpoint storage/recovery with strict restart revalidation and explicit operator-facing recovery accounting.

### Task List
- [x] **`redb`-Backed Mempool Checkpoint:** Added durable mempool checkpoint storage/recovery in `src/core/mempool_checkpoint.rs` using versioned metadata + network-domain checks (`mempool.checkpoint.redb`).
- [x] **Graceful + Periodic Flush Path:** Wired mempool checkpoint persistence into daemon shutdown flush (`persist_runtime_state`) and periodic maintenance ticks (`mempool_checkpoint_interval_ms`) when persistence is configured.
- [x] **Restart Revalidation + Pruning:** Added restart ingest path that revalidates recovered entries against recovered chain state and mempool uniqueness constraints, dropping invalid/stale/conflicting entries deterministically.
- [x] **Typed Recovery Counters:** Extended daemon recovery reporting with `mempool_recovered`, `mempool_dropped_invalid`, and `mempool_dropped_conflict`.
- [x] **Runtime Config + CLI Surface:** Added `mempool_checkpoint_interval_ms` to `node.toml`, CLI flags, config validation, and operator report output.
- [x] **Expansion:** Added `Mempool::checkpoint_entries(...)`, `Mempool::insert_recovered_checkpoint_entry(...)`, and focused checkpoint + daemon recovery/periodic persistence tests.
- [x] **Acceptance Gate:** Passed `cargo fmt --all`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-targets`, and `bash scripts/release_gate.sh`.

---

## 32. Phase 31: Persistent Indexer Pipeline (Expansion V25)

Add durable finalized-block event indexing with replayable recovery and bounded retention compaction.

### Task List
- [x] **Finalization-Boundary Event Log:** Added append-only finalized block event storage in `src/core/indexer.rs` (`redb`) and wired append calls at daemon finalization boundary.
- [x] **Persistent Query Indexes:** Implemented durable indexes:
  - `tx_by_hash`
  - `tx_by_sender_nonce`
  - `tx_by_address_timeline`
  - `block_by_height`
- [x] **Deterministic Replay/Rebuild:** Added startup/indexer rebuild routine that replays retained finalized events when secondary indexes are missing/out-of-sync/corrupt.
- [x] **Retention + Compaction Policy:** Added bounded retention policy (`index_max_retained_blocks`) with segment compaction that prunes old finalized events and corresponding secondary-index rows.
- [x] **Daemon + Config Wiring:** Integrated indexer attachment in daemon persistence configuration, added index diagnostics in persistence report, and exposed daemon query helpers for indexed block/transaction/timeline lookups.
- [x] **CLI/Config Surface:** Added `index_max_retained_blocks` to node config parsing/validation, CLI overrides, and `node.toml.example`.
- [x] **Expansion:** Added focused indexer unit coverage (roundtrip queries, rebuild flow, compaction pruning, idempotent ensure) plus daemon integration test proving finalized tx indexing path under persistent runtime.

---

## 33. Phase 32: Production Node Lifecycle Completion (Expansion V26)

Complete daemon lifecycle management with explicit startup/shutdown states, strict integrity checks, and operator-controlled recovery modes.

### Task List
- [x] **Explicit Lifecycle State Machine:** Added/operationalized `NodeLifecycleState::{Bootstrapping, Syncing, Ready, Draining, Stopped}` in daemon runtime transitions.
- [x] **Resilient Drain/Stop Semantics:** Added `drain_and_stop()` shutdown path that transitions to `Draining`, flushes checkpoints, drops index/swarm handles, and finalizes `Stopped`.
- [x] **Intake Stop Gate:** Enforced inbound intake rejection outside `Ready|Syncing` with typed `NodeDaemonError::IntakeStopped`.
- [x] **Startup Integrity Coherence Checks:** Added startup validation for recovered sync policy coherence, mempool-vs-state coherence, and finalized-index tip coherence with strict fail-closed behavior.
- [x] **Operator Recovery Modes:** Added config/runtime controls:
  - `strict_recovery`
  - `repair_index`
  - `ignore_mempool_checkpoint`
- [x] **Runtime Config + CLI + Example Wiring:** Extended `NodeRuntimeConfig`, `NodeRuntimeOverrides`, CLI args, and `node.toml.example` with all lifecycle/recovery-mode controls.
- [x] **Recovery/Shutdown Regression Coverage:** Added daemon tests for strict vs non-strict sync mismatch recovery, ignore-mempool checkpoint mode, explicit index repair mode, lifecycle transition to stopped, and post-stop intake rejection.
- [x] **Acceptance Gate:** Passed:
  - `cargo fmt --all`
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  - `cargo test --workspace --all-targets`
  - `bash scripts/release_gate.sh`

---

## 34. Phase 33: JSON-RPC + WS Node API (Expansion V27)

Add a production-oriented API surface for node query/submission and operator observability over JSON-RPC and WebSocket subscriptions.

### Task List
- [x] **RPC Server Module:** Added `src/node/rpc.rs` with runtime server bootstrapping (`axum`) and daemon-state integration.
- [x] **Daemon Runtime Wiring:** Wired RPC startup into `homa-node run` lifecycle using shared daemon state, graceful shutdown coordination, and stop/drain persistence semantics.
- [x] **Config/CLI Surface:** Added runtime/CLI options:
  - `rpc_listen_addr`
  - `rpc_max_body_bytes`
  - `rpc_rate_limit_per_sec`
  - `ws_max_subscriptions_per_conn`
- [x] **Core JSON-RPC Methods Implemented:**
  - `homa_getStatus`
  - `homa_getBlockByHeight`
  - `homa_getBlockByHash`
  - `homa_getBalance`
  - `homa_getTransaction`
  - `homa_sendRawTransaction`
  - `homa_getMempoolStats`
  - `homa_getPeers`
- [x] **WS Subscription Channels Implemented:**
  - `newHeads`
  - `txAccepted`
  - `syncStatus`
  - `peerReputationEvents`
- [x] **Request Hardening:** Enforced bounded request sizes (`DefaultBodyLimit` / WS message cap) and per-IP fixed-window rate limiting.
- [x] **Typed RPC Error Mapping:** Added JSON-RPC typed error object mapping for daemon/runtime failures and invalid request/params paths.
- [x] **Indexer Query Expansion:** Added `FinalizedIndexer::get_block_by_hash(...)` and daemon query wrappers for hash-based block resolution.
- [x] **Regression Coverage:** Added RPC unit tests for status query, raw transaction submit+pending lookup roundtrip, and rate limiter behavior.
- [x] **Acceptance Gate:** Passed:
  - `cargo fmt --all`
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  - `cargo test --workspace --all-targets`
  - `bash scripts/release_gate.sh`
