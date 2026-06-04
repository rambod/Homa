# Homa Project Roadmap

**Audit date:** 2026-04-25
**Status:** active pre-alpha, protocol/runtime feature complete in many local paths, not production-ready.

This file is the short current roadmap. `../Homa_Architecture_and_Implementation_Plan.md` remains the long-form phase history and detailed task tracker.

## Current Capability Audit

| Area | Current state | Evidence |
| --- | --- | --- |
| Crypto and addressing | Implemented: Ed25519 keys, network-domain addresses, checksum parsing, signature verification. | `src/crypto/` |
| Transactions | Implemented: signed transfer model, sender public-key authority binding, network-domain signing, bounded decode. | `src/core/transaction.rs` |
| Ledger state | Implemented: account balances/nonces, max supply cap, fee redistribution, deterministic state root. | `src/core/state.rs` |
| Blocks | Implemented: block/header model, transaction root, proposer proof validation, bounded decode. | `src/core/block.rs` |
| Mempool | Implemented: PoW admission, fee/PoW priority, TTL pruning, sender/peer throttles, durable checkpoint recovery. | `src/core/mempool.rs`, `src/core/mempool_checkpoint.rs` |
| Fast sync primitives | Implemented: snapshots, chunking, checkpoint verification, anti-rollback import, runtime assembly/quarantine, P2P advertisement/request/response orchestration. | `src/core/sync.rs`, `src/network/sync_runtime.rs`, `src/node/daemon.rs` |
| Finality | Implemented: `dev_self` and `quorum` modes, network-domain finality votes, quorum certificates, `finality-votes` gossip codec, duplicate/equivocation tracking, and certificate-gated pending block finalization in quorum mode. | `src/consensus/finality.rs`, `src/node/daemon.rs` |
| P2P boundary | Implemented: libp2p swarm setup, gossipsub topics, Kademlia bootstrap helpers, targeted sync wire codecs, snapshot advertisements, finality vote gossip codec. | `src/network/p2p.rs` |
| Reputation and runtime policy | Implemented: peer scoring, adaptive serve/dial penalties, checkpoint trust-set rotation. | `src/network/reputation.rs`, `src/network/runtime_policy.rs`, `src/network/checkpoint_rotation.rs` |
| Node daemon | Implemented: lifecycle states, pending block finalization, local block production, quorum-gated finality mode, restart recovery, persistence flush, swarm polling. | `src/node/daemon.rs` |
| RPC/WS | Implemented: JSON-RPC server, request limits, status/block/balance/tx/mempool/peer methods, WS subscriptions. | `src/node/rpc.rs` |
| Persistent indexer | Implemented: finalized block event log, transaction/block/address indexes, rebuild and retention compaction. | `src/core/indexer.rs` |
| Wallet CLI | Implemented: encrypted wallet, nonce state, local PoW, signed tx broadcast over gossipsub. | `src/wallet/cli.rs` |
| Tests and fuzzing | Implemented: unit tests, chaos integration tests, partition chaos fuzzer, three cargo-fuzz targets. | `tests/`, `fuzz/` |
| Deploy and ops docs | Present: Docker/systemd/logrotate, generated devnet configs/scripts, and baseline runbooks exist; production drills and observability export still need hardening. | `deploy/`, `scripts/devnet.sh`, `docs/runbooks/` |

## Main Gaps

1. **Distributed finality needs real-swarm hardening.** Validator votes, quorum certificates, gossip decoding, and quorum-gated daemon finalization now exist, but partition semantics, certificate persistence/index exposure, and multi-process finality tests remain.
2. **Validator membership is static.** Stake and trusted-checkpoint sets derive from deterministic genesis/bootstrap state. There is no on-chain staking, unbonding, validator activation, or slashing flow.
3. **Devnet needs extended end-to-end validation.** Per-node generation, stable P2P ports, snapshot advertisements, request publication, chunk serving, and response import are implemented; the remaining work is a stronger multi-process transaction/restart/catch-up test.
4. **Deployment config is still pre-production.** Devnet Docker/local tooling exists, but secrets, metrics, alerting, backup drills, and release artifacts still need production hardening.
5. **Observability is in-process only.** Counters/events exist, but there is no Prometheus/OpenTelemetry endpoint, alert set, dashboard, or production log schema.
6. **Operator procedures need drill validation.** Runbooks now include baseline commands and checks, but production needs exercised rollback criteria, ownership, and failure-mode decision trees.
7. **Security release posture is incomplete.** Release gates exist, but mainnet needs a threat model, external review, longer fuzz/soak runs, reproducible artifacts, genesis ceremony, and key-management policy.

## Priority Backlog

### P0: Production-Critical Protocol Safety

- [x] Define validator vote and finality certificate structures with network-domain-separated signatures.
- [x] Add vote gossip topic, vote admission, equivocation accounting, and duplicate vote handling.
- [x] Require quorum finality certificates before advancing finalized height in explicit quorum mode.
- [x] Keep local self-finalization as the default dev/test mode behind explicit config.
- [x] Add focused multi-validator tests for normal quorum finality, missing quorum, wrong network, duplicate validator, and equivocation accounting.
- [ ] Add real-swarm finality tests for delayed votes, partitions, invalid certificates, partition heal, and stalled finality recovery.
- [ ] Persist/index finality certificate metadata and expose certificate details in block/RPC lookups beyond status counters.

### P0: Real Multi-Node Devnet

- [x] Add per-node devnet config generation with unique state directories, producer keys, RPC ports, and bootstrap multiaddrs.
- [x] Fix container-facing defaults: RPC must bind `0.0.0.0` in Docker/devnet, and P2P listen ports must match exposed ports or be discoverable.
- [x] Complete sync request/response publication and serving in daemon runtime.
- [x] Add snapshot advertisement gossip and targeted sync request/response peer identities.
- [x] Add a single devnet command surface for generation, local/Docker bring-up, health checks, logs, smoke, and teardown.
- [ ] Add an end-to-end devnet test that starts 3 nodes, submits a transaction, produces/finalizes blocks, restarts a node, and verifies RPC/indexer recovery.
- [ ] Extend devnet smoke to assert lagging-node snapshot catch-up under real process/network churn.

### P1: Validator and Staking Lifecycle

- [ ] Decide whether staking is represented as dedicated transaction variants or a separate validator operation protocol.
- [ ] Add validator registration, stake increase/decrease, unbonding delay, epoch activation, and validator removal rules.
- [ ] Connect active validator set changes to leader election, checkpoint trust rotation, and RPC status.
- [ ] Add slashing/evidence state for double-signing and invalid finality votes.
- [ ] Replace hardcoded production genesis key material with a dev-only path plus mainnet genesis input/ceremony tooling.

### P1: RPC, Wallet, and Indexer Productization

- [ ] Publish a JSON-RPC/WS method reference with request/response examples and error codes.
- [ ] Add wallet `--rpc-url` submission mode using `homa_sendRawTransaction`, while retaining direct gossip broadcast as an advanced mode.
- [ ] Add RPC methods for address timelines, transaction-by-sender/nonce, block ranges, and node version/build info.
- [ ] Add HTTP/WS integration tests against a real bound RPC server.
- [ ] Add compatibility/versioning rules for API changes.

### P1: Operations and Observability

- [ ] Add metrics export endpoint and define alert rules for sync lag, slot misses, block rejection spikes, RPC rate limits, peer bans, and persistence failures.
- [ ] Drill-validate runbooks for bootstrap, restart, recovery, backup/restore, incident triage, and key rotation, then add expected outputs and rollback criteria.
- [ ] Harden systemd and Docker deployment: config templates, secrets handling, health checks, persistent volumes, and log rotation validation.
- [ ] Add backup restore drill automation against a temporary state directory.
- [ ] Add release artifact build and checksum/signature generation.

### P2: Security, Performance, and Release Readiness

- [ ] Write and review a formal threat model covering consensus, network, wallet, RPC, persistence, and deployment.
- [ ] Increase fuzz duration in CI nightlies and add corpus minimization/coverage reporting.
- [ ] Add property tests for finality, supply conservation, snapshot import, and indexer replay invariants.
- [ ] Run long soak tests with realistic mempool load, node restarts, and network churn.
- [ ] Resolve or explicitly document remaining supply-chain advisories and yanked transitive dependencies.

## Definition of Done for Production Beta

- [ ] A real multi-node devnet can run from clean checkout with one command.
- [x] Blocks finalize only with validator quorum certificates in explicit quorum mode.
- [ ] Quorum mode is validated by real multi-process devnet tests under partitions, restart, and catch-up.
- [ ] Validator set changes are deterministic, delayed by epoch rules, and covered by tests.
- [ ] Node restart, backup/restore, and index/mempool recovery are tested in automation.
- [ ] RPC and wallet flows are documented and covered by integration tests.
- [ ] Operators have actionable runbooks, metrics, alerts, and deployment templates.
- [ ] Full release gate plus longer fuzz/soak jobs pass on release branches.
- [ ] External security review findings are triaged before mainnet genesis.
