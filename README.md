# Homa (HMA)

Homa is a pure Rust Layer-1 blockchain project implementing a hybrid model:

- stake-weighted proposer selection (PoS side)
- client-side proof-of-work per transaction (PoW side)

This repository currently contains the protocol core, networking/sync hardening primitives, a node daemon CLI (`homa-node`), and a wallet CLI (`homa-cli`).

## Project Status

Homa is in active pre-alpha development.

Implemented in this repository today:

- core ledger/state/block/transaction primitives
- deterministic fork-choice and partition reconciliation helpers
- snapshot fast-sync with checkpoint verification and anti-rollback protections
- P2P transport and sync wire codecs
- peer reputation, adaptive penalties, and checkpoint-trust rotation logic
- node daemon runtime loop wiring with bounded pending-block finalization
- deterministic local block production (slot-scheduled leader gating + self-finalization)
- wallet CLI for key generation and transaction broadcasting
- deterministic chaos and fuzz testing harnesses

Not implemented yet (production gaps):

- full production node-daemon lifecycle (current daemon is a pre-alpha skeleton)
- RPC/REST/GraphQL APIs
- persistent mempool/indexer pipeline
- validator operations tooling and deployment automation

## Design Highlights

- `Pure Rust` codebase with strict linting and no `unsafe`.
- `Hybrid consensus`: deterministic stake-weighted leader election plus transaction-level PoW admission signal.
- `Hard supply cap`: `36,000,000 HMA` (`3_600_000_000_000_000` micro-homa).
- `Network-domain separation`: transaction and checkpoint signatures are bound to network IDs.
- `Fast sync hardening`:
  - snapshot payload/state-root verification
  - admission limits (size/account caps)
  - chunked sync with per-chunk integrity hashes
  - rollback-safe import mode checks
- `Abuse resistance`:
  - peer reputation scoring + decay + temporary bans
  - adaptive dial cooldown and serve throttling
  - sync-session checkpoint persistence for restart recovery
  - signed checkpoint trusted-set rotation with deterministic activation

## Repository Layout

- `src/consensus/`
  - `stake.rs`: validator stake accounting
  - `leader.rs`: deterministic stake-weighted leader election
  - `pow.rs`: transaction PoW hashing/verification
- `src/core/`
  - `transaction.rs`: signed tx model + zero-copy decode path
  - `mempool.rs`: admission controls, TTL pruning, rate limits
  - `block.rs`: block/header serialization + integrity checks
  - `state.rs`: account state machine and block application
  - `fork_choice.rs`: deterministic branch selection + reconciliation
  - `sync.rs`: snapshot/chunk/checkpoint verification and import
  - `recovery.rs`: crash-safe snapshot/WAL commit and recovery
  - `genesis.rs`: deterministic genesis allocations and forging
- `src/network/`
  - `p2p.rs`: libp2p transport, gossip topics, sync wire messages
  - `sync_engine.rs`: chunk scheduling, serve limiting, session state, persistence hooks
  - `reputation.rs`: peer scoring and adaptive penalties
  - `checkpoint_rotation.rs`: trusted-checkpoint-set rotation manager
- `src/node/`
  - `daemon.rs`: daemon runtime integrating inbound runtime loop, pending-block finalization, slot-scheduled block production, sync maintenance, and swarm polling
  - `config.rs`: typed `node.toml` config loading and startup validation
  - `cli.rs`: node daemon command-line entrypoint
- `src/observability/`
  - structured counters/events (`slot_miss`, `gossip_failure`, `sync_lag`)
- `src/wallet/`
  - CLI key management and tx send/broadcast
- `tests/`
  - integration chaos tests and deterministic partition fuzz harness
- `fuzz/`
  - `cargo-fuzz` target for untrusted gossip transaction payload decoding

## Build and Toolchain

Minimum toolchain from `Cargo.toml`:

- Rust `1.85+`
- Edition `2024`

Build:

```bash
cargo build
```

Run all tests:

```bash
cargo test --workspace --all-targets
```

Run strict lint gate:

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Format:

```bash
cargo fmt --all
```

Full pre-release gate:

```bash
bash scripts/release_gate.sh
```

## Wallet CLI (`homa-cli`)

The binary entrypoint is `homa-cli`.

Show help:

```bash
cargo run --bin homa-cli -- --help
cargo run --bin homa-cli -- keys --help
cargo run --bin homa-cli -- tx --help
```

### 1) Generate an encrypted wallet

```bash
cargo run --bin homa-cli -- keys generate --network testnet
```

Optional flags:

- `--wallet-path <PATH>`
- `--state-path <PATH>`
- `--passphrase <VALUE>` (or `HOMA_WALLET_PASSPHRASE`)

Defaults when not specified:

- wallet file: `~/.homa/wallet.key`
- local nonce state: `~/.homa/wallet_state.json`

### 2) Send a transaction

```bash
cargo run --bin homa-cli -- tx send <RECEIVER_HMA_ADDRESS> 1.25 \
  --network testnet \
  --seed-domain seed1.homanetwork.io \
  --broadcast-timeout-ms 8000
```

Useful options:

- `--nonce <N>` override local nonce
- `--fee-micro <U64>` fee in micro-homa (default `1`)
- `--min-pow-bits <U16>` minimum required PoW bits (default `10`)
- `--pow-time-ms <U64>` local PoW solve target duration (default `1500`)
- `--fallback-bootstrap <ENTRY>` repeatable; accepts `IP`, `IP:PORT`, or full multiaddr

Amount format:

- accepts HMA decimal strings with up to 8 decimals
- examples: `12`, `0.125`, `1.00000001`

## Node CLI (`homa-node`)

The binary entrypoint is `homa-node`.

Show help:

```bash
cargo run --bin homa-node -- --help
cargo run --bin homa-node -- run --help
```

Run from config file:

```bash
cp node.toml.example node.toml
cargo run --bin homa-node -- run --config node.toml
```

Run node daemon with bounded smoke steps (recommended for first run):

```bash
cargo run --bin homa-node -- run \
  --network devnet \
  --no-bootstrap \
  --max-steps 5
```

Run long-lived daemon (Ctrl+C to stop):

```bash
cargo run --bin homa-node -- run \
  --network testnet \
  --seed-domain seed1.homanetwork.io \
  --fallback-bootstrap /ip4/127.0.0.1/tcp/7000
```

Useful options:

- `--config <PATH>` load runtime settings from `node.toml`
- `--no-listen` skip opening local listen sockets
- `--no-bootstrap` skip DNS/fallback bootstrap dial attempts
- `--strict-bootstrap` fail startup if bootstrap cannot dial
- `--event-loop-tick-ms <U64>` runtime maintenance tick interval
- `--slot-duration-ms <U64>` consensus slot duration used for leader scheduling
- `--max-block-transactions <USIZE>` transaction cap for one locally produced block
- `--min-pow-bits <U16>` mempool admission PoW floor
- `--max-pending-blocks <USIZE>` pending decoded block queue bound
- `--max-steps <USIZE>` bounded event-loop steps for smoke/automation
- `--state-directory <PATH>` enable graceful shutdown persistence flush (state snapshot + sync checkpoint)
- `--producer-secret-key-hex <HEX>` enable local block production with a 32-byte Ed25519 secret key

Runtime behavior notes:

- each maintenance tick processes timeout/retry feedback, then attempts bounded pending-block finalization
- if a local producer key is configured, each new slot performs deterministic leader election and produces at most one block when local validator is elected
- pending blocks are finalized only when height and parent hash match the current finalized tip
- invalid/stale blocks are rejected; out-of-order future blocks are retained until parent blocks arrive
- transactions included in finalized blocks are evicted from mempool

## Security Model (Current)

- Wallet private keys are encrypted at rest:
  - key derivation: `Argon2`
  - encryption: `ChaCha20Poly1305`
- Wallet and state files are written with secure file mode on Unix (`0600`).
- Transactions include sender public key and enforce sender-address authority binding.
- Transaction signatures are network-domain bound.
- Snapshot checkpoint signatures enforce trusted-validator thresholds.
- Rotation updates for trusted checkpoint sets require signatures from currently active trusted validators.

## Networking and Sync Notes

Current gossip topics:

- `transactions`
- `blocks`
- `sync-requests`
- `sync-chunks`

Sync transport includes:

- bounded encode/decode for request/response envelopes
- malformed/oversized payload rejection
- retry-aware outbound chunk scheduler
- serve-side peer quota limiter
- per-session/per-peer in-flight windows with deterministic backoff
- optional strict checkpoint-aware handshake validation
- persisted sync-session checkpoint state for restart continuity

## Testing and Fuzzing

### Integration and chaos tests

```bash
cargo test --workspace --all-targets
```

Includes:

- delayed-link convergence checks
- temporary partition reconcile checks
- deterministic seed-replay partition chaos fuzzer

### Fuzz targets (network decode boundaries)

```bash
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz run gossipsub_tx_payload -- -max_total_time=60
cargo +nightly fuzz run block_payload -- -max_total_time=60
cargo +nightly fuzz run sync_chunk_payload -- -max_total_time=60
```

Targets:

- `gossipsub_tx_payload`: transaction gossip decode boundary
- `block_payload`: block gossip payload bound + decode/validation path
- `sync_chunk_payload`: sync wire/chunk decode path

## Architecture Plan and Tracker

The active architecture + implementation tracker is:

- `Homa_Architecture_and_Implementation_Plan.md`

This document is used as the project’s living phase/task source of truth.

## Development Principles in This Repo

- `unsafe` is forbidden by lint policy.
- Warnings are denied in CI-style workflows.
- Clippy `all` + `pedantic` are enabled and enforced.
- Typed error enums are preferred across modules.
- Deterministic serialization and validation boundaries are emphasized for untrusted network input.

## Contributing

1. Fork and create a feature branch.
2. Make changes with focused commits.
3. Run the full quality gate locally:

```bash
bash scripts/release_gate.sh
```

4. Open a PR with:
- problem statement
- design summary
- test evidence
- migration/compatibility notes (if applicable)

## License

Licensed under Apache-2.0.
