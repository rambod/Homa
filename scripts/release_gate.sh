#!/usr/bin/env bash
set -euo pipefail

require_cargo_subcommand() {
  local subcommand="$1"
  if ! cargo "${subcommand}" --version >/dev/null 2>&1; then
    echo "missing cargo subcommand: cargo ${subcommand}"
    echo "install with: cargo install cargo-${subcommand} --locked"
    exit 1
  fi
}

require_nightly_toolchain() {
  if ! rustup toolchain list | grep -q '^nightly'; then
    echo "missing nightly toolchain"
    echo "install with: rustup toolchain install nightly"
    exit 1
  fi
}

echo "==> fmt"
cargo fmt --all --check

echo "==> clippy"
cargo clippy --workspace --all-targets --all-features -- -D warnings

echo "==> tests"
cargo test --workspace --all-targets

echo "==> audit"
require_cargo_subcommand audit
cargo audit \
  --ignore RUSTSEC-2024-0436 \
  --ignore RUSTSEC-2025-0141 \
  --ignore RUSTSEC-2026-0097

echo "==> deny"
require_cargo_subcommand deny
cargo deny check advisories bans sources

echo "==> fuzz smoke"
require_nightly_toolchain
require_cargo_subcommand fuzz
(
  cd fuzz
  cargo +nightly fuzz run gossipsub_tx_payload -- -max_total_time=20
  cargo +nightly fuzz run block_payload -- -max_total_time=20
  cargo +nightly fuzz run sync_chunk_payload -- -max_total_time=20
)

echo "release gate passed"
