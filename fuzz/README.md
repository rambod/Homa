# Homa Fuzz Targets

## Run

```bash
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz run gossipsub_tx_payload -- -max_total_time=60
cargo +nightly fuzz run block_payload -- -max_total_time=60
cargo +nightly fuzz run sync_chunk_payload -- -max_total_time=60
```

Targets:

- `gossipsub_tx_payload`: transaction gossip decode boundary (`decode_transaction_gossip_payload`)
- `block_payload`: block gossip payload bound check + block decode/validation path
- `sync_chunk_payload`: sync wire/chunk request/chunk response decode boundaries
