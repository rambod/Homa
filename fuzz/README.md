# Homa Fuzz Targets

## Run

```bash
cargo install cargo-fuzz
cd fuzz
cargo fuzz run gossipsub_tx_payload -- -max_total_time=60
```

The `gossipsub_tx_payload` target continuously feeds malformed and random byte payloads to the transaction gossip decode boundary (`decode_transaction_gossip_payload`) to catch panics and memory safety issues in network-facing decoding.
