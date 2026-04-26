# Key Rotation Runbook

Current key rotation tooling updates local validator key material. Production validator-set membership and finality keys are still roadmap work, so coordinate any validator identity change with the active devnet/testnet process before restart.

1. Prepare new Ed25519 secret key.
2. Validate the key and derived address:

```bash
homa-node validator key load --network testnet --secret-key-hex <hex>
```

3. Write the key into the state directory:

```bash
homa-node validator key rotate \
  --state-directory /var/lib/homa \
  --network testnet \
  --new-secret-key-hex <hex>
```

4. Update `producer_secret_key_hex` in `node.toml` if the daemon still reads producer keys from config.
5. Restart the daemon during a maintenance window.
6. Validate:
   - `homa-node validator status --config /etc/homa/node.toml`
   - `homa_getStatus` reports a healthy lifecycle
   - produced-block counters increase only if the new key is an active staked validator

Rollback is to restore the previous key/config from backup and restart.
