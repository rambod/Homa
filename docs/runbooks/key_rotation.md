# Key Rotation Runbook

1. Prepare new Ed25519 secret key.
2. Run: `homa-node validator key rotate --state-directory <dir> --new-secret-key-hex <hex>`.
3. Update node config if needed and restart daemon.
4. Validate derived validator address and production eligibility.
