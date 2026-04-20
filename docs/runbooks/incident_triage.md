# Incident Triage Runbook

1. Capture current status (`homa_getStatus`, `homa_getPeers`, logs).
2. Classify issue: networking, consensus admission, storage, or recovery.
3. Apply scoped mitigations:
   - network isolation / peer bans
   - strict recovery restart
   - index repair or mempool ignore mode
4. Document root cause, remediation, and follow-up actions.
