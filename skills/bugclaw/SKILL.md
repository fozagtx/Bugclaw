# Bugclaw

Use Bugclaw only for source code the operator is authorized to review. Require an explicit authorization reference for every scan. Keep scans local and use the network-denied OpenShell runner for all generated proof-of-concept execution.

1. Call `bugclaw_scan` with the source path, authorization reference, and optional file/domain limits.
2. Follow progress with `bugclaw_status`; inspect returned candidates with `bugclaw_candidates`.
3. Use `bugclaw_reproduce` for a candidate and inspect all evidence with `bugclaw_evidence`.
4. Report outcomes as unverified until a human uses the HTTP signoff endpoint. Signoff is deliberately not an MCP tool. Never claim a candidate is confirmed.
