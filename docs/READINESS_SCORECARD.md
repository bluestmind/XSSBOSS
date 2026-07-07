# XSS Boss readiness scorecard

Snapshot: 2026-08-28

Current verified score: **9.4 / 10**

This is an evidence-based release score, not a count of payloads or features.
The system is now a strong research-grade platform. It is not honestly a 10/10
release yet because the accuracy corpus is still relatively small, the newest
revision has not completed hosted CI, and no independent security review is
attached.

| Area | Weight | Earned | Evidence / remaining gap |
|---|---:|---:|---|
| One-way flow and correctness | 1.5 | 1.45 | One URL owns recon, profiling, execution, correlation, research, and reporting checkpoints with one terminal outcome. |
| Detection and research intelligence | 2.0 | 1.80 | Persistent graph, ranked hypotheses, bundle/RSC/API recon, context-aware techniques, browser-oracle feedback, and tenant-level cross-run learning are integrated. More schema/state differential executors and independent benchmark targets remain. |
| Accuracy and evidence | 1.5 | 1.35 | Hard browser lab: TP 15, TN 3, FP 0, FN 0. Evidence is content-addressed and access-controlled. The corpus needs substantially more versioned negatives, framework variants, and stored/stateful cases. |
| Durability and recovery | 1.5 | 1.45 | Alembic fresh/upgrade through 0007, leases, idempotency, 10,000-case loss/duplicate proof, worker recovery, backup restore, and evidence hash revalidation pass. |
| Horizontal scale and performance | 1.5 | 1.45 | Durable micro-batches plus database reconciliation passed 100 runs/10,000 cases: queue P95 40.403 s, completion 84.578 s, zero duplicate executions, and 52 recovered cases after API/orchestrator/worker/Redis disruption. |
| Security and multi-tenancy | 1.25 | 1.20 | Tenant ORM boundaries, API auth, quotas, audit/retention, scoped artifact delivery, production config refusal, secret redaction, and safe capability canaries are tested. External security review remains. |
| Operations and product quality | 0.75 | 0.70 | P95 API latency is 203.983 ms at 1,000 requests/32 concurrency; metrics, alerts, dashboards, Compose, lazy UI routes, production build, and lint pass. CI still needs a real hosted green run for this exact revision. |
| **Total** | **10.0** | **9.40** | **High-end research platform; final independent and corpus gates remain.** |

## Evidence currently attached

- `reports/hard_lab_accuracy.json`
- `reports/scale_recovery.json`
- `reports/scale_recovery_final.json` (correctness green, queue SLO red)
- `reports/scale_recovery_reconciled.json` (current scale/recovery/SLO gate, green)
- `reports/backup_restore_verified.json`
- `reports/api_latency_async_audit.json`
- `reports/tenant_artifact_isolation.json`
- `reports/observability_gate.json`
- 92 passing backend tests, production UI build, and strict UI lint

## Remaining gates for 10/10

1. Expand the versioned browser corpus to cover more frameworks, encodings, CSP/Trusted Types, stored/multi-role workflows, postMessage, client-side routing, and hard negative controls.
2. Add active bounded executors for schema-derived GraphQL/OpenAPI operations and state-transition/role differentials; keep destructive actions opt-in and policy-gated.
3. Run the entire quality workflow on hosted CI and retain all evidence artifacts for the same commit.
4. Complete an external security review and a longer soak test with worker churn, Redis/PostgreSQL interruptions, and evidence-volume pressure.
