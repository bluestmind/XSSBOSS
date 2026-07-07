# XSS Boss 10/10 production gates

“10/10” is a release state, not a subjective label. A release earns it only when
every gate below is green in CI and in a production-like environment.

## Correctness

- Every endpoint and finding has an explicit run ownership row.
- Browser retries are idempotent under duplicate delivery and worker loss.
- A run has durable recon, profiling, execution, correlation, and reporting checkpoints.
- The one-shot URL reaches exactly one terminal result: completed or failed.
- Database migrations pass both fresh-install and upgrade-from-previous-release tests.

## Accuracy

- Versioned vulnerable and non-vulnerable corpus covers reflected, stored, DOM,
  encoded, CSP-constrained, and multi-step cases.
- Recall is at least 95%, precision at least 98%, and no high/critical regression
  is accepted relative to the previous release.
- Every confirmed finding links to immutable request, response, execution, and
  screenshot/DOM evidence hashes.

## Scale and recovery

- PostgreSQL is mandatory in production; Redis/Celery owns durable orchestration.
- Orchestration and browser workers run on separate queues and scale independently.
- Sustained test: 100 concurrent runs and 10,000 queued cases without lost work.
- Kill-test API, orchestrator, Redis connection, and browser workers mid-run; all
  work resumes, with zero duplicate completed executions.
- P95 API latency stays below 300 ms excluding scan execution; queue delay and scan
  completion SLOs have explicit budgets.

## Security and operations

- Production refuses SQLite, inline orchestration, default secrets, weak API auth,
  and localhost CORS origins.
- No credentials are committed. Oracle tokens are high entropy, scoped, expiring,
  and redacted from logs.
- Readiness checks database and queue; metrics have low-cardinality labels and no
  target URLs or payloads.
- Backups, restore drills, retention, tenant isolation, rate quotas, audit logging,
  dashboards, and alerts are tested.

## Release rule

The score is the weighted percentage of passing gates. A release cannot be
described as 10/10 until the expanded accuracy corpus, crash-recovery load test,
hosted CI run, and independent security review are attached to the same release.

The reproducible implementation for the sustained and kill/recovery checks is
`tools/scale_recovery_gate.py`. It refuses SQLite and sub-threshold run sizes so
a reduced local smoke cannot be mistaken for production evidence.

The current green scale artifact is `reports/scale_recovery_reconciled.json`.
It uses late-acked durable micro-batches and a database-backed recovery sweep so
broker-reserved work is reconstructed from authoritative case state after a
restart. Per-case leases and idempotency still absorb late duplicate delivery.

`tools/verify_restore.py` compares authoritative row counts and recomputes every
content-addressed artifact after the database and evidence volume are restored
to new locations. `tools/api_latency_gate.py` enforces the 1,000-request,
32-concurrent-client P95 API budget.
