# Autonomous research architecture

XSS Boss follows one bounded path from an authorized target to a defensible
result:

```text
authorized URL
  -> dynamic/passive recon
  -> run-owned attack-surface graph
  -> ranked security hypotheses
  -> context/filter-aware technique selection
  -> browser and direct-auditor execution
  -> immutable evidence
  -> hypothesis + technique feedback
  -> correlation and campaign report
```

## What makes the loop adaptive

The planner persists target, endpoint, parameter, reflection context, browser
sink, client script, DOM source, and sink-family nodes. Relationships record
whether a target exposes an endpoint, an endpoint accepts a parameter, a value
reflects into a context, a confirmed context flows to a sink, or a script merely
contains/co-locates static signals.

Hypotheses are ranked by confidence and impact. They currently cover reflected
and DOM XSS, open redirect, SSRF, traversal, SQL injection, CORS, GraphQL,
stateful workflows, client-side taint candidates, postMessage boundaries,
prototype pollution, and fingerprinted client-secret indicators.

Technique selection uses a tenant-scoped UCB-style exploration/exploitation
score. Its context fingerprint includes hypothesis type, parser context, WAF,
and CSP state. Execution feedback updates both the hypothesis and the exact
environment-specific technique statistic, allowing future runs to reuse useful
knowledge without mixing tenant data.

## Evidence rules

- A static source and sink in the same bundle is a lead with low-confidence
  `co_occurs_with` evidence, never a confirmed flow.
- A finding becomes supported only through browser-oracle execution, sink
  telemetry, or independent direct-auditor evidence.
- Client-secret candidates are SHA-256 fingerprinted; raw values and surrounding
  snippets are not persisted by the bundle analyzer.
- Each browser execution is idempotent and linked to content-addressed request,
  response, DOM, screenshot, and report artifacts where available.
- Research APIs and learned technique statistics inherit the tenant boundary.

## Safety boundary

Autonomous mode stays inside the stored target scope and skips destructive
navigation. Advanced WebView, IPC, opener, cookie, cache, and postMessage probes
are capability canaries: they call the local oracle when a boundary is present
but do not execute OS commands, exfiltrate document data, overwrite session
cookies, evaluate hash content, or run unbounded loops.

The next maturity step is a policy engine that separates passive, safe-active,
and explicitly destructive techniques, with per-target authorization and
budgets. Until then, destructive techniques must not be added to autonomous
execution.
