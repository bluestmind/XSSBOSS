# Bug Bounty Readiness Guide

Use XSS Boss only for programs, assets, and accounts where you have explicit authorization. The app now enforces target scope at import, experiment generation, queueing, manual execution, and worker execution, but the operator still owns program compliance.

## 1. Define Scope First

Create each target with a precise `base_url` and, when the program has more scope rules, add `scope_tags`.

Example:

```json
{
  "name": "Example Program",
  "base_url": "https://example.com",
  "bounty_platform": "hackerone",
  "scope_tags": {
    "in_scope": ["*.example.com", "app.example.com"],
    "out_of_scope": ["admin.example.com", "legacy.example.com"]
  }
}
```

Supported include keys: `allowed_hosts`, `in_scope`, `domains`, `hosts`.

Supported exclude keys: `blocked_hosts`, `deny_hosts`, `excluded_domains`, `excluded_hosts`, `out_of_scope`, `out_scope`.

Comma-separated, whitespace-separated, list, URL, bare host, and `*.domain.com` formats are accepted.

### Import Platform Programs

Use the Targets page's `Import Programs` action, or run the CLI importer:

```bat
.venv\Scripts\python.exe tools\import_bug_bounty_programs.py --platform hackerone --handle example --dry-run
.venv\Scripts\python.exe tools\import_bug_bounty_programs.py --platform yeswehack --slug example-program --dry-run
```

HackerOne uses official API credentials:

```bat
set HACKERONE_USERNAME=your_username
set HACKERONE_API_TOKEN=your_api_token
```

YesWeHack supports PAT or OAuth-style tokens:

```bat
set YESWEHACK_PAT=your_personal_access_token
set YESWEHACK_OAUTH_TOKEN=your_oauth_token
```

Imported programs are upserted as targets. The importer stores platform metadata, structured scopes, `in_scope`, `out_of_scope`, notes, and a browser profile path reference under `auth_info.browser_profile`. It references the existing profile at `F:\projects\Auto_Payment_checker_iran\automation_profile_selenium` by default when present, but it does not copy cookies or secrets.

## 2. Use The Safe Local Defaults

Simplified mode in `run_all.bat` uses:

- SQLite at `xssboss.db`
- inline Celery execution with `CELERY_TASK_ALWAYS_EAGER=True`
- API and Oracle bound to `127.0.0.1`
- CORS restricted to the local Vite UI origins

Distributed mode is for heavier runs and expects PostgreSQL, Redis, and a Celery worker.

## 3. Import Only Authorized Traffic

Import Burp/HAR traffic captured from authorized sessions. Requests outside the target scope are rejected during recon import. If a program changes scope, update the target before importing new traffic or starting experiments.

## 4. Run Focused Experiments

Prefer this order for real programs:

1. Start with `quick_light` on a small endpoint set.
2. Review contexts, filters, sinks, and findings.
3. Use `csp_aware` or `js_string_specialist` only on endpoints that show useful reflections or dangerous sinks.
4. Use `unicode_hunt` for targeted bypass work after you understand the filter behavior.

## 5. Manual Payloads

Manual payload execution is available through `/api/v1/test-cases/execute`. It validates that endpoint, parameter, and context belong together and refuses out-of-scope endpoints before queueing browser work.

## 6. Before Reporting

For each finding, confirm:

- the target is in scope for the program
- the account/session used is permitted
- the payload has a stable reproduction path
- the impact is clear
- screenshots, DOM evidence, and oracle token evidence match the same test case

## 7. Maximize Impact Safely

Use stored/cross-role verification when a reflected payload appears in a saved object such as a profile, comment, ticket, message, notification, template, invite, or settings page.

API example:

```json
POST /api/v1/verification/stored-xss
{
  "submit_endpoint_id": 12,
  "param_id": 44,
  "context_id": 91,
  "payload_template": "<svg/onload=__XSS__('{{TOKEN}}')>",
  "revisit_endpoint_ids": [13, 14],
  "role_contexts": [
    {
      "label": "author",
      "auth_context": {"Cookie": "session=AUTHOR_SESSION"}
    },
    {
      "label": "support-viewer",
      "auth_context": {"Cookie": "session=AUTHORIZED_SUPPORT_SESSION"}
    }
  ],
  "max_revisits": 20
}
```

The verifier submits the payload once, revisits selected pages with the browser oracle injected, records executions, and upgrades the finding evidence when stored or cross-role execution is confirmed.

Generate a bounty-ready report:

```text
GET /api/v1/results/findings/{finding_id}/bounty-report
POST /api/v1/results/findings/{finding_id}/bounty-report/refresh
```

Impact scoring favors confirmed browser execution, stored execution, cross-role execution, privileged viewers, dangerous sinks, and high-value workflows such as admin, support, billing, OAuth/SSO, invites, messages, comments, notifications, and templates.

Experiment queueing also uses high-value endpoint and parameter hints, so those same workflows receive higher fuzzing priority before lower-impact reflections.

For advanced DOM research probes, generate an opt-in bundle:

```json
POST /api/v1/modern/dom-probes
{
  "endpoint_id": 12,
  "payload_template": "<img src=x onerror=__XSS__('{{TOKEN}}')>",
  "include_live_fingerprint": true
}
```

This returns postMessage PoC HTML, prototype-pollution URL/hash variants, DOM clobbering payloads, sanitizer mXSS probes, framework fingerprints, CSP hints, and Trusted Types hints. Treat prototype pollution and DOM clobbering probes as fragile research techniques and only run them when the program scope and rules permit that testing.

Execute the generated modern probes in a browser and persist evidence:

```json
POST /api/v1/modern/dom-probes/execute
{
  "endpoint_id": 12,
  "param_id": 44,
  "context_id": 91,
  "families": ["post_message", "prototype_pollution", "dom_clobbering", "sanitizer_mxss"],
  "post_message_origin_modes": ["none", "starts_ends"],
  "serve_post_message_poc_http": true,
  "max_probes": 50,
  "payload_template": "<img src=x onerror=__XSS__('{{TOKEN}}')>"
}
```

The executor creates an experiment, runs standalone postMessage PoC pages, direct prototype-pollution URL/hash probes, and parameter-based clobbering/mXSS probes. postMessage PoCs are served from an ephemeral `127.0.0.1` HTTP origin by default, which is closer to a real attacker-controlled origin than a `data:` page.

`post_message_origin_modes` defaults to `none` and `starts_ends`. `none` uses the real local PoC origin. `starts_ends` instruments delivered `event.origin` so it starts with the target origin and ends with the target host, which helps catch flawed `startsWith`/`endsWith` checks. `exact` is also available for reachability triage, but exact-origin-only hits should not be reported as exploitability unless you can prove a real authorized origin bypass.

Oracle hits are stored as executions and confirmed findings with screenshots, DOM snapshots, probe family metadata, postMessage origin-mode metadata, and impact scoring.

## Verification Commands

Frontend:

```bat
cd ui
npm.cmd run lint
npm.cmd run build
```

Backend static compile:

```bat
python -m compileall -q backend_api analysis_engine browser_workers fuzzer oracle_server recon_engine mock_target.py hard_mock_target.py tools
```

## Hard Local XSS Lab

The hard lab is an intentionally vulnerable local target for checking whether XSS Boss can find real execution paths and avoid safe controls.

Fast payload coverage smoke:

```bat
.venv\Scripts\python.exe tools\hard_lab_payload_smoke.py --show-samples
```

Seed the hard lab into `xssboss.db`:

```bat
.venv\Scripts\python.exe tools\seed_hard_lab.py --reset
```

Run the full browser/oracle proof:

```bat
.venv\Scripts\python.exe tools\run_hard_lab_e2e.py --reset
```

The full proof starts `hard_mock_target.py` on `127.0.0.1:8099`, starts the oracle on `127.0.0.1:8001`, preflights Selenium/ChromeDriver, tries up to 8 candidate payloads per vulnerable manifest case by default, runs them through the existing browser worker, and compares oracle hits against the manifest's expected results. Use `--max-attempts N` to make the proof stricter or faster.

Modern DOM probe smoke:

```bat
.venv\Scripts\python.exe tools\modern_xss_profile_smoke.py
```

The hard lab also includes `/hard/post-message-origin-weak`, an intentionally weak postMessage origin check for the modern executor's `starts_ends` origin mode.
