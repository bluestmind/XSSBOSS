# XSSBOSS Collector

XSSBOSS Collector is a separate, collection-only attack-surface inventory tool derived from the reconnaissance ideas in XSSBOSS. It discovers, normalizes, deduplicates, preserves, and exports web application metadata. It does **not** generate payloads, fuzz parameters, submit forms, replay captured requests, exploit findings, or execute browser code.

Use it only on systems you own or have explicit permission to assess.

## What it collects

- HTTP `GET` responses within an exact allow/deny scope
- Linked pages, scripts, stylesheets, media/resource references, forms, CSS imports/URLs, inline event code, and static JavaScript route hints
- Endpoint methods and parameter names from HTML, URLs, JSON bodies, OpenAPI, HAR, and Burp XML
- `robots.txt`, sitemaps, `security.txt`, and API descriptions according to the selected profile
- Response status, timing, content type, selected security/transport headers, page titles, and technology signals
- Every statically discoverable JavaScript/TypeScript function, parameter/default/type input, return/throw/yield output, source, sink, call, module, global/export symbol, and likely source-to-sink flow
- Inline scripts, downloaded bundles, and original sources embedded in source maps
- Run lineage, endpoint relationships, compressed evidence, and comprehensive cross-run difference tables

The package uses only the Python 3.11+ standard library. There are no runtime dependencies.

## Safety properties

- Live collection will not start until `scope.authorized_use = true`.
- Every seed, redirect, discovered link, and probe is checked against explicit scope.
- Private, loopback, link-local, and special-use destinations are blocked by default.
- Network acquisition is GET-only. Non-GET methods found in forms/specs/captures are inventoried but never sent.
- Redirects are followed manually and cannot escape scope.
- Concurrency, per-host concurrency, request rate, depth, page count, timeout, response size, and retries are bounded.
- `robots.txt` is respected by default.
- Authorization headers, cookies, API keys, token-like strings, and configured sensitive parameters are redacted before persistence.
- Captured HAR/Burp requests are parsed offline and never replayed.
- Downloaded website mirrors are treated as bounded text evidence: files are never executed or served.

## Quick start

### Easiest: guided dashboard

On Windows, double-click `run.bat`. With no arguments it starts the local dashboard and opens it in your browser. The first-run guide asks for the exact authorized scope before live collection is enabled.

From a terminal:

```powershell
cd xssboss-collector
.\run.bat
```

The dashboard provides:

- guided scope and authorization setup with plain-language safety notes;
- drag-and-drop JS/TS files or whole-folder selection;
- safe site collection and offline HAR, Burp XML, OpenAPI JSON, URL-list, and whole website-mirror imports;
- recent run metrics, searchable run history, and one-click result viewing;
- searchable tables for endpoints plus every JavaScript entity;
- two-run comparison across all 20 categories; and
- one-click HTML, JSON, CSV, and Markdown downloads.

It listens only on `127.0.0.1` by default. To choose another local port or avoid opening the browser automatically:

```powershell
xsscollect ui --port 9000 --no-open --config collector.toml
```

### CLI and automation

```powershell
cd xssboss-collector
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\xsscollect.exe init .
```

Edit `collector.toml`: replace the example scope with the exact authorized URL or host rules, then set `authorized_use = true`.

```powershell
xsscollect collect https://app.example.com/ --config collector.toml
xsscollect stats --config collector.toml
xsscollect export --format html --output inventory.html --config collector.toml
```

Without installation, set the package path and run it directly:

```powershell
$env:PYTHONPATH = "src"
python -m xsscollector doctor
python -m xsscollector collect https://app.example.com/ --config collector.toml
```

## Scope rules

Rules may be an exact host, an explicit wildcard subdomain, or a URL with a path boundary.

```toml
[scope]
authorized_use = true
allow = [
  "https://app.example.com/",
  "https://api.example.com/v1/",
  "*.sandbox.example.com"
]
deny = [
  "https://api.example.com/v1/destructive/*",
  "https://admin.sandbox.example.com/*"
]
```

`*.example.com` includes subdomains but not the apex. A rule with an explicit scheme matches only that scheme. A path rule uses a segment boundary, so `/app/` does not accidentally include `/application`.

Private networks require both an explicit scope rule and `allow_private_networks = true`. This is useful for authorized staging/lab systems and intentionally requires a deliberate opt-in.

## Collection profiles

| Profile | Behavior |
|---|---|
| `passive` | Fetch seeds and follow in-page links only. |
| `standard` | Passive behavior plus `robots.txt`, sitemap, and `security.txt`. |
| `deep` | Standard behavior plus common OpenAPI descriptions and a GET-only GraphQL endpoint check. |

All profiles remain collection-only and obey the same limits.

## Offline imports

Imports are ideal when another approved tool or browser already captured traffic:

```powershell
xsscollect import har capture.har --config collector.toml
xsscollect import burp proxy-history.xml --config collector.toml
xsscollect import openapi openapi.json --base-url https://api.example.com --config collector.toml
xsscollect import urls urls.txt --config collector.toml
xsscollect import mirror .\downloaded-site --base-url https://app.example.com/ --config collector.toml
```

Imported items outside the configured scope are skipped. Request bodies are used only to derive parameter names/types unless retention is explicitly enabled.

Mirror import is designed to consume output from approved downloaders such as `web-clone`. It reads only HTML, CSS, JS/TS, JSON, source maps, XML, SVG, manifests, and text under `max_pages` and `max_response_bytes`; images, video, fonts, and other binary payloads are ignored. A `manifest.json`, `asset-manifest.json`, `url-manifest.json`, or `_cloner_report.txt` URL-to-file map is detected automatically, or can be supplied explicitly:

```powershell
xsscollect import mirror .\downloaded-site --base-url https://app.example.com/ --manifest .\downloaded-site\manifest.json --config collector.toml
```

The base URL must match configured scope. It restores web identities for local files so later mirror runs can be compared reliably. The dashboard offers the same workflow through **Import evidence → Website mirror folder**.

## Deep JavaScript analysis

Downloaded `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, and `.tsx` resources are analyzed automatically. Inline HTML scripts and source-map `sourcesContent` are analyzed as separate files. Local source trees can be analyzed without executing any code:

```powershell
xsscollect analyze-js .\src --recursive --base-url https://app.example.com/static-analysis/ --config collector.toml
```

The analyzer creates dedicated tables for:

| Table | Captured data |
|---|---|
| JS files | URL, content hash, byte size, module type, source-map reference, parse warnings |
| Functions | declarations, expressions, arrows, methods, callbacks, location, async/generator/export flags, complexity, body hash |
| Inputs | ordinary, rest, typed, defaulted, and destructured function parameters/members |
| Outputs | explicit returns, throws, yields, expression-body returns, and implicit `undefined` |
| Sources | URL/query, location, document URL/referrer/cookies, messages, storage, DOM/form input, Node requests, environment, argv, stdin |
| Sinks | HTML/DOM, code/command execution, navigation, attributes, network, storage, cross-context, filesystem, database, and HTTP responses |
| Calls | caller, callee, argument expressions, line, `await`, and optional chaining |
| Flows | source name/kind, propagation path, sink, confidence, and sanitizer state |
| Modules/symbols | ESM/CommonJS/dynamic imports, globals, and exports |

This is a conservative static inventory, not a JavaScript execution engine or proof of vulnerability. Dynamic property names, runtime-generated code, heavily malformed bundles, and flows requiring full semantic/runtime context may remain unresolved. Every match includes line/context and confidence so results can be reviewed instead of being silently overstated.

## Exports and change tracking

```powershell
xsscollect export --run 4 --format jsonl --output run-4.jsonl --config collector.toml
xsscollect export --run 4 --format csv --output run-4.csv --config collector.toml
xsscollect export --run 4 --format html --output run-4.html --config collector.toml
xsscollect diff --from-run 3 --to-run 4 --format html --output changes.html --config collector.toml
xsscollect diff --from-run 3 --to-run 4 --format markdown --output changes.md --config collector.toml
```

Inventory formats are JSON, JSONL, CSV, and self-contained HTML. Difference reports are JSON, Markdown, or self-contained HTML. The HTML inventory contains separate, scrollable tables for endpoints and every JavaScript entity type.

The comprehensive difference report independently compares 20 categories:

| Web/HTTP | JavaScript |
|---|---|
| endpoints | files |
| parameters | functions |
| HTTP status/content/size/errors | inputs |
| request headers | outputs |
| response headers | sources |
| technologies | sinks |
| evidence hashes | calls |
| observations | flows |
| relationships and artifacts | modules and symbols |

Each category reports added, removed, changed, and unchanged records. Changed records include their exact before/after values and changed field names. Endpoint identity remains stable across changing numeric IDs, UUIDs, hashes, dates, query values, and parameter order.

## Data layout

The SQLite database stores runs, endpoint patterns, run-specific metadata/technology membership, redacted samples, typed parameters, observations, relationships, artifact membership, and ten dedicated JavaScript analysis tables. Textual response evidence is token-redacted, compressed, and content-addressed under `data/evidence/<sha-prefix>/...`. Binary bodies are not retained.

Paths in the configuration are resolved relative to the configuration file, which makes each collector workspace portable.

## Architecture

```text
Explicit scope + authorization
            |
      bounded GET client ---- offline captures/specs/site mirrors
            |                              |
            +---- HTML/CSS/JS parsers -----+
                         |
          deep JS structure + flow analysis
                         |
              normalize + redact
                         |
       SQLite lineage + evidence store
                         |
      20-category diff / JSON / HTML tables
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for component and schema details.

## Development

```powershell
python -m pip install -e .
python -m pytest
python -m compileall -q src
```

The test suite includes exact scope behavior, private-network protection, normalization, secret redaction, broad HTML/CSS resource parsing, all import formats including mirror trees/manifests, run-accurate 20-category diffing, authorization gating, function/source/sink/call/flow analysis, source maps, inline scripts, report generation, and a real local GET-only end-to-end crawl.
