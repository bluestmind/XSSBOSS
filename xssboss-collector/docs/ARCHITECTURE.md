# Architecture

## Guided local dashboard

`xsscollect ui` serves a zero-dependency interface from the same Python package. It binds to loopback only, enforces scheme/host/port same-origin writes, adds a restrictive Content Security Policy, and calls the existing collection pipeline rather than maintaining a second analysis implementation. The dashboard supports setup, local JS/TS uploads, collection, capture/spec/mirror imports, run history, inventory exploration, report downloads, and comprehensive diffs.

## Design boundary

The system has one responsibility: build a trustworthy, reproducible inventory from authorized web data. It intentionally has no payload grammar, mutation engine, form submitter, captured-request replayer, authentication automation, execution oracle, or exploit workflow.

## Components

- `config.py` loads typed TOML configuration and validates operational bounds.
- `scope.py` enforces schemes, hosts, ports, path boundaries, exclusions, and public-address resolution.
- `http_client.py` provides asynchronous orchestration over a small blocking standard-library client. Redirects are disabled in the underlying client and re-evaluated one hop at a time.
- `parsers.py` extracts links, embedded assets, `srcset`, CSS imports/URLs/maps, style blocks/attributes, event-handler code, form schemas, static JavaScript routes, OpenAPI operations, sitemap locations, robots exclusions, page metadata, and technology signals.
- `js_analysis.py` masks non-code safely, discovers function boundaries and signatures, inventories inputs/outputs/modules/calls, applies a broad browser/Node source and sink taxonomy, and performs sanitizer-aware intra-function propagation.
- `importers.py` reads HAR, Burp XML, OpenAPI JSON, and URL lists without network replay.
- `mirror_import.py` converts bounded security-relevant files from a downloaded site tree into scoped records, reconstructing original URLs from folder layout or an optional manifest. It skips symlinks and binary assets and never serves or executes mirror contents.
- `normalize.py` converts volatile route values into stable endpoint patterns and extracts typed input names.
- `redact.py` removes configured secrets and common token shapes before persistence.
- `evidence.py` atomically stores redacted textual evidence under a SHA-256 address, optionally gzip-compressed.
- `storage.py` owns SQLite schema, upserts, run-specific membership, ten JavaScript analysis tables, observations, relationships, and statistics.
- `diffing.py` materializes run-accurate snapshots across 20 categories and produces added/removed/changed/unchanged sets.
- `pipeline.py` coordinates acquisition/import, parsing, redaction, and persistence.
- `exporters.py` creates JSON, JSONL, CSV, and standalone HTML output.
- `cli.py` is the stable operator interface.

## Endpoint identity

An endpoint fingerprint includes HTTP method, normalized scheme/host/port/path, sorted query parameter names, extra discovered input names, and media type. Values are excluded. Dynamic numeric, UUID, date, hash, and JWT path segments become typed placeholders.

This model prevents routine crawl variance from creating a new endpoint on every run while preserving meaningful method and input-shape differences.

## Persistence schema

- `runs`: lifecycle, mode, configuration digest, and execution statistics.
- `endpoints`: global deduplicated endpoint patterns and first/last seen lineage.
- `run_endpoints`: exact endpoint membership for each run.
- `samples`: redacted observed URLs/headers, response metadata, timing, errors, and evidence references.
- `parameters`: name, location, inferred type, redacted sample, and lineage.
- `observations`: structured metadata with confidence and optional evidence hash.
- `relationships`: discovery/reference edges between endpoints.
- `artifacts`: content-addressed evidence metadata.
- `run_endpoint_details`, `run_technologies`, `run_artifacts`: historical run-accurate membership and values.
- `js_files`: analyzed bundle, inline-script, local-file, and source-map-source identity.
- `js_functions`, `js_inputs`, `js_outputs`: function boundaries, signatures, input forms, and every return/throw/yield path found.
- `js_sources`, `js_sinks`, `js_calls`, `js_flows`: input origins, output/security-sensitive operations, call graph edges, and sanitizer-aware propagation paths.
- `js_modules`, `js_symbols`: imports/requires and global/export symbols.

SQLite uses foreign keys, WAL journaling, unique constraints, and targeted indexes. Each batch is committed so an interruption loses at most the current small batch.

## JavaScript analysis model

Analysis never evaluates JavaScript. A length-preserving masker removes comments and string contents for structural matching, balanced-delimiter scanning identifies function ranges, and original source slices provide reviewable expressions. The analyzer covers named/anonymous functions, assigned and callback arrows, class/object methods, TypeScript-style parameter annotations, destructuring, default/rest inputs, implicit and explicit outputs, ESM/CommonJS references, globals, exports, and call sites.

Sources and sinks are catalogued independently. A small taint lattice then seeds function inputs and recognized external sources, propagates them through assignments to a fixpoint, recognizes common encoders/sanitizers, and relates reachable values to sink value expressions. Confidence communicates heuristic certainty; a flow is evidence for review, not proof that a vulnerability is exploitable.

Source maps are never fetched outside the ordinary scoped GET pipeline. When a map is collected, only embedded `sourcesContent` is analyzed, bounded by `analysis.max_source_map_sources`.

## Difference model

The diff engine builds normalized snapshots for endpoints, parameters, HTTP state, request/response headers, technologies, evidence, observations, relationships, artifacts, and every JavaScript table. Stable identities are compared independently. Matching identities with changed values contain field-level before/after records; missing identities become additions/removals. This keeps a changed bundle hash, function body, sink expression, API response header, and endpoint presence visible as different events rather than collapsing them into one score.

## Trust and privacy model

Authorization is an operator assertion, not a substitute for permission. Scope is enforced independently at seed ingestion, discovery, redirect handling, and immediately before socket acquisition. DNS answers are rejected when any resolved address is private or special-use unless explicitly enabled.

Headers and parameter samples are redacted before database insertion. Only textual bodies are eligible for evidence retention. JSON is parsed and recursively redacted; other text is scrubbed for common token formats. For highly sensitive applications, disable `store_response_bodies` entirely.

## Extension approach

New parsers should accept bytes or structured input and return `ParsedDocument`; they must not perform network calls. New importers should return `RequestRecord` objects and must never replay them. Acquisition features must continue to use `ScopePolicy`, bounds, manual redirects, and GET-only behavior.
