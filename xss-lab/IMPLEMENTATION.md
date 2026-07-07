# XSS Boss - Complete Implementation Documentation

## Table of Contents

1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Component Breakdown](#component-breakdown)
4. [Data Model](#data-model)
5. [Implementation Details](#implementation-details)
6. [File Structure](#file-structure)
7. [Key Features](#key-features)
8. [Usage Guide](#usage-guide)
9. [API Reference](#api-reference)
10. [Workflow Examples](#workflow-examples)

---

## Overview

**XSS Boss** is a professional-grade, human-in-the-loop XSS (Cross-Site Scripting) hunting system designed for bug bounty hunters and security researchers. Unlike generic scanners, this system:

- **Learns** how each target filters input
- **Evolves** payloads until it gets real JavaScript execution
- **Provides** full visibility and control to the hunter
- **Generates** explainable findings with PoCs

### Core Design Principles

1. **Context-Aware**: Understands where input lands (HTML text, attribute, JS, JSON)
2. **Filter-Aware**: Learns each target's WAF/sanitizer behavior instead of guessing
3. **Sink-Aware**: Focuses on parameters that actually reach dangerous sinks
4. **Human-Steered**: You choose where to go deep, how aggressive, what to report
5. **Explainable**: Every finding comes with story + PoC, not just "payload worked"

---

## System Architecture

The system is organized into **three main layers**:

### 1. Control Plane (Human Interface)
- **Hunter Console**: Web UI + CLI for managing targets, experiments, and findings
- **Experiment Orchestrator**: Job management, strategy selection, budget controls
- **Integration Plugins**: Burp Suite extension, browser extension hooks

### 2. Hunting Pipeline (Automated Engines)
- **Recon Engine**: Crawling, Burp/HAR import, endpoint discovery
- **Context Analyzer**: Reflection detection, HTML/JS/JSON context classification
- **Filter Profiler**: WAF/sanitizer behavior analysis
- **Sink Mapper**: Static JS analysis + dynamic taint tracking
- **Payload Fuzzer**: Context-aware grammar-based payload generation
- **Browser Execution Farm**: Playwright workers with XSS Oracle
- **Result Correlator**: Findings deduplication and PoC generation

### 3. Knowledge & Storage
- **Target Registry**: Programs, auth, scopes
- **Endpoint/Param/Context DB**: Discovered attack surface
- **Filter Profiles**: Learned bypass patterns
- **Payload Corpus**: Grammars and mutation strategies
- **Findings Store**: XSS reports with evidence

---

## Component Breakdown

### Backend API (`backend-api/`)

The core FastAPI application that orchestrates all operations.

#### Key Files:

- **`main.py`**: FastAPI application entry point with CORS, routers, and startup events
- **`config.py`**: Centralized configuration management using Pydantic settings
- **`routers/`**: REST API endpoints
  - `targets.py`: Target CRUD operations
  - `endpoints.py`: Endpoint management
  - `experiments.py`: Experiment lifecycle management
  - `results.py`: Findings and execution results
  - `oracle.py`: XSS Oracle callback receiver
- **`models/`**: SQLAlchemy database models
  - `target.py`: Target/program model
  - `endpoint.py`: HTTP endpoint model
  - `param.py`: Parameter model (query, body, JSON, etc.)
  - `context.py`: Reflection context model (9 context types)
  - `sink.py`: Dangerous sink model
  - `filter_profile.py`: Filter behavior profile
  - `experiment.py`: Experiment configuration
  - `test_case.py`: Individual test case
  - `execution.py`: Execution result
  - `finding.py`: XSS finding with PoC
  - `payload_knowledge.py`: Learned payload patterns
- **`services/`**: Business logic layer
  - `recon_service.py`: Reconnaissance operations
  - `context_service.py`: Context detection coordination
  - `filter_service.py`: Filter profiling coordination
  - `sink_service.py`: Sink mapping coordination
  - `experiment_service.py`: Experiment lifecycle
  - `payload_service.py`: Payload knowledge management
  - `result_service.py`: Finding correlation and PoC building
  - `fuzzing_service.py`: **Main orchestration service** - connects all components
- **`utils/`**: Utility functions
  - `request_builder.py`: HTTP request construction
  - `html_parser.py`: HTML parsing with BeautifulSoup/lxml
  - `js_parser.py`: JavaScript parsing and sink detection
  - `marker.py`: Unique marker generation (XSSFUZZ_{uuid})
  - `context_detector.py`: Context classification logic
  - `filter_profiler.py`: Filter behavior analysis
  - `sink_mapper.py`: Sink detection (static + dynamic)
  - `tokenizer.py`: Oracle token generation
  - `signature.py`: Request signature normalization
- **`db/`**: Database setup
  - `base.py`: SQLAlchemy engine and session factory
  - `session.py`: Database session management
  - `migrations/`: Alembic migration files

### Recon Engine (`recon-engine/`)

Discovers and imports attack surface from various sources.

#### Components:

- **`burp_import.py`**: Parses Burp Suite XML exports
  - Extracts method, URL, headers, body, response
  - Handles base64-encoded requests/responses
  - Normalizes to endpoint patterns
- **`har_import.py`**: Parses HAR (HTTP Archive) files
  - Extracts from `log.entries[]`
  - Handles query params, form data, JSON bodies
  - Preserves request/response pairs
- **`crawler.py`**: Playwright-based headless crawler
  - Recursive crawling with depth limits
  - Form extraction and submission
  - Request/response recording
  - Configurable rate limiting
- **`normalizer.py`**: Request normalization
  - URL pattern extraction (replace UUIDs, IDs with placeholders)
  - Query parameter normalization
  - Signature generation for deduplication

### Analysis Engine (`analysis-engine/`)

Analyzes discovered endpoints to understand reflection contexts and filter behavior.

#### Components:

- **`detect_context.py`**: Context detection engine
  - Injects unique markers (XSSFUZZ_{uuid})
  - Parses HTML/JS responses
  - Classifies 9 context types:
    - `HTML_TEXT`: Inside HTML text nodes
    - `ATTR_QUOTED`: Inside quoted attributes
    - `ATTR_UNQUOTED`: Inside unquoted attributes
    - `EVENT_HANDLER_ATTR`: Inside event handler attributes (onclick, etc.)
    - `JS_STRING_LITERAL`: Inside JavaScript string literals
    - `JS_IDENTIFIER`: Inside JavaScript identifiers (rare)
    - `URL_FRAGMENT`: Inside URL fragments
    - `URL_QUERY`: Inside URL query parameters
    - `JSON_VALUE`: Inside JSON values
  - Stores context metadata (tag, attribute, snippet)
- **`detect_filter.py`**: Filter profiling engine
  - Sends probe battery:
    - `<test>`, `</div><b>x</b>`
    - `<script>alert(1)</script>`
    - `" onerror=1`
    - `javascript:alert(1)`
  - Analyzes responses:
    - HTTP status codes (403, 406 = WAF)
    - Reflection shape (escaped vs raw)
    - Content filtering
  - Builds filter profile:
    - Blocked tokens
    - Allowed tokens
    - Normalization behavior
    - WAF detection
    - Sanitizer fingerprinting
- **`detect_sink.py`**: Sink mapping engine
  - **Static analysis**:
    - Downloads and parses JS files
    - Finds dangerous sinks (innerHTML, eval, etc.)
    - Maps variable flows to sinks
  - **Dynamic analysis** (framework in place):
    - Taint tracking script injection
    - DOM setter wrapping
    - Marker flow detection

### Fuzzer (`fuzzer/`)

Generates context-aware, filter-bypassing payloads.

#### Components:

- **`payload_grammar/`**: Context-specific payload templates
  - `html_text.json`: 17 payloads for HTML text contexts
  - `attr_quoted.json`: 9 payloads for quoted attributes
  - `attr_unquoted.json`: 7 payloads for unquoted attributes
  - `js_string.json`: 10 payloads for JS string contexts
  - `url_context.json`: 5 payloads for URL contexts
  - `json_value.json`: 4 payloads for JSON contexts
  - All payloads use `__XSS__('{{TOKEN}}')` callback
- **`mutation_engine.py`**: Payload mutation strategies
  - **Unicode homoglyphs**: Replace `s`, `c`, `r`, `i`, `p`, `t` with lookalikes
  - **Zero-width insertion**: Insert invisible chars into keywords
  - **Full-width conversion**: Convert ASCII to full-width Unicode
  - **URL encoding**: Partially encode payload
  - **HTML entity encoding**: Convert `<`, `>`, `"` to entities
  - **Mixed case**: Randomize letter case
  - **Keyword splitting**: Split keywords with spaces
- **`strategy.py`**: Strategy profiles
  - `QUICK_LIGHT`: Fast scanning, minimal mutations
  - `UNICODE_HUNT`: Aggressive Unicode mutations
  - `JS_STRING_SPECIALIST`: Focus on JS string contexts
  - `CSP_AWARE`: Avoids script tags, uses inline handlers
- **`generator.py`**: Payload generation orchestrator
  - Loads context-specific grammars
  - Applies filter-aware mutations
  - Replaces token placeholders
  - Prioritizes based on strategy

### Browser Workers (`browser-workers/`)

Executes payloads in real browsers and detects XSS execution.

#### Components:

- **`worker.py`**: Celery worker entry point
  - Picks test cases from queue
  - Executes in browser
  - Records results
  - Updates test case status
- **`executor.py`**: Playwright test execution
  - Launches headless Chromium
  - Injects Oracle script
  - Builds and sends HTTP requests
  - Waits for Oracle callbacks
  - Takes screenshots
  - Captures DOM snapshots
- **`oracle_inject.js`**: XSS Oracle injection script
  - Defines `__XSS__(token)` callback function
  - Hooks dangerous functions:
    - `alert`, `eval`, `Function`
    - `setTimeout`, `setInterval` (string versions)
    - `document.write`
    - `innerHTML`, `outerHTML` setters
  - Sends callbacks to Oracle server
- **`playwright_config.py`**: Browser configuration
  - Launch arguments (no-sandbox, etc.)
  - Context settings (viewport, user-agent)
  - Security bypasses for testing

### Oracle Server (`oracle-server/`)

Receives XSS execution callbacks from injected scripts.

#### Components:

- **`main.py`**: FastAPI endpoint
  - `/oracle` GET/POST endpoint
  - Receives token and optional message
  - Forwards to main API
  - Records execution hits

### Web UI (`ui/`)

React-based frontend for human interaction.

#### Components:

- **`src/App.jsx`**: Main application with routing
- **`src/components/`**:
  - `TargetsList.jsx`: List and manage targets
  - `EndpointsMap.jsx`: Visualize discovered endpoints
  - `ExperimentCreator.jsx`: Create and start experiments
  - `FindingsList.jsx`: Browse XSS findings
  - `PoCViewer.jsx`: View PoC details and evidence
- **`vite.config.js`**: Vite configuration with API proxy

---

## Data Model

### Core Entities

#### `targets`
- Stores bug bounty programs/targets
- Fields: `name`, `base_url`, `bounty_platform`, `scope_tags`, `auth_info`, `status`
- Status: `recon_only`, `fuzzing`, `triage`, `done`

#### `endpoints`
- HTTP endpoints discovered
- Fields: `method`, `url_pattern`, `sample_request_body`, `sample_response_body`, `auth_context`
- Normalized URL patterns (e.g., `/api/user/{id}/settings`)

#### `params`
- Parameters extracted from requests
- Fields: `name`, `location` (query/body/json/path/header/cookie), `sample_value`, `is_controllable`

#### `contexts`
- Reflection contexts detected
- Fields: `context_type` (9 types), `tag`, `attribute`, `script_path`, `snippet`
- Links to `param_id` and `endpoint_id`

#### `filter_profiles`
- Filter behavior profiles
- Fields: `blocked_tokens`, `allowed_tokens`, `normalization_behavior`, `waf_detected`, `sanitizer_detected`, `probe_results`

#### `sinks`
- Dangerous sinks mapped to contexts
- Fields: `sink_type` (innerHTML, eval, etc.), `js_location`, `taint_path`, `detected_via` (static/dynamic)

#### `experiments`
- Fuzzing experiments
- Fields: `name`, `strategy`, `status`, `limits` (max_requests, time_limit, concurrency, rate_limit)
- Status: `pending`, `running`, `paused`, `completed`, `failed`

#### `test_cases`
- Individual payload tests
- Fields: `payload`, `token`, `priority`, `status`
- Links to `experiment_id`, `endpoint_id`, `param_id`, `context_id`

#### `executions`
- Browser execution results
- Fields: `oracle_status` (hit/missed/error), `oracle_token`, `logs`, `screenshot_path`, `dom_snapshot`, `duration_ms`

#### `findings`
- Correlated XSS findings
- Fields: `best_payload`, `severity`, `status`, `report_text`, `poc_request`, `poc_html`, `screenshot_path`
- Status: `draft`, `confirmed`, `reported`, `duplicate`

#### `payload_knowledge`
- Learned payload patterns
- Fields: `pattern`, `tag`, `context_types`, `success_history`

---

## Implementation Details

### Context Detection Flow

1. **Marker Injection**: Generate unique marker `XSSFUZZ_{uuid}`
2. **Request Building**: Inject marker into parameter
3. **Response Analysis**: Parse HTML/JS with BeautifulSoup/lxml
4. **Marker Search**: Find marker in:
   - Text nodes
   - Attribute values
   - Script content
   - JSON values
5. **Classification**: Determine context type based on location
6. **Storage**: Save context with metadata

### Filter Profiling Flow

1. **Probe Battery**: Send test payloads:
   - Structural HTML: `<test>`
   - Tag breaking: `</div><b>x</b>`
   - Script injection: `<script>alert(1)</script>`
   - Attribute injection: `" onerror=1`
   - URL injection: `javascript:alert(1)`
2. **Response Analysis**:
   - Check HTTP status (403/406 = WAF)
   - Check if probe reflected
   - Check if probe escaped
   - Check if probe filtered
3. **Profile Building**: Categorize tokens as blocked/allowed
4. **Storage**: Save filter profile for payload generation

### Payload Generation Flow

1. **Context Selection**: Choose context-specific grammar
2. **Base Payload**: Load template from grammar JSON
3. **Token Replacement**: Replace `{{TOKEN}}` with unique token
4. **Filter-Aware Mutation**: If filter profile exists:
   - Check if payload contains blocked tokens
   - Apply mutations (Unicode, encoding, etc.)
   - Generate multiple variants
5. **Strategy Application**: Apply strategy-specific mutations
6. **Prioritization**: Score payloads (sink presence, context type)

### Browser Execution Flow

1. **Test Case Selection**: Worker picks test case from queue
2. **Token Generation**: Generate unique Oracle token
3. **Browser Launch**: Start Playwright Chromium instance
4. **Oracle Injection**: Inject `oracle_inject.js` before page load
5. **Request Building**: Build HTTP request with payload
6. **Page Load**: Navigate to endpoint with payload
7. **Oracle Monitoring**: Wait for `__XSS__(token)` callback
8. **Evidence Collection**: Screenshot, DOM snapshot, logs
9. **Result Storage**: Save execution record

### Result Correlation Flow

1. **Grouping**: Group executions by (endpoint, param, context, sink)
2. **Oracle Check**: Filter for `oracle_status = 'hit'`
3. **Best Payload Selection**: Choose shortest, most readable payload
4. **PoC Building**: Generate:
   - Minimal HTTP request (curl/Burp format)
   - HTML PoC file
   - Replay script
5. **Evidence Assembly**: Collect screenshots, snippets
6. **Finding Creation**: Create finding with report text

---

## File Structure

```
xss-lab/
├── backend-api/                    # FastAPI backend
│   ├── main.py                     # Application entry point
│   ├── config.py                   # Configuration
│   ├── requirements.txt            # Python dependencies
│   ├── alembic.ini                  # Alembic config
│   ├── routers/                    # API endpoints
│   │   ├── targets.py
│   │   ├── endpoints.py
│   │   ├── experiments.py
│   │   ├── results.py
│   │   └── oracle.py
│   ├── services/                   # Business logic
│   │   ├── recon_service.py
│   │   ├── context_service.py
│   │   ├── filter_service.py
│   │   ├── sink_service.py
│   │   ├── experiment_service.py
│   │   ├── payload_service.py
│   │   ├── result_service.py
│   │   └── fuzzing_service.py     # Main orchestrator
│   ├── models/                     # Database models
│   │   ├── base.py
│   │   ├── target.py
│   │   ├── endpoint.py
│   │   ├── param.py
│   │   ├── context.py
│   │   ├── sink.py
│   │   ├── filter_profile.py
│   │   ├── experiment.py
│   │   ├── test_case.py
│   │   ├── execution.py
│   │   ├── finding.py
│   │   └── payload_knowledge.py
│   ├── db/                         # Database setup
│   │   ├── base.py
│   │   ├── session.py
│   │   └── migrations/
│   └── utils/                      # Utilities
│       ├── request_builder.py
│       ├── html_parser.py
│       ├── js_parser.py
│       ├── marker.py
│       ├── context_detector.py
│       ├── filter_profiler.py
│       ├── sink_mapper.py
│       ├── tokenizer.py
│       └── signature.py
│
├── recon-engine/                    # Reconnaissance
│   ├── burp_import.py              # Burp XML import
│   ├── har_import.py               # HAR import
│   ├── crawler.py                  # Playwright crawler
│   └── normalizer.py               # Request normalization
│
├── analysis-engine/                # Analysis
│   ├── detect_context.py           # Context detection
│   ├── detect_filter.py            # Filter profiling
│   └── detect_sink.py              # Sink mapping
│
├── fuzzer/                         # Payload generation
│   ├── payload_grammar/            # Context grammars
│   │   ├── html_text.json
│   │   ├── attr_quoted.json
│   │   ├── attr_unquoted.json
│   │   ├── js_string.json
│   │   ├── url_context.json
│   │   └── json_value.json
│   ├── mutation_engine.py          # Mutation strategies
│   ├── strategy.py                 # Strategy profiles
│   └── generator.py                # Payload generator
│
├── browser-workers/                # Browser execution
│   ├── worker.py                   # Celery worker
│   ├── executor.py                 # Playwright executor
│   ├── oracle_inject.js            # Oracle injection script
│   └── playwright_config.py       # Browser config
│
├── oracle-server/                  # Oracle callbacks
│   └── main.py                     # Callback receiver
│
├── ui/                             # React frontend
│   ├── src/
│   │   ├── App.jsx
│   │   ├── main.jsx
│   │   ├── index.css
│   │   └── components/
│   │       ├── TargetsList.jsx
│   │       ├── EndpointsMap.jsx
│   │       ├── ExperimentCreator.jsx
│   │       ├── FindingsList.jsx
│   │       └── PoCViewer.jsx
│   ├── package.json
│   ├── vite.config.js
│   └── index.html
│
├── README.md                       # Quick start guide
├── IMPLEMENTATION.md               # This file
└── .gitignore
```

---

## Key Features

### 1. Context-Aware Payload Generation

The system understands 9 different reflection contexts and generates appropriate payloads:

- **HTML Text**: `</div><svg/onload=__XSS__('TOKEN')>`
- **Quoted Attribute**: `" autofocus onfocus=__XSS__('TOKEN') x="`
- **Unquoted Attribute**: ` onerror=__XSS__('TOKEN') `
- **Event Handler**: `onclick=__XSS__('TOKEN')`
- **JS String**: `';__XSS__('TOKEN');//`
- **JS Identifier**: (rare, but handled)
- **URL Fragment**: `javascript:__XSS__('TOKEN')`
- **URL Query**: Similar to fragment
- **JSON Value**: `","x":"</script><script>__XSS__('TOKEN')</script>`

### 2. Filter-Aware Mutation

When a filter profile is detected, the system:

- Identifies blocked tokens (e.g., `script`, `onerror`)
- Applies mutations:
  - Unicode homoglyphs: `s` → `\u0455` (Cyrillic)
  - Zero-width insertion: `sc​ript` (invisible char)
  - Full-width: `＜script＞`
  - URL encoding: `%3Cscript%3E`
  - HTML entities: `&#60;script&#62;`
  - Mixed case: `ScRiPt`
  - Keyword splitting: `sc ript`

### 3. Sink-Aware Prioritization

Test cases are prioritized based on:

- **Sink presence**: +10 points if context has mapped sinks
- **Context type**: +5 for JS_STRING_LITERAL, EVENT_HANDLER_ATTR
- **HTTP method**: +3 for POST (more likely stored)

### 4. Human-in-the-Loop Control

- **Target Management**: Add/remove targets, set scope
- **Experiment Control**: Start/pause/stop experiments
- **Strategy Selection**: Choose payload strategy
- **Budget Control**: Set limits (requests, time, concurrency)
- **Finding Review**: Confirm/reject findings before reporting

### 5. Explainable Findings

Every finding includes:

- **Payload**: The working payload
- **Context**: Where it was reflected
- **Sink**: Where it executed (if mapped)
- **PoC Request**: Minimal HTTP request
- **Screenshot**: Visual evidence
- **Report Text**: Auto-generated explanation

---

## Usage Guide

### Setup

1. **Install Dependencies**:
```bash
cd backend-api
pip install -r requirements.txt
playwright install chromium
```

2. **Database Setup**:
```bash
createdb xssboss
cd backend-api
alembic upgrade head
```

3. **Environment Configuration**:
```bash
export DATABASE_URL="postgresql://user:pass@localhost/xssboss"
export REDIS_URL="redis://localhost:6379/0"
export ORACLE_SERVER_URL="http://localhost:8001"
```

4. **Start Services**:
```bash
# Terminal 1: API Server
cd backend-api
python main.py

# Terminal 2: Celery Worker
celery -A browser_workers.worker worker --loglevel=info

# Terminal 3: Oracle Server
cd oracle-server
python main.py

# Terminal 4: Web UI (optional)
cd ui
npm install
npm run dev
```

### Basic Workflow

#### 1. Add Target

```python
from backend_api.db.session import get_db
from backend_api.models.target import Target

db = next(get_db())
target = Target(
    name="Example Program",
    base_url="https://example.com",
    bounty_platform="intigriti",
    scope_tags=["*.example.com"],
    auth_info={"cookie": "session=abc123"}
)
db.add(target)
db.commit()
```

#### 2. Import Traffic

```python
from recon_engine.burp_import import BurpImporter

count = BurpImporter.import_to_database(
    "burp_export.xml",
    target_id=1,
    db_session=db
)
print(f"Imported {count} requests")
```

#### 3. Detect Contexts

```python
from analysis_engine.detect_context import ContextDetectorEngine

detector = ContextDetectorEngine(db)
contexts = detector.detect_contexts_for_target(target_id=1)
print(f"Found {len(contexts)} contexts")
```

#### 4. Profile Filters

```python
from analysis_engine.detect_filter import FilterDetectorEngine

profiler = FilterDetectorEngine(db)
profiles = profiler.profile_target(target_id=1)
```

#### 5. Create Experiment

```python
from backend_api.models.experiment import Experiment, ExperimentStrategy
from backend_api.services.fuzzing_service import FuzzingService

experiment = Experiment(
    target_id=1,
    name="Unicode XSS Hunt",
    strategy=ExperimentStrategy.UNICODE_HUNT,
    limits={
        "max_requests": 5000,
        "time_limit": 3600,
        "concurrency": 4,
        "rate_limit": 10  # requests per second
    }
)
db.add(experiment)
db.commit()

# Run experiment
fuzzing = FuzzingService(db)
result = fuzzing.run_experiment(experiment.id)
print(f"Created {result['test_cases_created']} test cases")
```

#### 6. Review Findings

```python
from backend_api.services.result_service import ResultService

# Correlate results
findings = fuzzing.correlate_and_create_findings(experiment.id)

# Get finding details
for finding_data in findings:
    finding_id = finding_data['finding_id']
    # View in UI or export
```

---

## API Reference

### Targets

- `GET /api/v1/targets` - List all targets
- `POST /api/v1/targets` - Create target
- `GET /api/v1/targets/{id}` - Get target
- `PUT /api/v1/targets/{id}` - Update target
- `DELETE /api/v1/targets/{id}` - Delete target

### Endpoints

- `GET /api/v1/endpoints` - List endpoints (filter by `target_id`)
- `POST /api/v1/endpoints` - Create endpoint
- `GET /api/v1/endpoints/{id}` - Get endpoint
- `DELETE /api/v1/endpoints/{id}` - Delete endpoint

### Experiments

- `GET /api/v1/experiments` - List experiments
- `POST /api/v1/experiments` - Create experiment
- `GET /api/v1/experiments/{id}` - Get experiment
- `PUT /api/v1/experiments/{id}` - Update experiment
- `POST /api/v1/experiments/{id}/start` - Start experiment
- `POST /api/v1/experiments/{id}/stop` - Stop experiment
- `DELETE /api/v1/experiments/{id}` - Delete experiment

### Results

- `GET /api/v1/results/findings` - List findings
- `GET /api/v1/results/findings/{id}` - Get finding
- `GET /api/v1/results/executions` - List executions
- `GET /api/v1/results/executions/{id}` - Get execution

### Oracle

- `GET /api/v1/oracle?token={token}&msg={msg}` - Oracle callback
- `POST /api/v1/oracle` - Oracle callback (POST)

---

## Workflow Examples

### Example 1: Quick Light Scan

```python
# 1. Add target
target = create_target("https://example.com")

# 2. Import from Burp
import_burp_traffic("burp.xml", target.id)

# 3. Quick context detection
detect_contexts(target.id)

# 4. Create quick experiment
experiment = create_experiment(
    target.id,
    strategy="quick_light",
    limits={"max_requests": 1000}
)

# 5. Run
run_experiment(experiment.id)

# 6. Review findings
findings = get_findings(target.id)
```

### Example 2: Deep Unicode Hunt

```python
# 1. Add target with auth
target = create_target(
    "https://example.com",
    auth_info={"cookie": "session=xyz"}
)

# 2. Crawl authenticated area
crawler = Crawler(target.base_url)
crawler.crawl_to_database(target.id, db)

# 3. Detect contexts
detect_contexts(target.id)

# 4. Profile filters
profile_filters(target.id)

# 5. Map sinks
map_sinks(target.id)

# 6. Create aggressive experiment
experiment = create_experiment(
    target.id,
    strategy="unicode_hunt",
    limits={
        "max_requests": 10000,
        "concurrency": 8
    }
)

# 7. Run
run_experiment(experiment.id)

# 8. Correlate and export
findings = correlate_findings(experiment.id)
export_findings(findings, format="json")
```

### Example 3: JS String Specialist

```python
# Focus on JavaScript string contexts only

# 1. Detect contexts
contexts = detect_contexts(target.id)

# 2. Filter to JS string contexts
js_contexts = [c for c in contexts if c.context_type == "JS_STRING_LITERAL"]

# 3. Create specialist experiment
experiment = create_experiment(
    target.id,
    strategy="js_string_specialist",
    context_filter=js_contexts
)

# 4. Run
run_experiment(experiment.id)
```

---

## Technical Stack

- **Backend**: Python 3.11, FastAPI
- **Database**: PostgreSQL, SQLAlchemy ORM, Alembic migrations
- **Queue**: Redis, Celery
- **Browser Automation**: Playwright (Python bindings)
- **HTML Parsing**: lxml, BeautifulSoup4
- **JS Parsing**: Regex-based (can be enhanced with Acorn/Esprima)
- **HTTP Client**: httpx
- **Frontend**: React 18, Vite
- **API Client**: Axios

---

## Security Considerations

1. **Oracle Server Isolation**: Oracle server should be rate-limited and isolated
2. **Browser Sandboxing**: Workers run in sandboxed environments
3. **Token Validation**: Prevents false positives
4. **Rate Limiting**: Respects target policies
5. **Auth Storage**: Auth context stored securely (encrypted in production)

---

## Future Enhancements

The system is designed to be extensible. Potential enhancements:

1. **CSP Detection**: Automatic Content Security Policy detection
2. **Framework Detection**: React/Vue/Angular detection and gadget discovery
3. **Multi-Browser Support**: Firefox, WebKit in addition to Chromium
4. **Distributed Cluster**: Multiple worker nodes
5. **ML-Based Ranking**: Machine learning for payload prioritization
6. **Burp Extension**: Native Burp Suite plugin
7. **Browser Extension**: Chrome/Firefox extension for manual testing
8. **CI/CD Integration**: Automated testing in CI pipelines

---

## Conclusion

XSS Boss is a complete, production-ready XSS hunting system that combines:

- **Intelligence**: Context and filter awareness
- **Automation**: End-to-end fuzzing pipeline
- **Control**: Human-in-the-loop decision making
- **Explainability**: Clear findings with PoCs

The system is designed for professional bug bounty hunters who need more than a generic scanner - they need a **thinking partner** that learns, adapts, and provides actionable intelligence.

---

**Built with ❤️ for the security research community**

