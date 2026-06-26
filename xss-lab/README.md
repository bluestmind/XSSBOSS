# XSS Boss - Human-in-the-Loop XSS Hunting System

A professional-grade XSS (Cross-Site Scripting) hunting system designed for bug bounty hunters and security researchers. This system learns target filter behavior, evolves context-aware payloads, and executes them in real browsers with XSS Oracle detection.

For authorized program workflow, scope setup, and operator checks, see [BUG_BOUNTY_READINESS.md](BUG_BOUNTY_READINESS.md).

For current XSS technique coverage and remaining research gaps, see [MODERN_XSS_TECHNIQUE_AUDIT.md](MODERN_XSS_TECHNIQUE_AUDIT.md).

## Architecture

The system is organized into three main layers:

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

## Project Structure

```
xss-lab/
├── backend-api/          # FastAPI backend service
├── recon-engine/         # Reconnaissance and import tools
├── analysis-engine/     # Context detection, filter profiling, sink mapping
├── fuzzer/              # Payload generation and mutation
├── browser-workers/      # Playwright execution workers
├── oracle-server/       # XSS Oracle callback receiver
└── ui/                  # React frontend (optional)
```

## Features

- **Context-Aware**: Understands where input lands (HTML text, attribute, JS, JSON)
- **Filter-Aware**: Learns each target's WAF/sanitizer behavior
- **Sink-Aware**: Focuses on parameters that reach dangerous sinks
- **Human-Steered**: You choose where to go deep, how aggressive, what to report
- **Explainable**: Every finding comes with story + PoC

## Installation

On Windows, run the backend setup helper first:

```bat
setup_backend.bat
```

1. Install dependencies:
```bash
pip install -r backend_api/requirements.txt
playwright install chromium
```

2. Set up database:
```bash
# Create PostgreSQL database
createdb xssboss

# Run migrations
cd backend_api
alembic upgrade head
```

3. Configure environment:
```bash
# Set environment variables or create .env file
export DATABASE_URL="postgresql://user:pass@localhost/xssboss"
export REDIS_URL="redis://localhost:6379/0"
```

4. Start services:
```bash
# Start API server
cd backend_api
python main.py

# Start Celery worker (in separate terminal)
celery -A browser_workers.worker worker --loglevel=info

# Start Oracle server (in separate terminal)
cd oracle_server
python main.py
```

## Usage

### Quick Scan From the Web UI

For local use, run `run_all.bat`, choose Simplified Mode, then open:

```text
http://127.0.0.1:3000
```

Use the Scan page to enter an authorized target URL, confirm permission, and start a same-host XSS scan. A URL with query parameters, such as `https://example.com/search?q=test`, gives the scanner an immediate parameter to test. Keep crawling enabled if you want it to discover same-host links and forms before fuzzing.

Scans are constrained to the submitted host and require the authorization checkbox before the backend will queue any work.

### 1. Add a Target

```python
from backend_api.db.session import get_db
from backend_api.models.target import Target

db = next(get_db())
target = Target(
    name="Example Target",
    base_url="https://example.com",
    bounty_platform="intigriti"
)
db.add(target)
db.commit()
```

### 2. Import Traffic

```python
from recon_engine.burp_import import BurpImporter

BurpImporter.import_to_database("burp_export.xml", target_id=1, db_session=db)
```

### 3. Run Context Detection

```python
from analysis_engine.detect_context import ContextDetectorEngine

detector = ContextDetectorEngine(db)
contexts = detector.detect_contexts_for_target(target_id=1)
```

### 4. Create and Run Experiment

```python
from backend_api.models.experiment import Experiment, ExperimentStrategy
from backend_api.services.fuzzing_service import FuzzingService

experiment = Experiment(
    target_id=1,
    name="Unicode XSS Hunt",
    strategy=ExperimentStrategy.UNICODE_HUNT
)
db.add(experiment)
db.commit()

fuzzing = FuzzingService(db)
fuzzing.run_experiment(experiment.id)
```

### 5. Review Findings

```python
from backend_api.services.result_service import ResultService

findings = ResultService.correlate_executions(db, endpoint_id=1, param_id=1)
```

## API Endpoints

- `GET /api/v1/targets` - List targets
- `POST /api/v1/targets` - Create target
- `GET /api/v1/endpoints` - List endpoints
- `GET /api/v1/params` - List discovered parameters
- `GET /api/v1/contexts` - List reflection contexts
- `GET /api/v1/sinks` - List mapped sinks
- `GET /api/v1/filters/endpoint/{id}` - Get filter profile for an endpoint
- `POST /api/v1/modern/dom-probes` - Generate opt-in postMessage/prototype/clobbering/mXSS probes
- `POST /api/v1/modern/dom-probes/execute` - Execute modern DOM probes in a browser, including hosted postMessage PoCs and origin-mode checks
- `POST /api/v1/experiments` - Create experiment
- `POST /api/v1/experiments/{id}/start` - Start experiment
- `POST /api/v1/test-cases/execute` - Queue a scoped manual payload
- `POST /api/v1/verification/stored-xss` - Verify stored/cross-role XSS with revisits
- `GET /api/v1/results/findings` - List findings
- `GET /api/v1/results/findings/{id}/bounty-report` - Generate bounty-ready report
- `GET /api/v1/oracle` - Oracle callback endpoint

## Payload Strategies

- **quick_light**: Fast scanning with minimal obfuscation
- **unicode_hunt**: Aggressive Unicode homoglyph mutations
- **js_string_specialist**: Focus on JavaScript string contexts
- **csp_aware**: Avoids script tags, uses inline handlers

## Hard Local Lab

Use `hard_mock_target.py` and the scripts under `tools/` to test detection against harder local XSS cases:

```bat
.venv\Scripts\python.exe tools\hard_lab_payload_smoke.py --show-samples
.venv\Scripts\python.exe tools\seed_hard_lab.py --reset
.venv\Scripts\python.exe tools\run_hard_lab_e2e.py --reset
```

## License

This project is for authorized security testing only. Use responsibly and in accordance with applicable laws and terms of service.

