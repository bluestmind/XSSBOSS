"""Runtime acceptance gate for metrics required by production alerts and dashboards."""
import argparse
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib.parse import urlparse

import httpx


ROOT = Path(__file__).resolve().parents[1]


def _wait_ready(base_url: str, timeout: int = 60) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if httpx.get(f"{base_url}/ready", timeout=2).status_code == 200:
                return
        except Exception:
            pass
        time.sleep(0.25)
    raise RuntimeError("observability gate API did not become ready")


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify production Prometheus metric families at runtime")
    parser.add_argument("--base-url", default="http://127.0.0.1:8126")
    parser.add_argument("--start-server", action="store_true")
    parser.add_argument("--artifact", type=Path, default=ROOT / "reports" / "observability_gate.json")
    args = parser.parse_args()

    args.artifact.parent.mkdir(parents=True, exist_ok=True)
    process = None
    log_handle = None
    report = {"schema_version": 1, "started_at": datetime.now(UTC).isoformat(), "passed": False}
    try:
        if args.start_server:
            parsed = urlparse(args.base_url)
            env = os.environ.copy()
            env.setdefault("PYTHONPATH", str(ROOT))
            log_handle = args.artifact.with_suffix(".server.log").open("w", encoding="utf-8")
            process = subprocess.Popen(
                [
                    sys.executable, "-m", "uvicorn", "backend_api.main:app",
                    "--host", parsed.hostname or "127.0.0.1", "--port", str(parsed.port or 8126),
                    "--log-level", "warning",
                ],
                cwd=ROOT,
                env=env,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
            )
        _wait_ready(args.base_url)
        httpx.get(f"{args.base_url}/health", timeout=5).raise_for_status()
        response = httpx.get(f"{args.base_url}/metrics", timeout=10)
        response.raise_for_status()
        body = response.text
        checks = {
            "prometheus_content_type": response.headers.get("content-type", "").startswith("text/plain"),
            "request_counter": bool(re.search(r"^xssboss_http_requests_total\{", body, re.MULTILINE)),
            "latency_histogram": bool(re.search(r"^xssboss_http_request_duration_seconds_bucket\{", body, re.MULTILINE)),
            "all_durable_queues": all(f'xssboss_queue_depth{{queue="{queue}"}}' in body for queue in ("orchestration", "browser", "audit", "maintenance")),
            "run_statuses": "xssboss_runs{status=" in body,
            "execution_leases": 'xssboss_execution_leases{state="active"}' in body and 'xssboss_execution_leases{state="stale"}' in body,
            "stage_leases": 'xssboss_stage_leases{state="stale"}' in body,
            "queue_delay_slo": "xssboss_oldest_queued_case_age_seconds " in body,
            "completion_slo": "xssboss_oldest_active_run_age_seconds " in body,
            "database_up": 'xssboss_dependency_up{dependency="database"} 1' in body,
            "redis_up": 'xssboss_dependency_up{dependency="redis"} 1' in body,
            "no_target_labels": "target=" not in body and "tenant=" not in body,
        }
        report.update({
            "checks": checks,
            "metric_lines": len([line for line in body.splitlines() if line and not line.startswith("#")]),
            "passed": all(checks.values()),
        })
    except Exception as error:
        import traceback

        report["error"] = f"{type(error).__name__}: {error}"
        report["traceback"] = traceback.format_exc()
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=15)
        if log_handle is not None:
            log_handle.close()
        report["finished_at"] = datetime.now(UTC).isoformat()
        args.artifact.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
