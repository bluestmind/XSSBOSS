"""Concurrent API latency acceptance gate with a hard P95 budget."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import time
import urllib.request

import httpx


ROOT = Path(__file__).resolve().parents[1]


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int((len(ordered) - 1) * percentile)))
    return ordered[index]


def _wait_ready(url: str, timeout: int = 60) -> None:
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status == 200:
                    return
        except Exception as error:
            last_error = error
        time.sleep(0.25)
    raise RuntimeError(f"API did not become ready: {last_error}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify production-like API P95 latency")
    parser.add_argument("--base-url", default="http://127.0.0.1:8124")
    parser.add_argument("--requests", type=int, default=1000)
    parser.add_argument("--concurrency", type=int, default=32)
    parser.add_argument("--p95-ms", type=float, default=300.0)
    parser.add_argument("--start-server", action="store_true")
    parser.add_argument("--start-audit-worker", action="store_true")
    parser.add_argument("--artifact", type=Path, default=ROOT / "reports" / "api_latency.json")
    args = parser.parse_args()
    if args.requests < 1000:
        raise SystemExit("The release gate requires at least 1,000 requests")

    process = None
    audit_process = None
    log_handle = None
    started_at = datetime.now(UTC)
    try:
        if args.start_server:
            from urllib.parse import urlparse

            parsed = urlparse(args.base_url)
            log_path = args.artifact.with_suffix(".server.log")
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_handle = log_path.open("w", encoding="utf-8")
            process = subprocess.Popen(
                [
                    sys.executable, "-m", "uvicorn", "backend_api.main:app",
                    "--host", parsed.hostname or "127.0.0.1",
                    "--port", str(parsed.port or 8124),
                    "--log-level", "warning",
                ],
                cwd=ROOT,
                env=os.environ.copy(),
                stdout=log_handle,
                stderr=subprocess.STDOUT,
            )
            if args.start_audit_worker:
                audit_process = subprocess.Popen(
                    [
                        sys.executable, "-m", "celery", "-A", "backend_api.task_queue:task_app",
                        "worker", "-Q", "audit", "--pool=solo", "--concurrency=1",
                        "--loglevel=WARNING", "--without-gossip", "--without-mingle",
                        "-n", "latency-audit-gate@%h",
                    ],
                    cwd=ROOT,
                    env=os.environ.copy(),
                    stdout=log_handle,
                    stderr=subprocess.STDOUT,
                )
        _wait_ready(f"{args.base_url}/ready")

        token = os.getenv("API_AUTH_TOKEN")
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        paths = ("/health", "/ready", "/api/v1/targets/?limit=10")
        durations = []
        statuses = []
        errors = []

        with httpx.Client(headers=headers, timeout=10.0) as client:
            for path in paths:
                client.get(f"{args.base_url}{path}")

            def request(index: int):
                begin = time.perf_counter()
                try:
                    response = client.get(f"{args.base_url}{paths[index % len(paths)]}")
                    return (time.perf_counter() - begin) * 1000, response.status_code, None
                except Exception as error:
                    return (time.perf_counter() - begin) * 1000, 0, str(error)

            with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
                futures = [pool.submit(request, index) for index in range(args.requests)]
                for future in as_completed(futures):
                    duration, status_code, error = future.result()
                    durations.append(duration)
                    statuses.append(status_code)
                    if error:
                        errors.append(error)

        p95 = _percentile(durations, 0.95)
        report = {
            "schema_version": 1,
            "started_at": started_at.isoformat(),
            "finished_at": datetime.now(UTC).isoformat(),
            "requests": args.requests,
            "concurrency": args.concurrency,
            "p50_ms": round(statistics.median(durations), 3),
            "p95_ms": round(p95, 3),
            "p99_ms": round(_percentile(durations, 0.99), 3),
            "max_ms": round(max(durations), 3),
            "budget_p95_ms": args.p95_ms,
            "errors": len(errors),
            "status_counts": {str(status): statuses.count(status) for status in sorted(set(statuses))},
            "passed": not errors and all(200 <= status < 400 for status in statuses) and p95 < args.p95_ms,
        }
        args.artifact.parent.mkdir(parents=True, exist_ok=True)
        args.artifact.write_text(json.dumps(report, indent=2), encoding="utf-8")
        if args.start_audit_worker:
            from redis import Redis

            redis_client = Redis.from_url(os.environ["REDIS_URL"])
            drain_deadline = time.monotonic() + 120
            while time.monotonic() < drain_deadline:
                if redis_client.llen("audit") == 0:
                    time.sleep(1)
                    if redis_client.llen("audit") == 0:
                        break
                time.sleep(0.25)
        print(json.dumps(report, indent=2))
        return 0 if report["passed"] else 1
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=15)
        if audit_process is not None and audit_process.poll() is None:
            audit_process.kill()
            audit_process.wait(timeout=15)
        if log_handle is not None:
            log_handle.close()


if __name__ == "__main__":
    raise SystemExit(main())
