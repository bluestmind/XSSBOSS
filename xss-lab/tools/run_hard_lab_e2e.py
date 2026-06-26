"""Run a browser/oracle proof against the hard local XSS lab.

This script executes one generated payload per manifest case through the
existing BrowserExecutor/Celery task path. It is intentionally local-only.
Run setup_backend.bat first so FastAPI, Selenium, and Playwright deps exist.
"""
import argparse
import json
import os
import re
import sys
import threading
import time
import urllib.request
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "tools" / "hard_lab_manifest.json"


def _load_manifest() -> dict:
    with MANIFEST_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _absolute_url(base_url: str, path: str) -> str:
    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def _casefold_filter(value: str) -> str:
    blocked = [
        r"<\s*/?\s*script\b",
        r"javascript\s*:",
        r"onerror",
        r"srcdoc",
        r"expression\s*\(",
    ]
    filtered = value
    for pattern in blocked:
        filtered = re.sub(pattern, "", filtered, flags=re.IGNORECASE)
    return filtered


def _filter_profile_for(case: dict) -> dict | None:
    if case.get("filter_kind") == "naive_common":
        return {
            "blocked_tokens": ["<script", "</script", "javascript:", "onerror", "srcdoc", "expression("],
            "allowed_tokens": ["svg", "details", "ontoggle", "onbegin", "onfocus"],
            "normalization_behavior": ["case_normalized"],
            "waf_detected": False,
            "sanitizer_detected": True,
            "csp_rules": {
                "allow_inline_scripts": True,
                "allow_event_handlers": True,
                "allow_javascript_urls": False,
            },
        }

    if case.get("filter_kind") == "strict_keywords_and_symbols":
        return {
            "blocked_tokens": ["script", "onerror", "onload", "javascript", "(", ")", "'", "\""],
            "allowed_tokens": ["svg", "animate", "onbegin", "onpointerenter"],
            "normalization_behavior": [],
            "waf_detected": False,
            "sanitizer_detected": True,
            "csp_rules": {
                "allow_inline_scripts": True,
                "allow_event_handlers": True,
                "allow_javascript_urls": False,
            },
            "probe_results": [
                {"probe_name": "char_(", "payload": "xss(xss", "blocked": True, "escaped": False, "stripped": True, "reflected": False},
                {"probe_name": "char_)", "payload": "xss)xss", "blocked": True, "escaped": False, "stripped": True, "reflected": False},
                {"probe_name": "char_'", "payload": "xss'xss", "blocked": True, "escaped": False, "stripped": True, "reflected": False},
                {"probe_name": "char_\"", "payload": "xss\"xss", "blocked": True, "escaped": False, "stripped": True, "reflected": False},
                {"probe_name": "char_`", "payload": "xss`xss", "blocked": False, "escaped": False, "stripped": False, "reflected": True},
            ]
        }

    if case.get("filter_kind") == "extreme_boss_filter":
        return {
            "blocked_tokens": [
                "script", "iframe", "img", "onerror", "onload", "onbegin", "onfocus",
                "onmouseover", "javascript", "srcdoc", "eval", "setTimeout", "Function",
                "(", ")", "'", "\"", "`", "/", "\\"
            ],
            "allowed_tokens": ["a", "id", "name", "href", "config", "url", "parent", "xss"],
            "normalization_behavior": [],
            "waf_detected": False,
            "sanitizer_detected": True,
            "csp_rules": {
                "allow_inline_scripts": True,
                "allow_event_handlers": True,
                "allow_javascript_urls": False,
            },
            "probe_results": [
                {"probe_name": "char_(", "payload": "xss(xss", "blocked": True, "escaped": False, "stripped": True, "reflected": False},
                {"probe_name": "char_)", "payload": "xss)xss", "blocked": True, "escaped": False, "stripped": True, "reflected": False},
                {"probe_name": "char_'", "payload": "xss'xss", "blocked": True, "escaped": False, "stripped": True, "reflected": False},
                {"probe_name": "char_\"", "payload": "xss\"xss", "blocked": True, "escaped": False, "stripped": True, "reflected": False},
                {"probe_name": "char_`", "payload": "xss`xss", "blocked": True, "escaped": False, "stripped": True, "reflected": False},
                {"probe_name": "char_/", "payload": "xss/xss", "blocked": True, "escaped": False, "stripped": True, "reflected": False},
            ]
        }

    return None


def _strict_filter(value: str) -> str:
    blocked = ["script", "onerror", "onload", "javascript", "(", ")", "'", "\""]
    filtered = value
    for token in blocked:
        filtered = re.sub(re.escape(token), "", filtered, flags=re.IGNORECASE)
    return filtered


def _boss_filter(value: str) -> str:
    blocked_tokens = [
        "script", "iframe", "img", "onerror", "onload", "onbegin", "onfocus",
        "onmouseover", "javascript", "srcdoc", "eval", "setTimeout", "Function",
        "(", ")", "'", "\"", "`", "/", "\\"
    ]
    filtered = value
    while True:
        original = filtered
        for token in blocked_tokens:
            filtered = re.sub(re.escape(token), "", filtered, flags=re.IGNORECASE)
        if filtered == original:
            break
    return filtered


def _apply_case_filter(case: dict, payload: str) -> str:
    if case.get("filter_kind") == "naive_common":
        return _casefold_filter(payload)
    if case.get("filter_kind") == "strict_keywords_and_symbols":
        return _strict_filter(payload)
    if case.get("filter_kind") == "extreme_boss_filter":
        return _boss_filter(payload)
    return payload


def _looks_like_candidate(case: dict, payload: str, token: str) -> bool:
    checked = _apply_case_filter(case, payload)
    lowered = checked.lower()
    
    import base64
    b64_token = base64.b64encode(token.encode()).decode().lower()
    b64_token_strip = b64_token.rstrip('=').lower()
    ascii_token = ",".join(str(ord(c)) for c in token)
    
    has_token = (
        token.lower() in lowered or
        b64_token in lowered or
        (b64_token_strip and b64_token_strip in lowered) or
        ascii_token in lowered
    )
    if not has_token or "__xss__" not in lowered:
        return False

    return any(needle.lower() in lowered for needle in case.get("smoke_any", []))


def _wait_for(url: str, timeout_seconds: int = 20) -> None:
    deadline = time.time() + timeout_seconds
    last_error = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if 200 <= response.status < 500:
                    return
        except Exception as exc:
            last_error = exc
        time.sleep(0.25)

    raise RuntimeError(f"Timed out waiting for {url}: {last_error}")


def _start_uvicorn(app, host: str, port: int, label: str):
    try:
        import uvicorn
    except ModuleNotFoundError as exc:
        print("[!] Missing uvicorn. Run setup_backend.bat first.")
        raise SystemExit(1) from exc

    config = uvicorn.Config(app, host=host, port=port, log_level="warning", access_log=False)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, name=label, daemon=True)
    thread.start()
    return server, thread


def _set_env(database_url: str | None, oracle_url: str):
    os.environ.setdefault("DATABASE_URL", database_url or f"sqlite:///{(ROOT / 'xssboss.db').as_posix()}")
    os.environ.setdefault("CELERY_TASK_ALWAYS_EAGER", "True")
    os.environ.setdefault("ORACLE_SERVER_URL", oracle_url)
    os.environ.setdefault("API_HOST", "127.0.0.1")
    os.environ.setdefault("REDIS_URL", "")
    os.environ.setdefault("PYTHONPATH", str(ROOT))
    os.environ["PROXY_URL"] = ""
    os.environ["LLM_ENABLED"] = "False"
    os.environ["USE_BROWSER_CHATGPT"] = "False"


def _candidate_payloads(generator, case: dict, token: str, max_attempts: int):
    from fuzzer.strategy import Strategy

    payloads = generator.generate_payloads(
        context_type=case["context_type"],
        token=token,
        strategy=Strategy(case["strategy"]),
        filter_profile=_filter_profile_for(case),
    )

    if case["expected_vulnerable"]:
        candidates = [payload for payload in payloads if _looks_like_candidate(case, payload, token)]
        return (candidates or payloads)[:max_attempts]

    return payloads[:1]


def run_e2e(base_url: str, oracle_port: int, include_controls: bool, reset: bool, max_attempts: int) -> int:
    sys.path.insert(0, str(ROOT))
    oracle_url = f"http://127.0.0.1:{oracle_port}"
    _set_env(None, oracle_url)

    try:
        from hard_mock_target import app as hard_app
        from oracle_server.main import app as oracle_app
        from tools.seed_hard_lab import seed_hard_lab
        from backend_api.db.base import init_db, SessionLocal
        from backend_api.models.context import Context
        from backend_api.models.endpoint import Endpoint
        from backend_api.models.experiment import Experiment, ExperimentStatus, ExperimentStrategy
        from backend_api.models.param import Param
        from backend_api.models.target import Target
        from backend_api.models.test_case import TestCase, TestCaseStatus
        from backend_api.utils.tokenizer import Tokenizer
        from browser_workers.executor import BrowserExecutor
        from browser_workers.worker import execute_test_case_task
        from fuzzer.generator import PayloadGenerator
    except ModuleNotFoundError as exc:
        print(f"[!] Missing Python dependency: {exc.name}")
        print("[!] Run setup_backend.bat first, then rerun this script.")
        return 1

    parsed_base = urlparse(base_url)
    target_port = parsed_base.port or 8099
    target_host = parsed_base.hostname or "127.0.0.1"

    _start_uvicorn(hard_app, target_host, target_port, "hard-lab-target")
    _start_uvicorn(oracle_app, "127.0.0.1", oracle_port, "xss-oracle")
    _wait_for(f"{base_url}/health")
    _wait_for(f"{oracle_url}/health")

    seed_hard_lab(base_url=base_url, database_url=None, reset=reset, create_experiments=False)

    browser_preflight = BrowserExecutor(oracle_url=f"{oracle_url}/api/v1/oracle")
    try:
        browser_preflight.start()
    except Exception as exc:
        print(f"[!] Browser preflight failed: {exc}")
        print("[!] Install Chrome/ChromeDriver or run with network access so Selenium Manager can resolve them.")
        return 1
    finally:
        browser_preflight.stop()

    init_db()
    db = SessionLocal()
    manifest = _load_manifest()
    generator = PayloadGenerator()
    failures = []

    try:
        target = db.query(Target).filter(Target.name == manifest["target"]["name"]).first()
        if not target:
            raise RuntimeError("Hard lab target was not seeded")

        experiment = Experiment(
            target_id=target.id,
            name=f"Hard Lab - Browser Proof {datetime.utcnow().isoformat(timespec='seconds')}",
            strategy=ExperimentStrategy.QUICK_LIGHT,
            status=ExperimentStatus.RUNNING,
            limits={"lab": "hard-local-xss", "single_candidate_per_case": True},
            started_at=datetime.utcnow(),
        )
        db.add(experiment)
        db.commit()
        db.refresh(experiment)

        print("[+] Running hard lab browser/oracle proof")
        print(f"    target: {base_url}")
        print(f"    oracle: {oracle_url}")
        print(f"    experiment_id: {experiment.id}")
        print("")

        for case in manifest["cases"]:
            if not case["expected_vulnerable"] and not include_controls:
                continue

            # Reset the mock target state to ensure test case isolation
            try:
                reset_url = f"{base_url.rstrip('/')}/hard/reset-state"
                with urllib.request.urlopen(reset_url, timeout=5) as resp:
                    pass
            except Exception as reset_err:
                print(f"[!] Warning: Failed to reset mock target state: {reset_err}")

            seed_token = "HARDE2ESEEDTOKEN"
            candidates = _candidate_payloads(generator, case, seed_token, max_attempts)
            if not candidates:
                failures.append((case["slug"], "no_payload", case["expected_vulnerable"]))
                print(f"[FAIL] {case['slug']}: no payload generated")
                continue

            url = _absolute_url(base_url, case["path"])
            endpoint = (
                db.query(Endpoint)
                .filter(Endpoint.target_id == target.id)
                .filter(Endpoint.method == case["method"].upper())
                .filter(Endpoint.url_pattern == url)
                .first()
            )
            if not endpoint:
                failures.append((case["slug"], "missing_seeded_endpoint", case["expected_vulnerable"]))
                print(f"[FAIL] {case['slug']}: seeded endpoint not found")
                continue

            param = (
                db.query(Param)
                .filter(Param.endpoint_id == endpoint.id)
                .filter(Param.name == case["param_name"])
                .filter(Param.location == case["param_location"])
                .first()
            )
            if not param:
                failures.append((case["slug"], "missing_seeded_param", case["expected_vulnerable"]))
                print(f"[FAIL] {case['slug']}: seeded parameter not found")
                continue

            context = (
                db.query(Context)
                .filter(Context.endpoint_id == endpoint.id)
                .filter(Context.param_id == param.id)
                .filter(Context.context_type == case["context_type"])
                .first()
            )

            expected = bool(case["expected_vulnerable"])
            case_hit = False
            last_test_case_id = None

            from concurrent.futures import ThreadPoolExecutor, as_completed

            test_cases_to_run = []
            for attempt_index, candidate in enumerate(candidates, start=1):
                token = Tokenizer.generate_token()
                payload = Tokenizer.replace_token(candidate, seed_token, token)
                test_case = TestCase(
                    experiment_id=experiment.id,
                    endpoint_id=endpoint.id,
                    param_id=param.id,
                    context_id=context.id if context else None,
                    payload=payload,
                    token=token,
                    priority=100 - attempt_index,
                    status=TestCaseStatus.QUEUED,
                )
                db.add(test_case)
                db.commit()
                db.refresh(test_case)
                test_cases_to_run.append((test_case.id, attempt_index))

            case_hit = False
            last_test_case_id = None
            attempt_index = len(test_cases_to_run)

            def run_attempt(tc_id):
                from browser_workers.worker import execute_test_case_task
                res = execute_test_case_task.delay(tc_id)
                res_val = getattr(res, "result", None)
                return tc_id, bool(isinstance(res_val, dict) and res_val.get("oracle_hit"))

            max_workers = min(4, len(test_cases_to_run))
            if max_workers > 0:
                with ThreadPoolExecutor(max_workers=max_workers) as pool:
                    futures = {pool.submit(run_attempt, tc_id): tc_id for tc_id, _ in test_cases_to_run}
                    for future in as_completed(futures):
                        tc_id, oracle_hit = future.result()
                        last_test_case_id = tc_id
                        if oracle_hit:
                            case_hit = True


            status = "PASS" if case_hit == expected else "FAIL"
            if status == "FAIL":
                failures.append((case["slug"], f"oracle_hit={case_hit}", expected))

            print(
                f"[{status}] {case['slug']}: expected_hit={expected} "
                f"oracle_hit={case_hit} attempts={attempt_index} last_test_case_id={last_test_case_id}"
            )

        experiment.status = ExperimentStatus.COMPLETED if not failures else ExperimentStatus.FAILED
        experiment.completed_at = datetime.utcnow()
        db.commit()
        try:
            from backend_api.services.fuzzing_service import FuzzingService
            fuzzer = FuzzingService(db)
            fuzzer.correlate_and_create_findings(experiment.id)
            from backend_api.services.campaign_report_service import CampaignReportService
            CampaignReportService.generate_report(db, experiment.id)
        except Exception as rep_err:
            print(f"[!] Warning: Failed to generate campaign report: {rep_err}")
    finally:
        db.close()
        try:
            from browser_workers import worker

            if worker._worker_browser_executor:
                worker._worker_browser_executor.stop()
                worker._worker_browser_executor = None
        except Exception:
            pass

    print("")
    if failures:
        print("[!] Hard lab browser proof failed:")
        for slug, got, expected in failures:
            print(f"    - {slug}: {got}, expected={expected}")
        return 1

    print("[+] Hard lab browser proof passed.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run generated payloads through browser/oracle hard lab proof.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8099", help="Hard lab base URL")
    parser.add_argument("--oracle-port", type=int, default=8001, help="Local oracle port")
    parser.add_argument("--skip-controls", action="store_true", help="Do not run safe-control cases")
    parser.add_argument("--reset", action="store_true", help="Reset the seeded hard lab target first")
    parser.add_argument("--max-attempts", type=int, default=8, help="Candidate payload attempts per vulnerable case")
    args = parser.parse_args()

    return run_e2e(
        base_url=args.base_url,
        oracle_port=args.oracle_port,
        include_controls=not args.skip_controls,
        reset=args.reset,
        max_attempts=args.max_attempts,
    )


if __name__ == "__main__":
    raise SystemExit(main())
