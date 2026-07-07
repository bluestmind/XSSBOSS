"""Score payload-generator coverage against the hard local XSS lab manifest.

This is not a browser execution test. It is a fast preflight that answers:
"Does the generator produce plausible payloads for each hard lab case?"
"""
import argparse
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "tools" / "hard_lab_manifest.json"
TOKEN = "HARDLABTOKEN"


def _load_manifest() -> dict:
    with MANIFEST_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


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
    if case.get("filter_kind") != "naive_common":
        return None

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


def _apply_case_filter(case: dict, payload: str) -> str:
    if case.get("filter_kind") == "naive_common":
        return _casefold_filter(payload)
    return payload


def _looks_like_candidate(case: dict, payload: str) -> bool:
    checked = _apply_case_filter(case, payload)
    lowered = checked.lower()
    if TOKEN.lower() not in lowered or "__xss__" not in lowered:
        return False

    needles = case.get("smoke_any") or []
    if not needles:
        return False

    return any(needle.lower() in lowered for needle in needles)


def run_smoke(show_samples: bool) -> int:
    sys.path.insert(0, str(ROOT))

    from fuzzer.generator import PayloadGenerator
    from fuzzer.strategy import Strategy

    manifest = _load_manifest()
    generator = PayloadGenerator()
    failures = []

    print("[+] Hard lab payload smoke")
    print(f"    manifest: {MANIFEST_PATH}")
    print(f"    token: {TOKEN}")
    print("")

    for case in manifest["cases"]:
        strategy = Strategy(case["strategy"])
        payloads = generator.generate_payloads(
            context_type=case["context_type"],
            token=TOKEN,
            strategy=strategy,
            filter_profile=_filter_profile_for(case),
        )
        candidates = [payload for payload in payloads if _looks_like_candidate(case, payload)]
        missing_token = [payload for payload in payloads if TOKEN not in payload]

        status = "PASS"
        if case["expected_vulnerable"] and not candidates:
            status = "FAIL"
            failures.append(case["slug"])
        elif not case["expected_vulnerable"]:
            status = "CONTROL"

        print(
            f"[{status}] {case['slug']}: "
            f"context={case['context_type']} strategy={case['strategy']} "
            f"payloads={len(payloads)} candidates={len(candidates)} missing_token={len(missing_token)}"
        )

        if show_samples and candidates:
            sample = _apply_case_filter(case, candidates[0])
            print(f"        sample: {sample[:180]}")

    print("")
    if failures:
        print("[!] Missing plausible candidates for:")
        for slug in failures:
            print(f"    - {slug}")
        return 1

    print("[+] Smoke passed: every expected-vulnerable hard case has at least one plausible candidate.")
    print("[*] Next step for proof is the full browser/oracle run against hard_mock_target.py.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Score generator coverage for the hard local XSS lab.")
    parser.add_argument("--show-samples", action="store_true", help="Print one candidate payload per passing case")
    args = parser.parse_args()
    return run_smoke(show_samples=args.show_samples)


if __name__ == "__main__":
    raise SystemExit(main())
