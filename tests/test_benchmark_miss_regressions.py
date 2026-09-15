"""Focused regressions for previously missed real-browser benchmark contexts."""

import pytest

from benchmarks.benchmark_real import BENCHMARK_ROUTES, RealBenchmarkRunner
from fuzzer.autonomous_xss_brain import AutonomousXSSBrain


MISSED_ROUTE_NAMES = {
    "Extreme Filter Bypass",
    "Unquoted Attribute Breakout",
    "Ultimate Boss",
}


def _route(name: str):
    return next(route for route in BENCHMARK_ROUTES if route.name == name)


def _contains_raw_constraint(payload: str, constraints: list[str]) -> bool:
    payload_lower = payload.lower()
    return any(
        constraint in payload
        if len(constraint) == 1
        else constraint.lower() in payload_lower
        for constraint in constraints
    )


@pytest.mark.parametrize("route_name", sorted(MISSED_ROUTE_NAMES))
def test_previously_missed_route_gets_a_viable_payload_within_budget(route_name: str):
    runner = RealBenchmarkRunner(max_payloads_per_route=30)
    token = "xB0ss_MISS_REGRESSION"
    route = _route(route_name)

    payloads = runner._generate_payloads(route, token)

    assert payloads
    if route_name == "Extreme Filter Bypass":
        viable = [
            payload
            for payload in payloads
            if "ontoggle=__XSS__`" in payload
            and not _contains_raw_constraint(
                payload, route.blocked_chars + route.blocked_keywords
            )
        ]
    elif route_name == "Unquoted Attribute Breakout":
        viable = [
            payload
            for payload in payloads
            if payload.startswith("x tabindex=0 autofocus onfocus=")
        ]
    else:
        viable = [
            payload
            for payload in payloads
            if "id=config name=url href=&#106;ava&#115;cript:" in payload
            and not _contains_raw_constraint(
                payload, route.blocked_chars + route.blocked_keywords
            )
        ]

    assert viable
    assert payloads.index(viable[0]) < 30


def test_autonomous_brain_honors_blocked_tokens_profile_key():
    route = _route("Extreme Filter Bypass")
    constraints = route.blocked_chars + route.blocked_keywords
    report = AutonomousXSSBrain().synthesize_attack_chain(
        context_type=route.context_type,
        token="xB0ss_CONSTRAINT_REGRESSION",
        filter_profile={"blocked_tokens": constraints},
        max_payloads=30,
    )

    assert report.top_payloads
    assert all(
        not _contains_raw_constraint(decision.payload, constraints)
        for decision in report.top_payloads
    )
    assert any(
        "ontoggle=__XSS__`" in decision.payload
        for decision in report.top_payloads
    )
