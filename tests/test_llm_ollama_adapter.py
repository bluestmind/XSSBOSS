"""Local Ollama integration stays structured, bounded, and advisory."""
from unittest.mock import MagicMock, patch

from backend_api.config import settings
from backend_api.services.llm_service import LLMService


def _response(payload):
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json.return_value = payload
    return response


def test_ollama_structured_request_uses_runtime_bounds():
    with (
        patch.object(settings, "LLM_API_URL", "http://127.0.0.1:11434/api/generate"),
        patch.object(settings, "LLM_MODEL", "WhiteRabbitNeo/WhiteRabbitNeo-V3-7B:latest"),
        patch.object(settings, "LLM_KEEP_ALIVE", "30m"),
        patch.object(settings, "LLM_NUM_CTX", 8192),
        patch.object(settings, "LLM_MAX_OUTPUT_TOKENS", 321),
        patch("backend_api.services.llm_service.requests.post") as post,
    ):
        post.return_value = _response({"response": '{"status":"ok"}'})
        result = LLMService._query_ollama("Return status", expect_json=True)

    assert result == '{"status":"ok"}'
    request = post.call_args.kwargs["json"]
    assert request["model"] == "WhiteRabbitNeo/WhiteRabbitNeo-V3-7B:latest"
    assert request["format"] == "json"
    assert request["stream"] is False
    assert request["keep_alive"] == "30m"
    assert request["options"]["num_ctx"] == 8192
    assert request["options"]["num_predict"] == 321
    assert "never expand scope" in request["prompt"]


def test_query_router_prefers_local_model():
    with (
        patch.object(settings, "LLM_ENABLED", True),
        patch.object(settings, "LLM_PREFER_LOCAL", True),
        patch.object(settings, "OPENAI_API_KEY", "configured-but-secondary"),
        patch.object(LLMService, "_query_ollama", return_value="local") as local,
        patch.object(LLMService, "_query_openai", return_value="remote") as remote,
    ):
        assert LLMService.query_model("task") == "local"
    local.assert_called_once()
    remote.assert_not_called()


def test_security_data_never_falls_back_remote_without_opt_in():
    with (
        patch.object(settings, "LLM_ENABLED", True),
        patch.object(settings, "LLM_PREFER_LOCAL", True),
        patch.object(settings, "LLM_ALLOW_REMOTE_SECURITY_DATA", False),
        patch.object(settings, "OPENAI_API_KEY", "configured-remote"),
        patch.object(LLMService, "_query_ollama", side_effect=RuntimeError("offline")),
        patch.object(LLMService, "_query_openai", return_value="remote") as remote,
    ):
        try:
            LLMService.query_model("private telemetry", security_data=True)
        except ValueError as error:
            assert "local: offline" in str(error)
        else:
            raise AssertionError("A failed local-only security query must fail closed")
    remote.assert_not_called()


def test_evidence_sanitizer_redacts_credentials_and_bounds_content():
    sanitized = LLMService.sanitize_evidence({
        "authorization": "Bearer should-not-leak",
        "nested": {
            "console": "Authorization: Bearer abcdefghijklmnop",
            "session_cookie": "private",
            "body": "x" * 1000,
        },
    })
    assert sanitized["authorization"] == "[redacted]"
    assert sanitized["nested"]["session_cookie"] == "[redacted]"
    assert "abcdefghijklmnop" not in sanitized["nested"]["console"]
    assert len(sanitized["nested"]["body"]) == 600


def test_hypothesis_advice_rejects_invented_ids_and_techniques():
    model_result = {
        "summary": "Prioritize the reachable high-impact path.",
        "recommendations": [
            {"id": 7, "priority_adjustment": 99, "technique": "svg-event", "rationale": "valid"},
            {"id": 8, "priority_adjustment": 2, "technique": "invented", "rationale": "bad technique"},
            {"id": 999, "priority_adjustment": 5, "technique": "ghost", "rationale": "bad id"},
        ],
    }
    with patch.object(LLMService, "query_model", return_value=__import__("json").dumps(model_result)):
        advice = LLMService.advise_hypotheses([
            {"id": 7, "type": "dom_xss", "confidence": 0.8, "impact": 90, "techniques": ["svg-event"]},
            {"id": 8, "type": "reflected_xss", "confidence": 0.5, "impact": 50, "techniques": ["html-element"]},
        ])

    assert advice["recommendations"] == [
        {"id": 7, "priority_adjustment": 5, "technique": "svg-event", "rationale": "valid"},
        {"id": 8, "priority_adjustment": 2, "technique": None, "rationale": "bad technique"},
    ]


def test_hypothesis_advice_uses_evidence_and_learned_history_locally():
    model_result = {"summary": "history-aware", "recommendations": []}
    with patch.object(
        LLMService, "query_model", return_value=__import__("json").dumps(model_result)
    ) as query:
        LLMService.advise_hypotheses([{
            "id": 3,
            "type": "dom_xss",
            "confidence": 0.6,
            "impact": 80,
            "techniques": ["dynamic-taint-confirmation"],
            "evidence": {"sink_count": 2, "cookie": "must-not-leak"},
            "technique_history": [{
                "technique": "dynamic-taint-confirmation",
                "uses": 9,
                "hits": 2,
                "mean_reward": 0.3,
            }],
        }])

    prompt = query.call_args.args[0]
    assert '"sink_count":2' in prompt
    assert '"uses":9' in prompt
    assert "must-not-leak" not in prompt
    assert query.call_args.kwargs == {"expect_json": True, "security_data": True}


def test_midscan_pivot_is_allowlisted_and_bounded():
    model_result = {
        "selected_candidate_id": 12,
        "priority_boost": 999,
        "confidence": 4,
        "rationale": "try the independent parser boundary",
    }
    with patch.object(LLMService, "query_model", return_value=__import__("json").dumps(model_result)) as query:
        result = LLMService.advise_pivot(
            {"runtime_logs": {"authorization": "do-not-leak", "sink": "innerHTML"}},
            [{
                "id": 12,
                "technique": "parser-differential",
                "utility": 73.2,
                "expected_success": 0.44,
                "information_gain": 0.98,
            }],
        )

    assert result["selected_candidate_id"] == 12
    assert result["technique"] == "parser-differential"
    assert result["priority_boost"] == 20
    assert result["confidence"] == 1.0
    assert "do-not-leak" not in query.call_args.args[0]
    assert query.call_args.kwargs == {"expect_json": True, "security_data": True}


def test_workflow_advice_cannot_invent_a_plan():
    model_result = {
        "selected_candidate_id": 999,
        "confidence": 0.95,
        "rationale": "invented",
    }
    with patch.object(LLMService, "query_model", return_value=__import__("json").dumps(model_result)):
        result = LLMService.advise_workflow([{
            "id": 4,
            "method": "POST",
            "field_names": ["body"],
            "submit_label": "Save draft",
            "step_count": 3,
            "field_coverage": 1.0,
            "exact_action_match": True,
        }])
    assert result["selected_candidate_id"] is None


def test_workflow_advice_rejects_objectively_dominated_choice():
    model_result = {
        "selected_candidate_id": 1,
        "confidence": 0.9,
        "rationale": "incorrect comparison",
    }
    with patch.object(LLMService, "query_model", return_value=__import__("json").dumps(model_result)):
        result = LLMService.advise_workflow([
            {
                "id": 0,
                "method": "POST",
                "field_names": ["bio", "name"],
                "submit_label": "Save changes",
                "step_count": 5,
                "field_coverage": 1.0,
                "exact_action_match": True,
            },
            {
                "id": 1,
                "method": "POST",
                "field_names": ["bio"],
                "submit_label": "Continue",
                "step_count": 8,
                "field_coverage": 0.5,
                "exact_action_match": True,
            },
        ])
    assert result["selected_candidate_id"] is None
    assert result["confidence"] == 0.0
    assert "dominated" in result["rationale"]


def test_provider_status_detects_installed_model():
    with (
        patch.object(settings, "LLM_ENABLED", True),
        patch.object(settings, "LLM_API_URL", "http://127.0.0.1:11434/api/generate"),
        patch.object(settings, "LLM_MODEL", "WhiteRabbitNeo/WhiteRabbitNeo-V3-7B:latest"),
        patch("backend_api.services.llm_service.requests.get") as get,
    ):
        get.return_value = _response({"models": [{"name": "WhiteRabbitNeo/WhiteRabbitNeo-V3-7B:latest"}]})
        status = LLMService.provider_status()
    assert status["reachable"] is True
    assert status["model_available"] is True
