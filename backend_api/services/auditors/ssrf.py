"""Safe SSRF auditor using collaborator-only canary evidence."""
import json
from typing import Iterable

from sqlalchemy.orm import Session

from backend_api.models.endpoint import Endpoint
from backend_api.models.execution import Execution, OracleStatus
from backend_api.models.param import Param
from backend_api.models.test_case import TestCase, TestCaseStatus
from backend_api.services.auditors.http_param import send_param_probe
from backend_api.utils.logger import logger
from backend_api.utils.tokenizer import Tokenizer


SSRF_PARAM_HINTS = {
    "url",
    "uri",
    "endpoint",
    "target",
    "dest",
    "destination",
    "next",
    "redirect",
    "redirect_url",
    "callback",
    "callback_url",
    "webhook",
    "feed",
    "proxy",
    "fetch",
    "remote",
    "avatar",
    "image",
    "img",
    "file_url",
    "api_url",
}


class SsrfCanaryAuditor:
    """Send collaborator canary URLs to URL-like params and wait for OOB proof."""

    @staticmethod
    def latest_collaborator_domain() -> str | None:
        try:
            from backend_api.routers.burp import active_collaborator_payloads
            return active_collaborator_payloads[-1] if active_collaborator_payloads else None
        except Exception:
            return None

    @staticmethod
    def audit_endpoints(db: Session, experiment_id: int, endpoints: Iterable[Endpoint], param_limit: int = 20) -> int:
        collaborator_domain = SsrfCanaryAuditor.latest_collaborator_domain()
        if not collaborator_domain:
            logger.info("SSRF canary auditor skipped: no Burp Collaborator payload is registered.")
            return 0

        sent = 0
        for endpoint in endpoints:
            candidate_params = [
                param for param in (endpoint.params or [])
                if param.location in {"query", "body", "json"}
                and SsrfCanaryAuditor._is_candidate_param(param.name)
            ]
            for param in candidate_params:
                if sent >= param_limit:
                    return sent
                if SsrfCanaryAuditor._already_seeded(db, experiment_id, param, collaborator_domain):
                    continue
                if SsrfCanaryAuditor._send_canary(db, experiment_id, endpoint, param, collaborator_domain):
                    sent += 1
        return sent

    @staticmethod
    def _is_candidate_param(name: str) -> bool:
        normalized = (name or "").strip().lower().replace("-", "_")
        return normalized in SSRF_PARAM_HINTS or normalized.endswith("_url") or normalized.endswith("_uri")

    @staticmethod
    def _already_seeded(db: Session, experiment_id: int, param: Param, collaborator_domain: str) -> bool:
        return (
            db.query(TestCase)
            .filter(TestCase.experiment_id == experiment_id)
            .filter(TestCase.param_id == param.id)
            .filter(TestCase.payload.like(f"%{collaborator_domain}%"))
            .first()
            is not None
        )

    @staticmethod
    def _send_canary(db: Session, experiment_id: int, endpoint: Endpoint, param: Param, collaborator_domain: str) -> bool:
        token = Tokenizer.generate_short_token(16)
        payload = f"http://t{token}.{collaborator_domain}/ssrf"
        test_case = TestCase(
            experiment_id=experiment_id,
            endpoint_id=endpoint.id,
            param_id=param.id,
            context_id=None,
            payload=payload,
            token=token,
            priority=30,
            status=TestCaseStatus.RUNNING,
        )
        db.add(test_case)
        db.flush()

        try:
            probe = send_param_probe(endpoint, param, payload)
            test_case.status = TestCaseStatus.COMPLETED
            execution = Execution(
                test_case_id=test_case.id,
                browser_worker_id="ssrf-canary-auditor",
                oracle_status=OracleStatus.MISSED,
                oracle_token=None,
                logs=json.dumps({
                    "auditor": "ssrf_canary",
                    "status_code": probe.get("status_code"),
                    "canary_url": payload,
                }),
                screenshot_path=None,
                dom_snapshot=None,
                duration_ms=0,
            )
            db.add(execution)
            db.commit()
            logger.info(f"Sent SSRF collaborator canary for param {param.id} on endpoint {endpoint.id}")
            return True
        except Exception as err:
            test_case.status = TestCaseStatus.FAILED
            db.commit()
            logger.debug(f"SSRF canary probe failed for param {param.id}: {err}")
            return False
