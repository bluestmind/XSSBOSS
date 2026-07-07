"""Browser execution for modern DOM XSS probes."""
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
import os
from urllib.parse import quote

from sqlalchemy.orm import Session

from backend_api.models.context import Context
from backend_api.models.endpoint import Endpoint
from backend_api.models.execution import Execution, OracleStatus
from backend_api.models.experiment import Experiment, ExperimentStatus, ExperimentStrategy
from backend_api.models.finding import Finding, FindingStatus
from backend_api.models.param import Param
from backend_api.models.test_case import TestCase, TestCaseStatus
from backend_api.utils.impact_scorer import ImpactScorer
from backend_api.utils.modern_xss_profiles import ModernXSSProfiles
from backend_api.utils.scope_guard import is_endpoint_in_scope
from backend_api.utils.tokenizer import Tokenizer
from browser_workers.executor import BrowserExecutor


DEFAULT_FAMILIES = ["post_message", "prototype_pollution", "dom_clobbering", "sanitizer_mxss"]


class ModernDOMProbeExecutor:
    """Run opt-in modern DOM probes in a real browser and persist evidence."""

    @staticmethod
    def execute(
        db: Session,
        endpoint_id: int,
        param_id: Optional[int] = None,
        context_id: Optional[int] = None,
        payload_template: Optional[str] = None,
        families: Optional[List[str]] = None,
        max_probes: int = 50,
        post_message_origin_modes: Optional[List[str]] = None,
        serve_post_message_poc_http: bool = True,
    ) -> Dict[str, Any]:
        """Execute modern probes against an in-scope endpoint."""
        endpoint = db.query(Endpoint).filter(Endpoint.id == endpoint_id).first()
        if not endpoint:
            raise ValueError(f"Endpoint {endpoint_id} not found")
        if not is_endpoint_in_scope(endpoint):
            raise ValueError("Endpoint is outside the target's configured scope")

        param = ModernDOMProbeExecutor._resolve_param(db, endpoint, param_id)
        context = ModernDOMProbeExecutor._resolve_context(db, endpoint, param, context_id)
        selected_families = families or DEFAULT_FAMILIES
        unknown_families = sorted(set(selected_families) - set(DEFAULT_FAMILIES))
        if unknown_families:
            raise ValueError(f"Unsupported modern probe families: {', '.join(unknown_families)}")
        selected_origin_modes = ModernXSSProfiles.normalize_post_message_origin_modes(post_message_origin_modes)
        experiment = ModernDOMProbeExecutor._create_experiment(
            db,
            endpoint.target_id,
            selected_families,
            {
                "post_message_origin_modes": selected_origin_modes,
                "serve_post_message_poc_http": serve_post_message_poc_http,
            },
        )

        executor = BrowserExecutor(oracle_url=os.getenv("ORACLE_SERVER_URL", "http://localhost:8001") + "/api/v1/oracle")
        executor.start()

        results: List[Dict[str, Any]] = []
        findings: List[int] = []

        try:
            probes = ModernDOMProbeExecutor._build_probe_plan(
                endpoint=endpoint,
                token_seed=None,
                payload_template=payload_template,
                families=selected_families,
                post_message_origin_modes=selected_origin_modes,
                serve_post_message_poc_http=serve_post_message_poc_http,
            )

            for probe in probes[:max_probes]:
                token = Tokenizer.generate_token()
                probe = ModernDOMProbeExecutor._render_probe(endpoint, probe, token, payload_template)
                test_case = ModernDOMProbeExecutor._create_test_case(
                    db=db,
                    experiment=experiment,
                    endpoint=endpoint,
                    param=param,
                    context=context,
                    probe=probe,
                    token=token,
                )

                try:
                    ModernDOMProbeExecutor._reset_browser(executor)
                    result = ModernDOMProbeExecutor._execute_probe(
                        executor=executor,
                        endpoint=endpoint,
                        param=param,
                        probe=probe,
                        token=token,
                        test_case_id=test_case.id,
                    )
                    execution = ModernDOMProbeExecutor._record_execution(db, test_case, result, probe)
                    test_case.status = TestCaseStatus.COMPLETED
                    db.flush()

                    finding = None
                    if result.get("oracle_hit"):
                        finding = ModernDOMProbeExecutor._create_or_update_finding(
                            db=db,
                            endpoint=endpoint,
                            param=param,
                            context=context,
                            test_case=test_case,
                            execution=execution,
                            probe=probe,
                        )
                        findings.append(finding.id)

                    row = {
                        "family": probe["family"],
                        "name": probe["name"],
                        "post_message_origin_mode": probe.get("post_message_origin_mode"),
                        "fake_message_origin": probe.get("fake_message_origin"),
                        "test_case_id": test_case.id,
                        "execution_id": execution.id,
                        "finding_id": finding.id if finding else None,
                        "oracle_hit": bool(result.get("oracle_hit")),
                        "duration_ms": result.get("duration_ms"),
                    }
                    results.append(row)
                except Exception as exc:
                    test_case.status = TestCaseStatus.FAILED
                    db.flush()
                    results.append({
                        "family": probe["family"],
                        "name": probe["name"],
                        "test_case_id": test_case.id,
                        "status": "failed",
                        "error": str(exc),
                    })

            experiment.status = ExperimentStatus.COMPLETED
            experiment.completed_at = datetime.utcnow()
            db.commit()
        finally:
            executor.stop()

        return {
            "status": "completed",
            "endpoint_id": endpoint.id,
            "param_id": param.id,
            "experiment_id": experiment.id,
            "executed": len(results),
            "hit_count": len([row for row in results if row.get("oracle_hit")]),
            "finding_ids": list(dict.fromkeys(findings)),
            "results": results,
        }

    @staticmethod
    def _resolve_param(db: Session, endpoint: Endpoint, param_id: Optional[int]) -> Param:
        if param_id is not None:
            param = db.query(Param).filter(Param.id == param_id).first()
            if not param or param.endpoint_id != endpoint.id:
                raise ValueError("Parameter does not belong to the selected endpoint")
            return param

        param = db.query(Param).filter(Param.endpoint_id == endpoint.id).first()
        if param:
            return param

        param = Param(
            endpoint_id=endpoint.id,
            name="__modern_probe",
            location="query",
            sample_value="modern-probe",
            is_controllable=True,
        )
        db.add(param)
        db.flush()
        return param

    @staticmethod
    def _resolve_context(
        db: Session,
        endpoint: Endpoint,
        param: Param,
        context_id: Optional[int],
    ) -> Optional[Context]:
        if context_id is None:
            return (
                db.query(Context)
                .filter(Context.endpoint_id == endpoint.id)
                .filter(Context.param_id == param.id)
                .first()
            )

        context = db.query(Context).filter(Context.id == context_id).first()
        if not context or context.endpoint_id != endpoint.id or context.param_id != param.id:
            raise ValueError("Context does not belong to the selected endpoint/parameter")
        return context

    @staticmethod
    def _create_experiment(
        db: Session,
        target_id: int,
        families: List[str],
        extra_limits: Optional[Dict[str, Any]] = None,
    ) -> Experiment:
        limits = {"mode": "modern_dom_probes", "families": families}
        if extra_limits:
            limits.update(extra_limits)
        experiment = Experiment(
            target_id=target_id,
            name=f"Modern DOM Probes {datetime.utcnow().isoformat(timespec='seconds')}",
            strategy=ExperimentStrategy.QUICK_LIGHT,
            status=ExperimentStatus.RUNNING,
            limits=limits,
            started_at=datetime.utcnow(),
        )
        db.add(experiment)
        db.flush()
        return experiment

    @staticmethod
    def _build_probe_plan(
        endpoint: Endpoint,
        token_seed: Optional[str],
        payload_template: Optional[str],
        families: List[str],
        post_message_origin_modes: Optional[List[str]] = None,
        serve_post_message_poc_http: bool = True,
    ) -> List[Dict[str, Any]]:
        token = token_seed or "{{TOKEN}}"
        probes: List[Dict[str, Any]] = []
        if "post_message" in families:
            post_message_probes = ModernXSSProfiles.generate_post_message_probes(
                endpoint.url_pattern,
                token,
                payload_template,
            )
            probes.extend(
                ModernXSSProfiles.expand_post_message_origin_modes(
                    post_message_probes,
                    endpoint.url_pattern,
                    post_message_origin_modes,
                    serve_http=serve_post_message_poc_http,
                )
            )
        if "prototype_pollution" in families:
            probes.extend(ModernXSSProfiles.generate_prototype_pollution_probes(endpoint.url_pattern, token, payload_template))
        if "dom_clobbering" in families:
            probes.extend(ModernXSSProfiles.generate_dom_clobbering_payloads(token))
        if "sanitizer_mxss" in families:
            probes.extend(ModernXSSProfiles.generate_sanitizer_mxss_payloads(token))
        return probes

    @staticmethod
    def _render_probe(
        endpoint: Endpoint,
        probe: Dict[str, Any],
        token: str,
        payload_template: Optional[str],
    ) -> Dict[str, Any]:
        family = probe["family"]
        if family == "postMessage":
            base_name = probe.get("base_name") or probe["name"].split("::origin-", 1)[0]
            rendered_probes = ModernXSSProfiles.generate_post_message_probes(
                endpoint.url_pattern,
                token,
                payload_template,
            )
            for rendered_probe in rendered_probes:
                if rendered_probe["name"] == base_name:
                    rendered = dict(rendered_probe)
                    for field in (
                        "base_name",
                        "post_message_origin_mode",
                        "fake_message_origin",
                        "serve_http",
                        "notes",
                    ):
                        if field in probe:
                            rendered[field] = probe[field]
                    if "post_message_origin_mode" in rendered:
                        rendered["name"] = f"{base_name}::origin-{rendered['post_message_origin_mode']}"
                    return rendered
            return rendered_probes[0]
        if family == "prototype_pollution":
            rendered = {}
            for key, value in probe.items():
                if isinstance(value, str):
                    rendered[key] = (
                        value
                        .replace("{{TOKEN}}", token)
                        .replace(quote("{{TOKEN}}"), quote(token))
                    )
                else:
                    rendered[key] = value
            return rendered

        payload = probe.get("payload", "").replace("{{TOKEN}}", token)
        rendered = dict(probe)
        rendered["payload"] = payload
        rendered["token"] = token
        return rendered

    @staticmethod
    def _create_test_case(
        db: Session,
        experiment: Experiment,
        endpoint: Endpoint,
        param: Param,
        context: Optional[Context],
        probe: Dict[str, Any],
        token: str,
    ) -> TestCase:
        test_case = TestCase(
            experiment_id=experiment.id,
            endpoint_id=endpoint.id,
            param_id=param.id,
            context_id=context.id if context else None,
            payload=probe.get("payload") or probe.get("target_url") or probe.get("poc_html", "")[:2000],
            token=token,
            priority=150,
            status=TestCaseStatus.RUNNING,
        )
        db.add(test_case)
        db.flush()
        return test_case

    @staticmethod
    def _execute_probe(
        executor: BrowserExecutor,
        endpoint: Endpoint,
        param: Param,
        probe: Dict[str, Any],
        token: str,
        test_case_id: int,
    ) -> Dict[str, Any]:
        family = probe["family"]
        screenshot_dir = Path(os.getenv("SCREENSHOT_DIR", "./screenshots"))
        headers, cookies = ModernDOMProbeExecutor._headers_and_cookies(endpoint.auth_context or {})

        if family == "postMessage":
            return executor.execute_poc_html(
                poc_html=probe["poc_html"],
                token=token,
                test_case_id=test_case_id,
                target_url=endpoint.url_pattern,
                cookies=cookies,
                screenshot_dir=screenshot_dir,
                serve_http=bool(probe.get("serve_http", True)),
                fake_message_origin=probe.get("fake_message_origin"),
            )

        if family == "prototype_pollution":
            return executor.execute_test_case(
                {
                    "test_case_id": test_case_id,
                    "method": "GET",
                    "url": probe.get("target_url") or probe.get("hash_url"),
                    "headers": headers,
                    "cookies": cookies,
                    "params": {},
                    "body": None,
                    "json": None,
                    "token": token,
                    "payload": probe.get("payload", ""),
                },
                screenshot_dir,
            )

        payload = probe.get("payload", "")
        probe_headers = dict(headers)
        probe_cookies = dict(cookies)
        if param.location == "header":
            probe_headers[param.name] = payload
        elif param.location == "cookie":
            probe_cookies[param.name] = payload

        return executor.execute_test_case(
            {
                "test_case_id": test_case_id,
                "method": endpoint.method,
                "url": endpoint.url_pattern,
                "headers": probe_headers,
                "cookies": probe_cookies,
                "params": {param.name: payload} if param.location == "query" else {},
                "body": {param.name: payload} if param.location == "body" else None,
                "json": {param.name: payload} if param.location == "json" else None,
                "token": token,
                "payload": payload,
            },
            screenshot_dir,
        )

    @staticmethod
    def _record_execution(
        db: Session,
        test_case: TestCase,
        result: Dict[str, Any],
        probe: Dict[str, Any],
    ) -> Execution:
        execution = Execution(
            test_case_id=test_case.id,
            browser_worker_id=f"modern-dom-probe:{probe['family']}",
            oracle_status=OracleStatus.HIT if result.get("oracle_hit") else OracleStatus.MISSED,
            oracle_token=test_case.token if result.get("oracle_hit") else None,
            logs=str(result.get("logs", {})),
            screenshot_path=result.get("screenshot_path"),
            dom_snapshot=result.get("dom_snapshot"),
            duration_ms=result.get("duration_ms"),
        )
        db.add(execution)
        db.flush()
        return execution

    @staticmethod
    def _create_or_update_finding(
        db: Session,
        endpoint: Endpoint,
        param: Param,
        context: Optional[Context],
        test_case: TestCase,
        execution: Execution,
        probe: Dict[str, Any],
    ) -> Finding:
        impact = ImpactScorer.score_components(
            endpoint=endpoint,
            param=param,
            context=context,
            execution=execution,
            verification={
                "stored": False,
                "cross_role": False,
                "roles": [],
                "modern_probe_family": probe["family"],
                "post_message_origin_mode": probe.get("post_message_origin_mode"),
                "fake_message_origin": probe.get("fake_message_origin"),
            },
        )
        impact_refs = {key: value for key, value in impact.items() if key != "severity"}

        finding = Finding(
            endpoint_id=endpoint.id,
            param_id=param.id,
            context_id=context.id if context else None,
            sink_id=None,
            best_payload=test_case.payload,
            severity=impact["severity"].value,
            status=FindingStatus.CONFIRMED.value,
        )
        db.add(finding)
        finding.evidence_refs = {
            "execution_ids": [execution.id],
            "test_case_id": test_case.id,
            "verification": {
                "stored": False,
                "cross_role": False,
                "roles": [],
                "modern_probe_family": probe["family"],
                "modern_probe_name": probe["name"],
                "post_message_origin_mode": probe.get("post_message_origin_mode"),
                "fake_message_origin": probe.get("fake_message_origin"),
            },
            "impact": impact_refs,
        }
        finding.poc_request = {
            "probe_family": probe["family"],
            "probe_name": probe["name"],
            "target_url": probe.get("target_url", endpoint.url_pattern),
            "hash_url": probe.get("hash_url"),
            "param": param.name,
            "post_message_origin_mode": probe.get("post_message_origin_mode"),
            "fake_message_origin": probe.get("fake_message_origin"),
        }
        finding.poc_html = probe.get("poc_html")
        finding.screenshot_path = execution.screenshot_path
        origin_mode = probe.get("post_message_origin_mode")
        origin_detail = f" postMessage origin mode: {origin_mode}." if origin_mode else ""
        finding.report_text = (
            f"Modern DOM XSS probe confirmed execution via {probe['family']} / {probe['name']} "
            f"on {endpoint.method} {endpoint.url_pattern}.{origin_detail}"
        )
        db.flush()

        try:
            from backend_api.services.burp_service import BurpService
            BurpService.auto_forward_finding(db, finding)
        except Exception as e:
            from backend_api.utils.logger import logger
            logger.error(f"Failed to auto-forward modern finding to Burp: {e}")

        return finding

    @staticmethod
    def _headers_and_cookies(auth_context: Dict[str, Any]):
        headers: Dict[str, str] = {}
        cookies: Dict[str, str] = {}
        for key, value in auth_context.items():
            if key.lower() == "cookie":
                for cookie_pair in str(value).split(";"):
                    if "=" in cookie_pair:
                        name, cookie_value = cookie_pair.split("=", 1)
                        cookies[name.strip()] = cookie_value.strip()
            else:
                headers[str(key)] = str(value)
        return headers, cookies

    @staticmethod
    def _reset_browser(executor: BrowserExecutor):
        try:
            executor.driver.delete_all_cookies()
            executor.driver.get("about:blank")
        except Exception:
            executor.stop()
            executor.start()
