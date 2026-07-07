"""Stored and cross-session XSS verification service."""
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import os

from sqlalchemy.orm import Session

from backend_api.models.context import Context
from backend_api.models.endpoint import Endpoint
from backend_api.models.execution import Execution, OracleStatus
from backend_api.models.experiment import Experiment, ExperimentStatus, ExperimentStrategy
from backend_api.models.finding import Finding, FindingStatus
from backend_api.models.param import Param
from backend_api.models.test_case import TestCase, TestCaseStatus
from backend_api.utils.impact_scorer import ImpactScorer
from backend_api.utils.scope_guard import is_endpoint_in_scope
from backend_api.utils.tokenizer import Tokenizer


class StoredXSSVerifier:
    """Verify whether a submitted payload executes on later page views."""

    @staticmethod
    def verify(
        db: Session,
        submit_endpoint_id: int,
        param_id: int,
        payload_template: str,
        context_id: Optional[int] = None,
        revisit_endpoint_ids: Optional[List[int]] = None,
        role_contexts: Optional[List[Dict[str, Any]]] = None,
        max_revisits: int = 20,
    ) -> Dict[str, Any]:
        """Submit a payload, revisit pages, and record stored/cross-role proof."""
        submit_endpoint = db.query(Endpoint).filter(Endpoint.id == submit_endpoint_id).first()
        if not submit_endpoint:
            raise ValueError(f"Endpoint {submit_endpoint_id} not found")
        if not is_endpoint_in_scope(submit_endpoint):
            raise ValueError("Submit endpoint is outside the target's configured scope")

        param = db.query(Param).filter(Param.id == param_id).first()
        if not param or param.endpoint_id != submit_endpoint.id:
            raise ValueError("Parameter does not belong to the submit endpoint")

        context = None
        if context_id is not None:
            context = db.query(Context).filter(Context.id == context_id).first()
            if not context or context.endpoint_id != submit_endpoint.id or context.param_id != param.id:
                raise ValueError("Context does not belong to the submit endpoint/parameter")

        token = Tokenizer.generate_token()
        payload = payload_template.replace("{{TOKEN}}", token)
        role_contexts = StoredXSSVerifier._normalize_roles(role_contexts)

        submit_result = StoredXSSVerifier._submit_payload(
            endpoint=submit_endpoint,
            param=param,
            payload=payload,
            auth_context=role_contexts[0].get("auth_context") or {},
        )

        revisit_endpoints = StoredXSSVerifier._resolve_revisit_endpoints(
            db=db,
            target_id=submit_endpoint.target_id,
            revisit_endpoint_ids=revisit_endpoint_ids,
            max_revisits=max_revisits,
            submit_endpoint=submit_endpoint,
        )

        experiment = StoredXSSVerifier._get_or_create_experiment(db, submit_endpoint.target_id)
        execution_results = []
        hits = []

        from browser_workers.executor import BrowserExecutor

        executor = BrowserExecutor(oracle_url=os.getenv("ORACLE_SERVER_URL", "http://localhost:8001") + "/api/v1/oracle")
        executor.start()
        try:
            for role in role_contexts:
                for revisit_endpoint in revisit_endpoints:
                    if not is_endpoint_in_scope(revisit_endpoint):
                        execution_results.append({
                            "endpoint_id": revisit_endpoint.id,
                            "role": role["label"],
                            "status": "skipped_out_of_scope",
                            "oracle_hit": False,
                        })
                        continue

                    test_case = TestCase(
                        experiment_id=experiment.id,
                        endpoint_id=revisit_endpoint.id,
                        param_id=param.id,
                        context_id=context.id if context else None,
                        payload=payload,
                        token=token,
                        priority=100,
                        status=TestCaseStatus.RUNNING,
                    )
                    db.add(test_case)
                    db.flush()

                    headers, cookies = StoredXSSVerifier._headers_and_cookies(
                        revisit_endpoint.auth_context or {},
                        role.get("auth_context") or {},
                    )
                    # Resolve path parameters for revisit endpoint URL
                    revisit_url = revisit_endpoint.url_pattern
                    revisit_path_params = {
                        p.name: (p.sample_value or "1")
                        for p in revisit_endpoint.params
                        if p.location == "path"
                    }
                    for p_name, p_val in revisit_path_params.items():
                        revisit_url = revisit_url.replace(f"{{{p_name}}}", p_val)

                    test_case_data = {
                        "test_case_id": test_case.id,
                        "method": revisit_endpoint.method,
                        "url": revisit_url,
                        "headers": headers,
                        "cookies": cookies,
                        "params": {},
                        "body": None,
                        "json": None,
                        "token": token,
                        "payload": payload,
                    }

                    result = executor.execute_test_case(
                        test_case_data,
                        Path(os.getenv("SCREENSHOT_DIR", "./screenshots")),
                    )
                    oracle_hit = bool(result.get("oracle_hit"))
                    execution = Execution(
                        test_case_id=test_case.id,
                        browser_worker_id=f"stored-verifier:{role['label']}",
                        oracle_status=OracleStatus.HIT if oracle_hit else OracleStatus.MISSED,
                        oracle_token=token if oracle_hit else None,
                        logs=str(result.get("logs", {})),
                        screenshot_path=result.get("screenshot_path"),
                        dom_snapshot=result.get("dom_snapshot"),
                        duration_ms=result.get("duration_ms"),
                    )
                    db.add(execution)
                    test_case.status = TestCaseStatus.COMPLETED
                    db.flush()

                    row = {
                        "endpoint_id": revisit_endpoint.id,
                        "url": revisit_endpoint.url_pattern,
                        "role": role["label"],
                        "test_case_id": test_case.id,
                        "execution_id": execution.id,
                        "oracle_hit": oracle_hit,
                        "duration_ms": result.get("duration_ms"),
                    }
                    execution_results.append(row)
                    if oracle_hit:
                        hits.append((row, revisit_endpoint, execution, test_case))

            finding = None
            if hits:
                finding = StoredXSSVerifier._create_or_update_finding(
                    db=db,
                    submit_endpoint=submit_endpoint,
                    param=param,
                    context=context,
                    payload=payload,
                    submit_result=submit_result,
                    hits=hits,
                    role_contexts=role_contexts,
                )

            experiment.completed_at = datetime.utcnow()
            experiment.status = ExperimentStatus.COMPLETED
            db.commit()

            return {
                "status": "stored_xss_confirmed" if hits else "not_confirmed",
                "token": token,
                "submit": submit_result,
                "revisit_count": len(revisit_endpoints),
                "role_count": len(role_contexts),
                "executions": execution_results,
                "hit_count": len(hits),
                "finding_id": finding.id if finding else None,
            }
        finally:
            executor.stop()

    @staticmethod
    def _normalize_roles(role_contexts: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        if not role_contexts:
            return [{"label": "same-session", "auth_context": {}}]

        normalized = []
        for index, role in enumerate(role_contexts):
            label = str(role.get("label") or f"role-{index + 1}")
            normalized.append({
                "label": label,
                "auth_context": role.get("auth_context") or {},
            })
        return normalized

    @staticmethod
    def _headers_and_cookies(*contexts: Dict[str, Any]) -> Tuple[Dict[str, str], Dict[str, str]]:
        headers: Dict[str, str] = {}
        cookies: Dict[str, str] = {}

        for context in contexts:
            for key, value in (context or {}).items():
                if key.lower() == "cookie":
                    for cookie_pair in str(value).split(";"):
                        if "=" in cookie_pair:
                            name, cookie_value = cookie_pair.split("=", 1)
                            cookies[name.strip()] = cookie_value.strip()
                else:
                    headers[str(key)] = str(value)

        return headers, cookies

    @staticmethod
    def _submit_payload(
        endpoint: Endpoint,
        param: Param,
        payload: str,
        auth_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        import httpx

        headers, cookies = StoredXSSVerifier._headers_and_cookies(endpoint.auth_context or {}, auth_context)
        params = {}
        data = None
        json_data = None

        # Resolve path parameters in the submit URL pattern
        url = endpoint.url_pattern
        path_params = {
            p.name: (p.sample_value or "1")
            for p in endpoint.params
            if p.location == "path"
        }
        for p_name, p_val in path_params.items():
            placeholder = f"{{{p_name}}}"
            if param.location == "path" and param.name == p_name:
                url = url.replace(placeholder, payload)
            else:
                url = url.replace(placeholder, p_val)

        # Load sample request body or JSON
        if endpoint.sample_request_body and isinstance(endpoint.sample_request_body, dict):
            if any(p.location == "json" for p in endpoint.params) or param.location == "json":
                json_data = endpoint.sample_request_body.copy()
            elif any(p.location == "body" for p in endpoint.params) or param.location == "body":
                data = endpoint.sample_request_body.copy()

        # Populate other parameters with their sample values
        for p in endpoint.params:
            if p.location == param.location and p.name == param.name:
                continue
            if p.location == "query":
                params[p.name] = p.sample_value or ""
            elif p.location == "body":
                if data is None:
                    data = {}
                data[p.name] = p.sample_value or ""
            elif p.location == "json":
                if json_data is None:
                    json_data = {}
                keys = p.name.split('.')
                current = json_data
                for key in keys[:-1]:
                    if key not in current or not isinstance(current[key], dict):
                        current[key] = {}
                    current = current[key]
                current[keys[-1]] = p.sample_value or ""
            elif p.location == "header":
                headers[p.name] = p.sample_value or ""
            elif p.location == "cookie":
                cookies[p.name] = p.sample_value or ""

        # Set fuzzed payload
        if param.location == "query":
            params[param.name] = payload
        elif param.location == "body":
            if data is None:
                data = {}
            data[param.name] = payload
        elif param.location == "json":
            if json_data is None:
                json_data = {}
            keys = param.name.split('.')
            current = json_data
            for key in keys[:-1]:
                if key not in current or not isinstance(current[key], dict):
                    current[key] = {}
                current = current[key]
            current[keys[-1]] = payload
        elif param.location == "header":
            headers[param.name] = payload
        elif param.location == "cookie":
            cookies[param.name] = payload
        elif param.location == "path":
            # Already resolved in URL
            pass
        else:
            raise ValueError(f"Unsupported stored verification parameter location: {param.location}")

        response = httpx.request(
            method=endpoint.method,
            url=url,
            headers=headers,
            cookies=cookies,
            params=params,
            data=data,
            json=json_data,
            follow_redirects=True,
            timeout=15,
        )

        return {
            "endpoint_id": endpoint.id,
            "method": endpoint.method,
            "url": url,
            "status_code": response.status_code,
            "reflected_immediately": payload in response.text,
        }

    @staticmethod
    def _resolve_revisit_endpoints(
        db: Session,
        target_id: int,
        revisit_endpoint_ids: Optional[List[int]],
        max_revisits: int,
        submit_endpoint: Optional[Endpoint] = None,
    ) -> List[Endpoint]:
        if revisit_endpoint_ids:
            endpoints = (
                db.query(Endpoint)
                .filter(Endpoint.id.in_(revisit_endpoint_ids))
                .filter(Endpoint.target_id == target_id)
                .all()
            )
        else:
            endpoints = (
                db.query(Endpoint)
                .filter(Endpoint.target_id == target_id)
                .filter(Endpoint.method == "GET")
                .all()
            )

        if submit_endpoint and len(endpoints) > 1:
            import urllib.parse
            sub_url = submit_endpoint.url_pattern
            sub_path = urllib.parse.urlparse(sub_url).path.strip("/")
            sub_parts = [p for p in sub_path.split("/") if p]
            sub_set = set(sub_parts)
            
            def calculate_rank(ep: Endpoint) -> Tuple[int, float]:
                ep_path = urllib.parse.urlparse(ep.url_pattern).path.strip("/")
                ep_parts = [p for p in ep_path.split("/") if p]
                ep_set = set(ep_parts)
                
                # 1. Prefix matches (consecutive matching segments from the start)
                prefix_match = 0
                for a, b in zip(sub_parts, ep_parts):
                    if a == b:
                        prefix_match += 1
                    else:
                        break
                        
                # 2. Jaccard similarity of path components
                jaccard = 0.0
                if sub_set or ep_set:
                    intersection = len(sub_set.intersection(ep_set))
                    union = len(sub_set.union(ep_set))
                    jaccard = intersection / union if union > 0 else 0.0
                    
                return (prefix_match, jaccard)
                
            endpoints.sort(key=calculate_rank, reverse=True)

        return endpoints[:max_revisits]

    @staticmethod
    def _get_or_create_experiment(db: Session, target_id: int) -> Experiment:
        experiment = Experiment(
            target_id=target_id,
            name=f"Stored XSS Verification {datetime.utcnow().isoformat(timespec='seconds')}",
            strategy=ExperimentStrategy.QUICK_LIGHT,
            status=ExperimentStatus.RUNNING,
            limits={"mode": "stored_verification", "single_payload": True},
            started_at=datetime.utcnow(),
        )
        db.add(experiment)
        db.flush()
        return experiment

    @staticmethod
    def _create_or_update_finding(
        db: Session,
        submit_endpoint: Endpoint,
        param: Param,
        context: Optional[Context],
        payload: str,
        submit_result: Dict[str, Any],
        hits: List[Tuple[Dict[str, Any], Endpoint, Execution, TestCase]],
        role_contexts: List[Dict[str, Any]],
    ) -> Finding:
        hit_rows = [hit[0] for hit in hits]
        execution_ids = [hit[2].id for hit in hits]
        test_case_id = hits[0][3].id
        revisit_urls = [hit[1].url_pattern for hit in hits]
        roles = [hit[0]["role"] for hit in hits]
        cross_role = len(set(roles)) > 1 or (roles and roles[0] != "same-session")

        verification = {
            "stored": True,
            "cross_role": cross_role,
            "roles": roles,
            "revisit_urls": revisit_urls,
            "submit": submit_result,
            "hits": hit_rows,
        }

        impact = ImpactScorer.score_components(
            endpoint=hits[0][1],
            param=param,
            context=context,
            execution=hits[0][2],
            sink=None,
            verification=verification,
        )
        impact_refs = {
            key: value
            for key, value in impact.items()
            if key != "severity"
        }

        finding = (
            db.query(Finding)
            .filter(Finding.endpoint_id == submit_endpoint.id)
            .filter(Finding.param_id == param.id)
            .filter(Finding.context_id == (context.id if context else None))
            .filter(Finding.sink_id.is_(None))
            .first()
        )

        if not finding:
            finding = Finding(
                endpoint_id=submit_endpoint.id,
                param_id=param.id,
                context_id=context.id if context else None,
                sink_id=None,
                best_payload=payload,
                severity=impact["severity"].value,
                status=FindingStatus.CONFIRMED.value,
            )
            db.add(finding)

        finding.best_payload = payload
        finding.severity = impact["severity"].value
        finding.status = FindingStatus.CONFIRMED.value
        finding.evidence_refs = {
            "execution_ids": execution_ids,
            "test_case_id": test_case_id,
            "verification": verification,
            "impact": impact_refs,
        }
        finding.poc_request = submit_result
        finding.screenshot_path = hits[0][2].screenshot_path
        finding.report_text = (
            f"Stored XSS confirmed for {submit_endpoint.method} {submit_endpoint.url_pattern}. "
            f"Payload executed on revisit URL(s): {', '.join(revisit_urls)}."
        )
        db.flush()

        try:
            from backend_api.services.burp_service import BurpService
            BurpService.auto_forward_finding(db, finding)
        except Exception as e:
            from backend_api.utils.logger import logger
            logger.error(f"Failed to auto-forward stored finding to Burp: {e}")

        return finding
