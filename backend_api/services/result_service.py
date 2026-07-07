"""Result correlation and PoC building service."""
from sqlalchemy.orm import Session
from typing import List, Dict, Any, Optional
from collections import defaultdict
from datetime import datetime
import json
import base64
import ast

from backend_api.models.test_case import TestCase, TestCaseStatus
from backend_api.models.execution import Execution, OracleStatus
from backend_api.models.finding import Finding, Severity, FindingStatus
from backend_api.models.endpoint import Endpoint
from backend_api.models.param import Param
from backend_api.models.context import Context
from backend_api.models.sink import Sink
from backend_api.utils.logger import logger
from backend_api.utils.impact_scorer import ImpactScorer


class ResultService:
    """Service for correlating results and building findings."""
    
    @staticmethod
    def correlate_executions(
        db: Session,
        experiment_id: int
    ) -> List[Finding]:
        """Correlate execution results into findings.
        
        Args:
            db: Database session
            experiment_id: Experiment ID
            
        Returns:
            List of created Finding records
        """
        # Get all test cases for experiment
        test_cases = (
            db.query(TestCase)
            .filter(TestCase.experiment_id == experiment_id)
            .all()
        )
        
        # Group by (endpoint, param, context, sink)
        groups = defaultdict(list)
        
        for test_case in test_cases:
            # Get executions for this test case
            executions = (
                db.query(Execution)
                .filter(Execution.test_case_id == test_case.id)
                .all()
            )
            
            # Check for oracle hits
            has_hit = any(
                exec.oracle_status == OracleStatus.HIT
                for exec in executions
            )
            
            if not has_hit:
                continue  # Skip test cases without hits
            
            successful_exec = next(
                (exec for exec in executions if exec.oracle_status == OracleStatus.HIT),
                None
            )
            auditor_vuln = ResultService._extract_auditor_vuln(successful_exec) if successful_exec else None
            vuln_type = auditor_vuln.get("vuln_type", "xss") if auditor_vuln else "xss"

            # Group key
            context_id = test_case.context_id
            sink_id = None
            
            # Try to find associated sink
            if context_id:
                context = db.query(Context).filter(Context.id == context_id).first()
                if context:
                    # Prioritize verified dynamic trace sinks over static matches
                    from backend_api.models.sink import DetectedVia
                    sink = (
                        db.query(Sink)
                        .filter(Sink.context_id == context_id)
                        .filter(Sink.detected_via == DetectedVia.DYNAMIC)
                        .first()
                    )
                    if not sink:
                        sink = (
                            db.query(Sink)
                            .filter(Sink.context_id == context_id)
                            .first()
                        )
                    if sink:
                        sink_id = sink.id
            
            group_key = (
                test_case.endpoint_id,
                test_case.param_id,
                context_id,
                sink_id,
                vuln_type,
            )
            
            groups[group_key].append({
                'test_case': test_case,
                'executions': executions,
                'has_hit': has_hit
            })
        
        # Process each group
        findings = []
        for group_key, items in groups.items():
            endpoint_id, param_id, context_id, sink_id, vuln_type = group_key
            
            # Find best payload
            best_item = ResultService._select_best_payload(items)
            
            if not best_item:
                continue
            
            test_case = best_item['test_case']
            executions = best_item['executions']
            
            # Get successful execution
            successful_exec = next(
                (e for e in executions if e.oracle_status == OracleStatus.HIT),
                None
            )
            
            if not successful_exec:
                continue
            auditor_vuln = ResultService._extract_auditor_vuln(successful_exec)

            sink_obj = db.query(Sink).filter(Sink.id == sink_id).first() if sink_id else None
            impact = ImpactScorer.score_test_case(
                test_case,
                execution=successful_exec,
                sink=sink_obj,
                verification={"stored": False, "cross_role": False, "roles": []},
            )
            impact_refs = {
                key: value
                for key, value in impact.items()
                if key != "severity"
            }
            
            # Build PoC artifacts
            poc_artifacts = ResultService._build_poc_artifacts(
                db,
                test_case,
                successful_exec
            )
            if auditor_vuln:
                poc_artifacts["html_poc"] = None
            
            # Determine severity
            severity = ResultService._severity_for_auditor(auditor_vuln) or impact["severity"]
            
            # Generate report text
            report_text = ResultService._generate_report_text(
                db,
                test_case,
                successful_exec,
                poc_artifacts,
                auditor_vuln=auditor_vuln,
            )
            
            # Check if finding already exists
            existing = (
                db.query(Finding)
                .filter(Finding.endpoint_id == endpoint_id)
                .filter(Finding.param_id == param_id)
                .filter(Finding.context_id == context_id)
                .filter(Finding.sink_id == sink_id)
                .filter(Finding.vuln_type == vuln_type)
                .first()
            )
            
            # Calculate tech stack and sink details
            import ast
            tech_stack = {}
            if successful_exec.logs:
                try:
                    logs_dict = ast.literal_eval(successful_exec.logs)
                    if isinstance(logs_dict, dict):
                        tech_stack = logs_dict.get('tech_stack', {})
                except Exception:
                    try:
                        import json
                        logs_dict = json.loads(successful_exec.logs)
                        if isinstance(logs_dict, dict):
                            tech_stack = logs_dict.get('tech_stack', {})
                    except Exception:
                        pass

            sink_details = {}
            if sink_obj:
                sink_details = {
                    'sink_type': sink_obj.sink_type,
                    'js_location': sink_obj.js_location,
                    'notes': sink_obj.notes
                }

            evidence_refs = {
                'execution_ids': [e.id for e in executions],
                'test_case_id': test_case.id,
                'vuln_type': vuln_type,
                'auditor_vuln': auditor_vuln,
                'verification': {
                    'stored': False,
                    'cross_role': False,
                    'roles': [],
                },
                'impact': impact_refs,
                'tech_stack': tech_stack,
                'sink_details': sink_details,
            }

            if existing:
                # Update existing finding
                existing.best_payload = test_case.payload
                existing.severity = severity
                existing.vuln_type = vuln_type
                existing.scanner_module = (auditor_vuln or {}).get("scanner_module", "xss_fuzzer")
                existing.confidence = (auditor_vuln or {}).get("confidence", "firm")
                existing.evidence_summary = (auditor_vuln or {}).get("evidence_summary")
                existing.report_text = report_text
                existing.evidence_refs = evidence_refs
                existing.poc_request = poc_artifacts['curl_request']
                existing.poc_html = poc_artifacts['html_poc']
                existing.screenshot_path = successful_exec.screenshot_path
                findings.append(existing)
            else:
                # Create new finding
                finding = Finding(
                    endpoint_id=endpoint_id,
                    param_id=param_id,
                    context_id=context_id,
                    sink_id=sink_id,
                    vuln_type=vuln_type,
                    scanner_module=(auditor_vuln or {}).get("scanner_module", "xss_fuzzer"),
                    confidence=(auditor_vuln or {}).get("confidence", "firm"),
                    evidence_summary=(auditor_vuln or {}).get("evidence_summary"),
                    best_payload=test_case.payload,
                    severity=severity.value if hasattr(severity, "value") else severity,
                    status=FindingStatus.DRAFT.value,
                    report_text=report_text,
                    evidence_refs=evidence_refs,
                    poc_request=poc_artifacts['curl_request'],
                    poc_html=poc_artifacts['html_poc'],
                    screenshot_path=successful_exec.screenshot_path
                )
                db.add(finding)
                findings.append(finding)
        
        # Auto-forward verified findings to Burp Repeater queue and Issues list
        try:
            from backend_api.services.burp_service import BurpService
            for finding in findings:
                BurpService.auto_forward_finding(db, finding)
        except Exception as e:
            logger.error(f"Failed to auto-forward findings to Burp: {e}")

        db.commit()
        
        # Refresh all findings
        for finding in findings:
            db.refresh(finding)
        
        logger.info(f"Correlated {len(findings)} findings from experiment {experiment_id}")
        return findings
    
    @staticmethod
    def _select_best_payload(items: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Select best payload from group.
        
        Criteria:
        - Prioritize active javascript-executing payloads (containing indicators like __XSS__, script, onerror, svg, etc.)
        - Shortest payload length within priority group
        - Has successful execution
        
        Args:
            items: List of test case items with executions
            
        Returns:
            Best item dictionary or None
        """
        # Filter to only items with hits
        items_with_hits = [item for item in items if item['has_hit']]
        if not items_with_hits:
            return None
        
        # Helper to check if payload is active or raw reflection probe
        def is_active_exploit(payload: str) -> bool:
            p_lower = payload.lower()
            indicators = ['__xss__', '<script', 'onerror', 'onload', 'onfocus', 'onclick', 'javascript:', '<svg', '<img', 'throw']
            return any(ind in p_lower for ind in indicators)
        
        # Sort key: active exploit (0) first, raw probe (1) second; then by payload length ascending
        items_with_hits.sort(key=lambda x: (
            0 if is_active_exploit(x['test_case'].payload) else 1,
            len(x['test_case'].payload)
        ))
        
        return items_with_hits[0]
    
    @staticmethod
    def _build_poc_artifacts(
        db: Session,
        test_case: TestCase,
        execution: Execution
    ) -> Dict[str, Any]:
        """Build Proof-of-Concept artifacts.
        
        Args:
            db: Database session
            test_case: Test case
            execution: Successful execution
            
        Returns:
            Dictionary with PoC artifacts
        """
        endpoint = test_case.endpoint
        param = test_case.param
        
        # Build curl request
        curl_request = ResultService._build_curl_request(endpoint, param, test_case.payload)
        
        # Build HTML PoC
        html_poc = ResultService._build_html_poc(test_case, execution)
        
        # Build replay script
        replay_script = ResultService._build_replay_script(endpoint, param, test_case.payload)
        
        return {
            'curl_request': curl_request,
            'html_poc': html_poc,
            'replay_script': replay_script
        }
    
    @staticmethod
    def _build_curl_request(
        endpoint: Endpoint,
        param: Param,
        payload: str
    ) -> Dict[str, Any]:
        """Build curl command for PoC.
        
        Args:
            endpoint: Endpoint
            param: Parameter
            payload: Payload
            
        Returns:
            Dictionary with curl command and metadata
        """
        url = endpoint.url_pattern
        method = endpoint.method
        headers = endpoint.auth_context or {}
        
        # Build command parts
        cmd_parts = ['curl', '-X', method]
        
        # Add headers
        for key, value in headers.items():
            if key.lower() not in ['content-length', 'host']:
                cmd_parts.extend(['-H', f'"{key}: {value}"'])
        
        # Add parameter based on location
        if param.location == "query":
            import urllib.parse
            url_parts = list(urllib.parse.urlparse(url))
            query_params = dict(urllib.parse.parse_qsl(url_parts[4]))
            query_params[param.name] = payload
            url_parts[4] = urllib.parse.urlencode(query_params)
            url = urllib.parse.urlunparse(url_parts)
        elif param.location == "body":
            if method == 'POST':
                cmd_parts.extend(['-d', f"{param.name}={payload}"])
        elif param.location == "json":
            json_data = {param.name: payload}
            if endpoint.sample_request_body and isinstance(endpoint.sample_request_body, dict):
                json_data = endpoint.sample_request_body.copy()
                json_data[param.name] = payload
            cmd_parts.extend(['-H', '"Content-Type: application/json"'])
            cmd_parts.extend(['-d', json.dumps(json_data)])
        elif param.location == "header":
            cmd_parts.extend(['-H', f'"{param.name}: {payload}"'])
        elif param.location == "cookie":
            cmd_parts.extend(['-H', f'"Cookie: {param.name}={payload}"'])
        
        cmd_parts.append(f'"{url}"')
        
        curl_command = ' '.join(cmd_parts)
        
        return {
            'command': curl_command,
            'method': method,
            'url': url,
            'headers': headers,
            'payload': payload,
            'param_location': param.location
        }
    
    @staticmethod
    def _build_html_poc(
        test_case: TestCase,
        execution: Execution
    ) -> str:
        """Build HTML PoC file.
        
        Args:
            test_case: Test case
            execution: Execution
            
        Returns:
            HTML content as string
        """
        endpoint = test_case.endpoint
        param = test_case.param
        payload = test_case.payload
        
        # Get context snippet if available
        context_snippet = ""
        if test_case.context_id:
            context = test_case.context
            if context and context.snippet:
                context_snippet = context.snippet[:500]
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>XSS PoC - {endpoint.url_pattern}</title>
    <style>
        body {{
            font-family: monospace;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #d32f2f;
        }}
        .info {{
            background: #fff3cd;
            padding: 15px;
            border-left: 4px solid #ffc107;
            margin: 20px 0;
        }}
        .payload {{
            background: #f8f9fa;
            padding: 15px;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            margin: 10px 0;
            word-break: break-all;
        }}
        .snippet {{
            background: #e9ecef;
            padding: 15px;
            border: 1px solid #ced4da;
            border-radius: 4px;
            margin: 10px 0;
            font-size: 12px;
            overflow-x: auto;
        }}
        iframe {{
            width: 100%;
            height: 600px;
            border: 1px solid #dee2e6;
            margin: 20px 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>XSS Proof of Concept</h1>
        
        <div class="info">
            <strong>Endpoint:</strong> {endpoint.method} {endpoint.url_pattern}<br>
            <strong>Parameter:</strong> {param.name} ({param.location})<br>
            <strong>Context:</strong> {test_case.context.context_type if test_case.context else 'Unknown'}<br>
            <strong>Execution ID:</strong> {execution.id}<br>
            <strong>Detected:</strong> {execution.executed_at.strftime('%Y-%m-%d %H:%M:%S') if execution.executed_at else 'Unknown'}
        </div>
        
        <h2>Payload</h2>
        <div class="payload">
            <code>{payload}</code>
        </div>
        
        {f'<h2>Context Snippet</h2><div class="snippet"><pre>{context_snippet}</pre></div>' if context_snippet else ''}
        
        <h2>Live PoC</h2>
        <p><strong>Warning:</strong> This iframe will execute the XSS payload. Only open in a safe environment.</p>
        <iframe src="data:text/html;base64,{base64.b64encode(f'<html><body>{payload}</body></html>'.encode()).decode()}" sandbox="allow-scripts"></iframe>
        
        <h2>Replay Instructions</h2>
        <ol>
            <li>Open browser developer tools</li>
            <li>Navigate to: <code>{endpoint.url_pattern}</code></li>
            <li>Set parameter <code>{param.name}</code> to: <code>{payload}</code></li>
            <li>Observe XSS execution</li>
        </ol>
    </div>
</body>
</html>"""
        
        return html
    
    @staticmethod
    def _build_replay_script(
        endpoint: Endpoint,
        param: Param,
        payload: str
    ) -> str:
        """Build Python replay script.
        
        Args:
            endpoint: Endpoint
            param: Parameter
            payload: Payload
            
        Returns:
            Python script as string
        """
        script = f"""#!/usr/bin/env python3
\"\"\"
XSS PoC Replay Script
Generated automatically
\"\"\"

import requests

# Configuration
URL = "{endpoint.url_pattern}"
METHOD = "{endpoint.method}"
PARAM_NAME = "{param.name}"
PARAM_LOCATION = "{param.location}"
PAYLOAD = "{payload}"

# Headers
HEADERS = {json.dumps(endpoint.auth_context or {}, indent=4)}

# Build request
if PARAM_LOCATION == "query":
    params = {{PARAM_NAME: PAYLOAD}}
    response = requests.request(METHOD, URL, params=params, headers=HEADERS)
elif PARAM_LOCATION == "body":
    data = {{PARAM_NAME: PAYLOAD}}
    response = requests.request(METHOD, URL, data=data, headers=HEADERS)
elif PARAM_LOCATION == "json":
    json_data = {{PARAM_NAME: PAYLOAD}}
    response = requests.request(METHOD, URL, json=json_data, headers=HEADERS)
elif PARAM_LOCATION == "header":
    HEADERS[PARAM_NAME] = PAYLOAD
    response = requests.request(METHOD, URL, headers=HEADERS)
elif PARAM_LOCATION == "cookie":
    cookies = {{PARAM_NAME: PAYLOAD}}
    response = requests.request(METHOD, URL, headers=HEADERS, cookies=cookies)
else:
    response = requests.request(METHOD, URL, headers=HEADERS)

print(f"Status: {{response.status_code}}")
print(f"Response length: {{len(response.text)}}")
print(f"Payload in response: {{PAYLOAD in response.text}}")
"""
        return script
    
    @staticmethod
    def _determine_severity(
        db: Session,
        test_case: TestCase,
        execution: Execution
    ) -> Severity:
        """Determine finding severity.
        
        Args:
            db: Database session
            test_case: Test case
            execution: Execution
            
        Returns:
            Severity enum
        """
        sink = None
        if test_case.context_id:
            sink = (
                db.query(Sink)
                .filter(Sink.context_id == test_case.context_id)
                .first()
            )

        impact = ImpactScorer.score_test_case(
            test_case,
            execution=execution,
            sink=sink,
            verification={"stored": False, "cross_role": False, "roles": []},
        )
        return impact["severity"]

    @staticmethod
    def _parse_execution_logs(logs: Optional[str]) -> Dict[str, Any]:
        if not logs:
            return {}
        for parser in (json.loads, ast.literal_eval):
            try:
                parsed = parser(logs)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                continue
        return {}

    @staticmethod
    def _extract_auditor_vuln(execution: Optional[Execution]) -> Optional[Dict[str, Any]]:
        if not execution:
            return None
        logs = ResultService._parse_execution_logs(execution.logs)
        vuln = logs.get("auditor_vuln")
        return vuln if isinstance(vuln, dict) else None

    @staticmethod
    def _severity_for_auditor(auditor_vuln: Optional[Dict[str, Any]]) -> Optional[Severity]:
        if not auditor_vuln:
            return None
        severity = str(auditor_vuln.get("severity") or "").lower()
        mapping = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }
        return mapping.get(severity)

    @staticmethod
    def _generate_auditor_report(
        test_case: TestCase,
        execution: Execution,
        auditor_vuln: Dict[str, Any],
    ) -> str:
        endpoint = test_case.endpoint
        param = test_case.param
        title = auditor_vuln.get("title") or auditor_vuln.get("vuln_type", "Vulnerability")
        evidence_summary = auditor_vuln.get("evidence_summary") or "The auditor confirmed a non-XSS vulnerability."
        details = auditor_vuln.get("details") if isinstance(auditor_vuln.get("details"), dict) else {}
        detail_lines = "\n".join(f"- {key}: `{value}`" for key, value in details.items())

        return f"""{title}

**Summary:**
{evidence_summary}

**Affected Endpoint:**
- Method: {endpoint.method}
- URL: {endpoint.url_pattern}
- Parameter: {param.name} ({param.location})

**Payload:**
```
{test_case.payload}
```

**Evidence:**
- Execution ID: {execution.id}
- Detected: {execution.executed_at.strftime('%Y-%m-%d %H:%M:%S') if execution.executed_at else 'Unknown'}
{detail_lines}

**Recommendation:**
Validate this parameter against an allowlist, reject untrusted external destinations, and bind redirects or trust decisions to known application origins only.
"""
    
    @staticmethod
    def _generate_report_text(
        db: Session,
        test_case: TestCase,
        execution: Execution,
        poc_artifacts: Dict[str, Any],
        auditor_vuln: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Generate human-readable report text.
        
        Args:
            db: Database session
            test_case: Test case
            execution: Execution
            poc_artifacts: PoC artifacts dictionary
            
        Returns:
            Report text string
        """
        endpoint = test_case.endpoint
        param = test_case.param
        context = test_case.context

        if auditor_vuln:
            return ResultService._generate_auditor_report(test_case, execution, auditor_vuln)
        
        # Get sink info
        sink_info = "None"
        forensic_evidence = ""
        if test_case.context_id:
            sink = (
                db.query(Sink)
                .filter(Sink.context_id == test_case.context_id)
                .first()
            )
            if sink:
                sink_info = f"Sink Type: {sink.sink_type}, JS Location: {sink.js_location}, Notes: {sink.notes or ''}"
                forensic_evidence = f"\n\n**JS Execution Trace Evidence:**\n"
                if sink.js_location and sink.js_location != "unknown":
                    forensic_evidence += f"- **Target Location:** `{sink.js_location}`\n"
                if sink.notes:
                    forensic_evidence += f"```text\n{sink.notes}\n```"

        evidence_info = f"Execution ID: {execution.id}, Detected Time: {execution.executed_at}, Screenshot Path: {execution.screenshot_path or 'Not available'}"

        # Try to generate bespoke bounty report using ChatGPT
        try:
            from backend_api.services.llm_service import LLMService
            bespoke_report = LLMService.generate_vulnerability_report(
                endpoint=endpoint,
                param=param,
                context=context,
                payload=test_case.payload,
                sink_info=sink_info,
                evidence_info=evidence_info
            )
            if bespoke_report:
                return bespoke_report
        except Exception as err:
            logger.warning(f"Bespoke report generation failed, using fallback template: {err}")

        # Fallback static template
        context_desc = context.context_type if context else "unknown context"
        report = f"""Cross-Site Scripting (XSS) Vulnerability

**Summary:**
A stored/reflected XSS vulnerability was identified in the {endpoint.method} {endpoint.url_pattern} endpoint. User-controlled input in the '{param.name}' parameter ({param.location}) is reflected unsanitized in the response within a {context_desc} context.

**Affected Parameter:**
- Name: {param.name}
- Location: {param.location}
- Context: {context_desc}

**Payload:**
```
{test_case.payload}
```

**Proof of Concept:**
The vulnerability can be demonstrated by sending the payload above in the '{param.name}' parameter. The payload executes JavaScript in the context of any user viewing the affected page.

**Impact:**
An attacker could:
- Steal user session cookies and authentication tokens
- Perform actions on behalf of the user
- Deface the website
- Redirect users to malicious sites
- Access sensitive user data

**Recommendation:**
- Implement proper output encoding/escaping based on the context
- Use Content Security Policy (CSP) headers
- Validate and sanitize all user input
- Use framework-provided templating that auto-escapes output

**Evidence:**
- Execution ID: {execution.id}
- Detected: {execution.executed_at.strftime('%Y-%m-%d %H:%M:%S') if execution.executed_at else 'Unknown'}
- Screenshot: {execution.screenshot_path or 'Not available'}{forensic_evidence}
"""
        return report
    
    @staticmethod
    def list_findings(
        db: Session,
        target_id: Optional[int] = None,
        endpoint_id: Optional[int] = None,
        status: Optional[FindingStatus] = None,
        severity: Optional[Severity] = None,
        skip: int = 0,
        limit: int = 100
    ) -> List[Finding]:
        """List findings with optional filters.
        
        Args:
            db: Database session
            target_id: Filter by target ID
            endpoint_id: Filter by endpoint ID
            status: Filter by status
            severity: Filter by severity
            skip: Skip count
            limit: Limit count
            
        Returns:
            List of Finding records
        """
        query = db.query(Finding)
        
        if target_id:
            query = query.join(Endpoint).filter(Endpoint.target_id == target_id)
        if endpoint_id:
            query = query.filter(Finding.endpoint_id == endpoint_id)
        if status:
            query = query.filter(Finding.status == status.value)
        if severity:
            query = query.filter(Finding.severity == severity.value)
        
        return query.order_by(Finding.created_at.desc()).offset(skip).limit(limit).all()
    
    @staticmethod
    def get_finding(db: Session, finding_id: int) -> Finding:
        """Get finding by ID.
        
        Args:
            db: Database session
            finding_id: Finding ID
            
        Returns:
            Finding record
        """
        finding = db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            raise ValueError(f"Finding {finding_id} not found")
        return finding

    @staticmethod
    def list_executions(
        db: Session,
        test_case_id: Optional[int] = None,
        oracle_status: Optional[OracleStatus] = None,
        skip: int = 0,
        limit: int = 100
    ) -> List[Execution]:
        """List executions with optional filters."""
        query = db.query(Execution)
        if test_case_id:
            query = query.filter(Execution.test_case_id == test_case_id)
        if oracle_status:
            query = query.filter(Execution.oracle_status == oracle_status.value)
        return query.order_by(Execution.created_at.desc()).offset(skip).limit(limit).all()

    @staticmethod
    def get_execution(db: Session, execution_id: int) -> Execution:
        """Get execution by ID."""
        execution = db.query(Execution).filter(Execution.id == execution_id).first()
        if not execution:
            raise ValueError(f"Execution {execution_id} not found")
        return execution
