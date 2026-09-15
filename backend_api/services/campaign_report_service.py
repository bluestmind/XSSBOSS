"""Campaign report generation service."""
import html
import os
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from backend_api.models.experiment import Experiment
from backend_api.models.test_case import TestCase, TestCaseStatus
from backend_api.models.finding import Finding, Severity
from backend_api.models.endpoint import Endpoint
from backend_api.models.param import Param
from backend_api.models.research import ResearchHypothesis, ResearchObservation
from backend_api.utils.logger import logger

class CampaignReportService:
    """Generates advanced, professional reports at the end of a scan campaign."""

    @staticmethod
    def get_findings_for_experiment(db: Session, experiment_id: int) -> List[Finding]:
        """Fetch all findings associated with test cases of this experiment."""
        test_case_ids = [tc_id for (tc_id,) in db.query(TestCase.id).filter(TestCase.experiment_id == experiment_id).all()]
        if not test_case_ids:
            return []
        
        all_findings = db.query(Finding).all()
        experiment_findings = []
        for finding in all_findings:
            ref = finding.evidence_refs or {}
            tc_id = ref.get("test_case_id")
            if tc_id in test_case_ids:
                experiment_findings.append(finding)
        return experiment_findings

    @staticmethod
    def generate_report(db: Session, experiment_id: int) -> Dict[str, Any]:
        """Compile campaign statistics and findings into markdown and HTML reports."""
        try:
            experiment = db.query(Experiment).filter(Experiment.id == experiment_id).first()
            if not experiment:
                logger.error(f"Experiment {experiment_id} not found for report generation")
                return {}

            # Gather findings
            findings = CampaignReportService.get_findings_for_experiment(db, experiment_id)
            
            # Gather stats
            total_cases = db.query(TestCase).filter(TestCase.experiment_id == experiment_id).count()
            completed_cases = db.query(TestCase).filter(
                TestCase.experiment_id == experiment_id, 
                TestCase.status == TestCaseStatus.COMPLETED
            ).count()
            failed_cases = db.query(TestCase).filter(
                TestCase.experiment_id == experiment_id, 
                TestCase.status == TestCaseStatus.FAILED
            ).count()
            research = CampaignReportService._research_snapshot(db, experiment_id)

            # Severities count
            sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for f in findings:
                sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity).lower()
                if sev in sev_counts:
                    sev_counts[sev] += 1
                else:
                    sev_counts["medium"] += 1  # Fallback

            # Duration calculation
            started_at = experiment.started_at
            completed_at = experiment.completed_at or datetime.utcnow()
            duration_str = "Unknown"
            if started_at:
                duration = completed_at - started_at
                hours, remainder = divmod(duration.total_seconds(), 3600)
                minutes, seconds = divmod(remainder, 60)
                duration_str = f"{int(hours)}h {int(minutes)}m {int(seconds)}s"

            # Create paths
            workspace_root = Path(__file__).resolve().parents[2]
            reports_dir = workspace_root / "reports"
            reports_dir.mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            md_filename = f"report_campaign_{experiment_id}_{timestamp}.md"
            html_filename = f"report_campaign_{experiment_id}_{timestamp}.html"
            
            md_path = reports_dir / md_filename
            html_path = reports_dir / html_filename

            # Build markdown content
            md_content = CampaignReportService._build_markdown(
                experiment=experiment,
                findings=findings,
                total_cases=total_cases,
                completed_cases=completed_cases,
                failed_cases=failed_cases,
                sev_counts=sev_counts,
                duration_str=duration_str,
                research=research,
            )
            
            # Build HTML content
            html_content = CampaignReportService._build_html(
                experiment=experiment,
                findings=findings,
                total_cases=total_cases,
                completed_cases=completed_cases,
                failed_cases=failed_cases,
                sev_counts=sev_counts,
                duration_str=duration_str,
                research=research,
            )

            # Write files
            md_path.write_text(md_content, encoding="utf-8")
            html_path.write_text(html_content, encoding="utf-8")

            logger.info(f"[+] Advanced reports generated for campaign #{experiment_id}:")
            logger.info(f"    - Markdown: {md_path}")
            logger.info(f"    - HTML: {html_path}")

            return {
                "markdown_path": str(md_path),
                "html_path": str(html_path),
                "findings_count": len(findings),
                "severity_counts": sev_counts
            }
        except Exception as e:
            logger.error(f"Failed to generate campaign report: {e}", exc_info=True)
            return {}

    @staticmethod
    def _research_snapshot(db: Session, experiment_id: int) -> Dict[str, Any]:
        hypotheses = db.query(ResearchHypothesis).filter_by(
            experiment_id=experiment_id
        ).order_by(ResearchHypothesis.priority.desc(), ResearchHypothesis.id).all()
        status_counts: Dict[str, int] = {}
        for hypothesis in hypotheses:
            status_counts[hypothesis.status] = status_counts.get(hypothesis.status, 0) + 1
        observation_count = db.query(ResearchObservation).join(ResearchHypothesis).filter(
            ResearchHypothesis.experiment_id == experiment_id
        ).count()
        return {
            "hypothesis_count": len(hypotheses),
            "observation_count": observation_count,
            "status_counts": status_counts,
            "top_hypotheses": [
                {
                    "title": row.title,
                    "type": row.hypothesis_type,
                    "status": row.status,
                    "confidence": float(row.confidence or 0.0),
                    "priority": float(row.priority or 0.0),
                    "techniques": list(row.technique_candidates or [])[:5],
                }
                for row in hypotheses[:8]
            ],
        }

    @staticmethod
    def _build_markdown(
        experiment: Experiment,
        findings: List[Finding],
        total_cases: int,
        completed_cases: int,
        failed_cases: int,
        sev_counts: Dict[str, int],
        duration_str: str,
        research: Optional[Dict[str, Any]] = None,
    ) -> str:
        research = research or {
            "hypothesis_count": 0, "observation_count": 0,
            "status_counts": {}, "top_hypotheses": [],
        }
        target = experiment.target
        limits = experiment.limits if isinstance(experiment.limits, dict) else {}
        coverage = limits.get("coverage") if isinstance(limits.get("coverage"), dict) else {}
        from backend_api.services.auth_session_service import AuthSessionService
        identity_count = len(AuthSessionService.identity_labels(target.auth_info)) if target.auth_info else 0
        open_interventions = len([
            item for item in limits.get("human_interventions", []) if item.get("status") == "open"
        ])
        started_str = experiment.started_at.strftime("%Y-%m-%d %H:%M:%S") if experiment.started_at else "N/A"
        completed_str = experiment.completed_at.strftime("%Y-%m-%d %H:%M:%S") if experiment.completed_at else "N/A"
        
        md = f"""# XSS Boss Scan Campaign Report
## Campaign Summary: #{experiment.id} - {experiment.name}

| Metric | Details |
| --- | --- |
| **Target Name** | {target.name} |
| **Target URL** | {target.base_url} |
| **Fuzzing Strategy** | {experiment.strategy.value} |
| **Campaign Status** | {experiment.status.value.upper()} |
| **Started At** | {started_str} |
| **Completed At** | {completed_str} |
| **Duration** | {duration_str} |
| **Total Test Cases** | {total_cases} ({completed_cases} completed, {failed_cases} failed) |
| **Authenticated Identities** | {identity_count} |
| **Endpoint Coverage** | {coverage.get('endpoint_coverage_percent', 'N/A')}% ({coverage.get('tested_endpoints', 0)}/{coverage.get('eligible_endpoints', 0)}) |
| **Completion Reason** | {(limits.get('done') or {}).get('reason', 'in progress')} |
| **Open Human Interventions** | {open_interventions} |
| **Total Vulnerabilities Found** | **{len(findings)}** |

### Severity Breakdown
- **CRITICAL**: {sev_counts['critical']}
- **HIGH**: {sev_counts['high']}
- **MEDIUM**: {sev_counts['medium']}
- **LOW**: {sev_counts['low']}

---

## Autonomous Research Summary

- **Hypotheses generated**: {research['hypothesis_count']}
- **Evidence observations**: {research['observation_count']}
- **States**: {', '.join(f"{key}={value}" for key, value in sorted(research['status_counts'].items())) or 'none'}

"""
        if research["top_hypotheses"]:
            md += "| Priority | Confidence | Status | Hypothesis | Techniques |\n"
            md += "| ---: | ---: | --- | --- | --- |\n"
            for item in research["top_hypotheses"]:
                techniques = ", ".join(item["techniques"]) or "n/a"
                md += (
                    f"| {item['priority']:.1f} | {item['confidence']:.2f} | "
                    f"{item['status']} | {item['title']} | {techniques} |\n"
                )
        md += """

---

## Findings Details

"""
        if not findings:
            md += "No vulnerabilities were identified during this campaign.\n"
            return md

        for idx, finding in enumerate(findings, 1):
            ep = finding.endpoint
            param = finding.param
            context = finding.context.context_type if finding.context else "unknown context"
            sev_label = finding.severity.value.upper()
            from backend_api.utils.cvss_engine import CVSSEngine
            is_stored = "stored" in (finding.vuln_type or "").lower()
            is_high = sev_label in ("HIGH", "CRITICAL")
            cvss_info = CVSSEngine.score_xss_finding(
                is_stored=is_stored,
                can_hijack_session=is_high,
                can_modify_state=is_high
            )
            
            md += f"""### Finding {idx}: {finding.vuln_type.upper()} in {ep.method} {ep.url_pattern}
- **Severity**: **{sev_label}** (CVSS 3.1: **{cvss_info['score']} {cvss_info['severity']}**)
- **CVSS Vector**: `{cvss_info['vector']}`
- **Vulnerable Parameter**: `{param.name}` ({param.location})
- **Reflection Context**: `{context}`
- **Scanner Module**: `{finding.scanner_module}`
- **Confidence**: `{finding.confidence}`

#### Best Payload:
```html
{finding.best_payload}
```

"""
            if finding.poc_request and isinstance(finding.poc_request, dict):
                curl_cmd = finding.poc_request.get("command", "")
                if curl_cmd:
                    md += f"""#### Curl Proof of Concept:
```bash
{curl_cmd}
```
"""
            if finding.evidence_summary:
                md += f"""#### Evidence Summary:
{finding.evidence_summary}

"""
            if finding.report_text:
                md += f"""#### Detailed Analysis & Impact:
{finding.report_text}

"""
            md += "---\n\n"
        return md

    @staticmethod
    def _build_html(
        experiment: Experiment,
        findings: List[Finding],
        total_cases: int,
        completed_cases: int,
        failed_cases: int,
        sev_counts: Dict[str, int],
        duration_str: str,
        research: Optional[Dict[str, Any]] = None,
    ) -> str:
        research = research or {
            "hypothesis_count": 0, "observation_count": 0,
            "status_counts": {}, "top_hypotheses": [],
        }
        target = experiment.target
        limits = experiment.limits if isinstance(experiment.limits, dict) else {}
        coverage = limits.get("coverage") if isinstance(limits.get("coverage"), dict) else {}
        from backend_api.services.auth_session_service import AuthSessionService
        identity_count = len(AuthSessionService.identity_labels(target.auth_info)) if target.auth_info else 0
        open_interventions = len([
            item for item in limits.get("human_interventions", []) if item.get("status") == "open"
        ])
        started_str = experiment.started_at.strftime("%Y-%m-%d %H:%M:%S") if experiment.started_at else "N/A"
        completed_str = experiment.completed_at.strftime("%Y-%m-%d %H:%M:%S") if experiment.completed_at else "N/A"
        
        findings_html = ""
        if not findings:
            findings_html = """
            <div class="no-findings">
                <h3>No Vulnerabilities Found</h3>
                <p>The fuzzing campaign did not trigger any out-of-band or in-browser security sinks.</p>
            </div>
            """
        else:
            for idx, finding in enumerate(findings, 1):
                ep = finding.endpoint
                param = finding.param
                context = finding.context.context_type if finding.context else "unknown context"
                sev_val = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity).lower()
                sev_badge = f'<span class="badge badge-{sev_val}">{html.escape(sev_val.upper())}</span>'
                
                curl_cmd = ""
                if finding.poc_request and isinstance(finding.poc_request, dict):
                    curl_cmd = finding.poc_request.get("command", "")

                report_markdown_body = finding.report_text or "No detailed report text available."
                report_html_body = CampaignReportService._markdown_to_html_simple(report_markdown_body)

                screenshot_element = ""
                if finding.screenshot_path:
                    screenshot_url = f"/api/v1/results/findings/{finding.id}/screenshot"
                    screenshot_element = f"""
                    <div class="evidence-screenshot">
                        <h4>Evidence Screenshot</h4>
                        <img src="{screenshot_url}" alt="PoC Execution Screenshot" onclick="window.open(this.src)" />
                    </div>
                    """

                escaped_payload = html.escape(finding.best_payload or "")
                escaped_curl = html.escape(curl_cmd)

                findings_html += f"""
                <div class="card finding-card">
                    <div class="finding-header">
                        <h3>Finding #{idx}: {html.escape((finding.vuln_type or 'unknown').upper())} Vulnerability</h3>
                        {sev_badge}
                    </div>
                    <div class="finding-meta">
                        <div><strong>Endpoint:</strong> <code class="http-method">{html.escape(ep.method if ep else "GET")}</code> <code>{html.escape(ep.url_pattern if ep else "n/a")}</code></div>
                        <div><strong>Parameter:</strong> <code>{html.escape(param.name if param else "n/a")}</code> ({html.escape(param.location if param else "n/a")})</div>
                        <div><strong>Context:</strong> <code>{html.escape(context)}</code></div>
                        <div><strong>Confidence:</strong> <code>{html.escape(str(finding.confidence))}</code></div>
                    </div>
                    
                    <div class="code-section">
                        <h4>Exploit Payload</h4>
                        <pre><code>{escaped_payload}</code></pre>
                    </div>
                    
                    {f'''
                    <div class="code-section">
                        <h4>Curl Proof of Concept</h4>
                        <pre><code class="language-bash">{escaped_curl}</code></pre>
                    </div>
                    ''' if curl_cmd else ''}
                    
                    <div class="analysis-section">
                        <h4>Detailed Analysis</h4>
                        <div class="report-text">{report_html_body}</div>
                    </div>
                    
                    {screenshot_element}
                </div>
                """

        research_rows = "".join(
            "<tr>"
            f"<td>{item['priority']:.1f}</td>"
            f"<td>{item['confidence']:.2f}</td>"
            f"<td>{html.escape(item['status'])}</td>"
            f"<td>{html.escape(item['title'])}</td>"
            f"<td>{html.escape(', '.join(item['techniques']) or 'n/a')}</td>"
            "</tr>"
            for item in research["top_hypotheses"]
        )
        research_html = f"""
        <section class="campaign-info">
            <h2 class="section-title">Autonomous Research</h2>
            <p>{research['hypothesis_count']} hypotheses &bull; {research['observation_count']} evidence observations</p>
            <div style="overflow-x:auto; margin-top:16px;">
                <table style="width:100%; border-collapse:collapse;">
                    <thead><tr><th>Priority</th><th>Confidence</th><th>Status</th><th>Hypothesis</th><th>Techniques</th></tr></thead>
                    <tbody>{research_rows or '<tr><td colspan="5">No research hypotheses generated.</td></tr>'}</tbody>
                </table>
            </div>
        </section>
        """

        html_document = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSS Boss Campaign Report - #{experiment.id}</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Outfit:wght@400;600;800&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-primary: #0b0f17;
            --bg-secondary: #131924;
            --bg-card: #1b2333;
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            --primary: #6366f1;
            --primary-glow: rgba(99, 102, 241, 0.15);
            --border: #2d3748;
            --critical: #ef4444;
            --high: #ec4899;
            --medium: #f59e0b;
            --low: #10b981;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            background-color: var(--bg-primary);
            color: var(--text-primary);
            font-family: 'Inter', sans-serif;
            line-height: 1.6;
            padding: 40px 20px;
        }}

        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}

        header {{
            margin-bottom: 40px;
            border-bottom: 1px solid var(--border);
            padding-bottom: 20px;
        }}

        h1, h2, h3, h4 {{
            font-family: 'Outfit', sans-serif;
            color: var(--text-primary);
        }}

        h1 {{
            font-size: 2.5rem;
            font-weight: 800;
            background: linear-gradient(135deg, #a78bfa, #6366f1);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }}

        .subtitle {{
            color: var(--text-secondary);
            font-size: 1.1rem;
        }}

        .grid-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}

        .card {{
            background-color: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            transition: transform 0.2s, box-shadow 0.2s;
        }}

        .card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
        }}

        .stat-card {{
            text-align: center;
        }}

        .stat-val {{
            font-size: 2rem;
            font-weight: 700;
            font-family: 'Outfit', sans-serif;
            color: var(--primary);
            margin: 8px 0;
        }}

        .stat-lbl {{
            color: var(--text-secondary);
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        .campaign-info {{
            background-color: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 40px;
        }}

        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 16px;
        }}

        .info-item {{
            display: flex;
            justify-content: space-between;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            padding-bottom: 8px;
        }}

        .info-item:last-child {{
            border-bottom: none;
        }}

        .info-lbl {{
            color: var(--text-secondary);
            font-weight: 500;
        }}

        .info-val {{
            font-family: 'Fira Code', monospace;
            font-size: 0.95rem;
        }}

        .section-title {{
            font-size: 1.75rem;
            margin-bottom: 24px;
            border-left: 4px solid var(--primary);
            padding-left: 12px;
        }}

        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        .badge-critical {{ background-color: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }}
        .badge-high {{ background-color: rgba(236, 72, 153, 0.2); color: var(--high); border: 1px solid var(--high); }}
        .badge-medium {{ background-color: rgba(245, 158, 11, 0.2); color: var(--medium); border: 1px solid var(--medium); }}
        .badge-low {{ background-color: rgba(16, 185, 129, 0.2); color: var(--low); border: 1px solid var(--low); }}

        .finding-card {{
            margin-bottom: 30px;
            border-left: 4px solid var(--primary);
        }}

        .finding-card:has(.badge-critical) {{ border-left-color: var(--critical); }}
        .finding-card:has(.badge-high) {{ border-left-color: var(--high); }}
        .finding-card:has(.badge-medium) {{ border-left-color: var(--medium); }}
        .finding-card:has(.badge-low) {{ border-left-color: var(--low); }}

        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
        }}

        .finding-meta {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 12px;
            background-color: rgba(255, 255, 255, 0.02);
            padding: 16px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 0.9rem;
            border: 1px solid rgba(255, 255, 255, 0.05);
        }}

        code {{
            font-family: 'Fira Code', monospace;
            background-color: rgba(255, 255, 255, 0.08);
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.9em;
        }}

        .http-method {{
            color: #818cf8;
            font-weight: 600;
        }}

        .code-section {{
            margin-bottom: 20px;
        }}

        .code-section h4 {{
            font-size: 1rem;
            margin-bottom: 8px;
            color: var(--text-secondary);
        }}

        pre {{
            background-color: #0d1117;
            padding: 16px;
            border-radius: 8px;
            overflow-x: auto;
            border: 1px solid var(--border);
        }}

        pre code {{
            background-color: transparent;
            padding: 0;
            color: #ff7b72;
        }}

        pre code.language-bash {{
            color: #c9d1d9;
        }}

        .analysis-section {{
            margin-bottom: 20px;
        }}

        .analysis-section h4 {{
            font-size: 1rem;
            margin-bottom: 8px;
            color: var(--text-secondary);
        }}

        .report-text {{
            background-color: rgba(255, 255, 255, 0.01);
            padding: 16px;
            border-radius: 8px;
            border: 1px solid rgba(255, 255, 255, 0.05);
            font-size: 0.95rem;
            color: #d1d5db;
        }}

        .evidence-screenshot {{
            margin-top: 20px;
        }}

        .evidence-screenshot h4 {{
            font-size: 1rem;
            margin-bottom: 8px;
            color: var(--text-secondary);
        }}

        .evidence-screenshot img {{
            max-width: 100%;
            border-radius: 8px;
            border: 1px solid var(--border);
            cursor: zoom-in;
            transition: opacity 0.2s;
        }}

        .evidence-screenshot img:hover {{
            opacity: 0.9;
        }}

        .no-findings {{
            text-align: center;
            padding: 60px 20px;
            background-color: var(--bg-card);
            border-radius: 12px;
            border: 1px dashed var(--border);
        }}

        .no-findings h3 {{
            font-size: 1.5rem;
            margin-bottom: 8px;
            color: var(--low);
        }}

        .no-findings p {{
            color: var(--text-secondary);
        }}

        footer {{
            text-align: center;
            margin-top: 60px;
            color: var(--text-secondary);
            font-size: 0.875rem;
            border-top: 1px solid var(--border);
            padding-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>XSS Boss Campaign Report</h1>
            <div class="subtitle">Campaign #{experiment.id} &bull; {html.escape(experiment.name or '')}</div>
        </header>

        <section class="grid-stats">
            <div class="card stat-card">
                <div class="stat-lbl">Total Findings</div>
                <div class="stat-val" style="color: {var_total_color(len(findings))}">{len(findings)}</div>
                <div class="stat-lbl">Confirmed Vulns</div>
            </div>
            <div class="card stat-card">
                <div class="stat-lbl">Critical / High</div>
                <div class="stat-val" style="color: var(--critical)">{sev_counts['critical'] + sev_counts['high']}</div>
                <div class="stat-lbl">Exploitable</div>
            </div>
            <div class="card stat-card">
                <div class="stat-lbl">Test Cases</div>
                <div class="stat-val">{total_cases}</div>
                <div class="stat-lbl">{completed_cases} Executed</div>
            </div>
            <div class="card stat-card">
                <div class="stat-lbl">Scan Duration</div>
                <div class="stat-val" style="font-size: 1.5rem; line-height: 2rem; margin: 12px 0;">{duration_str}</div>
                <div class="stat-lbl">Elapsed Time</div>
            </div>
        </section>

        <section class="campaign-info">
            <h3 style="margin-bottom: 16px;">Campaign Specifications</h3>
            <div class="info-grid">
                <div class="info-item">
                    <span class="info-lbl">Target Program:</span>
                    <span class="info-val" style="color: #f3f4f6; font-weight: 500;">{html.escape(target.name or "")}</span>
                </div>
                <div class="info-item">
                    <span class="info-lbl">Base URL:</span>
                    <span class="info-val"><a href="{html.escape(target.base_url or '', quote=True)}" target="_blank" rel="noopener noreferrer" style="color: var(--primary); text-decoration: none;">{html.escape(target.base_url or '')}</a></span>
                </div>
                <div class="info-item">
                    <span class="info-lbl">Fuzzing Strategy:</span>
                    <span class="info-val">{experiment.strategy.value}</span>
                </div>
                <div class="info-item">
                    <span class="info-lbl">Started At:</span>
                    <span class="info-val">{started_str}</span>
                </div>
                <div class="info-item">
                    <span class="info-lbl">Completed At:</span>
                    <span class="info-val">{completed_str}</span>
                </div>
                <div class="info-item">
                    <span class="info-lbl">Status:</span>
                    <span class="info-val" style="color: {var_status_color(experiment.status.value)}; font-weight: 600;">{experiment.status.value.upper()}</span>
                </div>
                <div class="info-item">
                    <span class="info-lbl">Authenticated Identities:</span>
                    <span class="info-val">{identity_count}</span>
                </div>
                <div class="info-item">
                    <span class="info-lbl">Endpoint Coverage:</span>
                    <span class="info-val">{coverage.get('endpoint_coverage_percent', 'N/A')}% ({coverage.get('tested_endpoints', 0)}/{coverage.get('eligible_endpoints', 0)})</span>
                </div>
                <div class="info-item">
                    <span class="info-lbl">Completion Reason:</span>
                    <span class="info-val">{html.escape(str((limits.get('done') or {}).get('reason', 'in progress')))}</span>
                </div>
                <div class="info-item">
                    <span class="info-lbl">Open Interventions:</span>
                    <span class="info-val">{open_interventions}</span>
                </div>
            </div>
        </section>

        {research_html}

        <section>
            <h2 class="section-title">Findings and PoC Showcase</h2>
            {findings_html}
        </section>

        <footer>
            <p>Generated automatically by XSS Boss &bull; {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </footer>
    </div>
</body>
</html>
"""
        return html_document

    @staticmethod
    def _markdown_to_html_simple(md: str) -> str:
        import re
        import html as html_lib

        # 1. Stash and escape code blocks
        pattern_code_block = re.compile(r'```(?:[a-zA-Z0-9_-]+)?\n?(.*?)\n?```', re.DOTALL)
        code_blocks = []
        def stash_code_block(match):
            idx = len(code_blocks)
            code_blocks.append(f'<pre><code>{html_lib.escape(match.group(1))}</code></pre>')
            return f"__CB_{idx}__"
        text = pattern_code_block.sub(stash_code_block, md)

        # 2. Stash and escape inline code
        inline_codes = []
        def stash_inline_code(match):
            idx = len(inline_codes)
            inline_codes.append(f'<code>{html_lib.escape(match.group(1))}</code>')
            return f"__IC_{idx}__"
        text = re.sub(r'`([^`]+)`', stash_inline_code, text)

        # 3. Escape raw HTML in prose
        text = html_lib.escape(text)

        # 4. Apply markdown bold formatting
        text = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', text)
        text = text.replace('\n', '<br>')

        # 5. Restore stashed blocks
        for idx, cb in enumerate(code_blocks):
            text = text.replace(f"__CB_{idx}__", cb)
        for idx, ic in enumerate(inline_codes):
            text = text.replace(f"__IC_{idx}__", ic)

        return text

def var_total_color(cnt: int) -> str:
    if cnt > 0:
        return "var(--critical)"
    return "var(--low)"

def var_status_color(status: str) -> str:
    s = status.lower()
    if s == "completed":
        return "var(--low)"
    if s == "running":
        return "var(--primary)"
    return "var(--medium)"
