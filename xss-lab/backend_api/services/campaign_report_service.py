"""Campaign report generation service."""
import os
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
from sqlalchemy.orm import Session

from backend_api.models.experiment import Experiment
from backend_api.models.test_case import TestCase, TestCaseStatus
from backend_api.models.finding import Finding, Severity
from backend_api.models.endpoint import Endpoint
from backend_api.models.param import Param
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
                duration_str=duration_str
            )
            
            # Build HTML content
            html_content = CampaignReportService._build_html(
                experiment=experiment,
                findings=findings,
                total_cases=total_cases,
                completed_cases=completed_cases,
                failed_cases=failed_cases,
                sev_counts=sev_counts,
                duration_str=duration_str
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
    def _build_markdown(
        experiment: Experiment,
        findings: List[Finding],
        total_cases: int,
        completed_cases: int,
        failed_cases: int,
        sev_counts: Dict[str, int],
        duration_str: str
    ) -> str:
        target = experiment.target
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
| **Total Vulnerabilities Found** | **{len(findings)}** |

### Severity Breakdown
- **CRITICAL**: {sev_counts['critical']}
- **HIGH**: {sev_counts['high']}
- **MEDIUM**: {sev_counts['medium']}
- **LOW**: {sev_counts['low']}

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
            
            md += f"""### Finding {idx}: {finding.vuln_type.upper()} in {ep.method} {ep.url_pattern}
- **Severity**: **{sev_label}**
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
        duration_str: str
    ) -> str:
        target = experiment.target
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
                sev_badge = f'<span class="badge badge-{sev_val}">{sev_val.upper()}</span>'
                
                curl_cmd = ""
                if finding.poc_request and isinstance(finding.poc_request, dict):
                    curl_cmd = finding.poc_request.get("command", "")

                report_markdown_body = finding.report_text or "No detailed report text available."
                report_html_body = CampaignReportService._markdown_to_html_simple(report_markdown_body)

                screenshot_element = ""
                if finding.screenshot_path:
                    # Resolve relative screenshot path from reports directory
                    screenshot_element = f"""
                    <div class="evidence-screenshot">
                        <h4>Evidence Screenshot</h4>
                        <img src="../{finding.screenshot_path}" alt="PoC Execution Screenshot" onclick="window.open(this.src)" />
                    </div>
                    """

                findings_html += f"""
                <div class="card finding-card">
                    <div class="finding-header">
                        <h3>Finding #{idx}: {finding.vuln_type.upper()} Vulnerability</h3>
                        {sev_badge}
                    </div>
                    <div class="finding-meta">
                        <div><strong>Endpoint:</strong> <code class="http-method">{ep.method}</code> <code>{ep.url_pattern}</code></div>
                        <div><strong>Parameter:</strong> <code>{param.name}</code> ({param.location})</div>
                        <div><strong>Context:</strong> <code>{context}</code></div>
                        <div><strong>Confidence:</strong> <code>{finding.confidence}</code></div>
                    </div>
                    
                    <div class="code-section">
                        <h4>Exploit Payload</h4>
                        <pre><code>{finding.best_payload}</code></pre>
                    </div>
                    
                    {f'''
                    <div class="code-section">
                        <h4>Curl Proof of Concept</h4>
                        <pre><code class="language-bash">{curl_cmd}</code></pre>
                    </div>
                    ''' if curl_cmd else ''}
                    
                    <div class="analysis-section">
                        <h4>Detailed Analysis</h4>
                        <div class="report-text">{report_html_body}</div>
                    </div>
                    
                    {screenshot_element}
                </div>
                """

        html = f"""<!DOCTYPE html>
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
            <div class="subtitle">Campaign #{experiment.id} &bull; {experiment.name}</div>
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
                    <span class="info-val" style="color: #f3f4f6; font-weight: 500;">{target.name}</span>
                </div>
                <div class="info-item">
                    <span class="info-lbl">Base URL:</span>
                    <span class="info-val"><a href="{target.base_url}" target="_blank" style="color: var(--primary); text-decoration: none;">{target.base_url}</a></span>
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
            </div>
        </section>

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
        return html

    @staticmethod
    def _markdown_to_html_simple(md: str) -> str:
        import re
        # 1. code blocks
        pattern_code_block = re.compile(r'```(?:[a-zA-Z0-9_-]+)?\n?(.*?)\n?```', re.DOTALL)
        def replace_code_block(match):
            content = match.group(1)
            content = content.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            return f'<pre><code>{content}</code></pre>'
        html = pattern_code_block.sub(replace_code_block, md)
        
        # 2. bold text
        pattern_bold = re.compile(r'\*\*(.*?)\*\*')
        html = pattern_bold.sub(r'<strong>\1</strong>', html)
        
        # 3. inline code
        pattern_code = re.compile(r'`([^`]+)`')
        html = pattern_code.sub(r'<code>\1</code>', html)
        
        # 4. newlines
        html = html.replace('\n', '<br>')
        return html

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
