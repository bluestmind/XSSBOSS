#!/usr/bin/env python3
"""
XSS Boss Unified CLI Interface.
A professional command-line auditing tool for targets, scanning, and finding management.
Supports both direct CLI arguments and an interactive selection menu mode.
"""
from __future__ import annotations

import os
import sys
import click
import json
import socket
from pathlib import Path
from datetime import UTC, datetime
from colorama import init, Fore, Style

# Initialize colorama
init()

# Ensure utf-8 encoding on stdout/stderr for Windows console
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Ensure workspace root is in python path
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

# Set default Database URL and eager execution for standalone CLI
os.environ.setdefault("DATABASE_URL", f"sqlite:///{ROOT / 'xssboss.db'}")
os.environ.setdefault("CELERY_TASK_ALWAYS_EAGER", "True")
DEFAULT_PROFILE_PATH = str(Path.home() / ".xssboss" / "browser_profile")

from backend_api.db.base import init_db, SessionLocal
# Auto-initialize database tables at startup
init_db()
from backend_api.models.target import Target, TargetStatus
from backend_api.models.experiment import Experiment, ExperimentStatus, ExperimentStrategy
from backend_api.models.finding import Finding, Severity, FindingStatus
from backend_api.models.endpoint import Endpoint
from backend_api.models.param import Param
from backend_api.services.program_import_service import ProgramImportService
from backend_api.services.fuzzing_service import FuzzingService
from backend_api.schemas.program_import import ProgramImportRequest
from fuzzer.payload_knowledge_base import PayloadKnowledgeBase, XSSCategory, InjectionContext
from fuzzer.autonomous_xss_brain import AutonomousXSSBrain
from recon_engine.modern_recon_hub import ModernReconHub
from recon_engine.framework_harvester import FrameworkHarvester
from recon_engine.api_discovery import APIDiscovery
from recon_engine.sourcemap_analyzer import SourceMapAnalyzer
from analysis_engine.enhanced_context_classifier import EnhancedContextClassifier, ClassifiedContext
from analysis_engine.filter_profiler import FilterProfiler, FilterProfile

BANNER = f"""{Fore.RED}{Style.BRIGHT}
__   _____ ___ ___  ___   ___  ___ ___ 
\\ \\ / / __/ __/ __| | _ ) / _ \\/ __/ __|
 \\ V /\\__ \\__ \\__ \\ | _ \\| (_) \\__ \\__ \\
  \\_/ |___/___/___/ |___/ \\___/|___/___/
{Style.RESET_ALL}{Fore.YELLOW}              [ Professional XSS Fuzzing Suite ]{Style.RESET_ALL}
"""

def print_table(headers: list[str], rows: list[list[any]], color_mappers: dict[int, callable] = None) -> None:
    if not rows:
        click.echo(f"{Fore.YELLOW}No entries found.{Style.RESET_ALL}")
        return
        
    str_rows = [[str(cell) for cell in row] for row in rows]
    widths = [len(h) for h in headers]
    for row in str_rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
            
    # Print headers
    header_line = " | ".join(f"{h:<{widths[i]}}" for i, h in enumerate(headers))
    click.echo(f"{Fore.CYAN}{Style.BRIGHT}{header_line}{Style.RESET_ALL}")
    click.echo(Fore.BLUE + "-" * (sum(widths) + 3 * (len(headers) - 1)) + Style.RESET_ALL)
    
    # Print rows
    for row in str_rows:
        row_str = []
        for i, cell in enumerate(row):
            cell_color = Fore.WHITE
            if color_mappers and i in color_mappers:
                cell_color = color_mappers[i](cell)
            row_str.append(f"{cell_color}{cell:<{widths[i]}}{Style.RESET_ALL}")
        click.echo(" | ".join(row_str))

def get_severity_color(val: str) -> str:
    s = val.lower()
    if "critical" in s:
        return Fore.RED + Style.BRIGHT
    if "high" in s:
        return Fore.MAGENTA + Style.BRIGHT
    if "medium" in s:
        return Fore.YELLOW
    return Fore.GREEN

def get_status_color(val: str) -> str:
    st = val.lower()
    if st in ["running", "fuzzing"]:
        return Fore.BLUE + Style.BRIGHT
    if st in ["completed", "done"]:
        return Fore.GREEN
    if st == "failed":
        return Fore.RED + Style.BRIGHT
    if st == "pending":
        return Fore.CYAN
    return Fore.WHITE

def is_port_open(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(('127.0.0.1', port)) == 0

# --- SHARED DOMAIN LOGIC ---

def list_targets_internal() -> None:
    db = SessionLocal()
    try:
        targets = db.query(Target).all()
        rows = []
        for t in targets:
            findings_count = db.query(Finding).join(Endpoint).filter(Endpoint.target_id == t.id).count()
            endpoints_count = db.query(Endpoint).filter(Endpoint.target_id == t.id).count()
            rows.append([t.id, t.name, t.base_url, t.bounty_platform or "custom", t.status.value, endpoints_count, findings_count])
            
        print_table(
            ["ID", "Name", "Base URL", "Platform", "Status", "Endpoints", "Findings"],
            rows,
            color_mappers={
                4: get_status_color,
                6: lambda x: Fore.RED + Style.BRIGHT if int(x) > 0 else Fore.GREEN
            }
        )
    finally:
        db.close()

def add_target_internal(name: str, url: str, notes: str) -> None:
    db = SessionLocal()
    try:
        t = Target(name=name, base_url=url, notes=notes, status=TargetStatus.RECON_ONLY)
        db.add(t)
        db.commit()
        db.refresh(t)
        click.echo(f"{Fore.GREEN}[+] Target '{name}' created successfully with ID: {t.id}{Style.RESET_ALL}")
    finally:
        db.close()

def import_target_internal(platform: str, slug: str, profile_path: str) -> None:
    init_db()
    request = ProgramImportRequest(
        platforms=[platform],
        handles=[slug] if platform == "hackerone" else [],
        slugs=[slug] if platform == "yeswehack" else [],
        limit_per_platform=1,
        max_scopes_per_program=100,
        yeswehack_types=["bug-bounty", "vdp", "pentest", "vdp-in-app"],
        update_existing=True,
        dry_run=False,
        browser_profile_path=profile_path,
        browser_profile_name="Default",
    )
    
    db = SessionLocal()
    try:
        click.echo(f"{Fore.CYAN}[*] Fetching and parsing rules for {slug} on {platform}...{Style.RESET_ALL}")
        result = ProgramImportService(db).import_programs(request)
        if result.get("errors"):
            for err in result["errors"]:
                click.echo(f"{Fore.RED}[-] Error importing: {err['message']}{Style.RESET_ALL}")
        else:
            imported = result.get("imported", 0)
            click.echo(f"{Fore.GREEN}[+] Import completed! Imported/Updated {imported} targets.{Style.RESET_ALL}")
    finally:
        db.close()

def crawl_target_internal(target_id: int, max_depth: int = 3, max_pages: int = 100) -> None:
    db = SessionLocal()
    try:
        t = db.query(Target).filter(Target.id == target_id).first()
        if not t:
            click.echo(f"{Fore.RED}[-] Target ID {target_id} not found.{Style.RESET_ALL}")
            return
            
        click.echo(f"{Fore.CYAN}[*] Running Selenium crawler for target: {t.name} ({t.base_url})...{Style.RESET_ALL}")
        
        from recon_engine.crawler import Crawler
        crawler = Crawler(base_url=t.base_url, max_depth=max_depth, max_pages=max_pages)
        count = crawler.crawl_to_database(target_id, db)
        click.echo(f"{Fore.GREEN}[+] Crawl finished! Discovered and added {count} endpoints and parameters.{Style.RESET_ALL}")
    finally:
        db.close()

def start_scan_internal(target_id: int, strategy: str) -> None:
    db = SessionLocal()
    try:
        target = db.query(Target).filter(Target.id == target_id).first()
        if not target:
            click.echo(f"{Fore.RED}[-] Target ID {target_id} not found.{Style.RESET_ALL}")
            return
            
        # Verify Oracle callback port
        if not is_port_open(8001):
            click.echo(f"{Fore.YELLOW}[!] Warning: Oracle Callback server (port 8001) is not running.{Style.RESET_ALL}")
            click.echo(f"{Fore.YELLOW}[!] Out-of-band XSS callback payloads will NOT trigger alerts.{Style.RESET_ALL}")
            if not click.confirm("Do you want to continue the scan anyway?"):
                return

        # Check endpoints count
        endpoints_count = db.query(Endpoint).filter(Endpoint.target_id == target_id).count()
        if endpoints_count == 0:
            click.echo(f"{Fore.RED}[-] Error: Target '{target.name}' has 0 endpoints.{Style.RESET_ALL}")
            click.echo(f"{Fore.YELLOW}[!] You must run target crawler or sync Burp traffic first before fuzzing!{Style.RESET_ALL}")
            if not click.confirm("Launch scan anyway?"):
                return
            
        click.echo(f"{Fore.CYAN}[*] Initializing audit campaign for target: {target.name} ({target.base_url}){Style.RESET_ALL}")
        click.echo(f"{Fore.CYAN}[*] Strategy: {strategy}{Style.RESET_ALL}")
        
        exp = Experiment(
            target_id=target_id,
            name=f"CLI Audit Campaign - {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            strategy=ExperimentStrategy(strategy),
            status=ExperimentStatus.RUNNING,
            started_at=datetime.now(UTC)
        )
        db.add(exp)
        db.commit()
        db.refresh(exp)
        
        click.echo(f"{Fore.GREEN}[+] Scan Campaign created with ID: {exp.id}{Style.RESET_ALL}")
        click.echo(f"{Fore.YELLOW}[*] Deploying River-to-Sea audit pipeline... (Press Ctrl+C to pause/abort){Style.RESET_ALL}\n")
        
        def cli_progress_callback(phase: str, message: str, doing_status: str = None, micro_state: dict = None, river_stage: str = None):
            symbols = {
                "springs": f"{Fore.CYAN}[The Springs]{Style.RESET_ALL}",
                "recon": f"{Fore.BLUE}[Recon Rapids]{Style.RESET_ALL}",
                "params": f"{Fore.MAGENTA}[Param Tributaries]{Style.RESET_ALL}",
                "contexts": f"{Fore.YELLOW}[Context Confluence]{Style.RESET_ALL}",
                "filters": f"{Fore.MAGENTA}[Filter Channels]{Style.RESET_ALL}",
                "auditors": f"{Fore.CYAN}[Auditor Cascades]{Style.RESET_ALL}",
                "browser": f"{Fore.BLUE}[Browser Whirlpool]{Style.RESET_ALL}",
                "sea": f"{Fore.GREEN}[Sea of Findings]{Style.RESET_ALL}",
            }
            stage_sym = symbols.get(river_stage or phase, f"{Fore.CYAN}[{phase.upper()}]{Style.RESET_ALL}")
            active_doing = doing_status or message
            click.echo(f"  {stage_sym} {active_doing}")

        fuzzer = FuzzingService(db)
        fuzzer.run_experiment(exp.id, progress_callback=cli_progress_callback)
        
        db.refresh(exp)
        if exp.status == ExperimentStatus.COMPLETED:
            click.echo(f"\n{Fore.GREEN}[+] Scan Campaign #{exp.id} completed successfully!{Style.RESET_ALL}")
        else:
            click.echo(f"\n{Fore.YELLOW}[*] Scan Campaign #{exp.id} finished with status: {exp.status.value}{Style.RESET_ALL}")
            
    except KeyboardInterrupt:
        click.echo(f"\n{Fore.YELLOW}[!] Audit campaign interrupted. Pausing...{Style.RESET_ALL}")
    finally:
        db.close()

def list_scans_internal() -> None:
    db = SessionLocal()
    try:
        experiments = db.query(Experiment).order_by(Experiment.id.desc()).all()
        rows = []
        for e in experiments:
            started = e.started_at.strftime('%Y-%m-%d %H:%M') if e.started_at else "pending"
            rows.append([e.id, e.target.name, e.strategy.value, e.status.value, started])
            
        print_table(
            ["ID", "Target", "Strategy", "Status", "Started At"],
            rows,
            color_mappers={
                3: get_status_color
            }
        )
    finally:
        db.close()

def list_findings_internal() -> None:
    db = SessionLocal()
    try:
        findings = db.query(Finding).all()
        rows = []
        for f in findings:
            rows.append([
                f.id,
                f.endpoint.target.name,
                f.severity.value,
                f.endpoint.method,
                f.endpoint.url_pattern,
                f.param.name,
                f.best_payload[:40]
            ])
            
        print_table(
            ["ID", "Target", "Severity", "Method", "Endpoint Pattern", "Param", "Payload"],
            rows,
            color_mappers={
                2: get_severity_color
            }
        )
    finally:
        db.close()

def view_finding_details(f: Finding) -> None:
    click.echo(f"\n{Fore.CYAN}{Style.BRIGHT}=== Finding #{f.id} details ==={Style.RESET_ALL}")
    click.echo(f"{Fore.WHITE}Target:       {Fore.YELLOW}{f.endpoint.target.name}")
    click.echo(f"{Fore.WHITE}Severity:     {get_severity_color(f.severity.value)}{f.severity.value.upper()}")
    click.echo(f"{Fore.WHITE}Method:       {Fore.GREEN}{f.endpoint.method}")
    click.echo(f"{Fore.WHITE}URL Pattern:  {Fore.GREEN}{f.endpoint.url_pattern}")
    click.echo(f"{Fore.WHITE}Parameter:    {Fore.YELLOW}{f.param.name} ({f.param.location})")
    click.echo(f"{Fore.WHITE}Payload:      {Fore.RED}{Style.BRIGHT}{f.best_payload}{Style.RESET_ALL}")
    click.echo(f"{Fore.WHITE}Status:       {get_status_color(f.status.value)}{f.status.value.upper()}{Style.RESET_ALL}")
    
    if f.screenshot_path:
        click.echo(f"{Fore.WHITE}Screenshot:   {Fore.BLUE}{f.screenshot_path}{Style.RESET_ALL}")
        
    if f.poc_request:
        click.echo(f"\n{Fore.CYAN}=== HTTP Request PoC ==={Style.RESET_ALL}")
        req = f.poc_request
        method = req.get("method", "GET")
        url = req.get("url", "")
        headers = req.get("headers", {})
        body = req.get("body", "")
        
        click.echo(f"{Fore.GREEN}{method} {url}{Style.RESET_ALL}")
        for k, v in headers.items():
            click.echo(f"{Fore.WHITE}{k}: {v}")
        if body:
            click.echo(f"\n{Fore.WHITE}{body}")
            
    if f.poc_html:
        click.echo(f"\n{Fore.CYAN}=== HTML PoC File content ==={Style.RESET_ALL}")
        click.echo(f.poc_html)

def system_status_internal() -> None:
    db = SessionLocal()
    try:
        targets_count = db.query(Target).count()
        findings_count = db.query(Finding).count()
        scans_count = db.query(Experiment).count()
        running_scans = db.query(Experiment).filter(Experiment.status == ExperimentStatus.RUNNING).count()
        kb_stats = PayloadKnowledgeBase.get_summary_statistics()
        
        click.echo(f"\n{Fore.CYAN}=== XSS Boss System Status ==={Style.RESET_ALL}")
        click.echo(f"{Fore.WHITE}Total Targets in DB:       {Fore.GREEN}{targets_count}")
        click.echo(f"{Fore.WHITE}Total Scan Campaigns:      {Fore.GREEN}{scans_count}")
        click.echo(f"{Fore.WHITE}Active running scans:      {Fore.BLUE}{running_scans}")
        click.echo(f"{Fore.WHITE}Total Confirmed Findings:  {Fore.RED if findings_count > 0 else Fore.GREEN}{findings_count}{Style.RESET_ALL}")
        click.echo(f"{Fore.WHITE}Knowledge Base Vectors:    {Fore.MAGENTA}{kb_stats['total_payloads']} payloads across {len(kb_stats['categories'])} categories{Style.RESET_ALL}")
    finally:
        db.close()

def knowledge_explorer_internal(category_filter: str = None, framework_filter: str = None, waf_filter: str = None) -> None:
    """Explore the XSS Knowledge Base interactively."""
    entries = PayloadKnowledgeBase.get_all_payloads()
    if category_filter:
        entries = [e for e in entries if category_filter.lower() in e.category.value.lower()]
    if framework_filter:
        entries = [e for e in entries if any(framework_filter.lower() in f.lower() for f in e.frameworks)]
    if waf_filter:
        entries = [e for e in entries if any(waf_filter.lower() in w.lower() for w in e.bypasses_wafs)]

    rows = []
    for e in entries:
        rows.append([
            e.id,
            e.name[:30],
            e.category.value,
            e.template[:45],
            ", ".join(e.frameworks) if e.frameworks else "general",
            e.cvss_score
        ])

    click.echo(f"\n{Fore.CYAN}=== XSS Knowledge Base ({len(entries)} Payloads) ==={Style.RESET_ALL}")
    print_table(
        ["ID", "Name", "Category", "Template Preview", "Frameworks", "CVSS"],
        rows,
        color_mappers={
            2: lambda x: Fore.MAGENTA,
            5: lambda x: Fore.RED + Style.BRIGHT if float(x) >= 8.0 else Fore.YELLOW
        }
    )

def autonomous_brain_internal(context_str: str, token: str, waf: str = None, frameworks: str = None) -> None:
    """Invoke the Autonomous XSS Brain directly to synthesize payload chains."""
    brain = AutonomousXSSBrain()
    fw_list = [f.strip() for f in frameworks.split(",")] if frameworks else []
    filter_prof = {}
    if waf:
        filter_prof["waf_name"] = waf

    click.echo(f"\n{Fore.CYAN}[*] Synthesizing optimal XSS attack chain...{Style.RESET_ALL}")
    click.echo(f"    Context: {Fore.YELLOW}{context_str}{Style.RESET_ALL} | Token: {Fore.YELLOW}{token}{Style.RESET_ALL} | WAF: {Fore.YELLOW}{waf or 'None'}{Style.RESET_ALL}")
    
    report = brain.synthesize_attack_chain(
        context_type=context_str,
        token=token,
        filter_profile=filter_prof,
        frameworks=fw_list,
        max_payloads=10
    )

    click.echo(f"\n{Fore.GREEN}[+] Synthesized {report.total_candidates_synthesized} high-confidence candidate payload(s):{Style.RESET_ALL}")
    for i, dec in enumerate(report.top_payloads, 1):
        click.echo(f"\n [{Fore.YELLOW}{i}{Style.RESET_ALL}] Confidence: {Fore.GREEN}{int(dec.confidence_score*100)}%{Style.RESET_ALL} | Category: {Fore.MAGENTA}{dec.category.value}{Style.RESET_ALL}")
        click.echo(f"     Payload:   {Fore.RED}{Style.BRIGHT}{dec.payload}{Style.RESET_ALL}")
        click.echo(f"     Reasoning: {Fore.WHITE}{dec.reasoning}{Style.RESET_ALL}")

# --- INTERACTIVE CONTROL PANEL ---

def interactive_menu() -> None:
    click.clear()
    click.echo(BANNER)
    while True:
        click.echo(f"\n{Fore.CYAN}{Style.BRIGHT}=== XSS BOSS INTERACTIVE CONTROL PANEL ==={Style.RESET_ALL}")
        click.echo(f" [{Fore.YELLOW}1{Style.RESET_ALL}] List Targets")
        click.echo(f" [{Fore.YELLOW}2{Style.RESET_ALL}] Add Target Manually")
        click.echo(f" [{Fore.YELLOW}3{Style.RESET_ALL}] Import Target Program (YesWeHack/HackerOne)")
        click.echo(f" [{Fore.YELLOW}4{Style.RESET_ALL}] Crawl Target URL (Selenium Endpoint Discovery)")
        click.echo(f" [{Fore.YELLOW}5{Style.RESET_ALL}] Start XSS Scan Campaign")
        click.echo(f" [{Fore.YELLOW}6{Style.RESET_ALL}] List Scan Campaigns")
        click.echo(f" [{Fore.YELLOW}7{Style.RESET_ALL}] List Triaged Findings")
        click.echo(f" [{Fore.YELLOW}8{Style.RESET_ALL}] View Specific Finding PoC")
        click.echo(f" [{Fore.YELLOW}9{Style.RESET_ALL}] Knowledge Base Explorer (CSTI, DOM Clobbering, mXSS, Gadgets)")
        click.echo(f" [{Fore.YELLOW}10{Style.RESET_ALL}] Autonomous XSS Brain (AI Payload Synthesis)")
        click.echo(f" [{Fore.YELLOW}11{Style.RESET_ALL}] Show System Status")
        click.echo(f" [{Fore.YELLOW}0{Style.RESET_ALL}] Exit")
        
        choice = click.prompt(f"\n{Fore.GREEN}Select option{Style.RESET_ALL}", type=str, default="1")
        click.echo("")
        
        if choice == "1":
            list_targets_internal()
        elif choice == "2":
            name = click.prompt("Enter target name", type=str)
            url = click.prompt("Enter target base URL", type=str)
            notes = click.prompt("Enter optional notes", type=str, default="")
            add_target_internal(name, url, notes)
        elif choice == "3":
            platform = click.prompt("Enter platform", type=click.Choice(["yeswehack", "hackerone"]), default="yeswehack")
            slug = click.prompt(f"Enter {platform} slug or handle", type=str)
            profile_path = click.prompt("Chrome profile directory path", type=str, default=DEFAULT_PROFILE_PATH)
            import_target_internal(platform, slug, profile_path)
        elif choice == "4":
            db = SessionLocal()
            try:
                targets = db.query(Target).all()
                if not targets:
                    click.echo(f"{Fore.RED}[-] No targets configured yet.{Style.RESET_ALL}")
                    continue
                click.echo(f"{Fore.CYAN}--- Select a Target to Crawl ---{Style.RESET_ALL}")
                for i, t in enumerate(targets):
                    click.echo(f" [{Fore.YELLOW}{i+1}{Style.RESET_ALL}] ID: {t.id} - {t.name} ({t.base_url})")
                
                t_choice = click.prompt(f"Select target index (1-{len(targets)})", type=int, default=1)
                if t_choice < 1 or t_choice > len(targets):
                    click.echo(f"{Fore.RED}[-] Invalid target selection.{Style.RESET_ALL}")
                    continue
                selected_target = targets[t_choice - 1]
                max_depth = click.prompt("Enter crawl max depth", type=int, default=3)
                max_pages = click.prompt("Enter crawl max pages limit", type=int, default=100)
                crawl_target_internal(selected_target.id, max_depth, max_pages)
            finally:
                db.close()
        elif choice == "5":
            db = SessionLocal()
            try:
                targets = db.query(Target).all()
                if not targets:
                    click.echo(f"{Fore.RED}[-] No targets configured yet.{Style.RESET_ALL}")
                    continue
                click.echo(f"{Fore.CYAN}--- Select a Target to Scan ---{Style.RESET_ALL}")
                for i, t in enumerate(targets):
                    click.echo(f" [{Fore.YELLOW}{i+1}{Style.RESET_ALL}] ID: {t.id} - {t.name} ({t.base_url})")
                
                t_choice = click.prompt(f"Select target index (1-{len(targets)})", type=int, default=1)
                if t_choice < 1 or t_choice > len(targets):
                    click.echo(f"{Fore.RED}[-] Invalid target selection.{Style.RESET_ALL}")
                    continue
                selected_target = targets[t_choice - 1]
                
                strategies = [s.value for s in ExperimentStrategy]
                click.echo(f"\n{Fore.CYAN}--- Select Fuzzing Strategy ---{Style.RESET_ALL}")
                for i, s in enumerate(strategies):
                    click.echo(f" [{Fore.YELLOW}{i+1}{Style.RESET_ALL}] {s}")
                
                s_choice = click.prompt(f"Select strategy index (1-{len(strategies)})", type=int, default=1)
                if s_choice < 1 or s_choice > len(strategies):
                    click.echo(f"{Fore.RED}[-] Invalid strategy selection.{Style.RESET_ALL}")
                    continue
                selected_strategy = strategies[s_choice - 1]
                
                start_scan_internal(selected_target.id, selected_strategy)
            finally:
                db.close()
        elif choice == "6":
            list_scans_internal()
        elif choice == "7":
            list_findings_internal()
        elif choice == "8":
            db = SessionLocal()
            try:
                findings = db.query(Finding).all()
                if not findings:
                    click.echo(f"{Fore.YELLOW}[*] No findings available to view.{Style.RESET_ALL}")
                    continue
                click.echo(f"{Fore.CYAN}--- Select a Finding ---{Style.RESET_ALL}")
                for i, f in enumerate(findings):
                    click.echo(f" [{Fore.YELLOW}{i+1}{Style.RESET_ALL}] ID: {f.id} - {f.endpoint.target.name} | {f.endpoint.url_pattern} | Param: {f.param.name}")
                
                f_choice = click.prompt(f"Select finding index (1-{len(findings)})", type=int, default=1)
                if f_choice < 1 or f_choice > len(findings):
                    click.echo(f"{Fore.RED}[-] Invalid selection.{Style.RESET_ALL}")
                    continue
                selected_finding = findings[f_choice - 1]
                view_finding_details(selected_finding)
            finally:
                db.close()
        elif choice == "9":
            cat = click.prompt("Optional category filter (csti/dom_clobbering/mutation_xss/prototype_pollution/csp_bypass/waf_evasion/all)", default="all")
            category_filter = None if cat.lower() == "all" else cat
            knowledge_explorer_internal(category_filter=category_filter)
        elif choice == "10":
            ctx_str = click.prompt("Enter context (HTML_TEXT, ATTR_QUOTED, JS_STRING, JS_TEMPLATE_LITERAL, JSON_VALUE)", default="HTML_TEXT")
            token = click.prompt("Enter oracle token", default="XSS_CANARY_123")
            waf = click.prompt("Detected WAF (cloudflare, aws_waf, modsecurity, none)", default="none")
            waf_val = None if waf.lower() == "none" else waf
            autonomous_brain_internal(context_str=ctx_str, token=token, waf=waf_val)
        elif choice == "11":
            system_status_internal()
        elif choice == "0" or choice.lower() == "exit":
            click.echo(f"{Fore.YELLOW}Exiting interactive console. Goodbye!{Style.RESET_ALL}")
            sys.exit(0)
        else:
            click.echo(f"{Fore.RED}[-] Invalid selection.{Style.RESET_ALL}")
            
        click.prompt(f"\n{Fore.CYAN}Press Enter to return to main menu...{Style.RESET_ALL}", default="", show_default=False)
        click.clear()

# --- CLICK CLI SUBCOMMAND ROUTING ---

@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """XSS Boss - Professional XSS Vulnerability Auditing & Scanning CLI."""
    if ctx.invoked_subcommand is None:
        interactive_menu()

# --- TARGET COMMANDS ---
@cli.group()
def target():
    """Manage target programs and scopes."""
    pass

@target.command(name="list")
def list_targets():
    """List all configured targets."""
    click.echo(BANNER)
    list_targets_internal()

@target.command(name="add")
@click.option("--name", required=True, help="Name of the target program.")
@click.option("--url", required=True, help="Base/root URL of the target web app.")
@click.option("--notes", default="", help="Optional notes or context.")
def add_target(name, url, notes):
    """Add a custom target URL manually."""
    add_target_internal(name, url, notes)

@target.command(name="import")
@click.option("--platform", required=True, type=click.Choice(["hackerone", "yeswehack"]), help="Platform name.")
@click.option("--slug", required=True, help="YesWeHack slug or HackerOne handle.")
@click.option("--profile-path", default=DEFAULT_PROFILE_PATH, help="Chrome profile directory path.")
def import_target(platform, slug, profile_path):
    """Import target scope rules from HackerOne or YesWeHack."""
    import_target_internal(platform, slug, profile_path)

@target.command(name="crawl")
@click.option("--target-id", required=True, type=int, help="Target ID to crawl.")
@click.option("--max-depth", default=3, type=int, help="Maximum crawler depth.")
@click.option("--max-pages", default=100, type=int, help="Maximum pages to crawl.")
def crawl_target(target_id, max_depth, max_pages):
    """Crawl a target URL to discover endpoints and parameters."""
    click.echo(BANNER)
    crawl_target_internal(target_id, max_depth, max_pages)

# --- SCAN COMMANDS ---
@cli.group()
def scan():
    """Start and monitor scanning campaigns."""
    pass

@scan.command(name="start")
@click.option("--target-id", required=True, type=int, help="Target ID to audit.")
@click.option("--strategy", default="quick_light", type=click.Choice([s.value for s in ExperimentStrategy]), help="Fuzzing strategy profile.")
def start_scan(target_id, strategy):
    """Start an XSS fuzzing campaign against a target."""
    click.echo(BANNER)
    start_scan_internal(target_id, strategy)

@scan.command(name="list")
def list_scans():
    """List all previous and active scan campaigns."""
    list_scans_internal()

# --- FINDINGS COMMANDS ---
@cli.group()
def findings():
    """View and triage verified XSS vulnerabilities."""
    pass

@findings.command(name="list")
def list_findings():
    """List all confirmed XSS vulnerabilities."""
    list_findings_internal()

@findings.command(name="view")
@click.argument("finding_id", type=int)
def view_finding(finding_id):
    """View detailed information and Proof of Concept (PoC) for an XSS finding."""
    db = SessionLocal()
    try:
        f = db.query(Finding).filter(Finding.id == finding_id).first()
        if not f:
            click.echo(f"{Fore.RED}[-] Finding ID {finding_id} not found.{Style.RESET_ALL}")
            return
        click.echo(BANNER)
        view_finding_details(f)
    finally:
        db.close()

# --- KNOWLEDGE BASE COMMANDS ---
@cli.group()
def knowledge():
    """Query and explore the built-in XSS knowledge base."""
    pass

@knowledge.command(name="list")
@click.option("--category", default=None, help="Filter by category (csti, dom_clobbering, mutation_xss, etc.).")
@click.option("--framework", default=None, help="Filter by framework (angularjs, vue, react, etc.).")
@click.option("--waf", default=None, help="Filter by WAF (cloudflare, aws_waf, modsecurity, etc.).")
def list_knowledge(category, framework, waf):
    """List payloads in the knowledge base matching filters."""
    click.echo(BANNER)
    knowledge_explorer_internal(category_filter=category, framework_filter=framework, waf_filter=waf)

@knowledge.command(name="stats")
def knowledge_stats():
    """Show statistics of the payload knowledge base."""
    click.echo(BANNER)
    stats = PayloadKnowledgeBase.get_summary_statistics()
    click.echo(f"{Fore.CYAN}=== Payload Knowledge Base Statistics ==={Style.RESET_ALL}")
    click.echo(f"Total Payloads: {Fore.GREEN}{stats['total_payloads']}{Style.RESET_ALL}")
    click.echo("\nCategories:")
    for cat, count in stats["categories"].items():
        click.echo(f" - {cat:<25}: {Fore.MAGENTA}{count}{Style.RESET_ALL}")
    click.echo(f"\nFrameworks: {', '.join(stats['frameworks_supported'])}")
    click.echo(f"Targeted WAFs: {', '.join(stats['wafs_targeted'])}")

# --- AUTONOMOUS BRAIN COMMAND ---
@cli.command(name="brain")
@click.option("--context", default="HTML_TEXT", help="Injection context (HTML_TEXT, ATTR_QUOTED, JS_STRING, etc.).")
@click.option("--token", default="ORACLE_TOKEN_123", help="Oracle token to embed.")
@click.option("--waf", default=None, help="Detected WAF (cloudflare, aws_waf, modsecurity, etc.).")
@click.option("--frameworks", default=None, help="Comma-separated frameworks (angularjs, vue, etc.).")
def run_brain(context, token, waf, frameworks):
    """Synthesize optimal XSS payloads using the Autonomous AI Brain."""
    click.echo(BANNER)
    autonomous_brain_internal(context_str=context, token=token, waf=waf, frameworks=frameworks)

# --- MODERN RECON COMMANDS ---
@cli.group()
def recon():
    """Modern reconnaissance, framework harvesting, API discovery, and source maps."""
    pass

@recon.command(name="run")
@click.option("--target-id", required=True, type=int, help="Target ID to perform recon against.")
@click.option("--threads", default=10, type=int, help="Concurrent worker threads.")
def run_recon(target_id, threads):
    """Execute the Modern Recon Hub against a target."""
    click.echo(BANNER)
    db = SessionLocal()
    try:
        hub = ModernReconHub(db, target_id=target_id, max_threads=threads)
        summary = hub.run_full_recon()
        click.echo(f"\n{Fore.GREEN}[+] Recon Hub Completed for {summary.target_name}:{Style.RESET_ALL}")
        click.echo(f"    Total Endpoints Imported: {Fore.CYAN}{summary.total_endpoints_imported}{Style.RESET_ALL}")
        click.echo(f"    Total Parameters Mined:   {Fore.CYAN}{summary.total_params_discovered}{Style.RESET_ALL}")
        click.echo(f"    Framework Routes:         {Fore.MAGENTA}{summary.framework_routes_count}{Style.RESET_ALL}")
        click.echo(f"    GraphQL Endpoints:        {Fore.YELLOW}{summary.graphql_endpoints_count}{Style.RESET_ALL}")
        click.echo(f"    OpenAPI Endpoints:        {Fore.YELLOW}{summary.openapi_endpoints_count}{Style.RESET_ALL}")
        click.echo(f"    Client Bundles Recorded:  {Fore.CYAN}{len(summary.details.get('client_bundles', []))}{Style.RESET_ALL}")
        click.echo(f"    DOM Sink Indicators:      {Fore.YELLOW}{summary.discovered_sinks_count}{Style.RESET_ALL}")
        click.echo(f"    Secret Indicators:        {Fore.YELLOW}{summary.discovered_tokens_count} (values redacted){Style.RESET_ALL}")
        from backend_api.services.recon_dossier_service import ReconDossierService

        dossier = ReconDossierService.build(db, target_id, observations=summary.details)
        dossier_path = ReconDossierService.export(
            dossier,
            ROOT / "reports" / f"recon_dossier_target_{target_id}.json",
        )
        active_classes = sum(
            1 for item in dossier["coverage_matrix"].values() if item["kind"] in {"fuzz", "auditor"}
        )
        research_classes = sum(
            1 for item in dossier["coverage_matrix"].values() if item["kind"] == "research"
        )
        click.echo(
            f"    Cross-bug classes routed: {Fore.CYAN}{active_classes} active + "
            f"{research_classes} research{Style.RESET_ALL}"
        )
        click.echo(f"    Full recon dossier:       {Fore.GREEN}{dossier_path}{Style.RESET_ALL}")
    finally:
        db.close()


@recon.command(name="dossier")
@click.option("--target-id", required=True, type=int, help="Target ID whose stored recon should be exported.")
@click.option("--output", default=None, type=click.Path(dir_okay=False, path_type=Path), help="Optional JSON output path.")
def recon_dossier(target_id: int, output: Path | None):
    """Export all stored recon data and its cross-vulnerability routing plan."""
    db = SessionLocal()
    try:
        from backend_api.services.recon_dossier_service import ReconDossierService

        dossier = ReconDossierService.build(db, target_id)
        path = output or ROOT / "reports" / f"recon_dossier_target_{target_id}.json"
        ReconDossierService.export(dossier, path)
        click.echo(
            f"{Fore.GREEN}[+] Exported {dossier['summary']['endpoints']} endpoint(s), "
            f"{dossier['summary']['parameters']} parameter(s), and "
            f"{dossier['summary']['bug_classes']} routed bug classes to {path}.{Style.RESET_ALL}"
        )
    finally:
        db.close()

@recon.command(name="har")
@click.argument("har_file")
@click.option("--target-id", required=True, type=int, help="Target to attach imported endpoints to.")
def recon_har(har_file, target_id):
    """Import a browser HAR capture (endpoints + params) into a target."""
    click.echo(BANNER)
    from recon_engine.har_import import HARImporter
    db = SessionLocal()
    try:
        count = HARImporter.import_to_database(har_file, target_id, db)
        click.echo(f"{Fore.GREEN}[+] Imported {count} endpoint(s) from {har_file} into target #{target_id}.{Style.RESET_ALL}")
    finally:
        db.close()


@recon.command(name="stored-flows")
@click.option("--target-id", required=True, type=int, help="Target to map stored plant→render edges for.")
@click.option("--max-sources", default=25, type=int, help="Max input sources to plant canaries into.")
def recon_stored_flows(target_id, max_sources):
    """Discover stored plant→render edges via inert canary correlation (feeds stored-XSS verification)."""
    click.echo(BANNER)
    from backend_api.services.stored_flow_discovery import StoredFlowDiscovery, SourceCandidate
    from backend_api.models.endpoint import Endpoint
    from backend_api.models.param import Param
    db = SessionLocal()
    try:
        endpoints = db.query(Endpoint).filter(Endpoint.target_id == target_id).all()
        render_ids = [e.id for e in endpoints]
        sources = [SourceCandidate(endpoint_id=e.id, param_id=p.id, label=p.name)
                   for e in endpoints for p in db.query(Param).filter(Param.endpoint_id == e.id).all()]
        if not sources:
            click.echo(f"{Fore.YELLOW}[!] No params found for target #{target_id}. Run recon first.{Style.RESET_ALL}")
            return
        edges = StoredFlowDiscovery.discover_for_target(db, target_id, sources, render_ids, max_sources=max_sources)
        confirmed = StoredFlowDiscovery.confirmed_edges(edges)
        click.echo(f"{Fore.GREEN}[+] Planted {len(edges)} canaries; {len(confirmed)} stored plant→render edge(s) found.{Style.RESET_ALL}")
        for e in confirmed:
            click.echo(f"    param#{e.param_id} @ endpoint#{e.source_endpoint_id} → renders on {e.render_endpoint_ids}")
    finally:
        db.close()


@recon.command(name="graphql")
@click.option("--url", required=True, help="Target base URL or GraphQL endpoint.")
def recon_graphql(url):
    """Probe and introspect GraphQL endpoints and queries/mutations."""
    click.echo(BANNER)
    click.echo(f"{Fore.CYAN}[*] Probing GraphQL endpoints on {url}...{Style.RESET_ALL}")
    api_disc = APIDiscovery(url)
    endpoints = api_disc.probe_graphql()
    click.echo(f"{Fore.GREEN}[+] Discovered {len(endpoints)} GraphQL operations/endpoints:{Style.RESET_ALL}")
    for ep in endpoints:
        click.echo(f"    - {Fore.YELLOW}{ep.method} {ep.url}{Style.RESET_ALL} -> {ep.description}")
        if ep.body_params:
            click.echo(f"      Parameters: {', '.join(ep.body_params)}")

@recon.command(name="openapi")
@click.option("--url", required=True, help="Target base URL.")
def recon_openapi(url):
    """Probe and parse OpenAPI / Swagger definitions."""
    click.echo(BANNER)
    click.echo(f"{Fore.CYAN}[*] Probing OpenAPI / Swagger specs on {url}...{Style.RESET_ALL}")
    api_disc = APIDiscovery(url)
    endpoints = api_disc.probe_openapi()
    click.echo(f"{Fore.GREEN}[+] Discovered {len(endpoints)} API endpoints from spec:{Style.RESET_ALL}")
    for ep in endpoints[:20]:
        click.echo(f"    - {Fore.YELLOW}{ep.method:<6} {ep.url}{Style.RESET_ALL} (Params: {len(ep.query_params + ep.path_params + ep.body_params)})")

@recon.command(name="sourcemap")
@click.option("--url", required=True, help="Target script bundle URL.")
def recon_sourcemap(url):
    """Download and analyze JavaScript source maps for hidden routes and DOM sinks."""
    click.echo(BANNER)
    click.echo(f"{Fore.CYAN}[*] Analyzing source map for {url}...{Style.RESET_ALL}")
    sm = SourceMapAnalyzer()
    findings = sm.analyze_script_for_sourcemap(url)
    click.echo(f"{Fore.GREEN}[+] Reconstructed {len(findings)} source files:{Style.RESET_ALL}")
    for f in findings:
        click.echo(f"    File: {Fore.MAGENTA}{f.original_file_path}{Style.RESET_ALL}")
        if f.discovered_endpoints:
            click.echo(f"      Endpoints:  {', '.join(f.discovered_endpoints)}")
        if f.discovered_parameters:
            click.echo(f"      Parameters: {', '.join(f.discovered_parameters)}")
        if f.dom_sinks:
            click.echo(f"      DOM Sinks:  {len(f.dom_sinks)} detected")

@recon.command(name="framework")
@click.option("--url", required=True, help="Target base URL.")
def recon_framework(url):
    """Harvest meta-framework routes (Next.js, Nuxt 3, Remix, SvelteKit, Angular)."""
    click.echo(BANNER)
    click.echo(f"{Fore.CYAN}[*] Harvesting framework routes on {url}...{Style.RESET_ALL}")
    harvester = FrameworkHarvester(url)
    routes = harvester.harvest_all()
    click.echo(f"{Fore.GREEN}[+] Discovered {len(routes)} framework routes:{Style.RESET_ALL}")
    for r in routes:
        click.echo(f"    [{Fore.MAGENTA}{r.framework}{Style.RESET_ALL}] {Fore.YELLOW}{r.method} {r.path}{Style.RESET_ALL} ({r.source_type})")

# --- CONTEXT AWARENESS COMMANDS ---
@cli.group()
def context():
    """Context awareness, reflection classification, and character filter profiling."""
    pass

@context.command(name="analyze")
@click.option("--html", default=None, help="HTML text content.")
@click.option("--file", default=None, type=click.Path(exists=True), help="Path to HTML file.")
@click.option("--marker", required=True, help="Canary marker string to locate.")
def analyze_context(html, file, marker):
    """Analyze and classify all reflection contexts of a canary marker."""
    click.echo(BANNER)
    content = ""
    if file:
        with open(file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    elif html:
        content = html
    else:
        click.echo(f"{Fore.RED}[-] Either --html or --file must be provided.{Style.RESET_ALL}")
        return

    classified = EnhancedContextClassifier.classify_all_reflections(content, marker)
    click.echo(f"\n{Fore.GREEN}[+] Discovered {len(classified)} reflection context(s) for marker '{marker}':{Style.RESET_ALL}\n")
    for i, c in enumerate(classified, 1):
        click.echo(f" [{Fore.YELLOW}{i}{Style.RESET_ALL}] Context Type:    {Fore.MAGENTA}{c.context_type.value}{Style.RESET_ALL}")
        if c.tag:
            click.echo(f"     Enclosing Tag:   {Fore.CYAN}<{c.tag}>{Style.RESET_ALL}")
        if c.attribute:
            click.echo(f"     Attribute:       {Fore.CYAN}{c.attribute}{Style.RESET_ALL} (Quote: {c.quote_char or 'None'})")
        click.echo(f"     Namespace:       {Fore.WHITE}{c.parent_namespace}{Style.RESET_ALL}")
        click.echo(f"     Breakout:        {Fore.YELLOW}{repr(c.breakout_sequence)}{Style.RESET_ALL}")
        click.echo(f"     Entity Decoded:  {Fore.GREEN if c.is_html_entity_decoded else Fore.RED}{c.is_html_entity_decoded}{Style.RESET_ALL}")
        click.echo(f"     JS Executable:   {Fore.GREEN if c.is_js_executable else Fore.RED}{c.is_js_executable}{Style.RESET_ALL}")
        click.echo(f"     Snippet:         {Fore.WHITE}{c.snippet[:120]}{Style.RESET_ALL}\n")

@context.command(name="profile")
@click.option("--url", required=True, help="Target URL.")
@click.option("--param", default="q", help="Parameter name to probe.")
@click.option("--method", default="GET", type=click.Choice(["GET", "POST"]), help="HTTP Method.")
def profile_param(url, param, method):
    """Actively probe character filters, escaping, and sanitizer transformations."""
    click.echo(BANNER)
    click.echo(f"{Fore.CYAN}[*] Profiling character filter on {url} (param: {param}, method: {method})...{Style.RESET_ALL}")
    profiler = FilterProfiler()
    profile = profiler.profile_endpoint_param(url=url, method=method, param_name=param)
    
    click.echo(f"\n{Fore.GREEN}[+] Character Filter Profile Summary:{Style.RESET_ALL}")
    click.echo(f"    Allowed Raw:       {Fore.GREEN}{''.join(sorted(profile.allowed_characters)) or 'None'}{Style.RESET_ALL}")
    click.echo(f"    Escaped (\\):      {Fore.YELLOW}{''.join(sorted(profile.escaped_characters)) or 'None'}{Style.RESET_ALL}")
    click.echo(f"    HTML Encoded:      {Fore.MAGENTA}{''.join(sorted(profile.encoded_characters)) or 'None'}{Style.RESET_ALL}")
    click.echo(f"    Stripped:          {Fore.RED}{''.join(sorted(profile.stripped_characters)) or 'None'}{Style.RESET_ALL}")
    click.echo(f"\n    Quotes Escaped:    {Fore.CYAN}{profile.quotes_escaped}{Style.RESET_ALL}")
    click.echo(f"    Angle Brackets:    {Fore.CYAN}{'Encoded' if profile.angle_brackets_encoded else 'Allowed'}{Style.RESET_ALL}")
    click.echo(f"    Parentheses:       {Fore.CYAN}{'Allowed' if profile.parentheses_allowed else 'Blocked'}{Style.RESET_ALL}")
    click.echo(f"    Backticks:         {Fore.CYAN}{'Allowed' if profile.backticks_allowed else 'Blocked'}{Style.RESET_ALL}")
    if profile.recommended_evasions:
        click.echo(f"\n    {Fore.YELLOW}Recommended Evasion Strategies:{Style.RESET_ALL}")
        for ev in profile.recommended_evasions:
            click.echo(f"     - {ev}")


# --- AUTONOMOUS BOUNTY HUNT ---
def hunt_internal(
    target_id: int | None,
    url: str | None,
    name: str | None,
    max_pages: int,
    strategy: str,
    auto_report: bool,
    max_cases: int = 30,
):
    from urllib.parse import urlparse
    db = SessionLocal()
    try:
        if not target_id:
            if not url:
                click.echo(f"{Fore.RED}[-] Either --target-id or --url must be provided.{Style.RESET_ALL}")
                return
            t_name = name or urlparse(url).netloc
            t = db.query(Target).filter((Target.name == t_name) | (Target.base_url == url)).first()
            if not t:
                t = Target(name=t_name, base_url=url, status=TargetStatus.RECON_ONLY)
                db.add(t)
                db.commit()
                db.refresh(t)
                click.echo(f"{Fore.GREEN}[+] Created target: {t.name} (ID: {t.id}){Style.RESET_ALL}")
            target_id = t.id

        target = db.query(Target).filter(Target.id == target_id).first()
        if not target:
            click.echo(f"{Fore.RED}[-] Target ID {target_id} not found.{Style.RESET_ALL}")
            return

        click.echo(f"{Fore.CYAN}[*] Starting Autonomous Bug Bounty Hunt against: {target.name} ({target.base_url}){Style.RESET_ALL}")
        click.echo(f"{Fore.CYAN}[*] Phase 1: Stealth Crawler & SPA Bundle Analysis (Max Pages: {max_pages}){Style.RESET_ALL}")

        # The supplied seed is itself an endpoint. Persist it before browser
        # crawling so a one-page run or crawler failure cannot silently produce
        # a zero-endpoint "successful" hunt.
        from urllib.parse import parse_qsl
        from backend_api.services.recon_service import ReconService
        seed_parsed = urlparse(target.base_url)
        ReconService.create_endpoint_from_request(
            db,
            target.id,
            "GET",
            target.base_url,
            {
                "headers": {},
                "query": dict(parse_qsl(seed_parsed.query, keep_blank_values=True)),
                "body": None,
                "json": None,
            },
        )
        db.commit()

        from recon_engine.crawler import Crawler
        c = Crawler(
            base_url=target.base_url,
            max_depth=3,
            max_pages=max_pages,
            progress_callback=lambda page_url, depth, visited, limit: click.echo(
                f"    [crawl] {visited}/{limit} depth={depth} {page_url}", err=True
            ),
        )
        c.db_session = db
        c.target_id = target.id
        c._target_obj = target
        c.crawl()

        total_ep = db.query(Endpoint).filter(Endpoint.target_id == target.id).count()
        click.echo(f"{Fore.GREEN}[+] Phase 1 Complete: {total_ep} endpoints discovered in target scope.{Style.RESET_ALL}")

        click.echo(f"{Fore.CYAN}[*] Phase 2: Autonomous Fuzzing & Multi-Auditor Engine (Strategy: {strategy}){Style.RESET_ALL}")
        exp = Experiment(
            target_id=target.id,
            name=f"Hunt-{target.name}-{datetime.now(UTC).strftime('%Y%m%d-%H%M')}",
            strategy=ExperimentStrategy(strategy),
            status=ExperimentStatus.RUNNING,
            started_at=datetime.now(UTC),
            limits={"max_test_cases": max_cases, "max_cases_per_param": 3, "browser_pool_size": 2}
        )
        db.add(exp)
        db.commit()
        db.refresh(exp)

        click.echo(f"{Fore.YELLOW}[*] Launched Experiment #{exp.id}. Executing auditors & WAF bypass engine...{Style.RESET_ALL}")
        fuzzing_svc = FuzzingService(db)
        fuzzing_svc.run_experiment(
            exp.id,
            progress_callback=lambda phase, message: click.echo(
                f"    [{phase}] {message}", err=True
            ),
        )
        db.expire_all()
        exp = db.query(Experiment).filter(Experiment.id == exp.id).first()

        limits = exp.limits if isinstance(exp.limits, dict) else {}
        coverage = limits.get("coverage") if isinstance(limits.get("coverage"), dict) else {}
        done = limits.get("done") if isinstance(limits.get("done"), dict) else {}
        status_color = Fore.GREEN if exp.status == ExperimentStatus.COMPLETED else Fore.RED
        click.echo(
            f"{status_color}[+] Phase 2 finished: Experiment #{exp.id} status={exp.status.value}; "
            f"coverage={coverage.get('tested_endpoints', 0)}/{coverage.get('eligible_endpoints', 0)}; "
            f"execution_errors={done.get('execution_errors', 0)}; reason={done.get('reason', 'unknown')}.{Style.RESET_ALL}"
        )

        # Triage and report
        from backend_api.services.campaign_report_service import CampaignReportService
        findings = CampaignReportService.get_findings_for_experiment(db, exp.id)
        finding_scope = "this run"
        if not findings:
            # Some native/auditor findings are target-scoped rather than linked
            # through a browser TestCase. Never hide already-confirmed target
            # evidence just because the current experiment produced no linked
            # rows (for example, a resumed/report-only hunt).
            findings = (
                db.query(Finding)
                .join(Endpoint, Finding.endpoint_id == Endpoint.id)
                .filter(
                    Endpoint.target_id == target.id,
                    Finding.status == FindingStatus.CONFIRMED,
                )
                .order_by(Finding.id.asc())
                .all()
            )
            finding_scope = "confirmed for this target"
        click.echo(
            f"\n{Fore.GREEN}[+] Discovered {len(findings)} finding(s) "
            f"{finding_scope} for {target.name}:{Style.RESET_ALL}"
        )

        rows = []
        for f in findings:
            ep_str = f"{f.endpoint.method} {f.endpoint.url_pattern[:40]}" if f.endpoint else "n/a"
            param_str = f.param.name if f.param else "n/a"
            rows.append([f.id, f.severity.value.upper(), f.vuln_type, ep_str, param_str, f.status.value])

        headers = ["ID", "Severity", "Vulnerability Type", "Endpoint", "Parameter", "Status"]
        print_table(headers, rows, {1: get_severity_color})

        if auto_report and findings:
            click.echo(f"\n{Fore.CYAN}[*] Phase 3: Generating Submission-Ready HackerOne Markdown Reports & HTML PoCs...{Style.RESET_ALL}")
            from backend_api.services.bounty_report_service import BountyReportService
            os.makedirs("reports", exist_ok=True)
            for f in findings:
                try:
                    rep = BountyReportService.build_report(db, f, report_format="hackerone")
                    md_name = f"reports/hunt_finding_{f.id}_{f.vuln_type}.md"
                    poc_name = f"reports/hunt_poc_{f.id}_{f.vuln_type}.html"
                    with open(md_name, "w", encoding="utf-8") as out:
                        out.write(rep["markdown"])
                    with open(poc_name, "w", encoding="utf-8") as out:
                        out.write(rep["poc_html"])
                    click.echo(f"    [+] Saved Finding #{f.id} Report -> {md_name} & {poc_name}")
                except Exception:
                    pass

    finally:
        db.close()

@cli.command(name="hunt")
@click.option("--target-id", default=None, type=int, help="Target ID to hunt.")
@click.option("--url", default=None, help="Target URL to hunt directly.")
@click.option("--name", default=None, help="Program name.")
@click.option("--max-pages", default=15, type=int, help="Max pages to crawl.")
@click.option("--max-cases", default=30, type=click.IntRange(1, 10000), help="Maximum browser test cases for this hunt.")
@click.option("--strategy", default="quick_light", type=click.Choice([s.value for s in ExperimentStrategy]), help="Fuzzing strategy profile.")
@click.option("--report", is_flag=True, default=True, help="Auto-generate HackerOne markdown report and standalone HTML PoC.")
def hunt(target_id, url, name, max_pages, max_cases, strategy, report):
    """Run an end-to-end autonomous Bug Bounty hunting operation."""
    click.echo(BANNER)
    hunt_internal(target_id, url, name, max_pages, strategy, report, max_cases=max_cases)

# --- SYSTEM STATUS ---
@cli.command(name="pipe")
@click.option("--candidates-only", is_flag=True, help="Only print URLs that look injectable.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON results.")
def pipe_cmd(candidates_only, as_json):
    """Fast HTTP triage of URLs from stdin (e.g. `cat urls.txt | xssboss pipe --candidates-only`)."""
    import sys as _sys
    import json as _json
    from backend_api.services.pipe_scan_service import PipeScanService
    urls = [ln.strip() for ln in _sys.stdin if ln.strip()]
    results = PipeScanService.scan_urls(urls, candidates_only=candidates_only)
    if as_json:
        click.echo(_json.dumps(results, indent=2))
        return
    for r in results:
        if r.get("error"):
            continue
        mark = f"{Fore.RED}[CANDIDATE]{Style.RESET_ALL}" if r["candidate"] else f"{Fore.GREEN}[clean]{Style.RESET_ALL}"
        click.echo(f"{mark} {r['url']}  libs={len(r.get('vulnerable_libraries', []))} "
                   f"dom={len(r.get('dom_sinks', []))}  ({r.get('reason')})")


@cli.command(name="mcp")
def mcp_cmd():
    """Run the MCP stdio server — expose XSSBOSS tools (taint/decide/scan) to AI agents."""
    from analysis_engine.mcp_server import McpServer
    McpServer().serve()


@cli.command(name="status")
def system_status():
    """Show the overall fuzzer database statistics."""
    click.echo(BANNER)
    system_status_internal()


# --- PROXY COMMANDS ---
@cli.group()
def proxy():
    """Manage and inspect free proxy rotation and pool health."""
    pass


@proxy.command(name="status")
def proxy_status_cmd():
    """Show active proxy pool metrics and rotation status."""
    click.echo(BANNER)
    from backend_api.utils.stealth import get_proxy_pool_status
    st = get_proxy_pool_status()
    click.echo(f"{Fore.CYAN}{Style.BRIGHT}=== XSS BOSS PROXY POOL STATUS ==={Style.RESET_ALL}\n")
    click.echo(f"  Enabled:         {Fore.GREEN if st['enabled'] else Fore.RED}{st['enabled']}{Style.RESET_ALL}")
    click.echo(f"  Active Proxies:  {Fore.YELLOW}{st['active_count']}{Style.RESET_ALL}")
    click.echo(f"  Ejected Proxies: {Fore.RED if st['ejected_count'] > 0 else Fore.WHITE}{st['ejected_count']}{Style.RESET_ALL}")
    click.echo(f"  Rotation Mode:   {Fore.CYAN}{st['rotation_mode']}{Style.RESET_ALL}")
    click.echo(f"  Static Proxy:    {st['static_proxy'] or 'None'}")
    click.echo(f"  Burp Proxy:      {st['burp_proxy'] or 'None'}")


@proxy.command(name="refresh")
def proxy_refresh_cmd():
    """Reload proxies from proxies.txt or environment configuration."""
    click.echo(BANNER)
    from backend_api.utils.stealth import _init_proxy_pool, get_proxy_pool_status
    _init_proxy_pool()
    st = get_proxy_pool_status()
    click.echo(f"{Fore.GREEN}[+] Proxy pool reloaded: {st['active_count']} active proxies ready.{Style.RESET_ALL}")


@proxy.command(name="test")
@click.option("--url", default="https://httpbin.org/ip", help="Target URL to test proxy connectivity.")
@click.option("--proxy-url", default=None, help="Specific proxy URL to test.")
@click.option("--timeout", default=5.0, type=float, help="Timeout in seconds.")
def proxy_test_cmd(url, proxy_url, timeout):
    """Test connectivity through the proxy pool."""
    click.echo(BANNER)
    import httpx
    import time
    from backend_api.utils.stealth import get_next_proxy, mark_proxy_success, mark_proxy_failed

    p = proxy_url or get_next_proxy()
    if not p:
        click.echo(f"{Fore.YELLOW}[!] No proxy available. Direct request will be made.{Style.RESET_ALL}")
        return

    click.echo(f"[*] Testing connectivity to {url} through {p} (timeout: {timeout}s)...")
    start = time.time()
    try:
        with httpx.Client(proxies=p, timeout=timeout, verify=False, follow_redirects=True) as client:
            resp = client.get(url)
            latency = (time.time() - start) * 1000
            mark_proxy_success(p)
            click.echo(f"{Fore.GREEN}[+] SUCCESS: HTTP {resp.status_code} ({latency:.0f}ms){Style.RESET_ALL}")
            click.echo(f"    Response snippet: {resp.text[:150]}")
    except Exception as exc:
        mark_proxy_failed(p)
        click.echo(f"{Fore.RED}[-] FAILED through {p}: {exc}{Style.RESET_ALL}")


# --- HACKERONE SCRAPER COMMANDS ---
@cli.group()
def hackerone():
    """Scrape, inspect, and sync HackerOne bug bounty programs and scopes."""
    pass


@hackerone.command(name="list")
@click.option("--bounty-only/--all", default=True, help="Filter for bounty-paying programs only.")
@click.option("--query", "-q", default=None, help="Search by program name or handle.")
@click.option("--asset-type", default=None, help="Filter by asset type (e.g. URL, DOMAIN, WILDCARD).")
@click.option("--limit", default=30, type=int, help="Max programs to display.")
def hackerone_list_cmd(bounty_only, query, asset_type, limit):
    """List public HackerOne programs with in-scope asset counts."""
    click.echo(BANNER)
    from backend_api.services.hackerone_scraper_service import HackerOneScraperService
    click.echo(f"[*] Fetching HackerOne programs (bounty_only={bounty_only}, query={query or '*'}, limit={limit})...\n")
    try:
        programs = HackerOneScraperService.fetch_all_programs(
            bounty_only=bounty_only,
            query=query,
            asset_type=asset_type,
            limit=limit,
        )
        if not programs:
            click.echo(f"{Fore.YELLOW}[!] No matching HackerOne programs found.{Style.RESET_ALL}")
            return

        click.echo(f"{Fore.CYAN}{Style.BRIGHT}{'#':<4} {'PROGRAM NAME':<35} {'HANDLE':<20} {'BOUNTY':<8} {'SCOPES':<8} {'PRIMARY URL'}{Style.RESET_ALL}")
        click.echo("-" * 105)
        for i, p in enumerate(programs, 1):
            bounty_str = f"{Fore.GREEN}YES{Style.RESET_ALL}" if p["offers_bounties"] else f"{Fore.WHITE}NO{Style.RESET_ALL}"
            primary = p["primary_url"][:40] + ("..." if len(p["primary_url"]) > 40 else "")
            click.echo(f"{i:<4} {p['name'][:34]:<35} @{p['handle'][:18]:<19} {bounty_str:<17} {p['in_scope_count']:<8} {Fore.BLUE}{primary}{Style.RESET_ALL}")
        click.echo(f"\n[+] Displayed {len(programs)} programs. Use 'xssboss hackerone view <handle>' for detailed scope.")
    except Exception as exc:
        click.echo(f"{Fore.RED}[-] Failed to fetch HackerOne programs: {exc}{Style.RESET_ALL}")


@hackerone.command(name="view")
@click.argument("handle")
def hackerone_view_cmd(handle):
    """View full in-scope targets and out-of-scope rules for a HackerOne program."""
    click.echo(BANNER)
    from backend_api.services.hackerone_scraper_service import HackerOneScraperService
    click.echo(f"[*] Looking up HackerOne program @{handle}...\n")
    prog = HackerOneScraperService.fetch_program_by_handle(handle)
    if not prog:
        click.echo(f"{Fore.RED}[-] Program @{handle} not found.{Style.RESET_ALL}")
        return

    click.echo(f"{Fore.CYAN}{Style.BRIGHT}=== {prog['name']} (@{prog['handle']}) ==={Style.RESET_ALL}")
    click.echo(f"  URL:             {prog['url']}")
    click.echo(f"  Website:         {prog['website'] or 'N/A'}")
    click.echo(f"  Bounties:        {Fore.GREEN if prog['offers_bounties'] else Fore.WHITE}{'Yes' if prog['offers_bounties'] else 'No (VDP)'}{Style.RESET_ALL}")
    click.echo(f"  State:           {prog['submission_state']}")
    click.echo(f"  In-Scope Count:  {Fore.YELLOW}{prog['in_scope_count']}{Style.RESET_ALL}")
    click.echo(f"  Out-Scope Count: {prog['out_of_scope_count']}")

    click.echo(f"\n{Fore.GREEN}{Style.BRIGHT}--- IN-SCOPE TARGETS ({len(prog['in_scope'])}) ---{Style.RESET_ALL}")
    for item in prog['in_scope'][:50]:
        ident = item.get("asset_identifier")
        atype = item.get("asset_type")
        bounty = "[Bounty]" if item.get("eligible_for_bounty") else "[No Bounty]"
        sev = item.get("max_severity") or ""
        click.echo(f"  - {Fore.WHITE}{ident}{Style.RESET_ALL} ({atype}) {Fore.GREEN}{bounty}{Style.RESET_ALL} {sev}")

    if len(prog['in_scope']) > 50:
        click.echo(f"  ... and {len(prog['in_scope']) - 50} more in-scope targets.")

    if prog['out_of_scope']:
        click.echo(f"\n{Fore.RED}{Style.BRIGHT}--- OUT-OF-SCOPE ASSETS / EXCLUSIONS ({len(prog['out_of_scope'])}) ---{Style.RESET_ALL}")
        for item in prog['out_of_scope'][:30]:
            click.echo(f"  - {Fore.YELLOW}{item.get('asset_identifier')}{Style.RESET_ALL} ({item.get('asset_type')})")


@hackerone.command(name="sync")
@click.option("--handle", default=None, help="Specific program handle to import (e.g. oppo_bbp).")
@click.option("--bounty-only/--all", default=True, help="Import bounty-offering programs only.")
@click.option("--limit", default=25, type=int, help="Max programs to import into target database.")
def hackerone_sync_cmd(handle, bounty_only, limit):
    """Sync HackerOne programs directly into XSS Boss Target database."""
    click.echo(BANNER)
    from backend_api.db.session import SessionLocal
    from backend_api.services.hackerone_scraper_service import HackerOneScraperService

    db = SessionLocal()
    try:
        handles = [handle] if handle else None
        click.echo(f"[*] Syncing HackerOne programs into XSS Boss target database (limit={limit})...")
        res = HackerOneScraperService.bulk_sync_to_database(
            db=db,
            handles=handles,
            bounty_only=bounty_only,
            limit=limit,
        )
        click.echo(f"{Fore.GREEN}[+] Successfully synced {res['imported_count']} HackerOne programs into targets!{Style.RESET_ALL}")
        for t in res["targets"][:10]:
            click.echo(f"  - Target #{t['target_id']}: {t['name']} (@{t['handle']}) -> {t['base_url']} ({t['scopes_count']} scopes)")
        if len(res["targets"]) > 10:
            click.echo(f"  ... and {len(res['targets']) - 10} more targets.")
    finally:
        db.close()


@hackerone.command(name="export")
@click.option("--output", "-o", default="hackerone_scopes.json", help="Output file path.")
@click.option("--format", "export_format", default="json", type=click.Choice(["json", "csv"]), help="Export format.")
@click.option("--bounty-only/--all", default=False, help="Export only bounty programs.")
@click.option("--query", "-q", default=None, help="Filter query.")
def hackerone_export_cmd(output, export_format, bounty_only, query):
    """Export scraped HackerOne programs and scopes to JSON or CSV."""
    click.echo(BANNER)
    from backend_api.services.hackerone_scraper_service import HackerOneScraperService
    click.echo(f"[*] Exporting HackerOne scopes (format={export_format}, bounty_only={bounty_only})...")
    programs = HackerOneScraperService.fetch_all_programs(bounty_only=bounty_only, query=query)
    data = HackerOneScraperService.export_programs(programs, export_format=export_format)
    with open(output, "w", encoding="utf-8") as f:
        f.write(data)
    click.echo(f"{Fore.GREEN}[+] Saved {len(programs)} program scopes to {output}{Style.RESET_ALL}")


@hackerone.command(name="scope")
@click.argument("target_id", type=int)
@click.option("--burp", "burp_output", default=None, help="Write a Burp Suite scope config to this file.")
@click.option("--limit", default=25, type=int, help="Max prioritized assets to display.")
def hackerone_scope_cmd(target_id, burp_output, limit):
    """Show a synced program's scope boundaries as a prioritized worklist (URL -> program mode)."""
    click.echo(BANNER)
    from backend_api.db.session import SessionLocal
    from backend_api.models.target import Target
    from backend_api.services.program_scope import ProgramScope

    db = SessionLocal()
    try:
        target = db.query(Target).filter(Target.id == target_id).first()
        if not target:
            click.echo(f"{Fore.RED}[!] Target #{target_id} not found. Run 'hackerone sync' first.{Style.RESET_ALL}")
            return
        ps = ProgramScope.from_target(target)
        s = ps.summary()
        click.echo(f"{Fore.CYAN}Program @{s['handle']}  bounties={s['offers_bounties']}  "
                   f"web_assets={s['web_assets']}  bounty_eligible={s['bounty_eligible_assets']}  "
                   f"exclusions={s['exclusions']}{Style.RESET_ALL}")
        rows = [
            [i + 1, a.host, a.asset_type or "-", "yes" if a.eligible_for_bounty else "no", a.max_severity or "-"]
            for i, a in enumerate(ps.worklist()[:limit])
        ]
        print_table(
            ["#", "Host", "Type", "Bounty", "Max Sev"], rows,
            color_mappers={3: lambda v: Fore.GREEN if v == "yes" else Fore.WHITE, 4: get_severity_color},
        )
        if burp_output:
            with open(burp_output, "w", encoding="utf-8") as f:
                json.dump(ps.to_burp_scope(), f, indent=2)
            click.echo(f"{Fore.GREEN}[+] Wrote Burp scope config ({len(ps.web_assets())} in-scope hosts) "
                       f"to {burp_output}. Load it via Burp > Target > Scope > Load options.{Style.RESET_ALL}")
    finally:
        db.close()


@hackerone.command(name="hunt-program")
@click.argument("target_id", type=int)
@click.option("--max-assets", default=10, type=int, help="Max in-scope assets to hunt (priority order).")
@click.option("--budget", default=1500, type=int, help="Total request budget across the whole program.")
@click.option("--per-asset", default=300, type=int, help="Per-asset request cap (protects the budget from one wildcard).")
@click.option("--strategy", default="quick_light", type=click.Choice([s.value for s in ExperimentStrategy]), help="Fuzzing strategy.")
@click.option("--stop-after", default=None, type=int, help="Stop the whole run after N confirmed findings.")
@click.option("--max-pages", default=15, type=int, help="Crawl page cap per asset.")
@click.option("--dry-run", is_flag=True, help="Show the prioritized plan without hunting.")
@click.option("--resume", is_flag=True, help="Resume from the last checkpoint — skip assets already hunted.")
def hackerone_hunt_program_cmd(target_id, max_assets, budget, per_asset, strategy, stop_after, max_pages, dry_run, resume):
    """Autonomously hunt an ENTIRE synced program asset-by-asset (the URL -> program upgrade)."""
    click.echo(BANNER)
    from pathlib import Path
    from backend_api.db.session import SessionLocal
    from backend_api.models.target import Target
    from backend_api.services.program_scope import ProgramScope
    from backend_api.services.program_run_orchestrator import ProgramRunOrchestrator, RunBudget
    from backend_api.services.program_run_checkpoint import JsonCheckpointStore

    checkpoint = JsonCheckpointStore(str(Path.home() / ".xssboss" / "checkpoints"))
    run_key = str(target_id)
    db = SessionLocal()
    try:
        target = db.query(Target).filter(Target.id == target_id).first()
        if not target:
            click.echo(f"{Fore.RED}[!] Target #{target_id} not found. Run 'hackerone sync' first.{Style.RESET_ALL}")
            return
        scope = ProgramScope.from_target(target)
        budget_obj = RunBudget(
            max_assets=max_assets, max_requests_total=budget,
            per_asset_request_cap=per_asset, stop_after_findings=stop_after,
        )

        if dry_run:
            report = ProgramRunOrchestrator.run(scope, lambda a, c: {}, budget_obj, dry_run=True)
            click.echo(f"{Fore.CYAN}Plan for @{scope.handle}: {len(report.outcomes)} assets (priority order){Style.RESET_ALL}")
            print_table(
                ["#", "Host", "Bounty", "Max Sev"],
                [[i + 1, o.host, "yes" if o.eligible_for_bounty else "no", o.max_severity or "-"]
                 for i, o in enumerate(report.outcomes)],
                color_mappers={3: get_severity_color},
            )
            return

        # Bind the orchestrator to the real crawl -> experiment -> findings path, per asset.
        from recon_engine.crawler import Crawler
        from backend_api.models.endpoint import Endpoint
        from backend_api.models.finding import Finding
        from backend_api.models.experiment import Experiment, ExperimentStatus
        from backend_api.services.fuzzing_service import FuzzingService

        def hunt_asset(asset, cap):
            seed = f"https://{asset.host}/"
            before = db.query(Finding).join(Endpoint).filter(Endpoint.target_id == target.id).count()
            ep_count = Crawler(base_url=seed, max_depth=2, max_pages=max_pages).crawl_to_database(target.id, db)
            exp = Experiment(target_id=target.id, strategy=ExperimentStrategy(strategy), status=ExperimentStatus.RUNNING)
            db.add(exp); db.commit(); db.refresh(exp)
            FuzzingService(db).run_experiment(exp.id)
            after = db.query(Finding).join(Endpoint).filter(Endpoint.target_id == target.id).count()
            # Request count is not instrumented end-to-end; estimate from endpoints and clamp to the cap.
            est_requests = min(cap, max(1, ep_count) * 12)
            return {"endpoints": ep_count, "findings": after - before, "requests_used": est_requests}

        if resume:
            done = len(checkpoint.load(run_key))
            click.echo(f"{Fore.CYAN}[*] Resuming: {done} asset(s) already hunted will be skipped.{Style.RESET_ALL}")
        click.echo(f"{Fore.YELLOW}[*] Hunting @{scope.handle}: up to {max_assets} assets, "
                   f"budget {budget} requests, strategy={strategy}...{Style.RESET_ALL}")
        report = ProgramRunOrchestrator.run(
            scope, hunt_asset, budget_obj,
            on_progress=lambda o: click.echo(
                f"  - {o.host}: {o.status}  endpoints={o.endpoints} findings={o.findings} req~{o.requests_used}"
            ),
            checkpoint=checkpoint, resume=resume, run_key=run_key,
        )
        print_table(
            ["Host", "Status", "Endpoints", "Findings", "Req~"],
            [[o.host, o.status, o.endpoints, o.findings, o.requests_used] for o in report.outcomes],
            color_mappers={1: get_status_color},
        )
        click.echo(f"{Fore.GREEN}[+] Program run complete: {report.total_findings} findings across "
                   f"{report.assets_run} assets (~{report.total_requests} requests). "
                   f"Stopped: {report.stopped_reason}.{Style.RESET_ALL}")
    finally:
        db.close()


if __name__ == "__main__":
    cli()
