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
        click.echo(f"{Fore.YELLOW}[*] Deploying browser audit pipeline... (Press Ctrl+C to pause/abort){Style.RESET_ALL}\n")
        
        fuzzer = FuzzingService(db)
        fuzzer.run_experiment(exp.id)
        
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
def hunt_internal(target_id: int | None, url: str | None, name: str | None, max_pages: int, strategy: str, auto_report: bool):
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
        
        from recon_engine.crawler import Crawler
        c = Crawler(base_url=target.base_url, max_depth=3, max_pages=max_pages)
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
            limits={"max_test_cases": 10, "max_cases_per_param": 3, "browser_pool_size": 2}
        )
        db.add(exp)
        db.commit()
        db.refresh(exp)

        click.echo(f"{Fore.YELLOW}[*] Launched Experiment #{exp.id}. Executing auditors & WAF bypass engine...{Style.RESET_ALL}")
        fuzzing_svc = FuzzingService(db)
        fuzzing_svc.run_experiment(exp.id)

        click.echo(f"{Fore.GREEN}[+] Phase 2 Complete: Experiment #{exp.id} finished with status: {exp.status.value}.{Style.RESET_ALL}")

        # Triage and report
        findings = db.query(Finding).join(Endpoint).filter(Endpoint.target_id == target.id).all()
        click.echo(f"\n{Fore.GREEN}[+] Discovered {len(findings)} Total Finding(s) for {target.name}:{Style.RESET_ALL}")

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
@click.option("--strategy", default="quick_light", type=click.Choice([s.value for s in ExperimentStrategy]), help="Fuzzing strategy profile.")
@click.option("--report", is_flag=True, default=True, help="Auto-generate HackerOne markdown report and standalone HTML PoC.")
def hunt(target_id, url, name, max_pages, strategy, report):
    """Run an end-to-end autonomous Bug Bounty hunting operation."""
    click.echo(BANNER)
    hunt_internal(target_id, url, name, max_pages, strategy, report)

# --- SYSTEM STATUS ---
@cli.command(name="status")
def system_status():
    """Show the overall fuzzer database statistics."""
    click.echo(BANNER)
    system_status_internal()

if __name__ == "__main__":
    cli()
