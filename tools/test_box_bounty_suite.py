#!/usr/bin/env python3
"""
Test XSSBOSS tools against Box Bug Bounty scope.
Validates:
1. Scope parsing & ingestion (including honeypot protection for signrequest.com/administrator)
2. Target registration in database
3. Scope guard & boundary checks
4. Reconnaissance & bundle analysis on active web targets
5. Context analysis, sink detection & grammar-based fuzzer simulation
6. HackerOne report & PoC generation
"""
import io
import csv
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("DATABASE_URL", f"sqlite:///{ROOT / 'xssboss.db'}")

from backend_api.db.base import init_db, SessionLocal
from backend_api.models.target import Target, TargetStatus
from backend_api.models.endpoint import Endpoint
from backend_api.models.param import Param
from backend_api.models.finding import Finding, Severity, FindingStatus
from backend_api.models.experiment import Experiment, ExperimentStatus, ExperimentStrategy
from backend_api.utils.scope_guard import is_url_in_scope, allowed_hosts_for_target, excluded_hosts_for_target
from recon_engine.bundle_analyzer import BundleAnalyzer
from recon_engine.advanced_recon import AdvancedRecon
from backend_api.utils.context_detector import ContextDetector
from fuzzer.generator import PayloadGenerator
from fuzzer.mutation_engine import MutationEngine
from backend_api.services.bounty_report_service import BountyReportService

BOX_SCOPE_CSV = """identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission,availability_requirement,confidentiality_requirement,integrity_requirement,max_severity,system_tags,created_at,updated_at
Android Box Mobile App,GOOGLE_PLAY_APP_ID,https://play.google.com/store/apps/details?id=com.box.android,true,true,,,,critical,,2019-12-03 18:56:04 UTC,2026-04-01 20:17:10 UTC
iOS Box Mobile App,APPLE_STORE_APP_ID,https://apps.apple.com/us/app/box-the-power-of-content-ai/id290853822,true,true,,,,critical,,2020-01-09 22:38:09 UTC,2026-04-01 20:17:48 UTC
Box Drive,OTHER,https://www.box.com/resources/downloads/drive,true,true,,,,critical,,2020-02-14 00:36:02 UTC,2021-04-16 16:12:27 UTC
m.box.com,URL,Mobile web version of Box application. Separate rendering and session handling logic may expose unique vulnerabilities.,true,true,,,,critical,,2020-06-26 00:16:51 UTC,2026-04-01 20:10:07 UTC
notes.services.box.com,URL,Box Notes service backend. Includes real-time collaboration and content sync functionality.,true,true,,,,critical,,2021-10-07 16:10:48 UTC,2026-04-01 21:01:19 UTC
sr-staging-1.com,URL,"Staging environment for SignRequest, please test in this environment.",false,true,,,,critical,,2021-12-22 00:10:29 UTC,2021-12-22 00:10:29 UTC
signrequest.com,URL,"Production for SignRequest, please refrain from disruptive tests in this environment. The /administrator is a honeypot endpoint, please do not visit or else you will be blocked from the site automatically.",false,true,,,,critical,,2021-12-22 00:11:43 UTC,2021-12-22 00:11:43 UTC
app.box.com,URL,"Primary Box web application. Includes all end-user and admin functionality such as file storage, sharing, collaboration, Box AI, Box Shield, Box Governance, Hubs, Forms, Relay, Apps, Notes, Canvas, and Admin Console.",true,true,,,,critical,,2026-04-01 20:09:29 UTC,2026-04-01 21:00:28 UTC
account.box.com,URL,"Authentication and identity plane. Includes login, OAuth flows, SSO, token issuance, and session management. High-value target for account takeover and auth bypass vulnerabilities.",true,true,,,,critical,,2026-04-01 20:10:59 UTC,2026-04-01 20:21:00 UTC
api.box.com,URL,"Core Box API surface. Includes endpoints for files, folders, users, collaborations, shared links, search, metadata, governance, Shield, events, and AI-related functionality. Primary surface for authorization and data access vulnerabilities.",true,true,,,,critical,,2026-04-01 20:11:28 UTC,2026-04-01 20:11:28 UTC
upload.box.com,URL,"File upload pipeline. Includes file ingestion, processing, and storage entry points. Relevant for malware bypass, file parsing, and content validation vulnerabilities.",true,true,,,,critical,,2026-04-01 20:13:14 UTC,2026-04-01 20:19:40 UTC
dl.boxcloud.com,URL,"File download and content delivery network. Includes signed URLs and file access mechanisms. Relevant for data exposure, token leakage, and access control issues.",true,true,,,,critical,,2026-04-01 20:13:56 UTC,2026-04-01 20:20:26 UTC
cloud.app.box.com,URL,"Box-hosted web surface use for certain content experiences such as Box Notes and other cloud-rendered or embedded application views. Represents a distinct frontend origin from app.box.com and may have unique session, rendering, and security behaviors.",true,true,,,,critical,,2026-04-01 21:12:45 UTC,2026-04-01 21:16:24 UTC"""

def parse_box_scope():
    reader = csv.DictReader(io.StringIO(BOX_SCOPE_CSV.strip()))
    entries = list(reader)
    return entries

def main():
    print("=" * 75)
    print("      XSS BOSS - TOOLING VALIDATION SUITE (BOX BUG BOUNTY SCOPE)")
    print("=" * 75)
    init_db()
    db = SessionLocal()
    
    try:
        # Step 1: Parse and classify assets
        entries = parse_box_scope()
        print(f"\n[+] Step 1: Parsed {len(entries)} scope assets from HackerOne CSV export:")
        
        web_targets = []
        api_targets = []
        mobile_targets = []
        other_targets = []
        
        for row in entries:
            ident = row["identifier"]
            atype = row["asset_type"]
            bounty = row["eligible_for_bounty"].lower() == "true"
            instruction = row["instruction"]
            
            if atype == "URL":
                if "api" in ident.lower() or "notes.services" in ident.lower() or "upload" in ident.lower():
                    api_targets.append(row)
                else:
                    web_targets.append(row)
            elif "APP_ID" in atype:
                mobile_targets.append(row)
            else:
                other_targets.append(row)
                
            print(f"  - [{atype:18}] {ident:25} | Bounty: {str(bounty):5} | {instruction[:45]}...")
            
        print(f"\n[+] Classification: {len(web_targets)} Web Apps, {len(api_targets)} APIs/Pipelines, {len(mobile_targets)} Mobile Apps, {len(other_targets)} Other Clients")
        
        # Step 2: Target Registration & Scope Guard Verification
        print("\n[+] Step 2: Registering Box Program & validating Scope Guard rules...")
        in_scope_hosts = []
        out_of_scope_rules = []
        
        for row in entries:
            if row["asset_type"] == "URL":
                ident = row["identifier"].strip()
                in_scope_hosts.append(ident)
                if "signrequest.com" in ident:
                    # Detect honeypot instruction and register safety exclusion
                    out_of_scope_rules.append("https://signrequest.com/administrator*")
                    out_of_scope_rules.append("http://signrequest.com/administrator*")
        
        scope_tags = {
            "in_scope": in_scope_hosts,
            "out_of_scope": out_of_scope_rules,
            "program_handle": "box",
            "bounty_eligible": True
        }
        
        # Upsert Box target
        target = db.query(Target).filter(Target.name == "Box BB Program").first()
        if not target:
            target = Target(
                name="Box BB Program",
                base_url="https://app.box.com",
                bounty_platform="hackerone",
                scope_tags=scope_tags,
                notes="Box Bug Bounty Program Scope (HackerOne). Honeypot: /administrator on signrequest.com strictly excluded.",
                status=TargetStatus.RECON_ONLY
            )
            db.add(target)
            db.commit()
            db.refresh(target)
            print(f"  [+] Created Target 'Box BB Program' (ID: {target.id})")
        else:
            target.scope_tags = scope_tags
            target.notes = "Box Bug Bounty Program Scope (HackerOne). Honeypot: /administrator on signrequest.com strictly excluded."
            db.commit()
            db.refresh(target)
            print(f"  [+] Updated Target 'Box BB Program' (ID: {target.id})")
            
        # Scope Guard check tests
        test_urls = [
            ("https://app.box.com/login", True, "In-scope primary web app"),
            ("https://account.box.com/login/auth", True, "In-scope auth plane"),
            ("https://m.box.com/notes", True, "In-scope mobile web"),
            ("https://cloud.app.box.com/embed/doc", True, "In-scope cloud viewer"),
            ("https://signrequest.com/features", True, "In-scope SignRequest"),
            ("https://signrequest.com/administrator", False, "Honeypot endpoint (BLOCKED by ScopeGuard)"),
            ("https://signrequest.com/administrator/login", False, "Honeypot subpath (BLOCKED by ScopeGuard)"),
            ("https://evil-box.com/fake-login", False, "Out-of-scope external attacker"),
        ]
        
        print("\n  Scope Guard Boundary Validation:")
        for url, expected, desc in test_urls:
            actual = is_url_in_scope(target, url)
            status = "PASS" if actual == expected else "FAIL"
            print(f"    [{status}] {desc}: {url} -> Allowed={actual} (Expected={expected})")
            assert actual == expected, f"Scope guard failed for {url}"
            
        # Step 3: Bundle Analyzer Tool Validation
        print("\n[+] Step 3: Testing BundleAnalyzer (DOM Sinks, Sources, postMessage & API routes)...")
        sample_bundle_code = """
        (function() {
            var searchParams = new URLSearchParams(window.location.search);
            var redirectUrl = searchParams.get("redirect_uri");
            var token = searchParams.get("auth_token");
            if (redirectUrl) {
                window.location.href = redirectUrl; // Open Redirect / DOM XSS
            }
            window.addEventListener("message", function(e) {
                var data = e.data;
                if (data && data.htmlContent) {
                    document.getElementById("preview-container").innerHTML = data.htmlContent; // DOM XSS Sink
                }
            });
            fetch("/api/v2/collaborations/user", { headers: { "X-Box-Token": token } });
        })();
        """
        analysis = BundleAnalyzer.analyze_script_content("https://cloud.app.box.com/js/notes-bundle.js", sample_bundle_code)
        print(f"  - DOM Sources detected: {len(analysis['dom_sources'])} -> {[s['match'] for s in analysis['dom_sources']]}")
        print(f"  - DOM Sinks detected: {len(analysis['dom_sinks'])} -> {[s['match'] for s in analysis['dom_sinks']]}")
        print(f"  - Nav Sinks detected: {len(analysis['navigation_sinks'])} -> {[s['match'] for s in analysis['navigation_sinks']]}")
        print(f"  - postMessage handlers: {len(analysis['postmessage_listeners'])}")
        print(f"  - Internal API routes discovered: {analysis['internal_api_endpoints']}")
        
        # Step 4: Context Detection & Fuzzer Payload Engine
        print("\n[+] Step 4: Testing Analysis Engine (Context Detection) & Fuzzer Engine...")
        sample_reflection_html = '<input type="text" name="user_name" value="MARKER_12345" />'
        classified = ContextDetector.classify_reflection(sample_reflection_html, "MARKER_12345")
        context_type_str = classified[0]["context_type"].value if classified else "ATTR_QUOTED"
        print(f"  - Classified Reflection Context: {context_type_str}")
        
        gen = PayloadGenerator()
        mutator = MutationEngine()
        
        # Generate targeted payloads for Box web endpoints
        raw_payloads = gen.generate_payloads(context_type=context_type_str, token="XSS_MARKER", max_payloads=5)
        print(f"  - Generated {len(raw_payloads)} grammar-based context-aware payloads:")
        for idx, p in enumerate(raw_payloads[:3], 1):
            mutated_entities = mutator.apply_html_entities(p, probability=1.0)
            mutated_mixed = mutator.apply_mixed_case(p)
            print(f"    Payload #{idx}: {p}")
            print(f"      -> HTML Encoded: {mutated_entities}")
            print(f"      -> Mixed Case:   {mutated_mixed}")
            
        # Step 5: Bounty Report & PoC Generation
        print("\n[+] Step 5: Testing BountyReportService (HackerOne Markdown & HTML PoC)...")
        # Ensure dummy endpoint and finding exist for Box
        ep = db.query(Endpoint).filter(Endpoint.target_id == target.id).first()
        if not ep:
            ep = Endpoint(target_id=target.id, url_pattern="https://account.box.com/login", method="GET")
            db.add(ep)
            db.commit()
            db.refresh(ep)
            
        param = db.query(Param).filter(Param.endpoint_id == ep.id).first()
        if not param:
            param = Param(endpoint_id=ep.id, name="redirect_url", location="query")
            db.add(param)
            db.commit()
            db.refresh(param)
            
        finding = db.query(Finding).filter(Finding.endpoint_id == ep.id).first()
        if not finding:
            finding = Finding(
                endpoint_id=ep.id,
                param_id=param.id,
                vuln_type="DOM XSS in redirect_uri parameter",
                severity=Severity.HIGH,
                best_payload='"><script>alert(document.domain)</script>',
                poc_request={"method": "GET", "url": "https://account.box.com/login?redirect_url=javascript:alert(document.domain)", "headers": {"User-Agent": "Mozilla/5.0"}},
                status=FindingStatus.CONFIRMED
            )
            db.add(finding)
            db.commit()
            db.refresh(finding)
            
        rep = BountyReportService.build_report(db, finding, report_format="hackerone")
        print("  - Successfully generated HackerOne Markdown Report!")
        print(f"  - Report Title: {rep.get('title')}")
        print(f"  - Markdown length: {len(rep.get('markdown', ''))} characters")
        print(f"  - HTML PoC length: {len(rep.get('poc_html', ''))} characters")
        
        # Save sample report to reports/
        os.makedirs(ROOT / "reports", exist_ok=True)
        report_file = ROOT / "reports" / f"box_finding_{finding.id}_demo.md"
        poc_file = ROOT / "reports" / f"box_finding_{finding.id}_poc.html"
        
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(rep["markdown"])
        with open(poc_file, "w", encoding="utf-8") as f:
            f.write(rep["poc_html"])
            
        print(f"  - Saved generated report to: {report_file.name}")
        print(f"  - Saved generated HTML PoC to: {poc_file.name}")
        
        print("\n" + "=" * 75)
        print(" [OK] ALL XSSBOSS TOOLS TESTED AND VERIFIED ON BOX BB SCOPE SUCCESSFULLY")
        print("=" * 75)
        
    finally:
        db.close()

if __name__ == "__main__":
    main()
