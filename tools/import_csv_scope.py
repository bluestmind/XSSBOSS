#!/usr/bin/env python3
"""
CSV Scope Importer for XSS Boss.
Imports HackerOne and Bug Bounty CSV scope exports directly into the XSS Boss Target database.
Automatically parses instructions, extracts honeypot and out-of-scope rules, and categorizes assets.
"""
from __future__ import annotations

import argparse
import csv
import io
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("DATABASE_URL", f"sqlite:///{ROOT / 'xssboss.db'}")

from backend_api.db.base import init_db, SessionLocal
from backend_api.models.target import Target, TargetStatus


def import_csv_scope(csv_text_or_path: str, program_name: str = "Box BB Program", platform: str = "hackerone") -> dict:
    """Parse CSV scope and upsert target program in database."""
    if os.path.exists(csv_text_or_path):
        with open(csv_text_or_path, "r", encoding="utf-8") as f:
            content = f.read()
    else:
        content = csv_text_or_path

    reader = csv.DictReader(io.StringIO(content.strip()))
    entries = list(reader)

    in_scope_urls: list[str] = []
    out_of_scope_rules: list[str] = []
    asset_breakdown = {
        "web": [],
        "api": [],
        "mobile": [],
        "other": []
    }

    for row in entries:
        ident = (row.get("identifier") or "").strip()
        atype = (row.get("asset_type") or "").strip()
        eligible_bounty = (row.get("eligible_for_bounty") or "true").strip().lower() == "true"
        instruction = (row.get("instruction") or "").strip()

        # Check for honeypot warnings in instruction
        if "honeypot" in instruction.lower():
            matches = re.findall(r"(/[a-zA-Z0-9_\-\.]+)", instruction)
            for m in matches:
                if "administrator" in m or "honeypot" in m or "trap" in m:
                    base_host = ident if atype == "URL" else "signrequest.com"
                    out_of_scope_rules.append(f"https://{base_host}{m}*")
                    out_of_scope_rules.append(f"http://{base_host}{m}*")

        if atype == "URL":
            in_scope_urls.append(ident)
            if any(k in ident.lower() for k in ["api", "service", "notes.services", "upload"]):
                asset_breakdown["api"].append(ident)
            else:
                asset_breakdown["web"].append(ident)
        elif "APP_ID" in atype:
            asset_breakdown["mobile"].append(ident)
        else:
            asset_breakdown["other"].append(ident)

    primary_url = in_scope_urls[0] if in_scope_urls else "https://app.box.com"
    if "app.box.com" in in_scope_urls:
        primary_url = "https://app.box.com"

    if not primary_url.startswith("http"):
        primary_url = f"https://{primary_url}"

    scope_tags = {
        "in_scope": in_scope_urls,
        "out_of_scope": out_of_scope_rules,
        "program_handle": program_name.lower().replace(" ", "-"),
        "bounty_eligible": True,
        "asset_breakdown": asset_breakdown
    }

    init_db()
    db = SessionLocal()
    try:
        target = db.query(Target).filter(Target.name == program_name).first()
        if not target:
            target = Target(
                name=program_name,
                base_url=primary_url,
                bounty_platform=platform,
                scope_tags=scope_tags,
                notes=f"Imported from CSV scope. Total in-scope assets: {len(in_scope_urls)}. Excluded rules: {len(out_of_scope_rules)}",
                status=TargetStatus.RECON_ONLY
            )
            db.add(target)
            db.commit()
            db.refresh(target)
            action = "created"
        else:
            target.base_url = primary_url
            target.scope_tags = scope_tags
            target.notes = f"Imported from CSV scope. Total in-scope assets: {len(in_scope_urls)}. Excluded rules: {len(out_of_scope_rules)}"
            db.commit()
            db.refresh(target)
            action = "updated"

        return {
            "target_id": target.id,
            "name": target.name,
            "action": action,
            "in_scope_count": len(in_scope_urls),
            "out_of_scope_count": len(out_of_scope_rules),
            "breakdown": asset_breakdown,
            "excluded_rules": out_of_scope_rules
        }
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(description="Import CSV scope into XSS Boss.")
    parser.add_argument("--file", help="Path to CSV scope file")
    parser.add_argument("--name", default="Box BB Program", help="Target program name")
    parser.add_argument("--platform", default="hackerone", help="Bounty platform")
    args = parser.parse_args()

    if args.file and os.path.exists(args.file):
        with open(args.file, "r", encoding="utf-8") as f:
            csv_data = f.read()
    else:
        # Default Box scope data
        csv_data = """identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission,availability_requirement,confidentiality_requirement,integrity_requirement,max_severity,system_tags,created_at,updated_at
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

    result = import_csv_scope(csv_data, program_name=args.name, platform=args.platform)
    print(f"[+] Target '{result['name']}' (ID: {result['target_id']}) {result['action']} successfully!")
    print(f"    - In-Scope Assets:  {result['in_scope_count']}")
    print(f"    - Excluded Rules:   {result['out_of_scope_count']} (Honeypot protections: {result['excluded_rules']})")
    print(f"    - Breakdown: {len(result['breakdown']['web'])} Web, {len(result['breakdown']['api'])} API, {len(result['breakdown']['mobile'])} Mobile, {len(result['breakdown']['other'])} Other")


if __name__ == "__main__":
    main()
