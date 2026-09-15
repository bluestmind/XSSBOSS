#!/usr/bin/env python3
"""Standalone Tool: Full HackerOne Bug Bounty Program, Scopes, and Assets Scraper.

Usage:
    python tools/import_hackerone_scraper.py --list
    python tools/import_hackerone_scraper.py --handle oppo_bbp
    python tools/import_hackerone_scraper.py --sync --bounty-only --limit 50
    python tools/import_hackerone_scraper.py --export-json hackerone_all.json
    python tools/import_hackerone_scraper.py --export-csv hackerone_all.csv
"""
import argparse
import json
import sys
from pathlib import Path

# Add project root to sys.path
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from backend_api.services.hackerone_scraper_service import HackerOneScraperService
from backend_api.db.session import SessionLocal


def main():
    parser = argparse.ArgumentParser(
        description="Scrape HackerOne bug bounty programs, in-scope targets, and rules."
    )
    parser.add_argument("--list", action="store_true", help="List all public HackerOne programs.")
    parser.add_argument("--handle", type=str, default=None, help="Inspect/import a specific program handle.")
    parser.add_argument("--query", "-q", type=str, default=None, help="Search filter by name or handle.")
    parser.add_argument("--bounty-only", action="store_true", default=False, help="Filter for bounty-paying programs only.")
    parser.add_argument("--asset-type", type=str, default=None, help="Filter by asset type (e.g. URL, DOMAIN, WILDCARD).")
    parser.add_argument("--limit", type=int, default=100, help="Max programs to process.")
    parser.add_argument("--sync", action="store_true", help="Sync fetched programs into the XSS Boss Target database.")
    parser.add_argument("--export-json", type=str, default=None, help="Save all scraped data to a JSON file.")
    parser.add_argument("--export-csv", type=str, default=None, help="Save all scraped data to a CSV file.")

    args = parser.parse_args()

    print("[*] Fetching HackerOne public directory and structured scopes...")
    if args.handle:
        prog = HackerOneScraperService.fetch_program_by_handle(args.handle)
        if not prog:
            print(f"[-] Error: Program @{args.handle} not found.")
            sys.exit(1)
        print(f"\n=== Program: {prog['name']} (@{prog['handle']}) ===")
        print(f"  URL:             {prog['url']}")
        print(f"  Website:         {prog['website']}")
        print(f"  Bounty Paying:   {prog['offers_bounties']}")
        print(f"  In-Scope Count:  {prog['in_scope_count']}")
        print(f"  Out-Scope Count: {prog['out_of_scope_count']}")
        print(f"\n--- In-Scope Targets ({len(prog['in_scope'])}) ---")
        for item in prog["in_scope"][:30]:
            print(f"  - {item.get('asset_identifier')} [{item.get('asset_type')}] (Bounty: {item.get('eligible_for_bounty')})")
        if len(prog["in_scope"]) > 30:
            print(f"  ... and {len(prog['in_scope']) - 30} more.")

        if args.sync:
            db = SessionLocal()
            try:
                target = HackerOneScraperService.import_program_as_target(db, prog)
                print(f"\n[+] Synced @{prog['handle']} to Target DB (ID: {target.id})")
            finally:
                db.close()
        return

    programs = HackerOneScraperService.fetch_all_programs(
        bounty_only=args.bounty_only,
        query=args.query,
        asset_type=args.asset_type,
        limit=args.limit,
    )
    print(f"[+] Loaded {len(programs)} programs.")

    if args.list or (not args.sync and not args.export_json and not args.export_csv):
        print(f"\n{'#':<4} {'NAME':<35} {'HANDLE':<20} {'BOUNTY':<8} {'SCOPES':<8} {'PRIMARY URL'}")
        print("-" * 105)
        for i, p in enumerate(programs[: args.limit], 1):
            b_str = "YES" if p["offers_bounties"] else "NO"
            primary = p["primary_url"][:40] + ("..." if len(p["primary_url"]) > 40 else "")
            print(f"{i:<4} {p['name'][:34]:<35} @{p['handle'][:18]:<19} {b_str:<8} {p['in_scope_count']:<8} {primary}")

    if args.sync:
        db = SessionLocal()
        try:
            print(f"\n[*] Syncing {len(programs)} programs into XSS Boss Target registry...")
            res = HackerOneScraperService.bulk_sync_to_database(
                db=db,
                bounty_only=args.bounty_only,
                limit=args.limit,
            )
            print(f"[+] Successfully synced {res['imported_count']} targets!")
        finally:
            db.close()

    if args.export_json:
        data = HackerOneScraperService.export_programs(programs, export_format="json")
        with open(args.export_json, "w", encoding="utf-8") as f:
            f.write(data)
        print(f"[+] Exported JSON -> {args.export_json}")

    if args.export_csv:
        data = HackerOneScraperService.export_programs(programs, export_format="csv")
        with open(args.export_csv, "w", encoding="utf-8") as f:
            f.write(data)
        print(f"[+] Exported CSV -> {args.export_csv}")


if __name__ == "__main__":
    main()
