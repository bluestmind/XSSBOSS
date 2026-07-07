"""Import HackerOne and YesWeHack programs into XSS Boss targets."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROFILE = Path.home() / ".xssboss" / "browser_profile"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("DATABASE_URL", f"sqlite:///{ROOT / 'xssboss.db'}")
os.environ.setdefault("BUG_BOUNTY_BROWSER_PROFILE_PATH", str(DEFAULT_PROFILE))

from backend_api.db.base import init_db, SessionLocal  # noqa: E402
from backend_api.schemas.program_import import ProgramImportRequest  # noqa: E402
from backend_api.services.program_import_service import ProgramImportService  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Import bug bounty program scopes from HackerOne and YesWeHack."
    )
    parser.add_argument(
        "--platform",
        action="append",
        choices=["hackerone", "yeswehack"],
        help="Platform to import. Repeat for both. Defaults to both.",
    )
    parser.add_argument(
        "--handle",
        action="append",
        help="Specific HackerOne handle to import. Repeat for multiple handles.",
    )
    parser.add_argument(
        "--slug",
        action="append",
        help="Specific YesWeHack slug to import. Repeat for multiple slugs.",
    )
    parser.add_argument("--limit", type=int, default=25, help="Max programs per platform.")
    parser.add_argument(
        "--max-scopes",
        type=int,
        default=500,
        help="Max scope entries fetched per program.",
    )
    parser.add_argument(
        "--yeswehack-type",
        action="append",
        choices=["bug-bounty", "vdp", "pentest", "vdp-in-app"],
        help="YesWeHack program type to import. Repeat for multiple types.",
    )
    parser.add_argument(
        "--profile-path",
        default=os.getenv("BUG_BOUNTY_BROWSER_PROFILE_PATH", str(DEFAULT_PROFILE)),
        help="Browser profile path to reference in imported targets.",
    )
    parser.add_argument("--profile-name", default="Default", help="Browser profile directory name.")
    parser.add_argument("--dry-run", action="store_true", help="Preview without writing targets.")
    parser.add_argument(
        "--no-update",
        action="store_true",
        help="Skip existing imported platform programs instead of updating them.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    init_db()
    request = ProgramImportRequest(
        platforms=args.platform or ["hackerone", "yeswehack"],
        handles=args.handle,
        slugs=args.slug,
        limit_per_platform=args.limit,
        max_scopes_per_program=args.max_scopes,
        yeswehack_types=args.yeswehack_type or ["bug-bounty", "vdp", "pentest", "vdp-in-app"],
        update_existing=not args.no_update,
        dry_run=args.dry_run,
        browser_profile_path=args.profile_path,
        browser_profile_name=args.profile_name,
    )

    db = SessionLocal()
    try:
        result = ProgramImportService(db).import_programs(request)
    finally:
        db.close()

    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
    return 1 if result.get("errors") else 0


if __name__ == "__main__":
    raise SystemExit(main())
