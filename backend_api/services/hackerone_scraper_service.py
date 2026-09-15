"""HackerOne Public Program and Scope Scraper Service."""
from typing import List, Dict, Any, Optional, Sequence
import csv
import io
import json
import logging
from urllib.parse import urlparse
import httpx
from sqlalchemy.orm import Session

from backend_api.models.target import Target, TargetStatus
from backend_api.utils.logger import logger


class HackerOneScraperService:
    """Service for scraping, searching, and importing HackerOne programs and scopes."""

    DATA_SOURCE_URL = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json"
    DIRECTORY_SEARCH_URL = "https://hackerone.com/programs/search"
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

    @classmethod
    def fetch_all_programs(
        cls,
        bounty_only: bool = False,
        query: Optional[str] = None,
        asset_type: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Fetch all HackerOne programs with complete scope details."""
        headers = {
            "User-Agent": cls.USER_AGENT,
            "Accept": "application/json, text/plain, */*",
        }
        from backend_api.utils.stealth import get_http_proxy_kwargs
        proxy_kwargs = get_http_proxy_kwargs(rotated=True)
        try:
            with httpx.Client(timeout=30.0, headers=headers, **proxy_kwargs) as client:
                resp = client.get(cls.DATA_SOURCE_URL)
                if resp.status_code != 200:
                    raise RuntimeError(f"Failed to fetch HackerOne dataset: HTTP {resp.status_code}")
                raw_programs = resp.json()
        except Exception:
            with httpx.Client(timeout=30.0, headers=headers) as client:
                resp = client.get(cls.DATA_SOURCE_URL)
                if resp.status_code != 200:
                    raise RuntimeError(f"Failed to fetch HackerOne dataset: HTTP {resp.status_code}")
                raw_programs = resp.json()

        results: List[Dict[str, Any]] = []
        for p in raw_programs:
            if bounty_only and not p.get("offers_bounties"):
                continue

            name = p.get("name", "")
            handle = p.get("handle", "")
            if query:
                q = query.lower().strip()
                if q not in name.lower() and q not in handle.lower():
                    continue

            in_scope = p.get("targets", {}).get("in_scope", [])
            out_of_scope = p.get("targets", {}).get("out_of_scope", [])

            # Filter by asset type (e.g. URL, DOMAIN, WILDCARD, OTHER, etc.)
            if asset_type:
                target_types = {str(t.get("asset_type", "")).upper() for t in in_scope}
                if asset_type.upper() not in target_types:
                    continue

            # Extract in-scope web targets (URLs and domains)
            web_targets = []
            for t in in_scope:
                atype = str(t.get("asset_type", "")).upper()
                ident = str(t.get("asset_identifier", "")).strip()
                if atype in ("URL", "DOMAIN", "WILDCARD") or ident.startswith("http") or "." in ident:
                    web_targets.append(ident)

            # Determine primary entry URL for target scanning
            primary_url = ""
            if web_targets:
                for wt in web_targets:
                    if wt.startswith("http://") or wt.startswith("https://"):
                        primary_url = wt
                        break
                if not primary_url:
                    clean = web_targets[0].lstrip("*.")
                    primary_url = f"https://{clean}"
            elif p.get("website"):
                primary_url = p.get("website")
            else:
                primary_url = p.get("url", f"https://hackerone.com/{handle}")

            normalized = {
                "id": p.get("id"),
                "name": name,
                "handle": handle,
                "url": p.get("url", f"https://hackerone.com/{handle}"),
                "website": p.get("website"),
                "offers_bounties": bool(p.get("offers_bounties")),
                "offers_swag": bool(p.get("offers_swag")),
                "submission_state": p.get("submission_state", "open"),
                "primary_url": primary_url,
                "in_scope_count": len(in_scope),
                "out_of_scope_count": len(out_of_scope),
                "web_targets_count": len(web_targets),
                "web_targets": web_targets,
                "in_scope": in_scope,
                "out_of_scope": out_of_scope,
                "response_efficiency": p.get("response_efficiency_percentage"),
                "avg_response_time": p.get("average_time_to_first_program_response"),
                "avg_bounty_time": p.get("average_time_to_bounty_awarded"),
            }
            results.append(normalized)
            if limit and len(results) >= limit:
                break

        return results

    @classmethod
    def fetch_program_by_handle(cls, handle: str) -> Optional[Dict[str, Any]]:
        """Look up a specific HackerOne program by handle."""
        target_handle = handle.lower().strip().lstrip("@")
        programs = cls.fetch_all_programs(bounty_only=False, query=target_handle)
        for p in programs:
            if p["handle"].lower() == target_handle:
                return p
        return programs[0] if programs else None

    @classmethod
    def import_program_as_target(
        cls,
        db: Session,
        program_data: Dict[str, Any],
        tenant_id: int = 1,
    ) -> Target:
        """Create or update a Target record in the database from scraped HackerOne program data."""
        handle = program_data.get("handle") or "unknown"
        name = program_data.get("name") or handle
        base_url = program_data.get("primary_url") or f"https://hackerone.com/{handle}"
        if not (base_url.startswith("http://") or base_url.startswith("https://")):
            base_url = f"https://{base_url.lstrip('*.')}"

        # Look for existing target by name or base_url within tenant
        existing = db.query(Target).filter(
            Target.tenant_id == tenant_id,
            (Target.name == name) | (Target.base_url == base_url)
        ).first()

        scope_tags = {
            "platform": "hackerone",
            "handle": handle,
            "program_url": program_data.get("url"),
            "website": program_data.get("website"),
            "offers_bounties": program_data.get("offers_bounties", True),
            "submission_state": program_data.get("submission_state", "open"),
            "in_scope_count": program_data.get("in_scope_count", 0),
            "out_of_scope_count": program_data.get("out_of_scope_count", 0),
            "in_scope": program_data.get("in_scope", []),
            "out_of_scope": program_data.get("out_of_scope", []),
            "web_targets": program_data.get("web_targets", []),
        }

        notes = (
            f"HackerOne Program: {name} (@{handle})\n"
            f"Bounty: {'Yes' if program_data.get('offers_bounties') else 'VDP (No Bounty)'}\n"
            f"In-Scope Assets: {program_data.get('in_scope_count', 0)}\n"
            f"Out-of-Scope Rules: {program_data.get('out_of_scope_count', 0)}\n"
            f"Program Policy: {program_data.get('url')}"
        )

        if existing:
            existing.name = name
            existing.base_url = base_url
            existing.bounty_platform = "hackerone"
            existing.scope_tags = scope_tags
            existing.notes = notes
            db.commit()
            db.refresh(existing)
            logger.info(f"[HackerOneScraper] Updated target ID {existing.id} ({name})")
            return existing
        else:
            new_target = Target(
                tenant_id=tenant_id,
                name=name,
                base_url=base_url,
                bounty_platform="hackerone",
                scope_tags=scope_tags,
                notes=notes,
                status=TargetStatus.RECON_ONLY,
            )
            db.add(new_target)
            db.commit()
            db.refresh(new_target)
            logger.info(f"[HackerOneScraper] Created new target ID {new_target.id} ({name})")
            return new_target

    @classmethod
    def bulk_sync_to_database(
        cls,
        db: Session,
        handles: Optional[Sequence[str]] = None,
        bounty_only: bool = True,
        limit: int = 50,
        tenant_id: int = 1,
    ) -> Dict[str, Any]:
        """Bulk import programs matching handles or top bounty programs into database."""
        imported_targets: List[Dict[str, Any]] = []
        errors: List[str] = []

        if handles:
            for h in handles:
                try:
                    prog = cls.fetch_program_by_handle(h)
                    if not prog:
                        errors.append(f"Handle not found: {h}")
                        continue
                    t = cls.import_program_as_target(db, prog, tenant_id=tenant_id)
                    imported_targets.append({
                        "target_id": t.id,
                        "name": t.name,
                        "handle": h,
                        "base_url": t.base_url,
                        "scopes_count": prog["in_scope_count"]
                    })
                except Exception as exc:
                    errors.append(f"Error importing {h}: {exc}")
        else:
            all_progs = cls.fetch_all_programs(bounty_only=bounty_only, limit=limit)
            for prog in all_progs:
                try:
                    t = cls.import_program_as_target(db, prog, tenant_id=tenant_id)
                    imported_targets.append({
                        "target_id": t.id,
                        "name": t.name,
                        "handle": prog["handle"],
                        "base_url": t.base_url,
                        "scopes_count": prog["in_scope_count"]
                    })
                except Exception as exc:
                    errors.append(f"Error importing {prog.get('handle')}: {exc}")

        return {
            "status": "success",
            "imported_count": len(imported_targets),
            "targets": imported_targets,
            "errors": errors,
        }

    @classmethod
    def export_programs(
        cls,
        programs: List[Dict[str, Any]],
        export_format: str = "json",
    ) -> str:
        """Export scraped program list and scopes as formatted JSON or CSV."""
        if export_format.lower() == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow([
                "Name", "Handle", "URL", "Website", "Offers Bounties",
                "Submission State", "Primary URL", "In-Scope Count", "Out-of-Scope Count", "Web Targets"
            ])
            for p in programs:
                writer.writerow([
                    p.get("name"),
                    p.get("handle"),
                    p.get("url"),
                    p.get("website"),
                    p.get("offers_bounties"),
                    p.get("submission_state"),
                    p.get("primary_url"),
                    p.get("in_scope_count"),
                    p.get("out_of_scope_count"),
                    "; ".join(p.get("web_targets", [])[:10]),
                ])
            return output.getvalue()
        else:
            return json.dumps(programs, indent=2)
