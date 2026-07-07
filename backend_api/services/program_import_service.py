"""Import bug bounty programs into the target registry."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup
from sqlalchemy.orm import Session

from pathlib import Path
from backend_api.models.target import Target, TargetStatus


DEFAULT_AUTOMATION_PROFILE = str(Path.home() / ".xssboss" / "browser_profile")
IMPORT_NOTES_TITLE = "=== Platform import ==="
SUPPORTED_PLATFORMS = {"hackerone", "yeswehack"}
YESWEHACK_PROGRAM_TYPES = {"bug-bounty", "vdp", "pentest", "vdp-in-app"}


@dataclass
class NormalizedProgram:
    """Platform-neutral program representation."""

    platform: str
    program_key: str
    name: str
    base_url: str
    program_url: str
    notes: str
    scope_tags: Dict[str, Any]


class ProgramImportService:
    """Fetch platform programs and upsert them as XSS Boss targets."""

    def __init__(self, db: Session):
        self.db = db

    def import_programs(self, request) -> Dict[str, Any]:
        """Import programs from requested platforms."""
        platforms = [_normalize_platform(p) for p in request.platforms]
        requested = list(dict.fromkeys(platforms))
        response = {
            "requested_platforms": requested,
            "dry_run": request.dry_run,
            "imported": 0,
            "updated": 0,
            "skipped": 0,
            "errors": [],
            "targets": [],
        }

        for platform in requested:
            if platform not in SUPPORTED_PLATFORMS:
                response["errors"].append(
                    {
                        "platform": platform,
                        "program_key": None,
                        "message": f"Unsupported platform '{platform}'",
                    }
                )
                response["skipped"] += 1
                continue

            try:
                programs = self._fetch_platform_programs(platform, request)
            except Exception as exc:
                response["errors"].append(
                    {"platform": platform, "program_key": None, "message": str(exc)}
                )
                continue

            for program in programs:
                try:
                    action, target = self._upsert_program(program, request)
                    if action == "created":
                        response["imported"] += 1
                    elif action == "updated":
                        response["updated"] += 1
                    else:
                        response["skipped"] += 1

                    response["targets"].append(
                        {
                            "action": action,
                            "platform": program.platform,
                            "program_key": program.program_key,
                            "name": program.name,
                            "base_url": program.base_url,
                            "target_id": None if request.dry_run or target is None else target.id,
                            "in_scope_count": len(program.scope_tags.get("in_scope", [])),
                            "out_of_scope_count": len(program.scope_tags.get("out_of_scope", [])),
                            "notes": program.notes,
                            "scope_tags": program.scope_tags if request.dry_run else None,
                        }
                    )
                except Exception as exc:
                    response["errors"].append(
                        {
                            "platform": program.platform,
                            "program_key": program.program_key,
                            "message": str(exc),
                        }
                    )

        return response

    def _fetch_platform_programs(self, platform: str, request) -> List[NormalizedProgram]:
        imported_at = _utc_now()
        profile_metadata = _profile_metadata(
            request.browser_profile_path,
            request.browser_profile_name,
        )

        if platform == "hackerone":
            return HackerOneProgramClient(
                limit=request.limit_per_platform,
                max_scopes=request.max_scopes_per_program,
                profile_metadata=profile_metadata,
                imported_at=imported_at,
            ).fetch_programs(request.handles)

        if platform == "yeswehack":
            return YesWeHackProgramClient(
                limit=request.limit_per_platform,
                max_scopes=request.max_scopes_per_program,
                program_types=request.yeswehack_types,
                profile_metadata=profile_metadata,
                imported_at=imported_at,
            ).fetch_programs(request.slugs)

        return []

    def _upsert_program(self, program: NormalizedProgram, request) -> Tuple[str, Optional[Target]]:
        existing = self._find_existing_target(program.platform, program.program_key)
        if existing and not request.update_existing:
            return "skipped", existing

        if request.dry_run:
            return "updated" if existing else "created", existing

        auth_info = {}
        profile_metadata = program.scope_tags.get("browser_profile")
        if profile_metadata:
            auth_info["browser_profile"] = profile_metadata

        if existing:
            existing.name = program.name
            existing.base_url = program.base_url
            existing.bounty_platform = program.platform
            existing.scope_tags = program.scope_tags
            existing.auth_info = auth_info or existing.auth_info
            existing.notes = _merge_import_notes(existing.notes, program.notes)
            self.db.commit()
            self.db.refresh(existing)
            return "updated", existing

        target = Target(
            name=program.name,
            base_url=program.base_url,
            notes=_merge_import_notes(None, program.notes),
            bounty_platform=program.platform,
            scope_tags=program.scope_tags,
            auth_info=auth_info or None,
            status=TargetStatus.RECON_ONLY,
        )
        self.db.add(target)
        self.db.commit()
        self.db.refresh(target)
        return "created", target

    def _find_existing_target(self, platform: str, program_key: str) -> Optional[Target]:
        targets = self.db.query(Target).filter(Target.bounty_platform == platform).all()
        for target in targets:
            scope_tags = target.scope_tags or {}
            keys = {
                str(scope_tags.get("program_key") or ""),
                str(scope_tags.get("program_handle") or ""),
                str(scope_tags.get("program_slug") or ""),
            }
            if program_key in keys:
                return target
        return None


class HackerOneProgramClient:
    """HackerOne API client for hacker program metadata."""

    API_BASE = "https://api.hackerone.com/v1/hackers"

    def __init__(
        self,
        limit: int,
        max_scopes: int,
        profile_metadata: Optional[Dict[str, Any]],
        imported_at: str,
    ):
        self.limit = limit
        self.max_scopes = max_scopes
        self.profile_metadata = profile_metadata
        self.imported_at = imported_at
        self.auth = _hackerone_auth()

    def fetch_programs(self, handles: Optional[Sequence[str]] = None) -> List[NormalizedProgram]:
        with httpx.Client(timeout=30.0, auth=self.auth, headers={"Accept": "application/json"}) as client:
            raw_programs = (
                [self._fetch_program(client, handle) for handle in handles]
                if handles
                else self._fetch_program_list(client)
            )

            programs: List[NormalizedProgram] = []
            for raw_program in raw_programs[: self.limit]:
                attrs = _json_attrs(raw_program)
                handle = str(attrs.get("handle") or raw_program.get("id") or "").strip()
                if not handle:
                    continue
                scopes = self._fetch_structured_scopes(client, handle)
                programs.append(self._normalize(raw_program, scopes))
            return programs

    def _fetch_program_list(self, client: httpx.Client) -> List[Dict[str, Any]]:
        programs: List[Dict[str, Any]] = []
        page = 1
        while len(programs) < self.limit:
            data = _get_json(
                client,
                f"{self.API_BASE}/programs",
                params={"page[number]": page, "page[size]": min(100, self.limit)},
            )
            programs.extend(data.get("data") or [])
            if not _has_next_link(data):
                break
            page += 1
        return programs[: self.limit]

    def _fetch_program(self, client: httpx.Client, handle: str) -> Dict[str, Any]:
        data = _get_json(client, f"{self.API_BASE}/programs/{handle}")
        return data.get("data") or {}

    def _fetch_structured_scopes(self, client: httpx.Client, handle: str) -> List[Dict[str, Any]]:
        scopes: List[Dict[str, Any]] = []
        page = 1
        while len(scopes) < self.max_scopes:
            data = _get_json(
                client,
                f"{self.API_BASE}/programs/{handle}/structured_scopes",
                params={"page[number]": page, "page[size]": min(100, self.max_scopes)},
            )
            scopes.extend(data.get("data") or [])
            if not _has_next_link(data):
                break
            page += 1
        return scopes[: self.max_scopes]

    def _normalize(self, raw_program: Dict[str, Any], raw_scopes: List[Dict[str, Any]]) -> NormalizedProgram:
        attrs = _json_attrs(raw_program)
        handle = str(attrs.get("handle") or raw_program.get("id")).strip()
        name = str(attrs.get("name") or handle).strip()
        program_url = f"https://hackerone.com/{handle}"
        scopes = [_normalize_hackerone_scope(scope) for scope in raw_scopes]
        in_scope = _dedupe(
            scope["asset"] for scope in scopes if scope.get("eligible_for_submission", True)
        )
        out_of_scope = _dedupe(
            scope["asset"] for scope in scopes if scope.get("eligible_for_submission") is False
        )
        base_url = _choose_base_url(in_scope) or program_url
        policy_text = _strip_markup(attrs.get("policy") or "")

        scope_tags = {
            "platform": "hackerone",
            "source": "hackerone_api",
            "program_key": handle,
            "program_handle": handle,
            "program_url": program_url,
            "imported_at": self.imported_at,
            "last_synced_at": self.imported_at,
            "in_scope": in_scope,
            "out_of_scope": out_of_scope,
            "structured_scopes": scopes,
            "program": _compact_dict(
                {
                    "id": raw_program.get("id"),
                    "name": name,
                    "handle": handle,
                    "state": attrs.get("state"),
                    "submission_state": attrs.get("submission_state"),
                    "offers_bounties": attrs.get("offers_bounties"),
                    "open_scope": attrs.get("open_scope"),
                    "currency": attrs.get("currency"),
                    "bookmarked": attrs.get("bookmarked"),
                    "triage_active": attrs.get("triage_active"),
                    "gold_standard_safe_harbor": attrs.get("gold_standard_safe_harbor"),
                    "fast_payments": attrs.get("fast_payments"),
                    "policy": policy_text,
                }
            ),
        }
        if self.profile_metadata:
            scope_tags["browser_profile"] = self.profile_metadata

        return NormalizedProgram(
            platform="hackerone",
            program_key=handle,
            name=name,
            base_url=base_url,
            program_url=program_url,
            notes=_build_notes(
                platform="HackerOne",
                name=name,
                program_url=program_url,
                imported_at=self.imported_at,
                in_scope_count=len(in_scope),
                out_scope_count=len(out_of_scope),
                extra=[
                    f"Handle: {handle}",
                    f"Submission state: {attrs.get('submission_state') or 'unknown'}",
                    f"Offers bounties: {_yes_no(attrs.get('offers_bounties'))}",
                    f"Open scope: {_yes_no(attrs.get('open_scope'))}",
                ],
            ),
            scope_tags=scope_tags,
        )


class YesWeHackProgramClient:
    """YesWeHack API client for program metadata."""

    DEFAULT_API_BASE = "https://apps.yeswehack.com"

    def __init__(
        self,
        limit: int,
        max_scopes: int,
        program_types: Sequence[str],
        profile_metadata: Optional[Dict[str, Any]],
        imported_at: str,
    ):
        self.limit = limit
        self.max_scopes = max_scopes
        self.program_types = [_normalize_ywh_type(t) for t in program_types if _normalize_ywh_type(t)]
        self.profile_metadata = profile_metadata
        self.imported_at = imported_at
        self.api_base = os.getenv("YESWEHACK_API_BASE", self.DEFAULT_API_BASE).rstrip("/")
        self.headers = _yeswehack_headers()

    def fetch_programs(self, slugs: Optional[Sequence[str]] = None) -> List[NormalizedProgram]:
        with httpx.Client(timeout=30.0, headers=self.headers) as client:
            raw_programs = (
                [self._fetch_program(client, slug) for slug in slugs]
                if slugs
                else self._fetch_hunter_programs(client)
            )

            programs: List[NormalizedProgram] = []
            seen = set()
            for raw_program in raw_programs:
                slug = _ywh_slug(raw_program)
                if not slug or slug in seen:
                    continue
                seen.add(slug)
                detail = raw_program
                if not _has_detail_scope_data(detail):
                    try:
                        detail = self._fetch_program(client, slug)
                    except Exception:
                        detail = raw_program
                scopes = self._fetch_scopes(client, slug, detail)
                programs.append(self._normalize(detail, scopes))
                if len(programs) >= self.limit:
                    break
            return programs

    def _fetch_hunter_programs(self, client: httpx.Client) -> List[Dict[str, Any]]:
        programs: List[Dict[str, Any]] = []
        errors: List[str] = []
        types = self.program_types or sorted(YESWEHACK_PROGRAM_TYPES)
        for program_type in types:
            try:
                data = _get_json(
                    client,
                    f"{self.api_base}/v2/hunter/access/programs/{program_type}",
                )
            except RuntimeError as exc:
                errors.append(str(exc))
                continue
            programs.extend(data.get("items") or data.get("data") or [])
            if len(programs) >= self.limit:
                break

        if len(programs) < self.limit:
            try:
                public_progs = self._fetch_public_programs(client)
                seen_slugs = {str(p.get("slug") or p.get("program_slug") or p.get("pid") or p.get("public_id") or "").strip() for p in programs}
                for p in public_progs:
                    slug = str(p.get("slug") or p.get("program_slug") or p.get("pid") or p.get("public_id") or "").strip()
                    if slug and slug not in seen_slugs:
                        programs.append(p)
                        seen_slugs.add(slug)
            except Exception as exc:
                if not programs:
                    if errors:
                        raise RuntimeError("; ".join([*errors, str(exc)]))
                    raise

        return programs[: self.limit]

    def _fetch_public_programs(self, client: httpx.Client) -> List[Dict[str, Any]]:
        programs: List[Dict[str, Any]] = []
        page = 1
        while len(programs) < self.limit:
            data = _get_json(
                client,
                f"{self.api_base}/programs",
                params={"page": page, "resultsPerPage": min(100, self.limit)},
            )
            programs.extend(data.get("items") or data.get("data") or [])
            nb_pages = int(data.get("nb_pages") or data.get("pagination", {}).get("nb_pages") or page)
            if page >= nb_pages:
                break
            page += 1
        return programs[: self.limit]

    def _fetch_program(self, client: httpx.Client, slug: str) -> Dict[str, Any]:
        return _get_json(client, f"{self.api_base}/programs/{slug}")

    def _fetch_scopes(
        self,
        client: httpx.Client,
        slug: str,
        detail: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        scopes = _extract_ywh_scopes(detail)
        if scopes:
            return scopes[: self.max_scopes]

        data = _get_json(client, f"{self.api_base}/programs/{slug}/scopes")
        return (data.get("items") or data.get("data") or [])[: self.max_scopes]

    def _normalize(self, raw_program: Dict[str, Any], raw_scopes: List[Dict[str, Any]]) -> NormalizedProgram:
        slug = _ywh_slug(raw_program)
        name = str(raw_program.get("title") or raw_program.get("name") or slug).strip()
        program_url = f"https://yeswehack.com/programs/{slug}"
        scopes = [_normalize_yeswehack_scope(scope) for scope in raw_scopes]
        in_scope = _dedupe(
            scope["asset"] for scope in scopes if not _is_ywh_out_of_scope(scope)
        )
        out_of_scope = _dedupe(
            scope["asset"] for scope in scopes if _is_ywh_out_of_scope(scope)
        )
        base_url = _choose_base_url(in_scope) or program_url

        scope_tags = {
            "platform": "yeswehack",
            "source": "yeswehack_api",
            "program_key": slug,
            "program_slug": slug,
            "program_url": program_url,
            "imported_at": self.imported_at,
            "last_synced_at": self.imported_at,
            "in_scope": in_scope,
            "out_of_scope": out_of_scope,
            "structured_scopes": scopes,
            "program": _compact_dict(
                {
                    "public_id": raw_program.get("public_id") or raw_program.get("pid"),
                    "title": name,
                    "slug": slug,
                    "type": raw_program.get("type"),
                    "status": raw_program.get("status"),
                    "public": raw_program.get("public"),
                    "bounty": raw_program.get("bounty"),
                    "vdp": raw_program.get("vdp"),
                    "archived": raw_program.get("archived"),
                    "demo": raw_program.get("demo"),
                    "scopes_count": raw_program.get("scopes_count"),
                    "last_update_at": raw_program.get("last_update_at"),
                    "rules": _strip_markup(raw_program.get("rules") or raw_program.get("description") or ""),
                }
            ),
        }
        if self.profile_metadata:
            scope_tags["browser_profile"] = self.profile_metadata

        return NormalizedProgram(
            platform="yeswehack",
            program_key=slug,
            name=name,
            base_url=base_url,
            program_url=program_url,
            notes=_build_notes(
                platform="YesWeHack",
                name=name,
                program_url=program_url,
                imported_at=self.imported_at,
                in_scope_count=len(in_scope),
                out_scope_count=len(out_of_scope),
                extra=[
                    f"Slug: {slug}",
                    f"Type: {raw_program.get('type') or 'unknown'}",
                    f"Status: {raw_program.get('status') or 'unknown'}",
                    f"Bounty: {_yes_no(raw_program.get('bounty'))}",
                ],
            ),
            scope_tags=scope_tags,
        )


def _get_json(client: httpx.Client, url: str, **kwargs) -> Dict[str, Any]:
    response = client.get(url, **kwargs)
    if response.status_code >= 400:
        raise RuntimeError(f"{response.status_code} from {url}: {_safe_error_text(response)}")
    data = response.json()
    return data if isinstance(data, dict) else {"items": data}


def _safe_error_text(response: httpx.Response) -> str:
    try:
        data = response.json()
        if isinstance(data, dict):
            return str(data.get("message") or data.get("detail") or data.get("errors") or "request failed")
    except Exception:
        pass
    return response.text[:240] or "request failed"


def _hackerone_auth() -> Tuple[str, str]:
    username = os.getenv("HACKERONE_USERNAME") or os.getenv("H1_USERNAME")
    token = (
        os.getenv("HACKERONE_API_TOKEN")
        or os.getenv("HACKERONE_TOKEN")
        or os.getenv("H1_API_TOKEN")
        or os.getenv("H1_TOKEN")
    )
    if not username or not token:
        raise RuntimeError(
            "Missing HackerOne API credentials. Set HACKERONE_USERNAME and HACKERONE_API_TOKEN."
        )
    return username, token


def _yeswehack_headers() -> Dict[str, str]:
    pat = (
        os.getenv("YESWEHACK_PAT")
        or os.getenv("YWH_PAT")
        or os.getenv("YESWEHACK_API_TOKEN")
        or os.getenv("YWH_API_TOKEN")
    )
    oauth = (
        os.getenv("YESWEHACK_OAUTH_TOKEN")
        or os.getenv("YESWEHACK_TOKEN")
        or os.getenv("YWH_OAUTH_TOKEN")
        or os.getenv("YWH_TOKEN")
    )
    if not pat and not oauth:
        raise RuntimeError(
            "Missing YesWeHack credentials. Set YESWEHACK_PAT/YWH_PAT or YESWEHACK_OAUTH_TOKEN."
        )

    headers = {"Accept": "application/json"}
    if pat:
        headers["X-AUTH-TOKEN"] = pat
    if oauth:
        headers["Authorization"] = f"Bearer {oauth}"
    return headers


def _normalize_platform(platform: str) -> str:
    return platform.strip().lower().replace(" ", "").replace("-", "")


def _normalize_ywh_type(value: str) -> Optional[str]:
    normalized = value.strip().lower()
    return normalized if normalized in YESWEHACK_PROGRAM_TYPES else None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _profile_metadata(
    requested_path: Optional[str],
    profile_name: Optional[str],
) -> Optional[Dict[str, Any]]:
    profile_path = (
        requested_path
        or os.getenv("BUG_BOUNTY_BROWSER_PROFILE_PATH")
        or DEFAULT_AUTOMATION_PROFILE
    )
    if profile_path:
        profile_path = os.path.expandvars(os.path.expanduser(profile_path))

    if not profile_path:
        return None

    return {
        "path": profile_path,
        "profile_directory": profile_name or os.getenv("BUG_BOUNTY_BROWSER_PROFILE_NAME") or "Default",
        "source_project": "xss-boss",
        "note": "Path reference only. Cookies and secrets are not copied into XSS Boss.",
    }


def _json_attrs(resource: Dict[str, Any]) -> Dict[str, Any]:
    attrs = resource.get("attributes")
    return attrs if isinstance(attrs, dict) else resource


def _has_next_link(data: Dict[str, Any]) -> bool:
    links = data.get("links") or {}
    return bool(links.get("next"))


def _normalize_hackerone_scope(scope: Dict[str, Any]) -> Dict[str, Any]:
    attrs = _json_attrs(scope)
    asset = str(attrs.get("asset_identifier") or attrs.get("identifier") or "").strip()
    return _compact_dict(
        {
            "id": scope.get("id"),
            "asset": asset,
            "asset_type": attrs.get("asset_type"),
            "eligible_for_submission": attrs.get("eligible_for_submission"),
            "eligible_for_bounty": attrs.get("eligible_for_bounty"),
            "max_severity": attrs.get("max_severity"),
            "instruction": _strip_markup(attrs.get("instruction") or ""),
            "created_at": attrs.get("created_at"),
            "updated_at": attrs.get("updated_at"),
            "confidentiality_requirement": attrs.get("confidentiality_requirement"),
            "integrity_requirement": attrs.get("integrity_requirement"),
            "availability_requirement": attrs.get("availability_requirement"),
        }
    )


def _normalize_yeswehack_scope(scope: Dict[str, Any]) -> Dict[str, Any]:
    asset = str(
        scope.get("asset_value")
        or scope.get("asset")
        or scope.get("value")
        or scope.get("scope")
        or ""
    ).strip()
    return _compact_dict(
        {
            "id": scope.get("id") or scope.get("public_id"),
            "asset": asset,
            "asset_type": scope.get("scope_type")
            or scope.get("scope_type_name")
            or scope.get("type")
            or scope.get("asset_type"),
            "scope": scope.get("scope"),
            "scope_type": scope.get("scope_type"),
            "scope_type_name": scope.get("scope_type_name"),
            "eligible_for_submission": scope.get("eligible_for_submission"),
            "eligible_for_bounty": scope.get("eligible_for_bounty") or scope.get("eligible"),
            "out_of_scope": scope.get("out_of_scope") or scope.get("outOfScope"),
            "instruction": _strip_markup(scope.get("instruction") or scope.get("description") or ""),
            "report_count": scope.get("report_count"),
        }
    )


def _extract_ywh_scopes(detail: Dict[str, Any]) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []
    for key in ("scopes", "scope", "in_scope", "out_of_scope", "out_of_scopes", "excluded_scopes"):
        value = detail.get(key)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    if key in {"out_of_scope", "out_of_scopes", "excluded_scopes"}:
                        item = {**item, "out_of_scope": True}
                    candidates.append(item)
                elif item:
                    candidates.append({"asset_value": str(item), "out_of_scope": key.startswith("out")})
    return candidates


def _has_detail_scope_data(detail: Dict[str, Any]) -> bool:
    return bool(_extract_ywh_scopes(detail))


def _is_ywh_out_of_scope(scope: Dict[str, Any]) -> bool:
    if scope.get("out_of_scope") is True:
        return True
    eligible = scope.get("eligible_for_submission")
    return eligible is False


def _ywh_slug(program: Dict[str, Any]) -> str:
    return str(
        program.get("slug")
        or program.get("program_slug")
        or program.get("pid")
        or program.get("public_id")
        or ""
    ).strip()


def _choose_base_url(scope_values: Sequence[str]) -> Optional[str]:
    for value in scope_values:
        base_url = _asset_to_base_url(value)
        if base_url:
            return base_url
    return None


def _asset_to_base_url(value: str) -> Optional[str]:
    raw = value.strip()
    if not raw:
        return None

    if raw.startswith("*."):
        raw = raw[2:]

    if "://" in raw:
        parsed = urlparse(raw)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"

    if _looks_like_hostname(raw):
        return f"https://{raw.strip('/')}"

    return None


def _looks_like_hostname(value: str) -> bool:
    if "/" in value or " " in value or "@" in value:
        return False
    return bool(re.match(r"^(?:\*\.)?[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$", value))


def _strip_markup(value: str) -> str:
    if not value:
        return ""
    text = BeautifulSoup(str(value), "html.parser").get_text("\n")
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def _dedupe(values: Iterable[str]) -> List[str]:
    seen = set()
    deduped: List[str] = []
    for value in values:
        normalized = str(value or "").strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        deduped.append(normalized)
    return deduped


def _compact_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    return {key: value for key, value in data.items() if value not in (None, "", [], {})}


def _build_notes(
    platform: str,
    name: str,
    program_url: str,
    imported_at: str,
    in_scope_count: int,
    out_scope_count: int,
    extra: Sequence[str],
) -> str:
    lines = [
        IMPORT_NOTES_TITLE,
        f"Imported from {platform}: {name}",
        f"Program URL: {program_url}",
        f"Last synced: {imported_at}",
        f"In-scope assets: {in_scope_count}",
        f"Out-of-scope assets: {out_scope_count}",
        *[line for line in extra if line and not line.endswith("None")],
        "Verify the current program rules before testing; platform scope can change.",
    ]
    return "\n".join(lines)


def _merge_import_notes(existing_notes: Optional[str], import_notes: str) -> str:
    if not existing_notes:
        return import_notes

    prefix = existing_notes.split(IMPORT_NOTES_TITLE, 1)[0].strip()
    return f"{prefix}\n\n{import_notes}" if prefix else import_notes


def _yes_no(value: Any) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "unknown"
