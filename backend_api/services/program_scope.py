"""Program-centric scope engine — the unit of work becomes a *program*, not a URL.

A HackerOne program (imported by ``HackerOneScraperService`` into ``Target.scope_tags``) carries
many in-scope assets, each with its own ``asset_type``, ``eligible_for_bounty`` and ``max_severity``,
plus out-of-scope exclusions. This engine turns that raw scope into two things the pipeline needs:

* :meth:`worklist` — a **prioritized list of web assets** to hunt (bounty-eligible + highest
  max-severity first), so a scarce request budget is spent where the payout is.
* :meth:`to_burp_scope` — a **Burp Suite scope configuration** (include/exclude host regexes) so
  Burp's proxy/scanner is constrained to exactly the program's boundary — full Burp advantage
  without ever straying out of scope.

Both are pure transforms over ``scope_tags``: no network, no DB, fully testable.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urlunparse

from backend_api.utils.scope_guard import scope_rule_matches_url

# Asset types worth fuzzing for web XSS (mobile/binary/source assets are skipped).
_WEB_ASSET_TYPES = {"URL", "DOMAIN", "WILDCARD", "API", "IP_ADDRESS", "CIDR", "OTHER", ""}
_SKIP_ASSET_TYPES = {
    "GOOGLE_PLAY_APP_ID", "APPLE_STORE_APP_ID", "OTHER_APK", "TESTFLIGHT",
    "SOURCE_CODE", "DOWNLOADABLE_EXECUTABLES", "HARDWARE", "AI_MODEL", "SMART_CONTRACT",
}
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0, "": 0}


@dataclass
class ScopeAsset:
    identifier: str
    asset_type: str = ""
    eligible_for_bounty: bool = False
    max_severity: str = ""
    instruction: str = ""
    source_identifier: str = ""

    @property
    def is_wildcard(self) -> bool:
        raw = self.identifier.strip().lower()
        # The type label alone is not authorization to widen an exact host.
        return raw.startswith("*.") or "://* .".replace(" ", "") in raw

    @property
    def host(self) -> str:
        return _extract_host(self.identifier)

    @property
    def path_pattern(self) -> str:
        parsed = _parse_identifier(self.identifier)
        return parsed.path or "/"

    @property
    def is_path_scoped(self) -> bool:
        parsed = _parse_identifier(self.source_identifier or self.identifier)
        return (parsed.path or "/") not in {"", "/"} or bool(parsed.query)

    @property
    def scope_key(self) -> str:
        return (self.identifier or self.host).strip().lower()

    @property
    def seed_url(self) -> Optional[str]:
        """Return a concrete authorized seed, or ``None`` for unresolved rules."""
        if self.is_wildcard:
            return None
        parsed = _parse_identifier(self.identifier)
        scheme = parsed.scheme.lower() if "://" in self.identifier else "https"
        if scheme not in {"http", "https"} or not parsed.hostname:
            return None
        try:
            port = parsed.port
        except ValueError:
            return None
        host = parsed.hostname.lower().strip(".")
        netloc = f"{host}:{port}" if port is not None else host
        path = parsed.path or "/"
        # A trailing star has a safe empty-prefix seed. More complex glob paths
        # need an observed concrete URL rather than a guessed request.
        if "*" in path:
            if not re.fullmatch(r"[^*]*\**", path):
                return None
            path = path.rstrip("*") or "/"
        query = parsed.query
        if "*" in query or "?" in query:
            return None
        seed = urlunparse((scheme, netloc, path, "", query, ""))
        return seed if scope_rule_matches_url(self.identifier, seed) else None

    @property
    def is_web(self) -> bool:
        atype = (self.asset_type or "").upper()
        if atype in _SKIP_ASSET_TYPES:
            return False
        return bool(self.host) and atype in _WEB_ASSET_TYPES

    @property
    def severity_rank(self) -> int:
        return _SEVERITY_RANK.get((self.max_severity or "").lower(), 0)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "identifier": self.identifier,
            "source_identifier": self.source_identifier or self.identifier,
            "asset_type": self.asset_type,
            "host": self.host,
            "seed_url": self.seed_url,
            "path_pattern": self.path_pattern,
            "eligible_for_bounty": self.eligible_for_bounty,
            "max_severity": self.max_severity,
            "is_wildcard": self.is_wildcard,
            "is_path_scoped": self.is_path_scoped,
        }


def _extract_host(value: str) -> str:
    """Best-effort host from a URL / bare domain / wildcard identifier."""
    if not value:
        return ""
    raw = value.strip()
    if raw.startswith("*."):
        raw = raw[2:]
    try:
        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        host = (parsed.hostname or "").strip().lower().strip(".")
        return host
    except Exception:
        # Fallback if bracketed text or invalid characters cause urlparse ValueError
        cleaned = re.sub(r"[\[\]<>\s]", "", raw)
        try:
            parsed = urlparse(cleaned if "://" in cleaned else f"https://{cleaned}")
            return (parsed.hostname or "").strip().lower().strip(".")
        except Exception:
            return ""


def _parse_identifier(value: str):
    raw = str(value or "").strip()
    return urlparse(raw if "://" in raw else f"https://{raw}")


def _host_to_regex(asset: "ScopeAsset") -> Optional[str]:
    host = asset.host
    if not host:
        return None
    escaped = re.escape(host)
    # An explicit *.example rule covers subdomains only; the apex needs its
    # own exact scope entry.
    return f"^(?:[^.]+\\.)+{escaped}$" if asset.is_wildcard else f"^{escaped}$"


def _path_to_regex(asset: "ScopeAsset") -> str:
    path = asset.path_pattern or "/"
    if path in {"", "/"}:
        return "^/.*"
    if "*" in path or "?" in path:
        escaped = re.escape(path).replace(r"\*", ".*").replace(r"\?", ".")
        return f"^{escaped}$"
    prefix = re.escape(path.rstrip("/"))
    return f"^{prefix}(?:/.*)?$"


def _coerce_asset(item: Any) -> Optional[ScopeAsset]:
    """Accept both rich dict items and bare host strings."""
    if isinstance(item, str):
        ident = item.strip()
        return ScopeAsset(identifier=ident, asset_type="") if ident else None
    if isinstance(item, dict):
        ident = str(item.get("asset_identifier") or item.get("identifier") or "").strip()
        if not ident:
            return None
        return ScopeAsset(
            identifier=ident,
            asset_type=str(item.get("asset_type") or ""),
            eligible_for_bounty=bool(item.get("eligible_for_bounty", False)),
            max_severity=str(item.get("max_severity") or ""),
            instruction=str(item.get("instruction") or ""),
        )
    return None


@dataclass
class ProgramScope:
    handle: str = ""
    offers_bounties: bool = False
    in_scope: List[ScopeAsset] = field(default_factory=list)
    out_of_scope: List[ScopeAsset] = field(default_factory=list)

    # ---------------------------------------------------------------- construction

    @classmethod
    def from_scope_tags(cls, scope_tags: Optional[Dict[str, Any]]) -> "ProgramScope":
        tags = scope_tags or {}
        raw_in = list(tags.get("in_scope", []) or [])
        structured = list(tags.get("structured_scopes", []) or [])
        if raw_in and structured:
            rich_by_identifier = {
                str(item.get("asset_identifier") or item.get("identifier") or "").strip(): item
                for item in structured if isinstance(item, dict)
            }
            raw_in = [
                rich_by_identifier.get(item, item) if isinstance(item, str) else item
                for item in raw_in
            ]
        elif not raw_in and structured:
            raw_in = structured
        in_assets = [a for a in (_coerce_asset(i) for i in raw_in) if a]
        out_assets = [a for a in (_coerce_asset(i) for i in tags.get("out_of_scope", []) or []) if a]
        # Fall back to the flat web_targets list if in_scope carried no rich items.
        if not in_assets and tags.get("web_targets"):
            in_assets = [a for a in (_coerce_asset(i) for i in tags["web_targets"]) if a]
        return cls(
            handle=str(tags.get("handle") or tags.get("program_handle") or ""),
            offers_bounties=bool(
                tags.get("offers_bounties", (tags.get("program") or {}).get("offers_bounties", False))
            ),
            in_scope=in_assets,
            out_of_scope=out_assets,
        )

    @classmethod
    def from_target(cls, target: Any) -> "ProgramScope":
        return cls.from_scope_tags(getattr(target, "scope_tags", None))

    # ---------------------------------------------------------------- worklist

    def web_assets(self) -> List[ScopeAsset]:
        return [a for a in self.in_scope if a.is_web]

    def contains_url(self, url: str) -> bool:
        """Apply complete include/exclude precedence to one concrete URL."""
        if any(scope_rule_matches_url(a.identifier, url) for a in self.out_of_scope):
            return False
        return any(scope_rule_matches_url(a.identifier, url) for a in self.web_assets())

    def worklist(self, bounty_first: bool = True) -> List[ScopeAsset]:
        """Prioritized hunting order: bounty-eligible + highest max-severity first."""
        assets = self.web_assets()

        def key(a: ScopeAsset):
            bounty = 1 if (a.eligible_for_bounty and self.offers_bounties) else 0
            # Wildcards last within a tier: a concrete host is a cheaper first probe than a whole tree.
            wildcard_penalty = 1 if a.is_wildcard else 0
            return (
                -(bounty if bounty_first else 0),
                -a.severity_rank,
                wildcard_penalty,
                a.host,
            )

        return sorted(assets, key=key)

    def concrete_worklist(self, candidate_urls: Optional[List[str]] = None) -> List[ScopeAsset]:
        """Resolve scope rules to concrete, revalidated execution seeds.

        Wildcard hosts are never converted to their apex. They run only when a
        previously observed endpoint supplies a matching concrete subdomain.
        """
        candidates = list(dict.fromkeys(str(url) for url in (candidate_urls or []) if url))
        resolved: List[ScopeAsset] = []
        seen = set()
        for rule in self.worklist():
            seeds: List[str] = []
            if rule.seed_url and self.contains_url(rule.seed_url):
                seeds.append(rule.seed_url)
            if rule.seed_url is None:
                for candidate in candidates:
                    if scope_rule_matches_url(rule.identifier, candidate) and self.contains_url(candidate):
                        parsed = urlparse(candidate)
                        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
                            continue
                        if rule.is_path_scoped:
                            seed = parsed._replace(fragment="").geturl()
                        else:
                            host = parsed.hostname.lower().strip(".")
                            try:
                                port = parsed.port
                            except ValueError:
                                continue
                            netloc = f"{host}:{port}" if port is not None else host
                            seed = urlunparse((parsed.scheme.lower(), netloc, "/", "", "", ""))
                        if self.contains_url(seed):
                            seeds.append(seed)
            for seed in seeds:
                key = seed.lower()
                if key in seen:
                    continue
                seen.add(key)
                resolved.append(ScopeAsset(
                    identifier=seed,
                    source_identifier=rule.identifier,
                    asset_type="URL",
                    eligible_for_bounty=rule.eligible_for_bounty,
                    max_severity=rule.max_severity,
                    instruction=rule.instruction,
                ))
        return resolved

    # ---------------------------------------------------------------- burp scope

    def to_burp_scope(self, protocol: str = "any") -> Dict[str, Any]:
        """Emit a Burp Suite advanced-scope config so Burp stays inside the program boundary."""
        def rule(asset: ScopeAsset) -> Optional[Dict[str, Any]]:
            host_rx = _host_to_regex(asset)
            if not host_rx:
                return None
            parsed = _parse_identifier(asset.identifier)
            # Burp's advanced scope schema has no query-pattern field. Mapping
            # a query-constrained program rule to its path would silently
            # authorize every query on that path, so omit it instead.
            if parsed.query:
                return None
            rule_protocol = parsed.scheme.lower() if "://" in asset.identifier else protocol
            try:
                rule_port = str(parsed.port) if parsed.port is not None else ""
            except ValueError:
                return None
            return {
                "enabled": True,
                "protocol": rule_protocol,
                "host": host_rx,
                "file": _path_to_regex(asset),
                "port": rule_port,
            }

        include = [r for r in (rule(a) for a in self.web_assets()) if r]
        exclude = [r for r in (rule(a) for a in self.out_of_scope) if r]
        # Preserve independent path and port rules on the same host. Collapsing
        # only by host silently widens or drops path-scoped program assets.
        def dedupe(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
            seen = set()
            result = []
            for item in rules:
                key = (
                    item["protocol"], item["host"], item["port"], item["file"]
                )
                if key not in seen:
                    seen.add(key)
                    result.append(item)
            return result

        include = dedupe(include)
        exclude = dedupe(exclude)
        return {"target": {"scope": {"advanced_mode": True, "include": include, "exclude": exclude}}}

    def burp_include_prefixes(self) -> List[str]:
        """URL prefixes for `api.scope().includeInScope(...)` calls from the Montoya extension."""
        prefixes = []
        for a in self.web_assets():
            # URL-prefix matching cannot faithfully express wildcard, path
            # boundary, or query rules ("/app" also prefixes "/application").
            # Advanced regex rules are authoritative for those assets.
            if a.is_wildcard or a.is_path_scoped:
                continue
            seed = a.seed_url
            if seed and seed not in prefixes and self.contains_url(seed):
                prefixes.append(seed)
        return prefixes

    def has_host_exclusions(self, url: str) -> bool:
        """Return whether an automated crawler could meet an exclusion on this host."""
        try:
            candidate_host = (urlparse(url).hostname or "").lower().strip(".")
        except Exception:
            return True
        if not candidate_host:
            return True
        for excluded in self.out_of_scope:
            excluded_host = excluded.host
            if not excluded_host:
                continue
            if excluded.is_wildcard:
                if candidate_host != excluded_host and candidate_host.endswith(f".{excluded_host}"):
                    return True
            elif candidate_host == excluded_host:
                return True
        return False

    def summary(self) -> Dict[str, Any]:
        wl = self.worklist()
        return {
            "handle": self.handle,
            "offers_bounties": self.offers_bounties,
            "web_assets": len(self.web_assets()),
            "bounty_eligible_assets": sum(1 for a in self.web_assets() if a.eligible_for_bounty),
            "exclusions": len(self.out_of_scope),
            "top_priority": [a.host for a in wl[:5]],
        }
