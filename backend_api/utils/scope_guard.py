"""Target scope validation utilities."""
import re
from fnmatch import fnmatchcase
from typing import Iterable, List, Optional
from urllib.parse import unquote, urlparse

from backend_api.models.endpoint import Endpoint
from backend_api.models.target import Target

IN_SCOPE_KEYS = ("allowed_hosts", "in_scope", "domains", "hosts", "web_targets")
OUT_OF_SCOPE_KEYS = (
    "blocked_hosts",
    "deny_hosts",
    "excluded_domains",
    "excluded_hosts",
    "out_of_scope",
    "out_scope",
)


def _hostname(value: str) -> str:
    """Return a normalized hostname from a URL or bare hostname."""
    if not value:
        return ""

    value = value.strip()
    if value.startswith("*."):
        value = value[2:]

    try:
        parsed = urlparse(value if "://" in value else f"https://{value}")
        host = (parsed.hostname or "").lower().strip(".")
    except Exception:
        cleaned = re.sub(r"[\[\]<>\s]", "", value)
        try:
            parsed = urlparse(cleaned if "://" in cleaned else f"https://{cleaned}")
            host = (parsed.hostname or "").lower().strip(".")
        except Exception:
            host = ""

    if host.startswith("*."):
        host = host[2:]
    if not host or any(char in host for char in "\\/%"):
        return ""
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return ""


def _host_pattern(value: str) -> str:
    """Return an exact host or an explicit ``*.host`` wildcard pattern."""
    if not value:
        return ""
    raw = value.strip()
    wildcard = raw.startswith("*.") or "://*." in raw
    host = _hostname(raw)
    if not host:
        return ""
    return f"*.{host}" if wildcard else host


def _split_scope_string(value: str) -> List[str]:
    """Split common bug bounty scope list formats into individual values."""
    return [item for item in re.split(r"[\s,]+", value.strip()) if item]


def _normalize_scope_items(raw_value) -> List[str]:
    """Normalize strings/lists/dicts from scope metadata into a flat list."""
    if isinstance(raw_value, str):
        return _split_scope_string(raw_value)

    if isinstance(raw_value, dict):
        for k in ("asset_identifier", "identifier", "target", "host", "endpoint", "url", "domain"):
            if k in raw_value and isinstance(raw_value[k], str):
                return _split_scope_string(raw_value[k])
        return []

    if isinstance(raw_value, list):
        values: List[str] = []
        for item in raw_value:
            values.extend(_normalize_scope_items(item))
        return values

    return []


def _iter_scope_values(scope_tags, keys: Iterable[str]) -> Iterable[str]:
    """Yield host/scope strings from flexible target scope metadata."""
    if not scope_tags:
        return []

    if isinstance(scope_tags, list):
        return _normalize_scope_items(scope_tags)

    if isinstance(scope_tags, dict):
        values: List[str] = []
        for key in keys:
            values.extend(_normalize_scope_items(scope_tags.get(key)))
        return values

    return []


def allowed_hosts_for_target(target: Target) -> List[str]:
    """Build exact/wildcard host rules for a target.

    Explicit platform scope is authoritative. The derived ``base_url`` must not
    silently widen a path- or host-specific imported scope.
    """
    explicit_scope = list(_iter_scope_values(target.scope_tags, IN_SCOPE_KEYS))
    values = explicit_scope or [target.base_url]
    hosts = []
    for value in values:
        host = _host_pattern(value)
        if host:
            hosts.append(host)

    return list(dict.fromkeys(hosts))


def excluded_hosts_for_target(target: Target) -> List[str]:
    """Build normalized excluded hosts for a target."""
    hosts = []
    for value in _iter_scope_values(target.scope_tags, OUT_OF_SCOPE_KEYS):
        host = _host_pattern(value)
        if host:
            hosts.append(host)

    return list(dict.fromkeys(hosts))


def _matches_host(host: str, candidate: str) -> bool:
    """Match an exact hostname or an explicitly configured wildcard."""
    if candidate.startswith("*."):
        suffix = candidate[2:]
        return host != suffix and host.endswith(f".{suffix}")
    return host == candidate


def _safe_path(path: str) -> bool:
    """Reject URL paths browsers/servers may normalize across a scoped prefix."""
    current = path
    for _ in range(4):
        if "\\" in current or any(ord(char) < 0x20 for char in current):
            return False
        if re.search(r"%(?![0-9a-fA-F]{2})", current):
            return False
        # Encoded path separators can be decoded by a downstream proxy after
        # the scope decision. Refuse them at every decoding layer.
        if re.search(r"%(?:2f|5c)", current, re.IGNORECASE):
            return False
        try:
            decoded = unquote(current)
        except (TypeError, ValueError, UnicodeError):
            return False
        if "\\" in decoded or any(segment in {".", ".."} for segment in decoded.split("/")):
            return False
        if decoded == current:
            return True
        current = decoded
    # More than four decoding layers is ambiguous and has no normal use in a
    # path-scoped program asset.
    return unquote(current) == current


def _effective_port(parsed) -> Optional[int]:
    try:
        if parsed.port is not None:
            return int(parsed.port)
    except ValueError:
        return None
    return {"http": 80, "ws": 80, "https": 443, "wss": 443}.get(parsed.scheme.lower())


def scope_rule_matches_url(rule: str, url: str) -> bool:
    """Match a web URL against a platform scope asset, including path rules."""
    if not rule or not url:
        return False

    raw_rule = str(rule).strip()
    try:
        candidate = urlparse(url if "://" in url else f"https://{url}")
        cand_scheme = candidate.scheme.lower()
        candidate_host = _hostname(url)
        candidate_username = candidate.username
        candidate_password = candidate.password
    except (TypeError, ValueError):
        return False
    if (
        cand_scheme not in {"http", "https", "ws", "wss"}
        or not candidate_host
        or candidate_username is not None
        or candidate_password is not None
        or not _safe_path(candidate.path or "/")
    ):
        return False

    has_explicit_scheme = "://" in raw_rule
    try:
        parsed_rule = urlparse(raw_rule if has_explicit_scheme else f"https://{raw_rule}")
        rule_username = parsed_rule.username
        rule_password = parsed_rule.password
        explicit_rule_port = parsed_rule.port
    except (TypeError, ValueError):
        return False
    if (
        rule_username is not None
        or rule_password is not None
        or parsed_rule.fragment
        or not _safe_path(parsed_rule.path or "/")
    ):
        return False
    host_pattern = _host_pattern(raw_rule)
    if not host_pattern or not _matches_host(candidate_host, host_pattern):
        return False

    if has_explicit_scheme:
        rule_scheme = parsed_rule.scheme.lower()
        scheme_map = {"http": {"http", "ws"}, "https": {"https", "wss"}, "ws": {"http", "ws"}, "wss": {"https", "wss"}}
        if cand_scheme not in scheme_map.get(rule_scheme, {rule_scheme}):
            return False

    if has_explicit_scheme:
        rule_port = _effective_port(parsed_rule)
        candidate_port = _effective_port(candidate)
        if rule_port is None or candidate_port is None or rule_port != candidate_port:
            return False
    elif explicit_rule_port is not None:
        try:
            candidate_port = candidate.port
        except ValueError:
            return False
        if candidate_port != explicit_rule_port:
            return False

    rule_path = parsed_rule.path or "/"
    candidate_path = candidate.path or "/"
    if rule_path not in {"", "/"}:
        if "*" in rule_path or "?" in rule_path:
            if not fnmatchcase(candidate_path, rule_path):
                return False
        else:
            prefix = rule_path.rstrip("/")
            if candidate_path != prefix and not candidate_path.startswith(f"{prefix}/"):
                return False

    if parsed_rule.query and not fnmatchcase(candidate.query, parsed_rule.query):
        return False
    return True


# Backward-compatible private name for callers/tests that imported it before
# the matcher became a shared program-scope primitive.
_scope_rule_matches_url = scope_rule_matches_url


def is_host_allowed(
    host: str,
    allowed_hosts: List[str],
    excluded_hosts: Optional[List[str]] = None,
) -> bool:
    """Return whether a host is included in scope and not excluded."""
    normalized = _hostname(host)
    if not normalized:
        return False

    for excluded in excluded_hosts or []:
        if _matches_host(normalized, excluded):
            return False

    for allowed in allowed_hosts:
        if _matches_host(normalized, allowed):
            return True
    return False


def is_url_in_scope(target: Target, url: str) -> bool:
    """Return whether a URL matches configured host, wildcard, path, and deny rules."""
    excluded_rules = list(_iter_scope_values(target.scope_tags, OUT_OF_SCOPE_KEYS))
    if any(scope_rule_matches_url(rule, url) for rule in excluded_rules):
        return False

    explicit_rules = list(_iter_scope_values(target.scope_tags, IN_SCOPE_KEYS))
    allowed_rules = explicit_rules or [target.base_url]
    return any(scope_rule_matches_url(rule, url) for rule in allowed_rules)


def is_endpoint_in_scope(endpoint: Endpoint) -> bool:
    """Return whether an endpoint URL is within its target's configured scope."""
    if not endpoint or not endpoint.target:
        return False

    return is_url_in_scope(endpoint.target, endpoint.url_pattern)
