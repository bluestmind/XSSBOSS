"""Target scope validation utilities."""
import re
from typing import Iterable, List, Optional
from urllib.parse import urlparse

from backend_api.models.endpoint import Endpoint
from backend_api.models.target import Target

IN_SCOPE_KEYS = ("allowed_hosts", "in_scope", "domains", "hosts")
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

    parsed = urlparse(value if "://" in value else f"https://{value}")
    host = (parsed.hostname or "").lower().strip(".")
    if host.startswith("*."):
        host = host[2:]
    return host


def _split_scope_string(value: str) -> List[str]:
    """Split common bug bounty scope list formats into individual values."""
    return [item for item in re.split(r"[\s,]+", value.strip()) if item]


def _normalize_scope_items(raw_value) -> List[str]:
    """Normalize strings/lists from scope metadata into a flat list."""
    if isinstance(raw_value, str):
        return _split_scope_string(raw_value)

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
    """Build normalized allowed hosts for a target."""
    hosts = []
    base_host = _hostname(target.base_url)
    if base_host:
        hosts.append(base_host)

    for value in _iter_scope_values(target.scope_tags, IN_SCOPE_KEYS):
        host = _hostname(value)
        if host:
            hosts.append(host)

    return list(dict.fromkeys(hosts))


def excluded_hosts_for_target(target: Target) -> List[str]:
    """Build normalized excluded hosts for a target."""
    hosts = []
    for value in _iter_scope_values(target.scope_tags, OUT_OF_SCOPE_KEYS):
        host = _hostname(value)
        if host:
            hosts.append(host)

    return list(dict.fromkeys(hosts))


def _matches_host(host: str, candidate: str) -> bool:
    """Return whether a normalized host matches a candidate or subdomain."""
    return host == candidate or host.endswith(f".{candidate}")


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
    """Return whether a URL is within the target's configured scope."""
    return is_host_allowed(
        _hostname(url),
        allowed_hosts_for_target(target),
        excluded_hosts_for_target(target),
    )


def is_endpoint_in_scope(endpoint: Endpoint) -> bool:
    """Return whether an endpoint URL is within its target's configured scope."""
    if not endpoint or not endpoint.target:
        return False

    return is_url_in_scope(endpoint.target, endpoint.url_pattern)
