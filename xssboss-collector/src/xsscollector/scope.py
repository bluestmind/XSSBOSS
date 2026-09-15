"""Exact scope enforcement and public-network safety checks."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from fnmatch import fnmatchcase
from urllib.parse import urlsplit


class ScopeError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ScopeRule:
    scheme: str | None
    host: str
    port: int | None
    path: str
    wildcard_subdomains: bool

    @classmethod
    def parse(cls, value: str) -> "ScopeRule":
        raw = value.strip()
        if not raw:
            raise ScopeError("empty scope rule")
        explicit_scheme = "://" in raw
        parsed = urlsplit(raw if explicit_scheme else f"https://{raw}")
        host = (parsed.hostname or "").lower().rstrip(".")
        wildcard = host.startswith("*.") or raw.startswith("*.")
        if host.startswith("*."):
            host = host[2:]
        if not host:
            raise ScopeError(f"invalid scope rule: {value}")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ScopeError(f"invalid port in scope rule: {value}") from exc
        return cls(
            scheme=parsed.scheme.lower() if explicit_scheme else None,
            host=host,
            port=port,
            path=parsed.path or "/",
            wildcard_subdomains=wildcard,
        )

    def matches(self, url: str) -> bool:
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            return False
        host = parsed.hostname.lower().rstrip(".")
        host_match = host == self.host
        if self.wildcard_subdomains:
            host_match = host != self.host and host.endswith(f".{self.host}")
        if not host_match:
            return False
        if self.scheme and parsed.scheme.lower() != self.scheme:
            return False
        try:
            candidate_port = parsed.port
            if self.port is not None and candidate_port != self.port:
                return False
        except ValueError:
            return False
        candidate_path = parsed.path or "/"
        if "*" in self.path or "?" in self.path:
            return fnmatchcase(candidate_path, self.path)
        prefix = self.path.rstrip("/")
        return not prefix or candidate_path == prefix or candidate_path.startswith(f"{prefix}/")


class ScopePolicy:
    def __init__(self, allow: list[str], deny: list[str] | None = None, allow_private_networks: bool = False):
        self.allow = [ScopeRule.parse(item) for item in allow]
        self.deny = [ScopeRule.parse(item) for item in (deny or [])]
        self.allow_private_networks = allow_private_networks

    def is_allowed(self, url: str) -> bool:
        return not any(rule.matches(url) for rule in self.deny) and any(rule.matches(url) for rule in self.allow)

    def require_allowed(self, url: str) -> None:
        if not self.is_allowed(url):
            raise ScopeError(f"URL is outside configured scope: {url}")

    def validate_destination(self, url: str) -> list[str]:
        """Resolve a destination and reject private/unsafe addresses by default."""
        self.require_allowed(url)
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})
        except socket.gaierror as exc:
            raise ScopeError(f"could not resolve {host}: {exc}") from exc
        if not addresses:
            raise ScopeError(f"could not resolve {host} to a usable address")
        if not self.allow_private_networks:
            private = []
            for address in addresses:
                try:
                    ip = ipaddress.ip_address(address)
                except ValueError as exc:
                    raise ScopeError(f"resolver returned an invalid address for {host}") from exc
                if not ip.is_global:
                    private.append(address)
            if private:
                raise ScopeError(
                    "destination resolves to private, loopback, link-local, or reserved address(es): "
                    + ", ".join(private)
                )
        return addresses
