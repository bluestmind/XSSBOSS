"""TOML configuration with conservative collection defaults."""

from __future__ import annotations

import hashlib
import json
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class ScopeConfig:
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    # Private and link-local destinations require an explicit authorization.
    allow_private_networks: bool = False
    authorized_use: bool = True


@dataclass(slots=True)
class CrawlConfig:
    profile: str = "standard"
    max_depth: int = 2
    max_pages: int = 500
    concurrency: int = 8
    per_host_concurrency: int = 2
    requests_per_second: float = 2.0
    timeout_seconds: float = 15.0
    max_response_bytes: int = 2_000_000
    retries: int = 2
    respect_robots: bool = True
    follow_redirects: bool = True
    user_agent: str = "XSSBOSS-Collector/1.3 (+authorized-security-inventory)"


@dataclass(slots=True)
class StorageConfig:
    database: str = "data/collector.db"
    evidence_dir: str = "data/evidence"
    store_response_bodies: bool = True
    compress_evidence: bool = True


@dataclass(slots=True)
class PrivacyConfig:
    redact_headers: list[str] = field(default_factory=lambda: [
        "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key"
    ])
    redact_parameters: list[str] = field(default_factory=lambda: [
        "password", "passwd", "secret", "token", "api_key", "apikey", "access_token",
        "refresh_token", "session", "jwt", "credit_card", "ssn"
    ])
    retain_query_values: bool = False
    retain_request_bodies: bool = False


@dataclass(slots=True)
class AnalysisConfig:
    javascript_enabled: bool = True
    analyze_inline_scripts: bool = True
    analyze_source_maps: bool = True
    max_source_map_sources: int = 10_000


@dataclass(slots=True)
class CollectorConfig:
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    crawl: CrawlConfig = field(default_factory=CrawlConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    privacy: PrivacyConfig = field(default_factory=PrivacyConfig)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    config_path: Path | None = None

    @classmethod
    def load(cls, path: str | Path) -> "CollectorConfig":
        config_path = Path(path).resolve()
        with config_path.open("rb") as handle:
            raw = tomllib.load(handle)
        cfg = cls(
            scope=ScopeConfig(**raw.get("scope", {})),
            crawl=CrawlConfig(**raw.get("crawl", {})),
            storage=StorageConfig(**raw.get("storage", {})),
            privacy=PrivacyConfig(**raw.get("privacy", {})),
            analysis=AnalysisConfig(**raw.get("analysis", {})),
            config_path=config_path,
        )
        cfg.validate()
        return cfg

    def validate(self) -> None:
        if self.crawl.profile not in {"passive", "standard", "deep"}:
            raise ValueError("crawl.profile must be passive, standard, or deep")
        if not 0 <= self.crawl.max_depth <= 20:
            raise ValueError("crawl.max_depth must be between 0 and 20")
        if not 1 <= self.crawl.max_pages <= 1_000_000:
            raise ValueError("crawl.max_pages must be between 1 and 1,000,000")
        if not 1 <= self.crawl.concurrency <= 100:
            raise ValueError("crawl.concurrency must be between 1 and 100")
        if not 1 <= self.crawl.per_host_concurrency <= self.crawl.concurrency:
            raise ValueError("per_host_concurrency must be between 1 and concurrency")
        if not 0.05 <= self.crawl.requests_per_second <= 100:
            raise ValueError("requests_per_second must be between 0.05 and 100")
        if not self.scope.allow:
            raise ValueError("scope.allow must contain at least one explicit rule")
        if not 0 <= self.analysis.max_source_map_sources <= 100_000:
            raise ValueError("analysis.max_source_map_sources must be between 0 and 100,000")

    def resolve_path(self, value: str) -> Path:
        path = Path(value)
        if path.is_absolute():
            return path
        base = self.config_path.parent if self.config_path else Path.cwd()
        return (base / path).resolve()

    def digest(self) -> str:
        data = asdict(self)
        data["config_path"] = str(self.config_path or "")
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

    def save(self, path: str | Path | None = None) -> Path:
        """Write a complete, deterministic TOML configuration."""
        destination = Path(path or self.config_path or "collector.toml").resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        sections = asdict(self)
        sections.pop("config_path", None)
        lines = ["# XSSBOSS Collector - explicit authorization and scope are mandatory."]
        for section, values in sections.items():
            lines.extend(["", f"[{section}]"])
            for key, value in values.items():
                lines.append(f"{key} = {_toml_value(value)}")
        destination.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.config_path = destination
        return destination


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(item) for item in value) + "]"
    if isinstance(value, (int, float)):
        return str(value)
    raise TypeError(f"unsupported TOML value: {type(value).__name__}")


def merge_dataclass(instance: Any, overrides: dict[str, Any]) -> Any:
    """Used by callers that need a typed, validated override without mutation."""
    values = asdict(instance)
    values.update({k: v for k, v in overrides.items() if v is not None})
    return type(instance)(**values)
