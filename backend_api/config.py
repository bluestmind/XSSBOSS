"""Configuration management for XSS Boss backend."""
import os
import sys
from pathlib import Path
from typing import Optional
import json
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings."""

    model_config = SettingsConfigDict(
        env_file=str(Path(__file__).parent.parent / ".env"),
        case_sensitive=True,
        extra="ignore",
    )

    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    TEST_DATABASE_URL: str = os.getenv("TEST_DATABASE_URL", "sqlite:///./xssboss_test.db")
    
    # Database (auto-routes to test database if testing environment or pytest is detected)
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "sqlite:///./xssboss_test.db" if (
            os.getenv("ENVIRONMENT") == "test" or
            "pytest" in sys.modules or
            bool(os.getenv("PYTEST_CURRENT_TEST"))
        ) else "sqlite:///./xssboss.db"
    )
    
    # Redis
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    # Celery
    CELERY_TASK_ALWAYS_EAGER: bool = os.getenv("CELERY_TASK_ALWAYS_EAGER", "False").lower() in ("true", "1", "t", "yes")
    ORCHESTRATION_MODE: str = os.getenv("ORCHESTRATION_MODE", "inline")
    CELERY_VISIBILITY_TIMEOUT: int = int(os.getenv("CELERY_VISIBILITY_TIMEOUT", "7200"))
    AUDIT_MODE: str = os.getenv("AUDIT_MODE", "inline")
    
    # API
    API_HOST: str = os.getenv("API_HOST", "127.0.0.1")
    API_PORT: int = int(os.getenv("API_PORT", "8000"))
    API_RELOAD: bool = os.getenv("API_RELOAD", "False").lower() in ("true", "1", "t", "yes")
    API_PREFIX: str = "/api/v1"
    
    # Oracle Server
    ORACLE_SERVER_URL: str = os.getenv(
        "ORACLE_SERVER_URL",
        "http://localhost:8001"
    )
    
    # Browser Workers
    BROWSER_WORKER_CONCURRENCY: int = int(os.getenv("BROWSER_WORKER_CONCURRENCY", "1"))
    BROWSER_TIMEOUT_MS: int = int(os.getenv("BROWSER_TIMEOUT_MS", "30000"))
    BROWSER_LEASE_SECONDS: int = int(os.getenv("BROWSER_LEASE_SECONDS", "900"))
    BROWSER_RESTART_EVERY_TESTS: int = int(os.getenv("BROWSER_RESTART_EVERY_TESTS", "20"))
    USE_UNDETECTED_CHROME: bool = os.getenv("USE_UNDETECTED_CHROME", "False").lower() in ("true", "1", "t", "yes")
    # Keep browser verification faithful to what a real user receives. CSP bypass
    # mode is diagnostic-only and must be explicitly enabled.
    BYPASS_CSP: bool = os.getenv("BYPASS_CSP", "False").lower() in ("true", "1", "t", "yes")
    # Capture modes: off/false/0, hits, all/true/1/yes
    CAPTURE_SCREENSHOTS: str = os.getenv("CAPTURE_SCREENSHOTS", "hits")
    CAPTURE_DOM_SNAPSHOT: str = os.getenv("CAPTURE_DOM_SNAPSHOT", "hits")
    # V8 precise coverage is passive but has a bounded CPU/memory cost. ``all``
    # retains activation evidence for both positive and negative browser runs;
    # use ``hits`` to retain it only when the execution oracle fires, or ``off``
    # to disable collection entirely.
    CAPTURE_RUNTIME_COVERAGE: str = os.getenv("CAPTURE_RUNTIME_COVERAGE", "all")
    # Runtime lineage keeps only bounded event relationships and fingerprints;
    # observed values and source text are never retained.
    CAPTURE_RUNTIME_LINEAGE: str = os.getenv("CAPTURE_RUNTIME_LINEAGE", "all")
    # Optional follow-up prioritization runs three isolated GET navigations with
    # inert alphanumeric markers in fixed A/A/B order. The result is order-
    # confounded and never confirms XSS; only the execution oracle does. It is
    # disabled by default because it increases target traffic; a test case may
    # also opt in explicitly through trusted research metadata.
    RUNTIME_LINEAGE_AAB_PROBES: bool = os.getenv(
        "RUNTIME_LINEAGE_AAB_PROBES", "False"
    ).lower() in ("true", "1", "t", "yes")
    # The HMAC authenticates the worker's redacted projection, not hostile-page
    # truth. Rotate this identifier whenever SECRET_KEY is rotated so stored
    # projections fail with an explicit key-version mismatch.
    RUNTIME_LINEAGE_HMAC_KEY_VERSION: str = os.getenv(
        "RUNTIME_LINEAGE_HMAC_KEY_VERSION", "1"
    )
    # Browser-native flattened DOM snapshots are reduced immediately to marker
    # placement metadata; raw snapshots are never persisted.
    CAPTURE_DOM_DIFFERENTIAL: str = os.getenv("CAPTURE_DOM_DIFFERENTIAL", "all")
    DOM_SNAPSHOT_MAX_CHARS: int = int(os.getenv("DOM_SNAPSHOT_MAX_CHARS", "8000"))
    EVIDENCE_DIR: str = os.getenv("EVIDENCE_DIR", "./evidence")
    
    # Proxy & Test Host Settings
    PROXY_URL: Optional[str] = os.getenv("PROXY_URL", None)
    OPEN_REDIRECT_TEST_HOST: str = os.getenv("OPEN_REDIRECT_TEST_HOST", "example.com")
 
    # Resource guards
    MAX_PAYLOADS_PER_CONTEXT: int = int(os.getenv("MAX_PAYLOADS_PER_CONTEXT", "32"))
    MAX_TEST_CASES_PER_EXPERIMENT: int = int(os.getenv("MAX_TEST_CASES_PER_EXPERIMENT", "1500"))
    MAX_QUEUE_ACTIVE: int = int(os.getenv("MAX_QUEUE_ACTIVE", "1"))
    MAX_PROFILING_WORKERS: int = int(os.getenv("MAX_PROFILING_WORKERS", "1"))
    
    # Rate limiting / throttling
    REQUEST_DELAY_MS: int = int(os.getenv("REQUEST_DELAY_MS", "1200"))  # ms between requests to same target
    MAX_REQUESTS_PER_MINUTE: int = int(os.getenv("MAX_REQUESTS_PER_MINUTE", "40"))  # hard cap per target per minute
    RATE_LIMIT_REDIS_ENABLED: bool = os.getenv(
        "RATE_LIMIT_REDIS_ENABLED", "True"
    ).lower() in ("true", "1", "t", "yes")
    # Distributed production workers must stop when their shared coordinator is
    # unavailable; otherwise each process can independently spend the full cap.
    RATE_LIMIT_REDIS_REQUIRED: bool = os.getenv(
        "RATE_LIMIT_REDIS_REQUIRED", "False"
    ).lower() in ("true", "1", "t", "yes")
    RATE_LIMIT_REDIS_RETRY_SECS: float = float(
        os.getenv("RATE_LIMIT_REDIS_RETRY_SECS", "30")
    )
    RATE_LIMIT_FALLBACK_WORKER_ESTIMATE: int = int(
        os.getenv("RATE_LIMIT_FALLBACK_WORKER_ESTIMATE", "4")
    )
    ADAPTIVE_THROTTLE: bool = os.getenv("ADAPTIVE_THROTTLE", "True").lower() in ("true", "1", "t", "yes")
    THROTTLE_BACKOFF_MULTIPLIER: float = float(os.getenv("THROTTLE_BACKOFF_MULTIPLIER", "2.5"))
    THROTTLE_MAX_DELAY_MS: int = int(os.getenv("THROTTLE_MAX_DELAY_MS", "60000"))
    JITTER_FACTOR: float = float(os.getenv("JITTER_FACTOR", "0.15"))
    
    # Circuit breaker — auto-pause scanning when target is unreachable
    CIRCUIT_BREAKER_ENABLED: bool = os.getenv("CIRCUIT_BREAKER_ENABLED", "True").lower() in ("true", "1", "t", "yes")
    CIRCUIT_BREAKER_THRESHOLD: int = int(os.getenv("CIRCUIT_BREAKER_THRESHOLD", "3"))
    CIRCUIT_BREAKER_RECOVERY_SECS: int = int(os.getenv("CIRCUIT_BREAKER_RECOVERY_SECS", "120"))
    
    # UA rotation — cycle through realistic User-Agent strings
    ROTATE_USER_AGENT: bool = os.getenv("ROTATE_USER_AGENT", "False").lower() in ("true", "1", "t", "yes")
    
    # WAF bypass headers — inject X-Forwarded-For, X-Originating-IP, etc.
    # Spoofed forwarding headers can violate program rules and change application
    # behavior, so require an explicit opt-in for authorized programs.
    WAF_BYPASS_HEADERS: bool = os.getenv("WAF_BYPASS_HEADERS", "False").lower() in ("true", "1", "t", "yes")
    
    # Proxy rotation — cycle through proxy list or file
    PROXY_ENABLED: bool = os.getenv("PROXY_ENABLED", "False").lower() in ("true", "1", "t", "yes")
    PROXY_LIST: str = os.getenv("PROXY_LIST", "")  # comma-separated: socks5://p1:1080,http://p2:8080
    PROXY_LIST_FILE: Optional[str] = os.getenv("PROXY_LIST_FILE", "proxies.txt")  # file with one proxy per line
    PROXY_ROTATION: str = os.getenv("PROXY_ROTATION", "round_robin")  # round_robin or random
    PROXY_MAX_FAILURES: int = int(os.getenv("PROXY_MAX_FAILURES", "3"))  # auto-eject proxy after N failures
    ALLOW_INSECURE_TLS: bool = os.getenv("ALLOW_INSECURE_TLS", "False").lower() in ("true", "1", "t", "yes")
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "change-me-in-production")
    API_AUTH_TOKEN: Optional[str] = os.getenv("API_AUTH_TOKEN", None)
    TENANT_API_TOKENS: str = os.getenv("TENANT_API_TOKENS", "")
    ALLOWED_ORIGINS: list[str] = os.getenv(
        "ALLOWED_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000"
    ).split(",")
    
    # Logging
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    
    # Burp Suite Settings
    BURP_API_URL: str = os.getenv("BURP_API_URL", "http://127.0.0.1:13337")
    BURP_API_KEY: Optional[str] = os.getenv("BURP_API_KEY") or None
    BURP_ENABLED: bool = os.getenv("BURP_ENABLED", "False").lower() in ("true", "1", "t", "yes")
    BURP_AUTO_START: bool = os.getenv("BURP_AUTO_START", "False").lower() in ("true", "1", "t", "yes")
    BURP_PROGRAM_AUTO_SCAN: bool = os.getenv("BURP_PROGRAM_AUTO_SCAN", "False").lower() in ("true", "1", "t", "yes")
    BURP_EXECUTABLE: Optional[str] = os.getenv("BURP_EXECUTABLE", None)
    BURP_JAVA_EXECUTABLE: Optional[str] = os.getenv("BURP_JAVA_EXECUTABLE", None)
    BURP_STARTUP_TIMEOUT_SECONDS: int = int(os.getenv("BURP_STARTUP_TIMEOUT_SECONDS", "45"))
    # Bound optional Burp startup during one-shot scans. Explicit Burp startup
    # operations retain the longer timeout above.
    BURP_SCAN_STARTUP_TIMEOUT_SECONDS: float = float(os.getenv("BURP_SCAN_STARTUP_TIMEOUT_SECONDS", "3"))
    BURP_STARTUP_ARGS: str = os.getenv("BURP_STARTUP_ARGS", "")
    BURP_PROJECT_FILE: Optional[str] = os.getenv("BURP_PROJECT_FILE", None)
    BURP_PROXY_URL: str = os.getenv("BURP_PROXY_URL", "http://127.0.0.1:8080")
    BURP_PROXY_WORKERS: bool = os.getenv("BURP_PROXY_WORKERS", "False").lower() in ("true", "1", "t", "yes")
    UPSTREAM_ROTATING_PROXY_ENABLED: bool = os.getenv("UPSTREAM_ROTATING_PROXY_ENABLED", "False").lower() in ("true", "1", "t", "yes")
    UPSTREAM_ROTATING_PROXY_HOST: str = os.getenv("UPSTREAM_ROTATING_PROXY_HOST", "127.0.0.1")
    UPSTREAM_ROTATING_PROXY_PORT: int = int(os.getenv("UPSTREAM_ROTATING_PROXY_PORT", "8899"))
    
    # LLM Settings
    LLM_API_URL: str = os.getenv("LLM_API_URL", "http://localhost:11434/api/generate")
    LLM_MODEL: str = os.getenv("LLM_MODEL", "mistral")
    LLM_ENABLED: bool = os.getenv("LLM_ENABLED", "False").lower() in ("true", "1", "t")
    LLM_PREFER_LOCAL: bool = os.getenv("LLM_PREFER_LOCAL", "True").lower() in ("true", "1", "t")
    LLM_TIMEOUT_SECONDS: int = int(os.getenv("LLM_TIMEOUT_SECONDS", "180"))
    LLM_KEEP_ALIVE: str = os.getenv("LLM_KEEP_ALIVE", "30m")
    LLM_NUM_CTX: int = int(os.getenv("LLM_NUM_CTX", "8192"))
    LLM_MAX_OUTPUT_TOKENS: int = int(os.getenv("LLM_MAX_OUTPUT_TOKENS", "768"))
    LLM_TEMPERATURE: float = float(os.getenv("LLM_TEMPERATURE", "0.1"))
    LLM_CAMPAIGN_ADVISOR: bool = os.getenv("LLM_CAMPAIGN_ADVISOR", "True").lower() in ("true", "1", "t")
    LLM_MIDSCAN_ADVISOR: bool = os.getenv("LLM_MIDSCAN_ADVISOR", "True").lower() in ("true", "1", "t")
    LLM_MIDSCAN_MAX_CALLS: int = int(os.getenv("LLM_MIDSCAN_MAX_CALLS", "8"))
    LLM_MIDSCAN_MIN_CONFIDENCE: float = float(os.getenv("LLM_MIDSCAN_MIN_CONFIDENCE", "0.65"))
    LLM_WORKFLOW_ADVISOR: bool = os.getenv("LLM_WORKFLOW_ADVISOR", "True").lower() in ("true", "1", "t")
    LLM_WORKFLOW_MAX_CALLS: int = int(os.getenv("LLM_WORKFLOW_MAX_CALLS", "6"))
    # Security telemetry can contain private URLs, source snippets, and session
    # artifacts. Keep it on the local model unless the operator explicitly opts in.
    LLM_ALLOW_REMOTE_SECURITY_DATA: bool = os.getenv(
        "LLM_ALLOW_REMOTE_SECURITY_DATA", "False"
    ).lower() in ("true", "1", "t")
    
    # OpenAI Settings
    OPENAI_API_KEY: Optional[str] = os.getenv("OPENAI_API_KEY", None)
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o")
    USE_BROWSER_CHATGPT: bool = os.getenv("USE_BROWSER_CHATGPT", "False").lower() in ("true", "1", "t")
    CHATGPT_PROFILE_PATH: str = os.getenv("CHATGPT_PROFILE_PATH", str(Path.home() / ".xssboss" / "chatgpt_profile"))
    CHATGPT_PROJECT_URL_chat: str = os.getenv("CHATGPT_PROJECT_URL", "https://chatgpt.com/g/g-p-6a2b92fbf78c81919ec268d1bfc16c6f-auto-xss-boss/c/6a2d8da3-625c-83eb-845c-a1ba8590c051")
    CHATGPT_PROJECT_URL: str = os.getenv("CHATGPT_PROJECT_URL", "https://chatgpt.com/g/g-p-6a2b92fbf78c81919ec268d1bfc16c6f-auto-xss-boss/project")

    def validate_runtime(self) -> None:
        """Reject unsafe or non-scalable settings when production mode is explicit."""
        if self.ENVIRONMENT.lower() != "production":
            return
        errors = []
        if not self.DATABASE_URL.startswith(("postgresql://", "postgresql+psycopg://")):
            errors.append("DATABASE_URL must use PostgreSQL")
        if self.ORCHESTRATION_MODE.lower() != "celery":
            errors.append("ORCHESTRATION_MODE must be celery")
        if self.AUDIT_MODE.lower() != "celery":
            errors.append("AUDIT_MODE must be celery")
        if not self.REDIS_URL:
            errors.append("REDIS_URL must be configured")
        if not self.RATE_LIMIT_REDIS_ENABLED or not self.RATE_LIMIT_REDIS_REQUIRED:
            errors.append(
                "distributed rate limiting must be enabled and required"
            )
        if self.SECRET_KEY == "change-me-in-production" or len(self.SECRET_KEY) < 32:
            errors.append("SECRET_KEY must be a unique value of at least 32 characters")
        lineage_key_version = self.RUNTIME_LINEAGE_HMAC_KEY_VERSION
        if (
            not lineage_key_version
            or len(lineage_key_version) > 32
            or any(
                character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
                for character in lineage_key_version
            )
        ):
            errors.append(
                "RUNTIME_LINEAGE_HMAC_KEY_VERSION must be a 1-32 character key identifier"
            )
        if not self.API_AUTH_TOKEN or len(self.API_AUTH_TOKEN) < 32:
            errors.append("API_AUTH_TOKEN must be set to at least 32 characters")
        if self.TENANT_API_TOKENS.strip():
            try:
                tenant_tokens = json.loads(self.TENANT_API_TOKENS)
                if not isinstance(tenant_tokens, dict) or any(
                    len(str(token)) < 32 for token in tenant_tokens.values()
                ):
                    errors.append("TENANT_API_TOKENS must map tenant slugs to tokens of at least 32 characters")
            except (TypeError, ValueError, json.JSONDecodeError):
                errors.append("TENANT_API_TOKENS must be valid JSON")
        if any("localhost" in origin or "127.0.0.1" in origin for origin in self.ALLOWED_ORIGINS):
            errors.append("ALLOWED_ORIGINS must not contain localhost")
        if errors:
            raise RuntimeError("Unsafe production configuration: " + "; ".join(errors))


settings = Settings()
