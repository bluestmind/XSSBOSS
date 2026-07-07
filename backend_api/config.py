"""Configuration management for XSS Boss backend."""
import os
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings."""
    
    # Database
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "sqlite:///./xssboss.db"
    )
    
    # Redis
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    # Celery
    CELERY_TASK_ALWAYS_EAGER: bool = os.getenv("CELERY_TASK_ALWAYS_EAGER", "False").lower() in ("true", "1", "t", "yes")
    
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
    BROWSER_RESTART_EVERY_TESTS: int = int(os.getenv("BROWSER_RESTART_EVERY_TESTS", "20"))
    USE_UNDETECTED_CHROME: bool = os.getenv("USE_UNDETECTED_CHROME", "False").lower() in ("true", "1", "t", "yes")
    BYPASS_CSP: bool = os.getenv("BYPASS_CSP", "True").lower() in ("true", "1", "t", "yes")
    # Capture modes: off/false/0, hits, all/true/1/yes
    CAPTURE_SCREENSHOTS: str = os.getenv("CAPTURE_SCREENSHOTS", "hits")
    CAPTURE_DOM_SNAPSHOT: str = os.getenv("CAPTURE_DOM_SNAPSHOT", "hits")
    DOM_SNAPSHOT_MAX_CHARS: int = int(os.getenv("DOM_SNAPSHOT_MAX_CHARS", "4000"))
    
    # Proxy Settings
    PROXY_URL: Optional[str] = os.getenv("PROXY_URL", None)
 
    # Resource guards
    MAX_PAYLOADS_PER_CONTEXT: int = int(os.getenv("MAX_PAYLOADS_PER_CONTEXT", "12"))
    MAX_TEST_CASES_PER_EXPERIMENT: int = int(os.getenv("MAX_TEST_CASES_PER_EXPERIMENT", "500"))
    MAX_QUEUE_ACTIVE: int = int(os.getenv("MAX_QUEUE_ACTIVE", "2"))
    MAX_PROFILING_WORKERS: int = int(os.getenv("MAX_PROFILING_WORKERS", "2"))
    
    # Rate limiting / throttling
    REQUEST_DELAY_MS: int = int(os.getenv("REQUEST_DELAY_MS", "1000"))  # ms between requests to same target
    MAX_REQUESTS_PER_MINUTE: int = int(os.getenv("MAX_REQUESTS_PER_MINUTE", "30"))  # hard cap per target per minute
    ADAPTIVE_THROTTLE: bool = os.getenv("ADAPTIVE_THROTTLE", "True").lower() in ("true", "1", "t", "yes")
    THROTTLE_BACKOFF_MULTIPLIER: float = float(os.getenv("THROTTLE_BACKOFF_MULTIPLIER", "2.0"))
    THROTTLE_MAX_DELAY_MS: int = int(os.getenv("THROTTLE_MAX_DELAY_MS", "10000"))  # max 10s between requests
    JITTER_FACTOR: float = float(os.getenv("JITTER_FACTOR", "0.5"))  # ±50% random noise on delays
    
    # Circuit breaker — auto-pause scanning when target is unreachable
    CIRCUIT_BREAKER_ENABLED: bool = os.getenv("CIRCUIT_BREAKER_ENABLED", "True").lower() in ("true", "1", "t", "yes")
    CIRCUIT_BREAKER_THRESHOLD: int = int(os.getenv("CIRCUIT_BREAKER_THRESHOLD", "5"))  # consecutive failures to trip
    CIRCUIT_BREAKER_RECOVERY_SECS: int = int(os.getenv("CIRCUIT_BREAKER_RECOVERY_SECS", "60"))  # wait before half-open probe
    
    # UA rotation — cycle through realistic User-Agent strings
    ROTATE_USER_AGENT: bool = os.getenv("ROTATE_USER_AGENT", "True").lower() in ("true", "1", "t", "yes")
    
    # WAF bypass headers — inject X-Forwarded-For, X-Originating-IP, etc.
    WAF_BYPASS_HEADERS: bool = os.getenv("WAF_BYPASS_HEADERS", "True").lower() in ("true", "1", "t", "yes")
    
    # Proxy rotation — cycle through proxy list
    PROXY_LIST: str = os.getenv("PROXY_LIST", "")  # comma-separated: socks5://p1:1080,http://p2:8080
    PROXY_ROTATION: str = os.getenv("PROXY_ROTATION", "round_robin")  # round_robin or random
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "change-me-in-production")
    ALLOWED_ORIGINS: list[str] = os.getenv(
        "ALLOWED_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000"
    ).split(",")
    
    # Logging
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    
    # Burp Suite Settings
    BURP_API_URL: str = os.getenv("BURP_API_URL", "http://127.0.0.1:13337")
    BURP_API_KEY: Optional[str] = os.getenv("BURP_API_KEY", "IwkfVoPpaGL3yKHrfMlwAOyBz9zfXn01")
    BURP_ENABLED: bool = os.getenv("BURP_ENABLED", "True").lower() in ("true", "1", "t", "yes")
    
    # LLM Settings
    LLM_API_URL: str = os.getenv("LLM_API_URL", "http://localhost:11434/api/generate")
    LLM_MODEL: str = os.getenv("LLM_MODEL", "mistral")
    LLM_ENABLED: bool = os.getenv("LLM_ENABLED", "True").lower() in ("true", "1", "t")
    
    # OpenAI Settings
    OPENAI_API_KEY: Optional[str] = os.getenv("OPENAI_API_KEY", None)
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o")
    USE_BROWSER_CHATGPT: bool = os.getenv("USE_BROWSER_CHATGPT", "False").lower() in ("true", "1", "t")
    CHATGPT_PROFILE_PATH: str = os.getenv("CHATGPT_PROFILE_PATH", str(Path.home() / ".xssboss" / "chatgpt_profile"))
    CHATGPT_PROJECT_URL_chat: str = os.getenv("CHATGPT_PROJECT_URL", "https://chatgpt.com/g/g-p-6a2b92fbf78c81919ec268d1bfc16c6f-auto-xss-boss/c/6a2d8da3-625c-83eb-845c-a1ba8590c051")
    CHATGPT_PROJECT_URL: str = os.getenv("CHATGPT_PROJECT_URL", "https://chatgpt.com/g/g-p-6a2b92fbf78c81919ec268d1bfc16c6f-auto-xss-boss/project")

    class Config:
        env_file = str(Path(__file__).parent.parent / ".env")
        case_sensitive = True


settings = Settings()
