"""Bug-class registry — the pluggable subsystems that find bugs beyond XSS.

XSS Boss already ships more than an XSS scanner: alongside the context-aware XSS fuzzer, every
experiment runs a suite of auditors for other vulnerability classes. This registry names those
subsystems in one place so the program run and dashboard can report coverage, and so adding a new
bug-class subsystem is a one-line ``register`` (plus its ``audit_endpoints`` implementation) rather
than another hardcoded import.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class BugClass:
    key: str
    name: str
    description: str
    impl: str          # dotted path to the fuzzer/auditor entry point
    kind: str          # "fuzz" (payload engine) | "auditor" (audit_endpoints)
    default_severity: str = "medium"


class BugClassRegistry:
    """The bug-class subsystems that run during a hunt."""

    _REGISTRY: Dict[str, BugClass] = {}

    @classmethod
    def register(cls, bug_class: BugClass) -> None:
        cls._REGISTRY[bug_class.key] = bug_class

    @classmethod
    def all(cls) -> List[BugClass]:
        return list(cls._REGISTRY.values())

    @classmethod
    def keys(cls) -> List[str]:
        return list(cls._REGISTRY.keys())

    @classmethod
    def get(cls, key: str) -> Optional[BugClass]:
        return cls._REGISTRY.get(key)

    @classmethod
    def auditors(cls) -> List[BugClass]:
        return [b for b in cls._REGISTRY.values() if b.kind == "auditor"]


# --- the subsystems that ship today (verified against backend_api/services/auditors/*) ---
for _bc in [
    BugClass("xss", "Cross-Site Scripting",
             "Context-aware fuzzer + SMT bypass + execution oracle (reflected/stored/DOM/mXSS).",
             "fuzzer.generator.PayloadGenerator", "fuzz", "high"),
    BugClass("cors", "CORS Misconfiguration",
             "Reflected-origin / null-origin / credentialed CORS weaknesses.",
             "backend_api.services.auditors.cors.CorsAuditor", "auditor", "medium"),
    BugClass("sqli", "SQL Injection (error-based)",
             "Error-signature SQL injection probing.",
             "backend_api.services.auditors.sqli.ErrorBasedSqliAuditor", "auditor", "high"),
    BugClass("ssrf", "Server-Side Request Forgery",
             "Out-of-band canary SSRF detection.",
             "backend_api.services.auditors.ssrf.SsrfCanaryAuditor", "auditor", "high"),
    BugClass("open_redirect", "Open Redirect",
             "Unvalidated redirect / forward parameters.",
             "backend_api.services.auditors.redirect.RedirectAuditor", "auditor", "low"),
    BugClass("crlf", "CRLF / HTTP Header Injection",
             "Header injection and response splitting into reflected XSS.",
             "backend_api.services.auditors.crlf_injection.CRLFInjectionAuditor", "auditor", "medium"),
    BugClass("path_traversal", "Path Traversal / LFI",
             "Directory traversal and local file inclusion.",
             "backend_api.services.auditors.path_traversal.PathTraversalAuditor", "auditor", "high"),
    BugClass("http_param", "HTTP Parameter Pollution",
             "Duplicate/ambiguous parameter handling flaws.",
             "backend_api.services.auditors.http_param.HttpParamPollutionAuditor", "auditor", "low"),
    BugClass("cache_deception", "Web Cache Deception",
             "Caching of authenticated responses via path confusion.",
             "backend_api.services.auditors.cache_deception.CacheDeceptionAuditor", "auditor", "medium"),
    BugClass("dangling_markup", "Dangling Markup Injection",
             "JS-less/CSP-proof data exfiltration via unterminated markup.",
             "backend_api.services.auditors.dangling_markup.DanglingMarkupAuditor", "auditor", "medium"),
    BugClass("idor_bola", "IDOR / Broken Object Authorization",
             "Recon-ranked object identifiers and ownership parameters for authorization differential research.",
             "backend_api.services.research_service.ResearchService", "research", "high"),
    BugClass("csrf", "Cross-Site Request Forgery",
             "State-changing routes prioritized for anti-CSRF and SameSite boundary verification.",
             "backend_api.services.research_service.ResearchService", "research", "medium"),
    BugClass("graphql_auth", "GraphQL Authorization",
             "Schema and operation surface prioritized for field/object authorization differentials.",
             "backend_api.services.research_service.ResearchService", "research", "high"),
    BugClass("command_injection", "OS Command Injection",
             "Command/host/process-like inputs retained as bounded research hypotheses.",
             "backend_api.services.research_service.ResearchService", "research", "critical"),
    BugClass("file_upload", "Unsafe File Upload / Import",
             "Upload, attachment, avatar, and import inputs prioritized for safe content-handling checks.",
             "backend_api.services.research_service.ResearchService", "research", "high"),
    BugClass("client_secret_exposure", "Client-Side Secret Exposure",
             "Redacted secret-like bundle/response indicators requiring metadata-only validation.",
             "backend_api.services.research_service.ResearchService", "research", "high"),
]:
    BugClassRegistry.register(_bc)
