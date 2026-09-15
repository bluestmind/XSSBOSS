"""Vulnerable JavaScript library scanner (retire.js-style) — the one real borrow from XSStrike.

Detects the JS libraries a page loads (from artifact paths and inline version banners), matches
their versions against a curated database of XSS / DOM / prototype-pollution / template-injection
advisories, and emits research leads. It also returns payload-family hints for later harmless
reachability checks. Version presence alone is never treated as proof that an affected API is used
or that the application is exploitable.
"""
from __future__ import annotations

import re
from hashlib import sha256
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import unquote, urlsplit


@dataclass(frozen=True)
class VulnEntry:
    below: Optional[str]           # affected if version < below; None = affected regardless of version
    ref: str                       # CVE / advisory id
    severity: str
    summary: str
    boosts: Tuple[str, ...] = ()   # payload families to prioritize when this matches


# Curated, XSS-relevant vulnerable-library DB (retire.js-inspired, trimmed to what matters for XSS).
VULN_DB: Dict[str, List[VulnEntry]] = {
    "jquery": [
        VulnEntry("1.9.0", "CVE-2011-4969", "medium",
                  "jQuery <1.9 XSS via $(location.hash) / selector interpolation", ("dom_selector_xss",)),
        VulnEntry("3.0.0", "CVE-2015-9251", "medium",
                  "jQuery <3.0 cross-domain ajax text/html executes scripts", ()),
        VulnEntry("3.4.0", "CVE-2019-11358", "medium",
                  "jQuery <3.4 Object.prototype pollution via $.extend", ("prototype_pollution",)),
        VulnEntry("3.5.0", "CVE-2020-11022", "medium",
                  "jQuery <3.5 htmlPrefilter XSS (html() with crafted markup)", ("mutation_xss", "html_injection")),
    ],
    "jquery-ui": [
        VulnEntry("1.13.2", "CVE-2022-31160", "medium", "jQuery UI <1.13.2 checkboxradio XSS", ("html_injection",)),
        VulnEntry("1.12.0", "CVE-2016-7103", "medium", "jQuery UI <1.12 dialog closeText XSS", ("html_injection",)),
    ],
    "angular": [
        VulnEntry(None, "CSTI", "high",
                  "AngularJS present — client-side template injection; sandbox escapes exist for every 1.x",
                  ("csti_angular",)),
        VulnEntry("1.6.0", "CVE-2019-10768-family", "high",
                  "AngularJS <1.6 expression sandbox is bypassable (RCE-in-context)", ("csti_angular",)),
    ],
    "bootstrap": [
        VulnEntry("3.4.0", "CVE-2019-8331", "medium", "Bootstrap <3.4 XSS via data-template/data-* attributes",
                  ("attr_injection", "html_injection")),
        VulnEntry("4.3.1", "CVE-2019-8331", "medium", "Bootstrap <4.3.1 XSS via data-* tooltip/popover",
                  ("attr_injection",)),
    ],
    "handlebars": [
        VulnEntry("4.1.2", "CVE-2019-19919", "high", "Handlebars <4.1.2 prototype pollution → RCE/XSS in templates",
                  ("prototype_pollution", "csti_generic")),
    ],
    "lodash": [
        VulnEntry("4.17.12", "CVE-2019-10744", "medium", "lodash <4.17.12 Object.prototype pollution",
                  ("prototype_pollution",)),
    ],
    "vue": [
        VulnEntry("2.6.11", "vue-mxss", "low", "Vue <2.6.11 mXSS in v-html on some browsers", ("mutation_xss",)),
    ],
    "mustache": [
        VulnEntry("2.2.1", "CVE-2015-8862", "medium", "Mustache <2.2.1 unescaped HTML in template lookups",
                  ("html_injection",)),
    ],
    "underscore": [
        VulnEntry("1.12.1", "CVE-2021-23358", "high", "Underscore <1.12.1 arbitrary code via template",
                  ("csti_generic",)),
    ],
}

# name -> regex: library name near a version, tolerant of filenames (jquery-1.6.4), CDN paths
# (angularjs/1.5.8/) and inline banners (jQuery v1.12.4). One capture group = the version.
_NV = r"[^0-9<>\"']{0,25}?"   # up to 25 non-digit, non-delimiter chars between name and version
_VER = r"([0-9]{1,6}\.[0-9]{1,6}(?:\.[0-9]{1,6})?)(?![0-9]|\.[0-9])"
_DETECTORS: Dict[str, str] = {
    "jquery-ui": r"jquery[-._/]ui" + _NV + _VER,
    "jquery": r"jquery(?![-._/]?ui)" + _NV + _VER,
    "angular": r"angular(?:js)?" + _NV + _VER,
    "bootstrap": r"bootstrap" + _NV + _VER,
    "handlebars": r"handlebars" + _NV + _VER,
    "lodash": r"lodash" + _NV + _VER,
    "vue": r"vue(?:\.js)?" + _NV + _VER,
    "mustache": r"mustache" + _NV + _VER,
    "underscore": r"underscore" + _NV + _VER,
}


@dataclass
class LibFinding:
    library: str
    version: str
    ref: str
    severity: str
    summary: str
    boosts: List[str] = field(default_factory=list)
    source: str = "content"
    source_fingerprint: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {"library": self.library, "version": self.version, "ref": self.ref,
                "severity": self.severity, "summary": self.summary, "boosts": self.boosts,
                "source": self.source, "source_fingerprint": self.source_fingerprint}


@dataclass(frozen=True)
class LibraryInstance:
    """One unique library/version observation from an artifact evidence source.

    ``source`` is deliberately a small enum-like label. The source material itself is never
    returned; ``source_fingerprint`` lets callers correlate duplicate observations without
    exposing a URL query, credentials, inline code, or other response content.
    """

    library: str
    version: str
    source: str
    source_fingerprint: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "library": self.library,
            "version": self.version,
            "source": self.source,
            "source_fingerprint": self.source_fingerprint,
        }


def _vtuple(v: str) -> Tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4]) or (0,)


def _lt(a: str, b: str) -> bool:
    ta, tb = _vtuple(a), _vtuple(b)
    ta = ta + (0,) * (len(tb) - len(ta))
    tb = tb + (0,) * (len(ta) - len(tb))
    return ta < tb


class VulnerableLibraryScanner:
    """Detect loaded JS libraries and flag known-vulnerable versions.

    Analysis is local and bounded. It never resolves or fetches a ``script_url``.
    """

    MAX_SCAN_CHARS = 8_000_000
    MAX_URL_CHARS = 8_192
    MAX_VERSIONS_PER_LIBRARY_SOURCE = 16
    MAX_LIBRARY_INSTANCES = 128
    MAX_FINDINGS = 256

    @staticmethod
    def _content_fingerprint(content: str) -> str:
        return sha256(content.encode("utf-8", errors="replace")).hexdigest()[:20]

    @staticmethod
    def _url_fingerprint(script_url: str) -> str:
        """Fingerprint a URL without retaining credentials, query values, or fragments."""
        try:
            parsed = urlsplit(script_url)
            host = (parsed.hostname or "").lower()
            port = f":{parsed.port}" if parsed.port is not None else ""
            canonical = f"{parsed.scheme.lower()}://{host}{port}{parsed.path}"
        except (TypeError, ValueError):
            # Hashing the bounded input is still privacy preserving when URL parsing fails.
            canonical = script_url
        return sha256(canonical.encode("utf-8", errors="replace")).hexdigest()[:20]

    @staticmethod
    def _url_path_evidence(script_url: str) -> str:
        """Use only the decoded artifact path as version evidence."""
        try:
            return unquote(urlsplit(script_url).path)
        except (TypeError, ValueError):
            return ""

    @classmethod
    def detect_library_instances(
        cls, content: str, script_url: Optional[str] = None,
    ) -> List[LibraryInstance]:
        """Return every unique library/version/source observation, within fixed bounds.

        URL text is evidence only: no network request is made. URL evidence is evaluated before
        content evidence because a versioned artifact path is usually more specific than a banner
        embedded in a generated bundle.
        """
        sources: List[Tuple[str, str, str]] = []
        if script_url:
            bounded_url = str(script_url)[:cls.MAX_URL_CHARS]
            # Decoding lets versioned CDN paths such as ``jquery%2D3.4.1.js`` contribute evidence.
            path_evidence = cls._url_path_evidence(bounded_url)
            if path_evidence:
                sources.append(("script_url", path_evidence, cls._url_fingerprint(bounded_url)))
        if content:
            bounded_content = str(content)[:cls.MAX_SCAN_CHARS]
            sources.append(("content", bounded_content, cls._content_fingerprint(bounded_content)))

        instances: List[LibraryInstance] = []
        seen = set()
        for source, evidence, source_fingerprint in sources:
            for lib, pattern in _DETECTORS.items():
                per_library = 0
                for match in re.finditer(pattern, evidence, re.IGNORECASE):
                    version = match.group(1)
                    key = (lib, version, source, source_fingerprint)
                    if key in seen:
                        continue
                    seen.add(key)
                    instances.append(LibraryInstance(lib, version, source, source_fingerprint))
                    per_library += 1
                    if len(instances) >= cls.MAX_LIBRARY_INSTANCES:
                        return instances
                    if per_library >= cls.MAX_VERSIONS_PER_LIBRARY_SOURCE:
                        break
        return instances

    # Concise alias for consumers interested in dependency inventory rather than advisories.
    inventory = detect_library_instances

    @classmethod
    def detect_libraries(cls, content: str, script_url: Optional[str] = None) -> Dict[str, str]:
        """Return the first version of each library (legacy compatibility view).

        Use :meth:`detect_library_instances` when multiple loaded versions matter.
        """
        found: Dict[str, str] = {}
        for instance in cls.detect_library_instances(content, script_url=script_url):
            found.setdefault(instance.library, instance.version)
        return found

    @classmethod
    def scan(cls, content: str, script_url: Optional[str] = None) -> List[LibFinding]:
        findings: List[LibFinding] = []
        for instance in cls.detect_library_instances(content, script_url=script_url):
            # This database's Angular entries describe AngularJS 1.x, not modern Angular.
            if instance.library == "angular" and _vtuple(instance.version)[0] != 1:
                continue
            for entry in VULN_DB.get(instance.library, []):
                if entry.below is None or _lt(instance.version, entry.below):
                    findings.append(LibFinding(
                        instance.library,
                        instance.version,
                        entry.ref,
                        entry.severity,
                        entry.summary,
                        list(entry.boosts),
                        instance.source,
                        instance.source_fingerprint,
                    ))
        # Retain distinct vulnerable versions and evidence sources. ``ref`` remains part of the
        # key because one library version can legitimately match several independent advisories.
        seen = set()
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        uniq = []
        for f in sorted(
            findings,
            key=lambda f: (order.get(f.severity, 9), f.library, _vtuple(f.version),
                           f.source, f.source_fingerprint, f.ref),
        ):
            key = (f.library, f.version, f.source, f.source_fingerprint, f.ref)
            if key not in seen:
                seen.add(key)
                uniq.append(f)
                if len(uniq) >= cls.MAX_FINDINGS:
                    break
        return uniq

    @classmethod
    def scan_artifact(cls, script_url: str, content: str) -> List[LibFinding]:
        """Scan one already-obtained script artifact using URL and content evidence.

        This method is intentionally passive: callers supply both values and the scanner never
        performs network I/O.
        """
        return cls.scan(content, script_url=script_url)

    @classmethod
    def payload_boosts(cls, findings: List[LibFinding]) -> List[str]:
        """Payload families to prioritize given the vulnerable libraries present."""
        boosts: List[str] = []
        for f in findings:
            for b in f.boosts:
                if b not in boosts:
                    boosts.append(b)
        return boosts
