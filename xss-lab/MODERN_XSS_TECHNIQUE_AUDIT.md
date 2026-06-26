# Modern XSS Technique Coverage Audit

Audit date: 2026-06-09

This project is strong for classic and practical bug bounty XSS, but it is not yet complete against every modern technique used by top client-side researchers. The strongest coverage is context-aware payloading, real-browser oracle validation, stored/cross-role verification, CSP/filter awareness, postMessage automation, and bounty-impact scoring. The biggest remaining gaps are dynamic taint-style DOM tracing, deeper client-side prototype pollution gadget discovery, DOM clobbering chains, framework-specific gadgets, and sanitizer-version-specific mXSS corpora.

## Sources Checked

- PortSwigger Web Security Academy XSS cheat sheet, 2026 edition
- PortSwigger DOM-based vulnerability source/sink model
- PortSwigger DOM Invader prototype pollution guidance
- PortSwigger postMessage DOM XSS guidance
- PortSwigger DOM clobbering and CSP bypass research
- OWASP XSS and DOM XSS prevention cheat sheets
- Google/web.dev Trusted Types DOM XSS guidance

## Coverage Matrix

| Technique family | Status | Current project coverage | Gap to top-tier coverage |
|---|---|---|---|
| Context-aware reflected XSS | Strong | HTML text, quoted/unquoted attr, event handler, JS string, JSON, URL context grammars | Keep syncing payload corpus with PortSwigger cheat sheet updates |
| Modern tags/events | Strong | SVG, MathML, iframe/srcdoc, animation, autofocus/focus, pointer, source/media events | Add automated browser compatibility scoring per vector |
| Filter/WAF mutation | Strong | case, whitespace, entities, URL encoding, Unicode, keyword splitting, wrappers | Add per-target payload learning from confirmed bypasses |
| CSP-aware payloading | Partial | Parses CSP and filters script/event/javascript URL families | Needs nonce/hash/strict-dynamic gadget discovery and allowlisted-script gadget inventory |
| Real-browser oracle | Strong | Hooks alert, eval, Function, timers, document.write, HTML setters, jQuery, resource attributes | Added newer sinks: document.writeln, Range.createContextualFragment, DOMParser.parseFromString, setHTML/setHTMLUnsafe, ShadowRoot.innerHTML, iframe.srcdoc |
| DOM sources | Partial+ | Static signatures now flag location, URLSearchParams, window.name, referrer, cookies, storage, postMessage, prototype pollution candidates; modern probe endpoint fingerprints frameworks/CSP/Trusted Types | Needs dynamic source-to-sink taint graph |
| postMessage DOM XSS | Strong | Static detection for message listeners/event.data, oracle telemetry for token-bearing message delivery, generated parent/iframe PoC HTML, browser execution endpoint with wildcard/exact-origin/delayed/nested variants, HTTP-hosted local PoC pages, and origin-mode expansion for real-local, startsWith/endsWith spoofing, and exact-origin triage | Needs external exploit-server integration for programs that provide a sanctioned exploit-hosting domain |
| Client-side prototype pollution | Partial+ | Static candidate/gadget detection, JSON payload seed, generated query/hash variants for `__proto__` and `constructor[prototype]`, browser execution endpoint | Needs deeper gadget search and rollback/isolation like DOM Invader |
| DOM clobbering | Partial+ | Generated clobbering payload families, hard-lab route, static named-property gadget candidates, browser execution endpoint | Needs CSP bypass chain discovery and lower-false-positive static analysis |
| mXSS/sanitizer bypass | Partial+ | DOMPurify/sanitize-html detection, parser-context payloads, generated mXSS regression probes | Needs sanitizer-version-specific bypass corpus |
| Stored XSS | Strong | Stored/cross-session verifier submits, revisits, records oracle hits, and creates confirmed findings | Add UI workflow and scheduled revisit jobs |
| Cross-role impact | Strong | Verifier supports multiple authorized role/session contexts and impact scoring | Add role profile manager in UI |
| Framework-specific XSS | Weak | React dangerouslySetInnerHTML static sink only | Needs Angular expression/CSP contexts, Vue directives, Markdown/rendering libraries, rich-text editors |
| Trusted Types | Partial | Detects `require-trusted-types-for`, policy names, script policy creation, and token-bearing CSP/Trusted Types telemetry | Needs UI surfacing and policy-specific bypass analysis |
| Report quality | Strong | Bounty report builder, evidence refs, impact score, screenshot/token refs | Add per-platform templates and duplicate-risk notes |

## Bottom Line

The project is already practical for real bug bounty XSS hunting, especially reflected, stored, cross-role, and postMessage-origin-validation cases. It is not yet at the level of a dedicated DOM Invader-style research browser for prototype pollution, DOM clobbering, framework gadgets, sanitizer parser differentials, and Trusted Types policy bypass analysis.

## Recommended Next Build Order

1. Add dynamic source-to-sink tracing so DOM source evidence can be connected to exact sinks without relying only on static signatures.
2. Add deeper client-side prototype pollution gadget search with browser isolation and automatic rollback.
3. Add DOM clobbering CSP bypass chain discovery with lower-false-positive static analysis.
4. Add framework/rendering-library payload profiles for Angular, Vue, React, Markdown, rich-text editors, and template engines.
5. Add UI surfacing for Trusted Types/CSP runtime telemetry.
6. Add sanitizer-version-specific mXSS regression corpus and version fingerprinting.
7. Add external exploit-server integration for programs that explicitly allow sanctioned PoC hosting.
