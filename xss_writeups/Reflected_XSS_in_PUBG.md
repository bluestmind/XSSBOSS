# Reflected XSS in PUBG

> **Author**: Monika sharma
> **Published**: Nov 13, 2025

---

Top highlight

## A single unsanitized parameter is all an attacker needs

![Monika sharma](https://miro.medium.com/v2/da:true/resize:fill:32:32/0*Tv4b4p5mb6J3IJwD)

8

4

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:700/1*8FMCPYVVzkWGvlaI6YQ6sg.png)

A security researcher reported a reflected cross-site scripting (XSS) issue on PUBG’s main site. At first glance it was the classic “reflected XSS” story(751870): a URL parameter was echoed into a page without proper escaping, and a crafted link could make a victim’s browser execute attacker-supplied JavaScript. But that simple description understates two important facts every web engineer and bug hunter should remember:

- Reflected XSS bugs are low-friction for attackers a single crafted link sent via chat, social media, or email is enough.
- The impact depends on the surrounding application: authentication, available actions, and what JavaScript can access.

Below I’ll walk through the vulnerability in plain language, explain why it matters, show safe verification practices (no exploit code), and give concrete mitigation and detection guidance for engineers and bug hunters.

### Summary

- Target: https://www.pubg.com
- Vulnerability class: Reflected Cross-Site Scripting
- Root cause: A GET parameter (p) was echoed into a page without adequate sanitization/escaping.

![image](https://miro.medium.com/v2/resize:fit:700/1*tDJwR17fJhZKySTwHDBHdQ.png)

- Exploitation vector: An attacker can craft a URL containing JavaScript in the p parameter; when a victim clicks that link, the injected script executes in the victim’s browser within the pubg.com origin.
- Potential impact: Arbitrary JavaScript execution in a victim’s browser enabling session token access, forged requests, UI manipulation, or social engineering depending on the site’s state and protections.

![image](https://miro.medium.com/v2/resize:fit:700/1*VexbIh7HcRuTkZ7L-IOJEg.png)

### How reflected XSS works

Reflected XSS happens when an application takes input from the request commonly query parameters inserts it into an HTML response, and the input is interpreted as executable code by the browser because it wasn’t escaped properly.

A secure flow looks like this:

- Server receives ?p=<user-supplied-value>.
- Server treats p as untrusted data and encodes/escapes any HTML-special characters before inserting into the response (e.g., converting < to &lt;).
- The response renders the escaped text; the browser shows it as text, not executable code.

When escaping fails, an attacker-controlled value containing scriptable constructs can be reflected back and executed by any user who loads the crafted URL which is exactly what the PUBG report described.

### Why this matters beyond “it pops an alert”

A vanilla PoC that triggers alert(…) is useful to prove the issue, but the real risk depends on context:

- Session theft or account takeover: If the site stores auth tokens in cookies accessible to JavaScript (i.e., not HttpOnly), a malicious script could read them and send them to an attacker-controlled server.
- Action forging: If sensitive actions rely solely on cookies and lack CSRF protection, an attacker can cause a victim’s browser to perform those actions.
- UX manipulation & phishing: Injected scripts can change the page content to trick users into revealing credentials, clicking premium actions, or authorizing dangerous workflows.
- Chaining to other bugs: XSS combined with a poorly-protected admin interface, or with open redirect and CSRF bugs, can dramatically raise impact.

The PUBG report called out the presence of unsanitized output in a GET parameter a textbook example with real-world consequences depending on cookie and session configurations.

### Responsible verification how to confirm safely

If you’re testing a target in-scope for bug bounty or permissioned testing, follow a minimal, non-destructive approach:

## Get Monika sharma’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

Do:

- Use non-destructive proofs such as alert(1) or other inert markers in a private test environment, or record response differences (headers, content-length) rather than extracting data.
- Test with a test account you control. Capture only metadata and structural differences; redact any real tokens or PII from reports.
- Prefer client-side, ephemeral proofs that don’t persist or affect other users.
- Document exact reproduction steps for triage teams, but sanitize outputs so no secrets are included.

Don’t:

- Attempt to exfiltrate other users’ data or tokens.
- Run mass automated scans that could cause harm or violate a program’s terms.
- Publish working exploit pages that automatically steal data.

The PUBG report contained demonstration artifacts (screenshots and a short screencast) to help triage reproduce the issue while keeping the PoC focused on behavior rather than on stolen data.

### How to fix it

Reflected XSS is a well-known class with straightforward mitigations. Apply defense-in-depth:

- Escape all untrusted output.

- For HTML contexts, HTML-encode characters like <, >, &, and “. Use framework-provided encoders instead of hand-rolled string replacements.

2. Use proper content security policies (CSP).

- CSP can significantly reduce the impact of XSS by restricting inline scripts and limiting which external scripts can run. However, CSP is a mitigation, not a substitute for proper escaping.

3. Mark cookies HttpOnly and SameSite where appropriate.

- HttpOnly prevents JavaScript from reading cookie values; SameSite mitigates some CSRF vectors.

4. Avoid reflecting raw user input into executable contexts.

- If you must render user-supplied content, sanitize it for the intended output context (HTML, JavaScript, attribute, URL, CSS) and use context-aware encoders.

5. Harden forms & state-changing endpoints with anti-CSRF.

- If XSS is present, CSRF becomes much more dangerous; combine protections to reduce overall risk.

6. Audit legacy endpoints and client-side templates.

- Old templates, localized strings, or early-stage debug pages are common sources of reflected input.

### Detection & monitoring recommendations

- Static analysis: Include templating engine rules and linting in CI to catch unescaped output during development.
- Automated scanning with caution: Use XSS scanners in safe environments (staging) and always respect target-scope and rate limits.
- Runtime protections: Deploy WAF rules to detect suspicious request patterns as a short-term control while fixing code.
- Bug bounty triage: Encourage reporters to provide sanitized PoCs, reproduction steps, and environment details so triage can validate without exposure.

### Takeaways for bug hunters and engineers

For bug hunters:

- Don’t discount reflected XSS — it’s simple to find and can still yield serious impact when composed with other issues.
- When reporting, include clear reproduction steps, sanitized evidence (headers, screenshots), and an impact statement that explains how the bug could be used in the wild. That clarity helps triage and increases the chance of a meaningful reward.

For engineers:

- Treat any user-supplied data as hostile. Use context-aware escaping and review templates that render query parameters.
- Combine server-side fixes with CSP, cookie hardening, and WAF rules for defense-in-depth.
- Pay special attention to legacy code and localized templates — they often evade modern sanitization patterns.

### Closing

Reflected XSS is one of the oldest web vulnerabilities, but it remains relevant because it’s easy to introduce and can be devastating when combined with weak session protections or other logic bugs. The PUBG report is a useful reminder: even mature public sites need continuous attention to output encoding, template hygiene, and layered defenses.

If you found this write-up helpful or learned something new, consider supporting my next caffeine-powered research:

## Monika

### Hi, I'm Monika - a bug bounty hunterI love breaking down complex vulnerabilities into simple, practical write-ups so…

buymeacoffee.com



---
*Original URL: [https://medium.com/bugbountywriteup/reflected-xss-in-pubg-7cee89243268?source=search_post---------139-----------------------------------](https://medium.com/bugbountywriteup/reflected-xss-in-pubg-7cee89243268?source=search_post---------139-----------------------------------)*
