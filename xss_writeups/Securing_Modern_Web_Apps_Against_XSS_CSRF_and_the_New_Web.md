# Securing Modern Web Apps Against XSS, CSRF, and the “New” Web

> **Author**: Praxen
> **Published**: Jan 12, 2026

---

## A practical, modern playbook for stopping the attacks that still win — using stricter browser defenses, safer defaults, and smarter server checks.

![Praxen](https://miro.medium.com/v2/resize:fill:32:32/1*CypQqPnSxslsVUqeQffAQg.png)

26

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:700/1*kyfuCD4dajX3ekEQ8SdyaQ.png)

Learn modern defenses for XSS, CSRF, clickjacking, and supply-chain risks using strict CSP, Trusted Types, Fetch Metadata, SameSite cookies, and more.

Let’s be real: most web breaches aren’t “Hollywood hacking.” They’re small trust mistakes at scale — one unsafe DOM write, one missing CSRF check, one dependency update that quietly turned into a liability. The good news? The modern web platform (and modern frameworks) have given us better tools than “sanitize everything and pray.” The trick is knowing which defenses actually move the needle in 2026 — and how to combine them without breaking your app.

## Why XSS and CSRF Still Work (Even in “Modern” Stacks)

Security teams love the idea that “we use React” or “we’re an API-only backend” means old attacks don’t apply. But attackers don’t care about your stack’s vibe.

- XSS happens when untrusted data becomes executable script — often through the DOM, not your server templates.
- CSRF happens when a browser automatically includes credentials (cookies) on a request the user didn’t intend to make.

What’s changed: browsers now provide stronger signals and controls (CSP nonces, Trusted Types, Fetch Metadata, SameSite). What hasn’t changed: developers still ship sharp edges.

## XSS in 2026: Treat the DOM Like a Loaded Weapon

## The “modern” XSS is DOM XSS

Classic reflected XSS is still around, but DOM XSS is the one that slips into “safe” SPAs: a string flows into innerHTML, insertAdjacentHTML, document.write, or a risky templating helper. One shortcut during a deadline, and boom—script execution.

Practical rule: if you must render HTML, make it a deliberate, gated action — never the default.

## Strict CSP: stop trusting host allowlists

A lot of CSP deployments look serious… and still allow XSS. Why? Because host allowlists (e.g., “scripts can load from these CDNs”) often get bypassed through JSONP, misconfigured endpoints, or “helpful” wildcarding.

A stricter pattern is nonce/hash-based CSP, where only scripts with a server-generated nonce (or a known hash) are allowed to execute. This is the direction modern guidance pushes because it focuses on preventing execution of injected script, not just controlling where scripts come from.

Here’s an example in Node/Express that sets a nonce per request:

```
import crypto from "crypto";

export function cspMiddleware(req, res, next) {
  const nonce = crypto.randomBytes(16).toString("base64");
  res.locals.cspNonce = nonce;

  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      `script-src 'nonce-${nonce}' 'strict-dynamic'`,
      "object-src 'none'",
      "base-uri 'self'",
      "frame-ancestors 'none'",
      "upgrade-insecure-requests"
    ].join("; ")
  );

  next();
}
```

Then in your HTML template:

```
<script nonce="{{cspNonce}}">
  window.__BOOTSTRAP__ = { /* safe JSON */ };
</script>
```

If you’re thinking “this will be painful,” you’re not wrong. But it’s the kind of painful that removes an entire class of worst-day incidents.

## Trusted Types: make unsafe DOM sinks refuse strings

This is one of the most underrated defenses for real-world apps. Trusted Types let you tell the browser: “Do not accept raw strings in dangerous DOM APIs.” That turns a whole category of DOM XSS into immediate runtime errors (or reports), forcing you to fix the flows instead of hoping code review catches them.

The enforcement is typically enabled via CSP:

- Content-Security-Policy: require-trusted-types-for 'script';

You can roll it out safely using Report-Only first, watch what breaks, and then tighten.

## “Sanitization” is not a strategy — precision is

Sanitizing HTML is necessary sometimes (e.g., rich text editors), but it’s not a blanket solution. Different contexts require different encoding rules:

- HTML text context ≠ attribute context ≠ URL context ≠ JS context.
- The safest path is output encoding by context and minimizing HTML injection surfaces.

So yes, sanitize when you must. But try to make “must” a rare word.

## Small checklist that prevents big regret

- Avoid dangerouslySetInnerHTML unless it’s isolated and justified.
- Never build HTML with string concatenation.
- Use templating systems with auto-escaping; don’t disable it casually.
- Add a CSP that actually blocks inline scripts (unless nonced).
- Add Trusted Types to eliminate accidental DOM sink usage.

## CSRF: Stop Treating It as “Just Add a Token”

CSRF protection used to mean: “Add a hidden input token, validate it server-side.” That still works. But modern apps now have better options — and better failure modes.

## SameSite cookies help… but don’t declare victory

Modern browsers treat cookies without an explicit SameSite attribute more strictly (often behaving like SameSite=Lax). This reduces some CSRF risk by default, especially for cross-site POSTs.

But here’s the catch: SameSite is partial protection, not a full CSRF solution. Top-level navigations, legacy browser behavior, and “state-changing GET” endpoints can still bite you. If your app has endpoints that change state via GET (it happens more than people admit), Lax won’t save you.

## Get Praxen’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

What to do:

- Set cookies explicitly: SameSite=Lax (or Strict where possible), Secure, and HttpOnly.
- Ensure all state-changing actions are POST/PUT/PATCH/DELETE.
- Keep server-side CSRF defenses in place for cookie-authenticated sessions.

## Fetch Metadata headers: the “new school” CSRF gate

Browsers send Fetch Metadata request headers like Sec-Fetch-Site that describe the context of the request. On the server, you can reject requests that are clearly cross-site for sensitive endpoints—without relying solely on tokens.

A pragmatic policy looks like:

- If Sec-Fetch-Site is cross-site, block requests to session-authenticated mutation endpoints (except maybe a few carefully chosen cases like OAuth callbacks).
- Allow same-origin and same-site.
- Handle missing headers conservatively (older clients, bots, edge cases).

Example Express middleware:

```
const SAFE_SITE_VALUES = new Set(["same-origin", "same-site", "none"]);

export function fetchMetadataCsrfGuard(req, res, next) {
  // Only enforce on state-changing requests
  const method = req.method.toUpperCase();
  const isMutation = !["GET", "HEAD", "OPTIONS"].includes(method);
  if (!isMutation) return next();

  const site = req.get("Sec-Fetch-Site");
  if (!site) {
    // Missing header: fall back to traditional CSRF token checks or Origin/Referer validation
    return res.status(403).send("Blocked: missing Fetch Metadata headers");
  }

  if (!SAFE_SITE_VALUES.has(site)) {
    return res.status(403).send("Blocked: cross-site request");
  }

  next();
}
```

OWASP explicitly calls out Sec-Fetch-Site as a strong signal for blocking CSRF-like cross-origin requests.

And yes, you can combine this with traditional tokens. Defense-in-depth isn’t paranoia; it’s just experience.

## Token CSRF still matters (especially for “none”)

Even with Fetch Metadata, you’ll see legitimate cases where Sec-Fetch-Site: none appears (user-initiated navigations). Some teams keep classic CSRF tokens for high-risk flows (money movement, password/email changes) and use Fetch Metadata as a broad gate.

If you’re building something serious, that combo is hard to beat.

## “And More”: The Attacks You Should Bundle Into Your Baseline

## Clickjacking: stop being frameable by default

If your app can be embedded in an attacker-controlled iframe, your UI can be tricked into “user clicks.” Modern CSP gives you a clean control:

- frame-ancestors 'none' (or a strict allowlist)

This is more reliable than legacy X-Frame-Options alone.

## Supply-chain XSS: when the script is “legit”

Some of the nastiest incidents come from compromised dependencies or third-party scripts. If you load scripts you don’t strictly need, you’re expanding your threat surface for… analytics convenience.

Practical moves:

- Keep third-party scripts to a minimum.
- Pin versions and audit diffs (yes, actually read them sometimes).
- Prefer self-hosting critical libraries.
- Use subresource integrity (SRI) where it makes sense.

## Session safety: cookies, tokens, and the boring stuff that matters

- Use short-lived sessions with rotation for sensitive apps.
- Protect session cookies with HttpOnly, Secure, and an explicit SameSite.
- Treat refresh tokens like crown jewels (storage and rotation matter).

## A Modern Security Posture Looks Like This

If you want a simple mental model, aim for three layers:

- Browser-level guards: strict CSP, Trusted Types, SameSite cookies, frame-ancestors.
- Server-level intent checks: Fetch Metadata policy, Origin checks, CSRF tokens for sensitive flows.
- App-level hygiene: safe DOM patterns, encoding by context, minimal third-party scripts, clean dependency practices.

You’re not trying to be “unhackable.” You’re trying to be the app that attackers abandon after five minutes because the easy paths are gone.

## Conclusion: Make Security a Default, Not a Feature

The shift in modern web security is subtle but powerful: we’re moving from “catch vulnerabilities” to “remove entire classes of mistakes.” Strict CSP and Trusted Types shrink XSS. Fetch Metadata shrinks CSRF. Good cookie defaults reduce ambient risk.

You might be wondering, “Is this too much for a small team?” Honestly — start with one thing you can ship this week:

- Add a nonce-based CSP in Report-Only mode.
- Turn on Trusted Types reporting.
- Block cross-site mutations using Fetch Metadata for your cookie-auth endpoints.

If you want, drop a comment with your stack (Next.js? Laravel? Django? Spring?) and the kind of auth you use (cookies vs tokens). I’ll suggest a clean rollout order that won’t torch your release schedule.



---
*Original URL: [https://medium.com/@Praxen/securing-modern-web-apps-against-xss-csrf-and-the-new-web-1c696ecc3a37?source=search_post---------85-----------------------------------](https://medium.com/@Praxen/securing-modern-web-apps-against-xss-csrf-and-the-new-web-1c696ecc3a37?source=search_post---------85-----------------------------------)*
