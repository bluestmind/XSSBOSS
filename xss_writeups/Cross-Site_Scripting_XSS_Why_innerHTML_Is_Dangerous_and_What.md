# Cross-Site Scripting (XSS): Why innerHTML Is Dangerous (and What Else to Avoid)

> **Author**: Comviva MFS Engineering Tech Blog
> **Published**: Mar 2, 2026

---

![Comviva MFS Engineering Tech Blog](https://miro.medium.com/v2/resize:fill:32:32/1*r_HXBhTBTvz9CCVXEMjJDg.png)

2

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:64/0*_SpvnKORd3MKnPJ1.png)

## Introduction

Cross-Site Scripting (XSS) is not an exotic vulnerability. It often hides inside everyday features like:

- remarks fields
- comments
- notes
- audit descriptions
- rich text inputs

The root cause is almost always the same:

Treating user input as executable HTML.

One of the biggest offenders is innerHTML — but it’s not the only one.

This article explains:

- why regex filtering doesn’t work
- why innerHTML is dangerous
- other APIs that cause XSS
- what attackers can actually do
- how to prevent it properly

This is written for engineers building real systems, not theoretical demos.

## The Typical Mistake: Rendering Remarks as HTML

Developers want to preserve formatting:

```
element.innerHTML = userInput;
```

To “secure” it, they add regex:

```
if (!/<script>/i.test(userInput)) {
 element.innerHTML = userInput;
}
```

This feels safe.

It is not.

Attackers don’t need <script>.

They can use:

```
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<a href="javascript:alert(1)">click</a>
```

Regex cannot predict all attack variations.

Security is not pattern matching.

It’s context-aware escaping.

## Why Regex Filtering Fails

Regex assumes attacks follow predictable patterns.

Attackers can:

- encode payloads
- nest tags
- split keywords
- abuse attributes
- use browser quirks
- inject via SVG or CSS
- use event handlers instead of script tags

There are hundreds of bypass techniques.

No regex can safely sanitize HTML.

Only an HTML parser can.

## What Happens During XSS

When you use innerHTML, the browser parses the string as DOM.

That means:

- scripts run
- event handlers execute
- injected CSS applies
- malicious links activate

The attacker’s code runs with your app’s permissions.

To the browser:

The attack is trusted content.

## What an Attacker Can Do

XSS is not just alert popups.

## Get Comviva MFS Engineering Tech Blog’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

Real damage includes:

- stealing session tokens
- account takeover
- data exfiltration
- injecting fake UI
- phishing inside your app
- hidden click hijacking via CSS
- persistent stored attacks

Stored XSS is especially dangerous because it spreads to all viewers.

## innerHTML Is Not the Only Dangerous API

Many APIs silently execute HTML or scripts.

Avoid these with untrusted input:

## Dangerous APIs

- innerHTML
- outerHTML
- insertAdjacentHTML
- document.write
- eval()
- new Function()
- setTimeout(string)
- React: dangerouslySetInnerHTML
- Angular: bypassSecurityTrustHtml

These APIs are unsafe only when used with untrusted data. Untrusted includes any data that ultimately originated from users, external systems, logs, or databases — even if it’s now stored internally.

## Safe Alternatives

## Use text rendering instead of HTML

```
element.textContent = userInput;
```

This treats input as text.

No execution. No parsing. Safe by default.

## If HTML formatting is required

Use a real sanitizer:

- DOMPurify
- sanitize-html
- OWASP HTML Sanitizer

```
element.innerHTML = DOMPurify.sanitize(userInput);
```

Sanitizers understand DOM structure.

Regex does not.

## Defense in Depth

Even sanitized systems should add extra protection.

## Enable Content Security Policy (CSP)

```
Content-Security-Policy: default-src 'self';
```

CSP limits script execution and reduces XSS impact.

Not a replacement — a safety net.

## Escape on output, not input

Store raw data.

Escape when rendering.

Input validation ≠ output encoding.

## Treat stored content as untrusted

Even database data.

Stored XSS is one of the most common enterprise vulnerabilities.

## Practical Engineering Checklist

Before rendering dynamic content:

- Are we using textContent instead of innerHTML?
- If HTML is needed, are we sanitizing with a real library?
- Are React/Angular escape hatches avoided?
- Is CSP enabled?
- Are remarks/comment fields reviewed specifically?
- Are logs and audit text escaped?

Remarks fields are the #1 hidden XSS surface.

## Closing Thoughts

XSS happens when data becomes code.

Regex filtering gives false confidence.

The real rule is simple:

Never execute user input as HTML.
Sanitize with proper tools.
Default to safe rendering

Originally published at https://medium.com on March 2, 2026.



---
*Original URL: [https://medium.com/@dfs.techblog/cross-site-scripting-xss-why-innerhtml-is-dangerous-and-what-else-to-avoid-0a11e550dda9?source=search_post---------52-----------------------------------](https://medium.com/@dfs.techblog/cross-site-scripting-xss-why-innerhtml-is-dangerous-and-what-else-to-avoid-0a11e550dda9?source=search_post---------52-----------------------------------)*
