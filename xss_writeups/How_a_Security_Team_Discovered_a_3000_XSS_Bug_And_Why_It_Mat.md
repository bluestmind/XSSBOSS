# How a Security Team Discovered a $3,000 XSS Bug — And Why It Matters for Every Company

> **Author**: Cybervolt
> **Published**: Nov 26, 2025

---

![Cybervolt](https://miro.medium.com/v2/resize:fill:32:32/1*NPNuSSSvxdRJVk0HGddrzg.png)

10

1

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:275/1*MKoy3NVvG9GoORcBR1I6Gg.jpeg)

Cross-Site Scripting (XSS) remains one of the most consistently rewarded and impactful vulnerabilities in modern bug bounty programs. Even today — with frameworks, security headers, and filtering libraries — one overlooked input field is all it takes for an attacker to gain access to user sessions, perform unauthorized actions, or run malicious scripts inside a victim’s browser.

Recently, a security team participating in a private bug bounty program uncovered a $3,000 XSS vulnerability inside a popular SaaS platform. Although the reward was impressive, the journey to uncover it was even more valuable: it revealed how vulnerabilities can survive despite strong security processes — and why attackers still succeed.

Here’s a breakdown of how the team approached the target, the scenario they uncovered, and the lessons your engineering team should take away.

## Step 1: The Recon Phase — Understanding How the Application Thinks

The SaaS platform had a well-protected authentication flow, CSP headers on major pages, and input validation on most user-facing features. At first glance, it looked bulletproof.

But experienced pentesters know:
XSS rarely hides in obvious places.
It hides in:

- forgotten legacy modules
- new features developed quickly
- admin-only pages
- user-generated content previews
- search filters
- mobile endpoints repurposed for web

During recon, the team focused on understanding how data moved through the system, not just where users typed text. That meant checking:

- What content gets rendered back to users?
- Which parts of the UI pull data using dynamic JavaScript?
- Are there pages that accept HTML-like characters?
- Are there “preview” or “draft” features?

A key find emerged: a feature that allowed users to customize their profile bio with formatting options.

## Step 2: The Discovery — A Formatting Feature With a Flaw

The profile bio editor allowed bold, italics, and colored text. The platform used a filtering library intended to remove unsafe tags — but a specific formatting option slipped through the cracks.

## Real-World Style Scenario (Safe Example)

Imagine this flow:

- A user writes a profile bio and adds special formatting.
- The system stores the formatted content.
- Other users viewing the profile see that content rendered dynamically.

Most formatting tags were sanitized, but one lesser-used attribute — intended for text styling — allowed unexpected characters inside it. When rendered by the browser, it could be interpreted in ways the developers never intended.

This isn’t unusual. XSS often appears in:

- SVG attributes
- data-* attributes
- markdown preview features
- custom-made rich text editors
- helpdesk ticket replies
- product review fields

The team noticed something odd:
When previewing the bio, the application inserted user content inside a JavaScript template string, which is notoriously tricky to secure if even one character is improperly escaped.

This was the opening.

## Step 3: Triggering the Bug — Without Breaking Anything

Even during a bounty test, responsible security teams avoid sending disruptive or malicious scripts. Instead, they use safe, harmless payloads that simply confirm whether code executes, such as:

- harmless pop-up test
- benign console message
- safe DOM event

Once the team confirmed that their harmless test executed, they documented:

- the exact field
- how the data traveled
- which browser context executed it
- whether authentication was needed
- whether other users could be affected

The key detail:
Any visitor who viewed the malicious profile would unknowingly execute the script.

## Get Cybervolt’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

That made it a stored XSS, which is more severe (and higher paying) than reflected XSS.

## Step 4: Real-World Impact — Why the Severity Was High Enough for $3,000

The platform hosted thousands of business accounts. If exploited by a malicious actor, the vulnerability could have allowed:

- session token theft
- full account takeover
- impersonation of users
- fraud or unauthorized billing actions
- phishing inside the platform
- spreading malware across user profiles

Because it was stored XSS, the exploit could spread passively: one compromised profile could trigger hundreds of cascading attacks as other users viewed it.

That level of systemic risk is exactly why bug bounty programs reward XSS so highly.

## Step 5: The Report — Clear Evidence, Zero Noise

A strong report is often the difference between $300 and $3,000.

The team provided:

- a clean explanation of the flaw
- steps to reproduce (non-destructive)
- safe screenshots of the executed test
- affected endpoints
- recommended fix (server-side sanitization + CSP strengthening)
- impact analysis showing real business risk

The response from the platform’s security engineers was immediate. They acknowledged:

- XSS slipped through during a UI redesign
- automated scanning hadn’t caught the flaw
- their filter library was outdated in this module

The team received a $3,000 reward within 48 hours.

## Real-World Lessons for Developers and Companies

This story highlights critical points every engineering and security team should understand:

## 1. New features often introduce old vulnerabilities.

A UI redesign, new editor, or new form field is enough to reintroduce XSS.

## 2. Client-side filters are not security.

Server-side validation and consistent escaping rules are non-negotiable.

## 3. CSP helps, but it cannot replace good coding practices.

## 4. Stored XSS is especially dangerous.

It spreads silently to every viewer.

## 5. Bug bounty hunters succeed because they think like attackers.

They go beyond automated scanners. They look at context, not just input boxes.

## Final Thoughts

This $3,000 XSS bug wasn’t discovered with fancy zero-days or elite tricks. It was found through methodical analysis, attention to detail, and a deep understanding of how web applications render user data.

For companies, it’s a reminder:
One small oversight can lead to large-scale compromise.

For pentesters and bounty hunters, it shows:
Understanding the application is your greatest weapon — not the payload



---
*Original URL: [https://medium.com/@cybervolt/how-a-security-team-discovered-a-3-000-xss-bug-and-why-it-matters-for-every-company-42801ffbb27f?source=search_post---------149-----------------------------------](https://medium.com/@cybervolt/how-a-security-team-discovered-a-3-000-xss-bug-and-why-it-matters-for-every-company-42801ffbb27f?source=search_post---------149-----------------------------------)*
