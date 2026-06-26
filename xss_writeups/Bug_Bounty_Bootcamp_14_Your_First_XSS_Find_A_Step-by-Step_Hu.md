# “Bug Bounty Bootcamp #14: Your First XSS Find — A Step-by-Step Hunter’s Methodology”

> **Author**: Aman Sharma
> **Published**: Jan 12, 2026

---

Member-only story

## Forget spraying alert(1) everywhere. Learn the systematic approach that turns random testing into reliable, bounty-worthy Cross-Site Scripting discoveries.

![Aman Sharma](https://miro.medium.com/v2/da:true/resize:fill:64:64/0*gTsmBWudIxLcZoel)

71

Listen

Share

Free link

![image](https://miro.medium.com/v2/resize:fit:700/1*ZrTDcgQji-VzmMendLMWhw.avif)

Welcome back to the Bootcamp. You understand the web’s language and its weak points. Now, we target one of the most common and impactful vulnerabilities: Cross-Site Scripting (XSS). Finding XSS isn’t about magic payloads; it’s a repeatable process of input discovery, output tracking, and careful escalation. This guide will walk you through the exact methodology used by hunters to go from a simple text box to a verified JavaScript execution.

## Step 1: The Hunter’s Fingerprint — Planting a Unique Test String

Your first action is never to inject a script. It’s to trace your input.

- Find Every Input: Look at all parameters in the URL (?name=, ?search=, ?id=), every field in a form (visible and hidden via "Inspect Element"), and any JSON body in POST requests.
- Plant Your Marker: In each input, inject a unique, identifiable string. The course example uses test123. You might use…



---
*Original URL: [https://medium.com/the-first-digit/bug-bounty-bootcamp-14-your-first-xss-find-a-step-by-step-hunters-methodology-097b4639bf46?source=search_post---------73-----------------------------------](https://medium.com/the-first-digit/bug-bounty-bootcamp-14-your-first-xss-find-a-step-by-step-hunters-methodology-097b4639bf46?source=search_post---------73-----------------------------------)*
