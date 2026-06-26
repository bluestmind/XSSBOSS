# Reflected XSS with Base64 — Breaching Obscurity in Seconds

> **Author**: embossdotar
> **Published**: Nov 24, 2025

---

Member-only story

![embossdotar](https://miro.medium.com/v2/resize:fill:64:64/1*BYH6jT1pxbg2kqBFRpRD0g.png)

35

3

Listen

Share

Why “security by obscurity” (yes, base64 too) is a bad idea — explained

Hi — recently I was invited to perform a pentest and harden the security posture of a well-known organization. I accepted the challenge.

Every security researcher develops a set of intuitions and small tricks that repeatedly pay off. I won’t reveal sensitive details about the target, but I will share a short, focused story and the lessons it illustrates — because the takeaway is broadly useful: obscuring data with base64 is not security.

In my case, it took literally seconds, manually and without automated scanners, to reach the right place and demonstrate a reflected cross-site scripting (XSS) vector. Popcorn time 🍿

Disclaimer: This writeup is for educational and ethical-hacking purposes only. Do not use the techniques described here for unlawful or harmful actions. If you discover a vulnerability, follow responsible disclosure and coordinate with the affected organization.

On an SSO login flow, an error page displayed a textual message after a bad code was submitted. The human-readable message looked fine, but the URL contained a parameter filled with odd characters. A quick inspection showed the parameter was base64-encoded text that the app decoded and reflected back into the page.

Two simple facts made this risky:

- The application decoded user-controlled input and rendered it to the…



---
*Original URL: [https://medium.com/bugbountywriteup/reflected-xss-with-base64-breaching-obscurity-in-seconds-e1f9e50a4709?source=search_post---------140-----------------------------------](https://medium.com/bugbountywriteup/reflected-xss-with-base64-breaching-obscurity-in-seconds-e1f9e50a4709?source=search_post---------140-----------------------------------)*
