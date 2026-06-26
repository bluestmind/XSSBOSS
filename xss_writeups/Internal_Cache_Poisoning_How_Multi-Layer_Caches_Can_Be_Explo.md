# Internal Cache Poisoning: How Multi-Layer Caches Can Be Exploited for Stored XSS

> **Author**: Bash Overflow
> **Published**: Nov 5, 2025

---

Member-only story

![Bash Overflow](https://miro.medium.com/v2/resize:fill:64:64/1*JoM8_WC11wsYSOwkJ1oqxQ.png)

3

Listen

Share

Learn how inconsistent cache key handling across layers can expose modern web applications to hidden injection risks.

🔓 Free Link

![Internal Cache Poisoning: How Multi-Layer Caches Can Be Exploited for Stored XSS](https://miro.medium.com/v2/resize:fit:700/1*L1N5K2Fe4j9o80SqKsRTuQ.png)

Disclaimer:
The techniques described in this document are intended solely for ethical use and educational purposes. Unauthorized use of these methods outside approved environments is strictly prohibited, as it is illegal, unethical, and may lead to severe consequences.

It is crucial to act responsibly, comply with all applicable laws, and adhere to established ethical guidelines. Any activity that exploits security vulnerabilities or compromises the safety, privacy, or integrity of others is strictly forbidden.

## Table of Contents

- Summary of the Vulnerability
- Steps to Reproduce & Proof of Concept (PoC)
- Impact

## Summary of the Vulnerability

This lab demonstrates a web cache poisoning flaw where multiple caching layers (an external cache and an internal fragment cache) treat different parts of an HTTP request inconsistently when building their cache keys.



---
*Original URL: [https://medium.com/the-first-digit/internal-cache-poisoning-how-multi-layer-caches-can-be-exploited-for-stored-xss-9e15b0367780?source=search_post---------153-----------------------------------](https://medium.com/the-first-digit/internal-cache-poisoning-how-multi-layer-caches-can-be-exploited-for-stored-xss-9e15b0367780?source=search_post---------153-----------------------------------)*
