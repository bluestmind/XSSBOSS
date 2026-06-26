# XSS Attacks: A Practical Methodology for Security Testing

> **Author**: Israel Aráoz Severiche
> **Published**: Jan 15, 2026

---

Member-only story

![Israel Aráoz Severiche](https://miro.medium.com/v2/resize:fill:64:64/2*o_hfMmEqah3r-SxKiyi8Cw.png)

18

2

Listen

Share

Cross-Site Scripting (XSS) is one of the most common vulnerabilities found in web applications today. It allows attackers to inject malicious scripts into web pages viewed by other users. According to OWASP, XSS consistently ranks among the top 10 web application security risks, making it a critical target for bug bounty hunters and security professionals.

![image](https://miro.medium.com/v2/resize:fit:700/1*CXWcSKKBVKGhzPCPHyzDrg.png)

This article provides a practical methodology for identifying and exploiting three main types of XSS vulnerabilities: Reflected XSS, Stored XSS, and DOM-based XSS.

## 👥 Join the AppSec Community

Want more hands-on guides, vulnerable labs, and live sessions?
👉 Join our AppSec community: nas.io/appsec

## Understanding XSS Types

### 1. Reflected XSS (Non-Persistent)

Reflected XSS occurs when user input is immediately returned by a web application without proper sanitization. The malicious script is “reflected” off the web server and executed in the victim’s browser.

### How It Works:

The attack follows this flow:

- Attacker crafts a malicious URL containing JavaScript code
- Victim clicks the…



---
*Original URL: [https://medium.com/@iaraoz/xss-attacks-a-practical-methodology-for-security-testing-6bff4d0fae1e?source=search_post---------80-----------------------------------](https://medium.com/@iaraoz/xss-attacks-a-practical-methodology-for-security-testing-6bff4d0fae1e?source=search_post---------80-----------------------------------)*
