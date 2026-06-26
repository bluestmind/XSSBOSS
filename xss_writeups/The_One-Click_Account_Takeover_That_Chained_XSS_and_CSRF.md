# “The One-Click Account Takeover That Chained XSS and CSRF”

> **Author**: Aman Sharma
> **Published**: Nov 10, 2025

---

Member-only story

![Aman Sharma](https://miro.medium.com/v2/da:true/resize:fill:64:64/0*gTsmBWudIxLcZoel)

18

Listen

Share

During my analysis of web application vulnerability chains, I came across a brilliant finding from researcher Milly that demonstrates how combining seemingly minor vulnerabilities can lead to catastrophic results. This case shows the power of chaining XSS with CSRF to achieve complete account takeover on a major platform like TikTok.

### The Vulnerability Chain: XSS + CSRF = Account Takeover

The attack combined two separate vulnerabilities that individually had limited impact but together created a devastating exploit.

![image](https://miro.medium.com/v2/resize:fit:700/1*TjNebpDgLA3e2AK1raWx0w.png)

Vulnerability 1: Reflected XSS

- Location: URL parameter on www.tiktok.com and m.tiktok.com
- Issue: Parameter value reflected without proper sanitization
- Impact: Could execute arbitrary JavaScript in victim’s browser context
- Limitation: Required user interaction to visit malicious URL

Vulnerability 2: CSRF in Password Reset

- Location: Password reset endpoint for third-party authenticated accounts
- Issue: Missing CSRF protection on password change functionality
- Impact: Could change passwords for accounts that used social login



---
*Original URL: [https://medium.com/@amannsharmaa/the-one-click-account-takeover-that-chained-xss-and-csrf-cd4ebe22fb7f?source=search_post---------145-----------------------------------](https://medium.com/@amannsharmaa/the-one-click-account-takeover-that-chained-xss-and-csrf-cd4ebe22fb7f?source=search_post---------145-----------------------------------)*
