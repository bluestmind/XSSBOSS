# Guide to XSS Fundamentals: Vulnerabilities, Payloads, and WAF/CSP Bypasses

> **Author**: JPablo13
> **Published**: Mar 7, 2026

---

Member-only story

## Master Cross-site scripting: injection strategies, attack vectors, WAF evasion, and advanced CSP bypass techniques.

![JPablo13](https://miro.medium.com/v2/resize:fill:64:64/1*Gdw1mZ2WRem1uHwr8FlRkQ.jpeg)

23

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:700/1*HB3HBYKoLjbchN2uGEBxhg.png)

## What is Cross-site scripting (XSS)?

It is a web security vulnerability that allows an attacker to compromise the interactions users have with a vulnerable application. It allows bypassing the same-origin policy, which is designed to segregate different websites from each other. These vulnerabilities typically allow an attacker to access any of the data. If the victim user has privileged access within the application, then full control over all application functionality and data could be obtained.

## Execution Contexts

Success depends on how you “break” the code where your payload lands.

```
| Context     | Input Situation          | Injection Strategy            | Reference Payload                |
| ----------- | ------------------------ | ----------------------------- | -------------------------------- |
| HTML (Text) | <div>YOU_HERE</div>      | Break current tag.            | ><svg onload=alert(1)>           |
| Attribute   | <input value="YOU_HERE"> | Close quotes and add event.   | " autofocus…
```



---
*Original URL: [https://medium.com/system-weakness/guide-to-xss-fundamentals-vulnerabilities-payloads-and-waf-csp-bypasses-6811853b8226?source=search_post---------49-----------------------------------](https://medium.com/system-weakness/guide-to-xss-fundamentals-vulnerabilities-payloads-and-waf-csp-bypasses-6811853b8226?source=search_post---------49-----------------------------------)*
