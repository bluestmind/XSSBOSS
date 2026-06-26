# Threat Management as Frontend Engineer — XSS

> **Author**: ZIS
> **Published**: Jan 11, 2026

---

Member-only story

![ZIS](https://miro.medium.com/v2/resize:fill:64:64/0*pDHivtH8xeRToX1D.)

1

Listen

Share

Let me ask you a normal question, and one of the answers to that question. What is frontend?

I believe your head has already generated a lot of answers, but let me answer this for you for this post. Frontend is an application’s user interface that resides on your computer or anyone over the internet using the application via a browser. In other words, your app is in everyone’s browser where they can do whatever they want their using the JavaScript.

This sounds scary, but we have already taken a lot of security measures, from protocols to servers and so on, to avoid that. However, there are still some risks. In this post, I will try to write some of the threats we may or already faced in our applications and some caution measures that can be taken.

## Cross-Site Scripting (XSS)

This is the most common threat FE Engineers tackled, and every major FE Framework has support to prevent this. In XSS, an attacker injects malicious JavaScript into a trusted web application to

- Steal cookies and session tokens
- Perform actions as the user (account takeover)
- Modify UI content (defacement)
- Capture keystrokes
- Redirect users to malicious sites

### Scenario 1 - Stored (Persistent):

Let me give you an example of how it is done. Let’s say you have a blog site, and the…



---
*Original URL: [https://medium.com/@zisuzon/threat-management-as-frontend-engineer-xss-a9b4259a53d7?source=search_post---------89-----------------------------------](https://medium.com/@zisuzon/threat-management-as-frontend-engineer-xss-a9b4259a53d7?source=search_post---------89-----------------------------------)*
