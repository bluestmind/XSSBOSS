# Open Redirect to XSS

> **Author**: elcezeri
> **Published**: Jan 14, 2026

---

![elcezeri](https://miro.medium.com/v2/resize:fill:32:32/1*2eJqXfp4TQ1hPcVQpcEZfw.jpeg)

27

2

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:700/1*VC_Ol0YnIDj_79VJkuhQJA.png)

Many bug bounty hunters overlook Open Redirect vulnerabilities, thinking they are “just a phishing vector.” But what if I told you that a redirect parameter could lead to full-blown Javascript execution? Today, I will share my journey of how I discovered an Open Redirect and escalated it to a rewarding XSS vulnerability.

## What is Open Redirect?

Open Redirect occurs when an application takes user-provided input and uses it to redirect the user to another page without proper validation. Attackers often use this to make malicious links look like they belong to a trusted domain.

Friend Link

## The Discovery: Hunting for Parameters

While exploring my target (redacted.com), I focused on the login flow. I noticed a common parameter in the URL: https://redacted.com/login?redirect_url=/my-account

This parameter tells the server where to send the user after a successful login. I immediately tested the obvious: https://redacted.com/login?redirect_url=https://evil.com

The Result: Blocked! The developers had implemented a basic filter.

## The Bypass Strategy

I didn’t give up. I tried several bypass techniques using slashes and encoding:

- ///evil.com
- /\/evil.com
- \/\/evil.com

One of these variations worked perfectly. After logging in, the browser redirected me straight to my external malicious site.

## The Escalation: Turning Redirect into XSS

An Open Redirect is good, but XSS is better. I wondered if the redirect_url parameter supported the javascript: URI scheme.

## Get elcezeri’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

I crafted the following payload: https://redacted.com/login?redirect_url=javascript:alert(1)

The Moment of Truth: I logged into the application. Instead of being redirected to a new page, the browser executed my JavaScript code on the redacted.com domain. XSS Triggered!

![image](https://miro.medium.com/v2/resize:fit:278/1*pAQnyafB7hwhfJgvuaWicw.png)

## Pro Tips for Hunters

- Dorking: Use dorks like site:target.com inurl:url= to find hidden redirect parameters.
- Payloads: Always try javascript:alert(1) on redirect parameters. If the application uses the input in a window.location assignment, you have a high chance of success.

Result: Reported to the team and rewarded with a $$ bounty!

## Stay Connected

- X (Twitter): @xelcezeri
- LinkedIn: Samet Yiğit



---
*Original URL: [https://medium.com/@xelcezeri/open-redirect-to-xss-3a579bf64ed2?source=search_post---------71-----------------------------------](https://medium.com/@xelcezeri/open-redirect-to-xss-3a579bf64ed2?source=search_post---------71-----------------------------------)*
