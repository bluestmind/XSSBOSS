# $200 Bounty: XSS via X-Forwarded-Host Header That Also Triggered an Open Redirect

> **Author**: Monika sharma
> **Published**: Dec 16, 2025

---

## When Blind Trust in HTTP Headers Turned a Secure Website Into an Attack Surface

![Monika sharma](https://miro.medium.com/v2/da:true/resize:fill:32:32/0*Tv4b4p5mb6J3IJwD)

94

2

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:700/1*k2rHIp_MFg4vdg8-9Mdr4w.jpeg)

### Introduction

Not every high-impact vulnerability comes from complex payloads, OAuth confusion, or deep JavaScript logic.
Sometimes, the most dangerous bugs exist because of one simple mistake: trusting user-controlled input without validation

While reading HackerOne reports, I came across this Omise vulnerability (Report ID #1392935) and immediately liked it not because it was complicated, but because it was clean, logical, and very realistic.

A single HTTP header, X-Forwarded-Host, was trusted by the server and reflected back into the response. That one decision resulted in Reflected XSS, and with a slight tweak, even caused an Open Redirect

In this article, I’ll break down the bug step by step in a very simple way so even beginners can understand:

- What went wrong
- How it was exploited
- Why it mattered
- And what lessons bug hunters should take from it

Report Overview

- Report ID: 1392935
- Reported By: oblivionlight
- Bounty Paid: $200
- Vulnerability Types: Reflected XSS, Open Redirect
- Attack Vector: X-Forwarded-Host HTTP header
- Affected URL: https://www.omise.co/

### Understanding the Root Cause

The core issue was very simple:

The server read the X-Forwarded-Host header directly from the request and reflected it back in the response without sanitization.

This is dangerous because:

- HTTP headers are fully controllable by attackers
- Browsers trust whatever HTML the server sends
- Any JavaScript reflected into the page executes automatically

Many developers wrongly assume that headers like X-Forwarded-Host are “internal” or “safe”.
They are not.

### How the XSS Vulnerability Worked

The attacker injected JavaScript inside the X-Forwarded-Host header.

Payload Used

```
X-Forwarded-Host: bing.com"><img src/onerror=prompt(document.cookie)>
```

Because the server reflected this value into the HTML response, the browser executed it resulting in Reflected XSS.

Once triggered, the attacker could:

- Read cookies
- Steal session tokens
- Rewrite page content
- Perform actions as the victim

And all of this happened without authentication.

Step-by-Step Reproduction (Easy Version)

- Visit:

```
https://www.omise.co/
```

2. Intercept the request using Burp Suite

3. Send the request to Repeater

## Get Monika sharma’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

4. Add this header below the Host header:

```
X-Forwarded-Host: bing.com"><img src/onerror=prompt(document.cookie)>
```

5. Send the request

6. Observe a JavaScript popup showing cookie data

That’s it.

No complex chain. No bypass tricks.

### The Open Redirect Angle

The vulnerability didn’t stop at XSS.

When the attacker used a non-malicious value like:

```
X-Forwarded-Host: bing.com
```

And then:

- Opened the response in the browser
- Clicked the “Sign in” button

The website redirected the user to the attacker-controlled domain.

This created an Open Redirect, which is extremely useful for:

- Phishing attacks
- Credential harvesting
- Social engineering
- Trust abuse using a legitimate domain

### Why This Bug Was Dangerous

This vulnerability allowed attackers to:

- Execute arbitrary JavaScript on a trusted domain
- Steal sensitive user data
- Redirect users to malicious websites
- Chain XSS + redirect for advanced phishing attacks

All because one HTTP header was trusted blindly.

### Mitigation What Should Have Been Done

- Never trust X-Forwarded-* headers by default
- Do not reflect unvalidated headers into responses
- Sanitize and encode all user-controlled data
- Use strict allowlists for redirect destinations

### Key Takeaway for Bug Hunters

This report teaches an important lesson:

Headers are user input too.

If you’re hunting bugs:

- Test X-Forwarded-Host
- Test X-Forwarded-For
- Test X-Host, Forwarded, Origin, Referer
- Look for reflections and redirects

Many high-quality bugs hide in places most people ignore.

### Conclusion

This Omise vulnerability proves that simple bugs can still have serious impact. One unsanitized header caused both XSS and Open Redirect two vulnerabilities attackers love to chain together.
Clean logic, real-world impact, and a well-earned $200 bounty.

☕ If this article helped you understand real-world vulnerabilities better,
consider buying me a coffee: https://buymeacoffee.com/monikaak47



---
*Original URL: [https://medium.com/the-first-digit/200-bounty-xss-via-x-forwarded-host-header-that-also-triggered-an-open-redirect-9582bc59f6a7?source=search_post---------105-----------------------------------](https://medium.com/the-first-digit/200-bounty-xss-via-x-forwarded-host-header-that-also-triggered-an-open-redirect-9582bc59f6a7?source=search_post---------105-----------------------------------)*
