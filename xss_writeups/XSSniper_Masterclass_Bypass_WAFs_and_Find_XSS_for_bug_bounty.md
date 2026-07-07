# XSSniper Masterclass Bypass WAFs and Find XSS (for bug bounty)

> **Author**: Jackson Mittag
> **Published**: Nov 9, 2025

---

![Jackson Mittag](https://miro.medium.com/v2/resize:fill:32:32/1*g4hAeEN0_VghDLy-0mWlrA.jpeg)

8

Listen

Share

Watch the video walkthrough:

Quick disclaimer: This article is for educational purposes only. The demo site used here is a lab environment and not a real target. Please only test on authorized systems or lab environments.

Github link: https://github.com/gbrindisi/xsssniper?tab=readme-ov-file

## Intro

Today’s going to be a quick walkthrough on how to use XSS Sniper — a Python-based tool for scanning web applications for Cross-Site Scripting (XSS) vulnerabilities.

We’ll use it against the Test PHP VM website — a safe testing lab — and go through both automated testing with XSS Sniper and some manual payloads to understand what’s going on behind the scenes.

## What Is XSS Sniper?

XSS Sniper is a feature-rich Python tool created by Gianluca Brindisi (check them out on GitHub under this name gbrindisi). It’s built for quickly testing endpoints for XSS vulnerabilities with a wide variety of payloads and built-in WAF (Web Application Firewall) bypasses.

You can:

- Scan a single URL or a list of URLs
- Enable multi-threading
- Auto-detect and bypass WAFs (Cloudflare, AWS, Barracuda, etc.)
- Add custom payloads
- Export results to multiple report formats
- Use custom user-agents (helpful for bug bounty submissions)
- Crawl and recursively test discovered links

In short, it’s an excellent addition to your bug bounty or web app testing workflow.

## Basic Setup & Usage

Let’s start by exporting our target as a variable for convenience:

Press enter or click to view image in full size

![image](https://miro.medium.com/v2/resize:fit:700/0*FkpJz0YvaBqrS4l1.png)

Now, run XSS Sniper with:

Press enter or click to view image in full size

![image](https://miro.medium.com/v2/resize:fit:700/0*LgM9IW26FEcWEt7P.png)

A quick breakdown:

- -u → Specifies the target URL
- --waf-bypass → Enables firewall evasion techniques
- --user-agent → Sets a custom user-agent (useful for organized bug bounty testing)

You can also use:

- -l → Load from a list of URLs
- --discover-params → Auto-discover input parameters
- --output → Save results to a report

## Watching the Traffic (Optional)

If you want to see what’s happening under the hood, open Wireshark while XSS Sniper is running.

## Get Jackson Mittag’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

Press enter or click to view image in full size

![image](https://miro.medium.com/v2/resize:fit:700/0*QTEewEfcty2IBmjd.png)

You’ll see all the payloads being fired off — things like:

- onerror=
- <iframe> injections
- Encoded and decoded JavaScript payloads

This gives you a clear idea of how the tool interacts with your target and what data is being sent.

## Detecting Reflected XSS

When we run the scan, XSS Sniper reports:

Press enter or click to view image in full size

![image](https://miro.medium.com/v2/resize:fit:700/0*0mOkA4zafr004a_N.png)

If we manually inspect the page, the vulnerable parameter is searchfor, visible in the form field on the site.

Press enter or click to view image in full size

![image](https://miro.medium.com/v2/resize:fit:700/0*bGWDQeibFu0FH4Cc.png)

When executed, it triggers a JavaScript alert showing the domain — confirming reflected XSS.

```
<svg onload=alert(document.domain)>
```

Press enter or click to view image in full size

![image](https://miro.medium.com/v2/resize:fit:700/0*f69W1eQ_TlJBOrN2.png)

## Trying Other Tools

For comparison, you can use XSSer — another older tool:

```
xsser -u "http://testphp.vulnweb.com/?test=XSS"
```

Press enter or click to view image in full size

![image](https://miro.medium.com/v2/resize:fit:700/0*ZfOGijhXszGg5Pwn.png)

It works by injecting unique hashes into parameters and checking if they’re reflected in the HTML source.

In this case, the challenge site is quite old, but it’s still a solid environment for practicing and experimenting with different payloads.

## Manual vs. Automated Testing

While tools like XSS Sniper are powerful, don’t rely solely on automation.
They might miss payloads that a manual test would catch due to encoding issues or non-standad contexts.

For example, in a recent bug bounty program I worked on, XSS Sniper didn’t detect a reflected XSS — I only found it manually. Always double-check with your own tests.

## Final thoughts

That’s it for today’s quick lab!

- We learned how to use XSS Sniper to find reflected XSS
- We looked at manual payloads and WAF bypasses
- We saw how to verify findings visually through Wireshark

If you enjoyed this tutorial, make sure to subscribe to the YouTube channel for more bug bounty and web security content.

Thanks for watching/reading. If you’ve got questions, hit me up on Discord.

Peace.

Discord link: discord.com/invite/RBXkUUT5aB



---
*Original URL: [https://medium.com/@0dayscyber/xssniper-masterclass-bypass-wafs-and-find-xss-for-bug-bounty-e2f045b50752?source=search_post---------142-----------------------------------](https://medium.com/@0dayscyber/xssniper-masterclass-bypass-wafs-and-find-xss-for-bug-bounty-e2f045b50752?source=search_post---------142-----------------------------------)*
