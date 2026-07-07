# From a P5 XSS to iFrame Injection via Encoded Payloads

> **Author**: Rohit_443
> **Published**: Dec 14, 2025

---

![Rohit_443](https://miro.medium.com/v2/resize:fill:32:32/1*r_JPGHy4_n5U3IOgBZI7kw@2x.jpeg)

67

Listen

Share

While testing a private program on Bugcrowd, I found a parameter that reflected user input on the page. I injected a JavaScript payload, but it was only reflected back in my own session and did not execute in an attacker-controlled way. Since the behavior was limited to self-XSS, the report was marked as P5 (informational).

Initial Finding (Self-XSS — P5)

In the beginning, one parameter was reflecting user input back into the response. I tried common XSS payloads, but:

- Payloads worked only in self-XSS scenarios
- No real attack was possible for other users

Because of this, the security team marked the report as P5.

At that point, the issue did not look exploitable.

Finding Another Parameter

Even after the report was closed, I kept testing other parameters related to the same functionality. During this time, I found another search parameter that behaved differently.

This parameter became interesting because the filtering logic was not the same as the first one.

At first, I tried using a normal payload, but it was blocked by the WAF. Instead of blindly changing payloads, I tried to understand how the request was being processed.

At first, the normal payload was blocked by the WAF, so instead of randomly changing payloads, I focused on understanding how the request was being processed and why the filtering was happening.

## Get Rohit_443’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

IFrame Injection

After crafting the payload properly, I sent it through the search parameter. This time, the application decoded the payload and the browser rendered it as HTML.

As a result, an actual Iframe was loaded on the web page, inside the trusted application.

This confirmed the presence of an iFrame injection vulnerability.

Affected endpoint:

https://blog.example.com/recipes/?keyword=

Encoded payload:

%3c%69%66%72%61%6d%65%20%73%72%63%3d%22%68%74%74%70%73%3a%2f%2f%65%78%61%6d%70%6c%65%2e%63%6f%6d%22%20%77%69%64%74%68%3d%22%31%30%30%25%22%20%68%65%69%67%68%74%3d%22%33%30%30%22%3e%3c%2f%69%66%72%61%6d%65%3e

Impact

This issue can be abused for content spoofing and social engineering attacks, allowing attackers to misuse user trust and potentially cause serious reputational damage to the application.

![image](https://miro.medium.com/v2/resize:fit:700/1*y9kLvfyQw5woKXYypEjUdw.png)

For upcoming writeup.

Follow me on twitter https://x.com/Rohit_443



---
*Original URL: [https://medium.com/@rohit443/from-a-p5-xss-to-iframe-injection-via-encoded-payloads-1081cf1c0098?source=search_post---------103-----------------------------------](https://medium.com/@rohit443/from-a-p5-xss-to-iframe-injection-via-encoded-payloads-1081cf1c0098?source=search_post---------103-----------------------------------)*
