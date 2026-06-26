# How I Identified a Reflected XSS in Citrix NetScaler Logout Flow (CVE-2025–12101)

> **Author**: Sri Sowmya Nemani
> **Published**: Dec 31, 2025

---

![Sri Sowmya Nemani](https://miro.medium.com/v2/resize:fill:32:32/1*f94Cjqaz1V0P9oqtu5UUCQ.png)

12

Listen

Share

Introduction:A reflected Cross-Site Scripting (XSS) vulnerability exists in the logout functionality of Citrix NetScaler ADC/Gateway instances, tracked as CVE-2025–12101.
The issue occurs when attacker-controlled input supplied via the RelayState parameter is reflected unsanitized in an HTML response during logout handling. This affects the authentication infrastructure, making it higher risk than typical reflected XSS bugs.

## Get Sri Sowmya Nemani’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

Root Cause: This occurs even though the response is an HTTP 302 redirect, which is still capable of exposing reflected content depending on browser behavior.

- Accepts attacker-controlled input in RelayState
- Reflects it verbatim in the response body
- Uses Content-Type: text/html
- Applies no output encoding or sanitisation

Proof of Concept(POC)

- While reviewing the scope of a public responsible disclosure program, I identified several public-facing authentication subdomains used for remote access.
- The subdomains followed patterns commonly associated with Citrix NetScaler ADC/Gateway deployments.
- During research on recent Citrix-related vulnerabilities, I reviewed newly disclosed CVEs affecting NetScaler authentication flows.
One of them, CVE-2025–12101, described a reflected XSS issue involving the RelayState parameter in the logout functionality
- I sent a single, non-intrusive POST request to the logout endpoint: /cgi/logout
- Request:

POST /cgi/logout HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded

SAMLResponse=test&RelayState=<script>alert(1)</script>

6. Response:

HTTP/1.1 302 Object Moved
Content-Type: text/html

<script>alert(1)</script>

The vulnerability was confirmed because:

- The RelayState parameter is reflected without sanitization
- The response is returned as HTML
- The endpoint is unauthenticated
- Behavior matches CVE-2025–12101

References:

- https://github.com/6h4ack/CVE-2025-12101-checker
- https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX695486&articleURL=NetScaler_ADC_and_NetScaler_Gateway_Security_Bulletin_for_CVE_2025_12101
- https://www.secpod.com/blog/relaystate-ruse-exploiting-reflected-xss-in-citrix-netscaler/#:~:text=The%20identified%20reflected%20XSS%20vulnerability,Proof%20of%20Concept%20(PoC)



---
*Original URL: [https://medium.com/@srisowmya.nemani/how-i-identified-a-reflected-xss-in-citrix-netscaler-logout-flow-cve-2025-12101-6da7aea7d253?source=search_post---------112-----------------------------------](https://medium.com/@srisowmya.nemani/how-i-identified-a-reflected-xss-in-citrix-netscaler-logout-flow-cve-2025-12101-6da7aea7d253?source=search_post---------112-----------------------------------)*
