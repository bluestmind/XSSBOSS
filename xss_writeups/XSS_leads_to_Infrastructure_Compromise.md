# XSS leads to Infrastructure Compromise

> **Author**: Rahul Singh Chauhan
> **Published**: Feb 8, 2026

---

Member-only story

![Rahul Singh Chauhan](https://miro.medium.com/v2/resize:fill:64:64/1*6Zw9HGzZfk5gtMih8eoTxA.jpeg)

50

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:700/0*seQYGAKPg_hVuu5L)

Hi everyone, in this article I’ll be talking about an issue that one of my colleagues found during a web application pentest. When reading through the article, you’ll notice that the issue has been exploited multiple times but in this article, I’ll discuss why some can lead to infrastructure compromise which the rest will not be more than a simple plain XSS.

In this article, I’ll cover the following:

- Overview of the web application
- The issue and it’s impact
- Why the issue was exploitable

## Overview

The web application, besides other features, also allowed it’s customer to create invoices. The invoices had some fields such as name, address, organization name, the services used by the customer, etc.

## The Issue and its Impact

As mentioned above, the application had a invoice feature which was vulnerable to XSS. It was observed that if XSS payloads were passed in the name field, an XSS would be triggered when the PDF was viewed. The PDF was displayed in the same domain as the target domain. So, it could be used to fetch the user’s JWT tokens. But that wouldn’t be much of an impact as we would only end up getting either our own JWT token or someone from our organization who had the…



---
*Original URL: [https://medium.com/the-first-digit/xss-leads-to-infrastructure-compromise-396945a701c1?source=search_post---------66-----------------------------------](https://medium.com/the-first-digit/xss-leads-to-infrastructure-compromise-396945a701c1?source=search_post---------66-----------------------------------)*
