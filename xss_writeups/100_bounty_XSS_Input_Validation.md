# $100 bounty — XSS & Input Validation

> **Author**: StvRoot
> **Published**: Dec 27, 2025

---

Member-only story

![StvRoot](https://miro.medium.com/v2/resize:fill:64:64/1*4jX0brJ315JNfuzvigpyFg.jpeg)

106

3

Listen

Share

I discovered a private programme via google dork. It was a coding platform.

Link for friends

I found RCE and got a bounty for it. Soon after that I reported 2 XSS. But first of all I would like to say f*ck taxes.

## How I made ₹8000 in 10 minutes from bug bounty

### I bet we all want some quick bounties and believe me they are just floating , all we have to do is just catch it.

osintteam.blog

## #1 XSS :

After creating a profile there was a upload resume section.

I upload a pdf file from : https://github.com/luigigubello/PayloadsAllThePDFs/tree/main/pdf-payloads

![image](https://miro.medium.com/v2/resize:fit:700/1*V1EFAmE7S9iWuebK3hgv0g.png)

and achieved XSS. Reported and got paid for it.

![image](https://miro.medium.com/v2/resize:fit:640/1*pFr4fizvdXqkO64_sPB4pQ.png)

## #2 Input validation:

When I joined a challenge hosted on the website. In the team_name section I was restricted to 15 chars but when I used Burp I was able to inject fuck load of chars XD . Resulting in DoS



---
*Original URL: [https://medium.com/bugbountywriteup/100-bounty-xss-input-validation-1ccfb35c5e1f?source=search_post---------100-----------------------------------](https://medium.com/bugbountywriteup/100-bounty-xss-input-validation-1ccfb35c5e1f?source=search_post---------100-----------------------------------)*
