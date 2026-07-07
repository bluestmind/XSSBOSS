# How a Null Byte Unlocked a $XXXX Bounty: My Reflected XSS Story

> **Author**: Santhosh Adiga U
> **Published**: Nov 3, 2025

---

Member-only story

![Santhosh Adiga U](https://miro.medium.com/v2/resize:fill:64:64/1*dojCa94kq35UZEbvuRvC0Q.png)

101

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:700/1*lWkl873gGuEht6YZlM2bcw.jpeg)

I was staring at the search bar, and it was staring right back at me. Taunting me.

The target was a sleek, modern e-commerce site. My mission: find a reflected Cross-Site Scripting (XSS) vulnerability in their product search functionality. It seemed like the perfect candidate. You type a query, it appears on the page. Classic.

I started with the usual suspects, my go-to arsenal of payloads:

```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
" onclick="alert(1)
```

The response was a polite but firm rejection. The payloads were either silently stripped, encoded into harmless text, or triggered nothing at all. The Web Application Firewall (WAF) was wide awake, and my classic tricks were putting it to sleep. After an hour of trying every common payload I had bookmarked, a sinking feeling set in. Maybe this one's just not vulnerable.

![image](https://miro.medium.com/v2/resize:fit:660/1*3vATQigEEbau8TfmdRLpfQ.jpeg)

I had already mapped out a good portion of the application and hadn't found anything else juicy. The dreaded "No Issue Found" loomed over me. It’s in these moments of frustration that you have a choice: give up, or dig deeper into your own bag…



---
*Original URL: [https://medium.com/@santhosh-adiga-u/how-a-null-byte-unlocked-a-xxxx-bounty-my-reflected-xss-story-cb1b94f8ea12?source=search_post---------151-----------------------------------](https://medium.com/@santhosh-adiga-u/how-a-null-byte-unlocked-a-xxxx-bounty-my-reflected-xss-story-cb1b94f8ea12?source=search_post---------151-----------------------------------)*
