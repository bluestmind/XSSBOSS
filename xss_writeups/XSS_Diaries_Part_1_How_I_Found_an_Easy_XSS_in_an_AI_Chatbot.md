# XSS Diaries (Part 1): How I Found an Easy XSS in an AI Chatbot

> **Author**: Sudeepa Shiranthaka
> **Published**: Jan 25, 2026

---

Member-only story

![Sudeepa Shiranthaka](https://miro.medium.com/v2/da:true/resize:fill:64:64/1*W1v3N9rwNYE26myRJq64Rg.gif)

44

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:700/1*E8V_HDdoeQDrZzDhL4VaBw.png)

Finding a security weakness in a web application may not be difficult; however, with the correct testing methodologies and thorough enumeration, it becomes much easier to identify.

Sometimes, for vulnerabilities such as XSS, a simple payload like

```
<script>alert(1)(/script)
```

is sufficient to demonstrate a proof of concept. However, the real challenge is identifying where exactly to place the payload. Finding the injectable parameter is often the hardest part of the process — it’s like finding a needle in a haystack. In most cases, more advanced payload structures are required to successfully exploit XSS vulnerabilities.

In this article, I explain one of my XSS diary entries that I successfully uncovered while performing a security assessment.

Note: This issue was reported responsibly to the appropriate custodians, and at the time of writing this article, it has been fully remediated. No URLs or names are included in this post.

### Introduction

While AI applications are rapidly evolving, many still rely on traditional web components, making classic vulnerabilities like XSS surprisingly common.

Why do chatbots matter?



---
*Original URL: [https://medium.com/bugbountywriteup/xss-diaries-part-1-how-i-found-an-easy-xss-in-an-ai-chatbot-4f5f916525e5?source=search_post---------83-----------------------------------](https://medium.com/bugbountywriteup/xss-diaries-part-1-how-i-found-an-easy-xss-in-an-ai-chatbot-4f5f916525e5?source=search_post---------83-----------------------------------)*
