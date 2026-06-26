# Hidden in the Source: Discovering Reflected XSS via Manual Code Review

> **Author**: elcezeri
> **Published**: Jan 17, 2026

---

![elcezeri](https://miro.medium.com/v2/resize:fill:32:32/1*2eJqXfp4TQ1hPcVQpcEZfw.jpeg)

16

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:682/1*vviHX7g90DnsvJhzq8EUTw.png)

In bug bounty hunting, when automated scanners fail and the scope is narrow, your best weapon is your own eyes. Today, I’ll share how I discovered a Reflected XSS vulnerability on a protected login page by simply digging into the application’s source code.

## The Hunt Begins

While browsing a VDP program on HackerOne, I encountered a login screen reserved for company members. It was a simple interface requiring an ID and a password. I tried standard attacks like SQL Injection, Default Credentials, and Request Manipulation, but the application was solid.

![image](https://miro.medium.com/v2/resize:fit:700/1*ScN3R-h7pIH8UKHm7Pqz-g.png)

## The Discovery: Reading Between the Lines

Instead of moving on, I decided to perform a Manual Source Code Review. While inspecting the page’s source, I discovered an interesting path used for internal search functionality.

## Get elcezeri’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

The path took two parameters and seemed to be used for filtering data. I copied the path and immediately started testing for input reflection: https://target.com/inc/search_xxxx?xxxx=”123<>

![image](https://miro.medium.com/v2/resize:fit:700/1*nN48Ua71mfWkJnP6sGEd5Q.png)

When I saw that the characters <> were reflected directly into the page without any sanitization, I knew I had found a potential entry point.

## Exploitation: From HTML to Javascript

First, I confirmed HTML Injection was possible.

![image](https://miro.medium.com/v2/resize:fit:700/1*tzJXTebkm_Ghy5CKE0mKqQ.png)

Then, I took it a step further to achieve Cross-Site Scripting (XSS). I tried the following payloads:

- ”><script>alert(“cezeri”)</script>
- “><img src/onerror=prompt(document.cookie)>

The Result: Both payloads executed perfectly. The application was rendering the xxxx parameter directly into the DOM, allowing for full client-side code execution.

![image](https://miro.medium.com/v2/resize:fit:700/1*C7W4cQYQ6qVoTiLxecuGHQ.png)

The Lesson: Never underestimate the power of Ctrl+U. Automated tools are great, but manual source code analysis can uncover vulnerabilities hidden in plain sight.

## Stay Connected

- X (Twitter): @xelcezeri
- LinkedIn: Samet Yiğit



---
*Original URL: [https://medium.com/@xelcezeri/hidden-in-the-source-discovering-reflected-xss-via-manual-code-review-c2a697d9d8c1?source=search_post---------72-----------------------------------](https://medium.com/@xelcezeri/hidden-in-the-source-discovering-reflected-xss-via-manual-code-review-c2a697d9d8c1?source=search_post---------72-----------------------------------)*
