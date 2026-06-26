# 🎯 DOM XSS Using Web Messages and Javascript URL (window.postMessage → innerHTML Sink)

> **Author**: Aditya Bhatt
> **Published**: Dec 18, 2025

---

## DOM XSS via Web Messages: Exploits unsafe postMessage handling and innerHTML injection to execute arbitrary JavaScript.

![Aditya Bhatt](https://miro.medium.com/v2/resize:fill:32:32/1*6TFmlC58KtmaRsYHdjy9Qg.jpeg)

1

Listen

Share

Write-Up by Aditya Bhatt | DOM-Based XSS | Web Message Injection | BurpSuite

## ⭐ TL;DR

This PortSwigger lab demonstrates a DOM XSS vulnerability via web messages. The webpage listens for postMessage events and directly injects received data into innerHTML without validating origin or sanitizing content. By abusing an iframe and sending a crafted message containing an <img> tag with an onerror handler, we trigger JavaScript execution and solve the lab.

Lab: DOM XSS using web messages

Free Article Link
Lab Link: https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages
GitHub PoC Link: https://github.com/AdityaBhatt3010/DOM-XSS-using-web-messages-and-JavaScript-URL

![image](https://miro.medium.com/v2/resize:fit:700/0*lO4vGSXcwR7a4K1D.jpeg)

## 🔥 Introduction

Web messaging (window.postMessage) is a powerful API intended for secure cross-origin communication. However, when developers fail to validate message origins or sanitize the content, it becomes an extremely dangerous DOM XSS vector.

This lab showcases that exact scenario:

- Source: Untrusted postMessage
- Sink: innerHTML
- Impact: Full DOM XSS via HTML injection

Below is the full walkthrough of the exploitation steps, PoC, payload explanation, and why this pattern remains common in real-world bug bounty programs.

## 🧪 PoC (Step-by-Step with Screenshots)

## 1. Open the Website

We begin by loading the lab homepage to inspect how it handles external messages.

![image](https://miro.medium.com/v2/resize:fit:700/0*1mPMA-x2KB7tQzfq.png)

➤ Why? Understanding what functionality is exposed helps us trace potential DOM sinks.

## 2. Inspect the JavaScript Code

Inside DevTools, we find this message listener:

```
window.addEventListener('message', function(e) {
    document.getElementById('ads').innerHTML = e.data;
})
```

![image](https://miro.medium.com/v2/resize:fit:700/0*ZMWCp7BHLtlUF0Rz.png)

➤ Why this matters?

- message events accept data from any origin.
- The app blindly injects that data into innerHTML.
- innerHTML executes scripts via event handlers.

This is a direct DOM XSS gadget.

## 3. Crafting the Exploit Using the Exploit Server

We now create an iframe on the exploit server that automatically sends a malicious message to the vulnerable page.

### ✔ Payload Used

```
<iframe src="https://0a9f0043036cdfb780f203d8009e0075.web-security-academy.net/"
onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
```

![image](https://miro.medium.com/v2/resize:fit:700/0*66ObpRlhKcfNXZXi.png)

### ✔ Payload Explanation

Why an iframe?

We need the target site to load inside our exploit environment so we can send a postMessage to it.

## Get Aditya Bhatt’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

Why postMessage()?

Because the lab’s code listens for any incoming message and directly renders its content.

Why this HTML payload?

```
<img src=1 onerror=print()>
```

- The <img> tag gets inserted into the DOM.
- Invalid src=1 triggers onerror.
- print() executes, proving successful XSS.

Thus the chain becomes:

iframe loads → sends message → message injected via innerHTML → error handler executes JavaScript

## 4. Deliver the Exploit → Lab Solved

After hitting “Deliver exploit to victim,” the payload executes immediately upon injection.

![image](https://miro.medium.com/v2/resize:fit:700/0*Z5YXKgigeBrI1jIh.png)

➤ Why? Because innerHTML renders HTML as active content, not as plain text.

## 🧠 Technical Summary

### Source:

window.postMessage() (untrusted origin)

### Sink:

element.innerHTML = e.data

### Result:

Full DOM XSS — attacker-controlled HTML → JS execution.

### Real-World Impact:

- Session theft
- Phishing redirections
- Account takeover
- Stored XSS chains when paired with message relays
- Hard to detect via WAFs because the payload exists only in the DOM

## 🛠 Fix Recommendations

✔ Validate message origin

```
if (e.origin !== "https://trusted.com") return;
```

✔ Avoid using innerHTML Use textContent or safe DOM creation APIs.

✔ Sanitize HTML Use DOMPurify before insertion.

✔ Strict CSP Disallow inline JavaScript where possible.

## 🔥 Final Thoughts

This lab demonstrates how postMessage + innerHTML creates a perfect storm for DOM XSS. No backend involvement. No URL parameters. Just unsafe client-side logic.

A simple oversight that leads to full browser control.

Stay curious. Stay offensive. ~ Aditya Bhatt 🔥

## ⭐ Follow Me & Connect

🔗 GitHub: https://github.com/AdityaBhatt3010
💼 LinkedIn: https://www.linkedin.com/in/adityabhatt3010/
✍️ Medium: https://medium.com/@adityabhatt3010
▶️ XSS Playlist: https://medium.com/@adityabhatt3010/list/xss-cross-site-scripting-a218a9d9cd93
🧪 Lab Link: https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages
🐈‍⬛ GitHub PoC Link: https://github.com/AdityaBhatt3010/DOM-XSS-using-web-messages-and-JavaScript-URL



---
*Original URL: [https://medium.com/stackademic/dom-xss-using-web-messages-and-javascript-url-window-postmessage-innerhtml-sink-fda6c0064a4e?source=search_post---------116-----------------------------------](https://medium.com/stackademic/dom-xss-using-web-messages-and-javascript-url-window-postmessage-innerhtml-sink-fda6c0064a4e?source=search_post---------116-----------------------------------)*
