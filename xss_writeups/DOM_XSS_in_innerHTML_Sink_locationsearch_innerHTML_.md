# DOM XSS in innerHTML Sink (location.search → innerHTML) 🎯

> **Author**: Aditya Bhatt
> **Published**: Dec 12, 2025

---

## DOM-based XSS flaw where location.search is injected into the page via innerHTML, letting us execute arbitrary JavaScript.

![Aditya Bhatt](https://miro.medium.com/v2/resize:fill:32:32/1*6TFmlC58KtmaRsYHdjy9Qg.jpeg)

Listen

Share

Write-Up by Aditya Bhatt | DOM-Based XSS | innerHTML Sink | BurpSuite

This PortSwigger lab contains a DOM-based XSS vulnerability inside the blog’s search feature. The JavaScript takes user input from location.search and injects it directly into the page using innerHTML, making it instantly exploitable.

Free Article Link
Lab Link: https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-innerhtml-sink
GitHub Repository Link: https://github.com/AdityaBhatt3010/DOM-XSS-in-innerHTML-sink-using-source-location.search-BurpSuite-Lab
My XSS PlayList Link: https://medium.com/@adityabhatt3010/list/xss-cross-site-scripting-a218a9d9cd93

![image](https://miro.medium.com/v2/resize:fit:700/0*ySrNFmyKH5IeJxhs.jpeg)

## 🧪 PoC (Step-by-Step with Screenshots)

## 1. Open the Lab website.

We first load the lab to observe how the search function behaves and how input flows through the DOM.

![image](https://miro.medium.com/v2/resize:fit:700/0*Hih3ItUPwLYVxADl.png)

➤ Why? Understanding the initial page structure helps identify where user-controlled data appears.

## 2. Enter any string in the search box and press Enter.

We start with something harmless like test to see how the application handles reflection.

![image](https://miro.medium.com/v2/resize:fit:700/0*82EjrxaOTF0jhyQw.png)

➤ Why? A baseline request shows how the input appears in the DOM, which is crucial for confirming a sink like innerHTML.

## 3. Open Inspect Element to check where the input is inserted.

The HTML reveals that the search term is directly injected via innerHTML, confirming unsafe behavior.

![image](https://miro.medium.com/v2/resize:fit:700/0*KQDd2rMcAFQzY3Ie.png)

➤ Why? This proves that location.search → innerHTML, which is a classic DOM XSS pattern.

## 4. Use the payload:

```
<svg onload=alert(1)>
```

Paste it in the search bar and click Search.

![image](https://miro.medium.com/v2/resize:fit:700/0*b5N382DPM0BpMAoR.png)

➤ Why this payload works?

- <svg> is a powerful XSS vector processed by the browser even without visible rendering.
- onload executes as soon as the SVG is parsed.
- Since innerHTML interprets input as real HTML, the JS engine executes the event handler instantly.

This confirms the DOM XSS vulnerability.

## 5. Lab Suggested Payload:

```
<img src=1 onerror=alert(1)>
```

This also works.

![image](https://miro.medium.com/v2/resize:fit:700/0*Im3OVsHdhO7UDKu9.png)

➤ Why this payload works?

- img tag attempts to load src=1, which is invalid.
- Image loading fails → triggers onerror → fires alert(1).

## 6. Click OK → Lab Solved 🎉

![image](https://miro.medium.com/v2/resize:fit:700/0*JTleggocEaMh-zbU.png)

## 🧠 Payload Explanation (Difference Between Both)

### ✔ Payload 1: <svg onload=alert(1)>

This payload relies on the fact that SVG elements fire onload as soon as the browser parses them. Perfect for innerHTML-based DOM XSS, because the browser immediately executes the event.

## Get Aditya Bhatt’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

✓ No need for external resources
✓ Executes instantly
✓ Works even in strict CSP in many cases

### ✔ Payload 2: <img src=1 onerror=alert(1)>

This is PortSwigger’s recommended payload.

- The browser tries to load an image from 1
- That fails → triggers the onerror handler → runs alert(1)

This is one of the most universal and reliable XSS payloads.

## 🔍 Which is better?

![image](https://miro.medium.com/v2/resize:fit:700/1*JK1_XyZbN1iefH2NscNYyw.png)

Both are excellent — the SVG payload is preferred for DOM sinks, while the IMG payload is preferred for server-side injection.

## 💰 Real-World Bug Bounty Relevance (Why This XSS Matters)

DOM XSS is highly rewarded in bug bounties because:

### ✔ Most modern apps rely heavily on client-side JavaScript

React, Angular, Vue, jQuery — all vulnerable if unsafe sinks are used.

### ✔ Often bypasses -side security

Since it never touches the backend, WAFs & filters rarely detect it.

### ✔ Stealthy — no server logs

Perfect for attacks like token extraction.

### ✔ Common attack vectors

Attackers send malicious URLs like:

```
victim.com/search?q=<img src=1 onerror=alert(document.cookie)>
```

## ❗ Why DOM XSS Happens

- Unsafe JavaScript sinks such as:
- innerHTML
- outerHTML
- document.write
- insertAdjacentHTML
- Direct use of URL-based sources:
- location.search
- location.hash
- location.pathname
- No sanitization or encoding The browser interprets injected tags as real HTML.

## 🛠 How To Fix DOM XSS

### ✔ Use .textContent instead of .innerHTML

This prevents HTML parsing entirely.

### ✔ Sanitize using libraries like DOMPurify

Removes harmful tags/attributes.

### ✔ Validate/escape dangerous characters

Like < > " '.

### ✔ Implement strong Content Security Policy (CSP)

Blocks inline script execution.

## 🔥 Final Thoughts

This lab demonstrates how dangerous innerHTML + location.search combinations are. The moment user input is inserted into HTML without sanitization, attackers can execute arbitrary JavaScript.

DOM XSS is fast, silent, reliable, and common — making it a frequent bug bounty target.

Stay offensive.
~ Aditya Bhatt 🔥

## ⭐ Follow Me & Connect

If you enjoyed this write-up or want to stay connected with my cybersecurity research:

🔗 GitHub: https://github.com/AdityaBhatt3010
💼 LinkedIn: https://www.linkedin.com/in/adityabhatt3010/
✍️ Medium: https://medium.com/@adityabhatt3010
👨‍💻👩‍💻 GitHub Repository Link: https://github.com/AdityaBhatt3010/DOM-XSS-in-innerHTML-sink-using-source-location.search-BurpSuite-Lab
▶️My XSS PlayList Link: https://medium.com/@adityabhatt3010/list/xss-cross-site-scripting-a218a9d9cd93
🧪 Lab Link: https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-innerhtml-sink



---
*Original URL: [https://medium.com/system-weakness/dom-xss-in-innerhtml-sink-location-search-innerhtml-e2c11b21a6cb?source=search_post---------117-----------------------------------](https://medium.com/system-weakness/dom-xss-in-innerhtml-sink-location-search-innerhtml-e2c11b21a6cb?source=search_post---------117-----------------------------------)*
