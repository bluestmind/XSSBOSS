# 🎯 DOM XSS in jQuery href Attribute Sink (location.search → jQuery.attr)

> **Author**: Aditya Bhatt
> **Published**: Dec 12, 2025

---

## DOM XSS in jQuery anchor href attribute sink using location.search source

![Aditya Bhatt](https://miro.medium.com/v2/resize:fill:32:32/1*6TFmlC58KtmaRsYHdjy9Qg.jpeg)

2

Listen

Share

Write-Up by Aditya Bhatt | DOM-Based XSS | jQuery Attribute Injection | BurpSuite

Lab: DOM XSS in jQuery anchor href attribute sink using location.search source

This PortSwigger lab contains a DOM XSS vulnerability inside the Submit Feedback page. The JavaScript takes user input from location.search, feeds it into jQuery's $() selector, and dynamically updates the anchor tag’s href attribute — making it vulnerable to attribute-based JavaScript execution.

Free Article Link
Lab Link: https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-href-attribute-sink
GitHub Repository Link: https://github.com/AdityaBhatt3010/DOM-XSS-in-jQuery-anchor-href-attribute-sink-using-location.search-source
My XSS PlayList Link: https://medium.com/@adityabhatt3010/list/xss-cross-site-scripting-a218a9d9cd93

![image](https://miro.medium.com/v2/resize:fit:700/0*ez37wtDCWc_NuYGC.jpeg)

## 🧪 PoC (Step-by-Step with Screenshots)

## 1. Open the Lab website.

We begin by loading the lab to examine how the feedback page uses the returnPath parameter.

![image](https://miro.medium.com/v2/resize:fit:700/0*JSW5kt3tRqHmRJ6F.png)

➤ Why? Understanding where the data flows from the URL helps confirm whether the sink is manipulable.

## 2. Go to the Submit Feedback page.

The URL looks like:

```
?returnPath=/
```

This pattern hints that the application dynamically modifies the Back link based on this parameter.

![image](https://miro.medium.com/v2/resize:fit:700/0*fhp-A_ApnwbNTgni.png)

➤ Why? Any parameter that controls attributes like href, src, or action is a prime XSS candidate.

## 3. Enter any random string in the feedback form, submit, and inspect the Back link.

After testing with “hii”, we find the DOM reflects it as:

```
<a id="backlink" href="/hii">Back</a>
```

![image](https://miro.medium.com/v2/resize:fit:700/0*aiCQmWJhFUscDXSE.png)

➤ Why? This confirms location.search → jQuery.attr(“href”), a dangerous pattern because browsers execute JavaScript when href starts with javascript:.

## 4. Use the payload to turn href into executable JavaScript.

```
javascript:alert(document.cookie)
```

![image](https://miro.medium.com/v2/resize:fit:700/0*zCRluGVj9-3483Go.png)

➤ Why this payload works?

- Browsers allow URLs starting with javascript: inside href attributes.
- Clicking such a link executes the JavaScript directly.
- Since jQuery blindly injects user-controlled data into .attr("href", ...), it becomes executable code.

This lets us run:

```
alert(document.cookie)
```

which proves DOM XSS.

## 5. Click the “Back” link — XSS triggers immediately!

![image](https://miro.medium.com/v2/resize:fit:700/0*aEM8nYUM5lQCi9xN.png)

➤ Why? The link no longer points to a webpage — it now executes JavaScript when clicked, thanks to our crafted payload.

## 🧠 Payload Explanation

### ✔ Payload Used

```
javascript:alert(document.cookie)
```

### 🔍 What it does

- The javascript: protocol turns an anchor click into script execution.
- Browsers interpret everything after it as inline JavaScript.
- With DOM sinks like jQuery .attr(), this is one of the simplest ways to weaponize XSS.

## 🔥 Difference from Earlier DOM XSS Payloads

![image](https://miro.medium.com/v2/resize:fit:700/1*K7hfOJq5MEb79_ARZcGc8w.png)

This lab uses an href attribute sink, so the most effective payload is javascript: over HTML tag payloads.

## 💰 Real-World Bug Bounty Relevance

DOM XSS of this type is extremely common in modern JavaScript-heavy apps.

### ✔ Why companies pay for it:

- Can steal session cookies
- Can perform account takeover
- Can redirect users to phishing pages
- Works even when backend validation is perfect
- Harder for WAFs to detect because no request contains malicious script output

### ✔ Especially dangerous when:

- jQuery’s $() processes attacker-controlled selectors
- .attr() populates href, src, data-*, action, onclick attributes
- URL parameters directly influence UI behavior (like “redirect” links)

## ❗ Why This XSS Happens

- Unsafe JavaScript Sink

```
$("#backlink").attr("href", userInput);
```

2. Unsafe Source

```
userInput = location.search
```

3. jQuery automatically treats attribute values as literal strings, not sanitized ones.

## Get Aditya Bhatt’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

4. The browser interprets javascript: URLs as executable JavaScript.

Result → full DOM XSS.

## 🛠 How To Fix This

### ✔ Validate allowed values

Allow only known safe paths like /home, /feedback.

### ✔ Strip dangerous prefixes

Block anything starting with:

```
javascript:
data:
vbscript:
```

### ✔ Use DOMPurify for input sanitization

Sanitize everything coming from URL parameters before injecting into the DOM.

### ✔ Avoid constructing attributes from user input

Instead, use server-side verified redirects.

## 🔥 Final Thoughts

This lab showcases a classic jQuery-based DOM XSS where user-controlled input manipulates an anchor’s href attribute. By injecting a javascript: protocol, attackers can turn a normal link into an executable payload — leading to full DOM XSS.

Short, simple, and extremely common in bug bounty programs.

Stay curious. Stay offensive.
~ Aditya Bhatt 🔥

## ⭐ Follow Me & Connect

If you enjoyed this write-up or want to stay connected with my cybersecurity research:

🔗 GitHub: https://github.com/AdityaBhatt3010
💼 LinkedIn: https://www.linkedin.com/in/adityabhatt3010/
✍️ Medium: https://medium.com/@adityabhatt3010
👨‍💻👩‍💻 GitHub Repository Link: https://github.com/AdityaBhatt3010/DOM-XSS-in-jQuery-anchor-href-attribute-sink-using-location.search-source
▶️My XSS PlayList Link: https://medium.com/@adityabhatt3010/list/xss-cross-site-scripting-a218a9d9cd93
🧪 Lab Link: https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-href-attribute-sink



---
*Original URL: [https://medium.com/system-weakness/dom-xss-in-jquery-href-attribute-sink-location-search-jquery-attr-958ce0e52904?source=search_post---------115-----------------------------------](https://medium.com/system-weakness/dom-xss-in-jquery-href-attribute-sink-location-search-jquery-attr-958ce0e52904?source=search_post---------115-----------------------------------)*
