# How I Found 3 Critical Reflected XSS Bugs Using Simple URL Encoding Tricks

> **Author**: Ahmad Suhendra
> **Published**: Jan 24, 2026

---

![Ahmad Suhendra](https://miro.medium.com/v2/da:true/resize:fill:32:32/0*r9rra_3wYDNmA1Pl)

61

2

Listen

Share

In an age where modern frameworks promise built-in security, it’s surprising how even seemingly minor lapses can lead to critical security vulnerabilities. In this article, I share how I discovered three reflected XSS (Cross-Site Scripting) vulnerabilities on an academic web application — all of which were exposed using basic URL encoding techniques.

What made this interesting wasn’t the complexity of the payloads — but rather how overlooked vectors and improper sanitization opened the door to full client-side code execution.

## 🧠 What Makes Reflected XSS Dangerous?

Reflected XSS vulnerabilities allow attackers to inject malicious scripts into a web page by reflecting unsanitized input directly back into the HTML response. If the browser interprets this input as executable JavaScript, it could allow:

- Account takeover via stolen cookies
- Redirection to malicious sites
- Unauthorized actions on behalf of users

But what makes this case special is how URL encoding helped bypass naive filtering and demonstrated the importance of context-aware output escaping.

## 💥 Vulnerability #1: XSS via Malicious Encoded Path

## 🔗 Payload (URL Encoded)

```
https://target-site.com/index.php/%22--%3E%3Cscript%3Ealert(document.domain)%3C/script%3E/index.php
```

## 🧪 Decoded View:

```
/"--> <script>alert(document.domain)</script> /index.php
```

![image](https://miro.medium.com/v2/resize:fit:700/1*Ma36REHmpUaNJYIa6lo4-w.png)

## 🕵️ Discovery Method:

I noticed the application reflected parts of the URL path in the page (possibly as part of breadcrumbs or error messages). This inspired me to craft a path payload instead of the usual query param.

The encoded portion %22--%3E%3Cscript%3E... breaks out of HTML context and executes the script. Let’s break it down:

EncodedDecodedDescription%22"Closes an attribute--%3E-->Closes a comment (HTML)%3C<Begins <script> tag%3E>Ends a tag%28(Begins function argument%29)Ends function argument

🧩 Insight: The injection worked because the path input was interpolated directly into HTML without any escaping. By encoding the payload, I bypassed potential WAFs or regex-based input checks.

## 💥 Vulnerability #2: Classic XSS via Encoded Query Parameter

## 🔗 Payload (Encoded):

```
https://target-site.com/index.php?destination=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E&p=member
```

## 🧪 Decoded View:

```
destination="><script>alert(document.domain)</script>
```

## 🕵️ Discovery Method:

I noticed that the app used a destination parameter to redirect users after login or actions. These parameters are often rendered in anchor tags or JavaScript redirection code.

## Get Ahmad Suhendra’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

The idea: inject into an HTML attribute or inline JS, break the context, and run code.

Technique Highlight:

- %22 (") breaks out of the attribute value.
- ><script>...</script> injects new HTML.
- The application reflected the destination parameter unsanitized into the DOM.

🧩 Insight: This is a textbook example of reflected XSS, but URL encoding gave it stealth — making the payload less obvious in logs and to input filters.

![image](https://miro.medium.com/v2/resize:fit:700/1*pTZ7Nph6074tV84-fJd4Gw.png)

## 💥 Vulnerability #3: Login Flow XSS With Encoded Redirection

## 🔗 Payload (Encoded):

```
https://target-site.com/index.php?_csrf_token=...&destination=zbuip%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3Ejgoihbmmygl&logMeIn=Login&memberID=admin&memberPassWord=password&p=member
```

## 🧪 Decoded Segment of destination Param:

```
zbuip"><script>alert(document.domain)</script>jgoihbmmygl
```

## 🕵️ Discovery Method:

After inspecting how the site handled failed login redirects, I found it used the destination parameter to determine where to redirect or display messages post-login.

This meant that if the app reflected the destination back in the HTML—perhaps in a form or a message—it could be a hidden XSS vector. And it was.

🧩 Insight: Even though CSRF tokens and login forms were present, the XSS was purely in the rendering of the destination. I didn’t need valid credentials—just a cleverly encoded string.

## 🔬 Why URL Encoding Matters

URL encoding is a double-edged sword:

- To developers, it’s a way to safely pass characters via URLs.
- To attackers, it’s a way to obfuscate payloads, bypass filters, and sneak malicious input through shallow input validation.

In these cases, the vulnerable system failed to:

- Properly decode and validate input server-side.
- Encode output based on its context (HTML, attribute, or JS).

![image](https://miro.medium.com/v2/resize:fit:700/1*SyYZPP28IBfi_KrGzOqTTQ.png)



---
*Original URL: [https://medium.com/@ahmad.suhendra1405/how-i-found-3-critical-reflected-xss-bugs-using-simple-url-encoding-tricks-215d1c33bbea?source=search_post---------68-----------------------------------](https://medium.com/@ahmad.suhendra1405/how-i-found-3-critical-reflected-xss-bugs-using-simple-url-encoding-tricks-215d1c33bbea?source=search_post---------68-----------------------------------)*
