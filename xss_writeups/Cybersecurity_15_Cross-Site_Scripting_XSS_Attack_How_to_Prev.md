# Cybersecurity #15: Cross-Site Scripting (XSS) Attack & How to Prevent It

> **Author**: mohandika
> **Published**: Nov 20, 2025

---

## The Cybersecurity Tutorial Series

![mohandika](https://miro.medium.com/v2/resize:fill:32:32/1*tdsbqbibcGJjEwZmQKVLcQ.png)

51

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:700/0*k_V1nhW3g7ds5Skn)

Cross‑Site Scripting (XSS) is a type of code‑injection attack that is executed on the client side of a web application.
The client side is usually the software used to interact with the web application — in most cases, this means the web browser.

In an XSS attack, an attacker injects a malicious script into the browser so that the web application performs actions it was never intended to perform. The malicious code may execute when the victim visits a web page or interacts with the server.

### Purpose of the Attack

XSS attacks are typically used to:

- Steal sensitive information, such as cookies, session tokens, usernames, and passwords.
- Modify website content, since XSS is a form of code injection.

### How XSS Works

To understand how it works, consider this scenario:

- A user accesses a website through a browser using an internet connection.
- The browser sends a request to the web server.
- The server sends back a response, which is displayed as a webpage in the browser.

In an XSS attack:

- The attacker injects malicious code into the website.
- The code is then either sent to the victim’s browser or stored on the server.
- When the victim visits the affected page, the script runs and can steal sensitive data or perform unauthorized actions.

### Types of Cross‑Site Scripting (XSS)

There are three main types of XSS attacks:

- Reflected XSS

- The malicious script is delivered through a request (for example, via a URL parameter or form).
- It is not stored on the server.
- The attack is triggered when the victim opens the crafted link.

2. Stored XSS

- The malicious script is stored on the web server (in a database, comment section, forum, etc.).
- Each time the page loads, the script executes in the victim’s browser.

3. DOM‑based XSS

- The attack occurs within the Document Object Model (DOM) on the client side.
- It doesn’t necessarily involve communication with the server.

## Reflected Cross‑Site Scripting

For demo you can use Damn Vulnerable Web Application (DVWA) — a training tool for learning web‑security attacks.

Steps:

- Access a page that has an input field (for example, Name).
- Enter a normal value and submit.

- The page displays: “Hello, [your name]”.

3. Try injecting a simple HTML tag:

```
<h1>Under Attack</h1>
```

- If the display changes, it indicates the page is vulnerable to XSS.

4. Now try injecting a script:

```
<script>alert("Hello")</script>
```

- If a pop‑up appears, the site is confirmed vulnerable.

### Why Is This Dangerous?

With slight modification, the script can be used to steal cookies:

```
<script>alert(document.cookie)</script>
```

Cookies contain a Session ID, a unique string assigned by the web server to identify each user session.
If an attacker obtains this ID, they can use tools like Burp Suite to log into the victim’s account without knowing their username or password.

### Testing Different Security Levels in DVWA

1. Low Security

- The script runs without any filtering.
- The site is easily exploitable.

2. Medium Security

- The application starts filtering <script> tags.
- Bypass example using a nested script:

```
<scr<script>ipt>alert("Bypassed")</scr<script>ipt>
```

- When the outer <script> is removed by the filter, the remaining part forms a valid tag and executes.

3. High Security

- The app uses regular expressions to remove all <script> tags.
- Bypass by using another HTML tag with an event handler:

```
<img src="x" onmouseover="alert('Hello')">
```

- The pop‑up appears when the user hovers the cursor over the image.

You can replace src="x" with a real image, such as one that says “Click Here.”
When the victim hovers over the image, the malicious code executes.

## Stored Cross-Site Scripting (Stored XSS)

In Reflected XSS, data is not stored on the server — the script is executed directly in the browser.
However, in Stored XSS, the malicious script is stored and executed from the server.

Many modern web applications (e.g., Facebook, forums, comment sections) store user data in a database. When another user accesses a page, the server fetches the stored data and displays it in their browser. In a Stored XSS attack, an attacker injects a malicious script that gets saved in the database, so every user who views that data will execute the script.

### Demonstration of Stored XSS

In DVMA, example page for Stored XSS, you will see fields for Name and Message.

- Enter:

- Name: test1
- Message: message1
Click Sign Guestbook.

2. The data remains even after refreshing, because it is stored in the database.

Now attempt to inject malicious code:

- Name: Test2
- Message:

```
<script>alert("Hello")</script>
```

A pop-up appears, showing the application is vulnerable to Stored XSS. Because the script is saved in the database, it executes every time the page loads — for every user.

### Increasing Security Levels (DVWA)

Before continuing with the next security level, clear the guestbook to prevent old payloads from executing repeatedly.

1. Medium Security

## Get mohandika’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

Try the same malicious input:

- Name: test1
- Message: <script>alert("Hello")</script>

No pop-up appears — this means the medium-level security filters are sanitizing script tags.

There is another limitation: the input fields have a maxlength="10" attribute.
To bypass this:

- Inspect the input element.
- Change maxlength="10" to maxlength="100".

Now you can enter more characters.

However, even with a longer input, the script still doesn’t execute — the server-side filter removes <script> tags.

To bypass this, use nested script tags, similar to Reflected XSS:

```
<scr<script>ipt>alert('Hello')</scr<script>ipt>
```

After adjusting the maxlength and entering this nested payload, the pop-up appears. The filter removes the outer <script> tag, but the inner portion recombines into a valid script that still executes.

2. High Security

At this level, even nested tags do not work.

The server code uses regular expressions to completely strip out all <script> tags. So an alternative tag is needed.

Use another HTML element with an event handler, such as:

```
<img src="x" onmouseover="alert('Hello')">
```

Since the handler is onmouseover, the pop-up appears when the cursor hovers over the image.

## DOM-Based XSS

DOM (Document Object Model) represents the structure of a webpage.
DOM-Based XSS occurs entirely on the client side.
The malicious script is not sent to the server, nor stored in any database.

In DOM XSS, the sequence is:

- Browser requests the page.
- Server responds with a normal page.
- The server-side script runs.
- Then the malicious code is injected through DOM manipulation and executed in the browser.

### Demonstration of DOM XSS

In the vulnerable DOM XSS page, there is a list of languages. When you select one, the URL changes, for example:

```
...?default=English
```

There is no text box, so all injection must be done through the URL.

Try modifying the URL:

```
...?default=<script>alert("Hello")</script>
```

A pop-up appears, showing that the page is vulnerable to DOM XSS.

### DOM XSS on Medium Security

At medium security:

- Script tags are removed.
- The page resets to the default language (English).
- Nested script tags also fail.

To bypass this:

- Inspect the page structure (select and option tags).
- Modify the URL so that you prematurely close the HTML tags and inject your payload.

Example payload:

```
...?default=</option></select><body onload="alert('Hello')">
```

When the server constructs the page, your injected closing tags disrupt the structure, and the malicious code executes.

### DOM XSS on High Security

At high security:

- The server only accepts predefined languages (e.g., English, French, German).
- Any other input resets the page to default.
- Previous bypasses do not work.

To bypass this, we use anchor tags (#).

The # symbol is used to point to a specific section of a webpage.
The server ignores everything after the #, but the browser still parses and executes JavaScript in that portion.

Payload:

```
...?default=English#<script>alert("Hello")</script>
```

The browser executes the script, and the pop-up appears.

## How to Prevent Cross-Site Scripting (XSS) Attacks

### 1. Escape User Input

Some special characters — such as “<”, “>”, and the percent symbol (%) — are commonly used in HTML tags or malicious scripts.
By escaping these characters, you remove their special meaning and treat them as normal text characters.

### 2. Treat All Input as Untrusted

Since users have full control over what they can submit, assume every input is a potential threat.
All input must be sanitized, validated, and processed carefully.

### 3. Validate Input

Use data validation to ensure that the input follows the expected format.
For example, for an email input field, the format should typically include:

```
username@domain.com
```

By validating data, you can prevent attackers from injecting malicious code.

### 4. Sanitize Data

As shown in the demo, some webpages sanitize input by:

- Removing <script> tags,
- Removing any script-tag variations,
- Using regular expressions to detect and eliminate potentially harmful patterns.

This sanitization helps prevent malicious scripts from executing.

### 5. Encode the Output

Sometimes characters like “<” and “>” are interpreted as script syntax.
Using encoding (such as URL encoding), you convert these characters into safe sequences, such as:

```
<  →  %3C
>  →  %3E
```

Once encoded, the characters are no longer processed as part of a script.

### 6. Use Proper Response Headers

Configure HTTP response headers to control what data can be sent or received by the browser.
Proper headers help prevent attackers from forcing the browser to execute malicious code.

### 7. Implement Content Security Policy (CSP)

A Content Security Policy (CSP) is a security standard that helps prevent XSS by:

- Restricting which sources scripts can be loaded from,
- Blocking inline scripts,
- Limiting content to trusted domains.

You can search for Content Security Policy (CSP) to learn more about these standards.



---
*Original URL: [https://medium.com/meetcyber/cybersecurity-15-cross-site-scripting-xss-attack-how-to-prevent-it-c5b9754fd376?source=search_post---------152-----------------------------------](https://medium.com/meetcyber/cybersecurity-15-cross-site-scripting-xss-attack-how-to-prevent-it-c5b9754fd376?source=search_post---------152-----------------------------------)*
