# Found Stored XSS in a Production Workflow

> **Author**: Saniya Inayath
> **Published**: Mar 24, 2026

---

![Saniya Inayath](https://miro.medium.com/v2/da:true/resize:fill:32:32/0*CPTcpS9EIq4V7a1x)

17

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:700/1*PaFi44dLBMYkuJyU5DsuAA.png)

The finding came from one of the most ordinary parts of the application: a Production Comment field inside the Job Summary workflow.

The platform was used to manage job orders, production updates, and client-related service records. Users could log in, open job entries, and leave internal notes against records as part of their day-to-day workflow.

XSS happens when a web app treats user input as code instead of plain text.
Stored XSS is when that input gets saved and executes later whenever someone views it.

The application had a Job Summary Sheet feature and each job record included a simple textarea where users could add production notes. Fields like these are often overlooked during security reviews. Developers usually focus on login forms, search bars and more obvious inputs, while comment boxes and note fields get less attention. But any field that stores and later renders user input can become an XSS sink.

While testing that workflow, I started with the most basic check:

```
<b>test</b>
```

When I reopened the record, the word appeared in bold. That was the first clue. The application was rendering raw HTML instead of safely encoding user input.

To confirm whether script execution was possible, I used a harmless proof-of-concept payload:

![image](https://miro.medium.com/v2/resize:fit:700/1*nyY_4wW_CM8LZjB05uF41g.png)

```
<script>alert("xss")</script>
```

The application accepted it, stored it and executed it when the affected record was opened again.

![image](https://miro.medium.com/v2/resize:fit:700/1*3RhBeKf2mV1x_2uj1s5Z4g.png)

That confirmed the presence of a stored XSS vulnerability.

What made this more than just a simple popup was persistence. The payload was not reflected once and gone. It was saved by the application and rendered later, which meant any user opening that record in the vulnerable context could potentially trigger it.

In a real attack scenario, that <script> tag could contain anything. That kind of issue can let attacker-controlled JavaScript run in another user’s browser inside a trusted application. Depending on the context, that can lead to unauthorized actions, exposure of sensitive page data or manipulation of what the user sees.

## Get Saniya Inayath’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

That is why stored XSS matters. A very ordinary field can become a reliable execution point if user input is stored and later rendered unsafely.

### Why it happened?

Three things went wrong simultaneously:

- No input sanitization on save
The server accepted and stored raw HTML without stripping dangerous tags. A simple sanitization library would have neutered the payload before it ever hit the database.
- No output encoding on render
When displaying stored comments, the application injected the raw value directly into the DOM. The character `<` should have been rendered as `&lt;` making it display as text rather than execute as HTML.
- No Content Security Policy
There was no CSP header restricting which scripts the browser was allowed to run. Even if encoding had failed, a properly configured CSP like:
Content-Security-Policy: default-src 'self'; script-src 'self'
would have blocked the inline script from executing entirely.All three protections were missing. Any one of them would have been enough to prevent this.

### Severity

This kind of vulnerability can reasonably be rated High, especially when a low-privileged authenticated user can store the payload and another user only needs to view the affected page for execution to happen.

Sample CVSS: 7.2 (AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N)

That score reflects a vulnerability that:
-can be exploited over the network
-is low complexity
-requires only low privileges
-needs a user to load the page
-can significantly affect confidentiality and integrity

### How developers can fix it?

The fix is straightforward, even if the impact is not.

- Sanitize input before storing it
Do not allow unsafe HTML or script content to be saved unless there is a very specific and controlled need.
- Escape output before rendering it
Stored comments and notes should be displayed as text, not interpreted as HTML or JavaScript.
- Add a strong Content Security Policy
A restrictive CSP helps reduce the impact of injected scripts, especially inline script execution.
- Review all stored text fields
Comment boxes, notes, descriptions, and internal message fields are common places where stored XSS gets missed.

This finding was a reminder that not every important vulnerability starts in a complicated place. Sometimes it starts with a field everyone assumes is harmless.

For developers, the lesson is simple: if user input is stored and later displayed, it needs proper sanitization and output encoding. For testers, it is a good reminder not to skip boring fields. They are often where the real findings hide.

### Responsible disclosure

This issue was identified during an authorized security assessment and reported privately with reproduction details and remediation guidance. Sensitive details and identifying information have been excluded from this writeup.

If you found this useful, follow for more real-world penetration testing walkthroughs and web security breakdowns.

#WebSecurity #XSS #PenetrationTesting #CyberSecurity #OWASP #EthicalHacking



---
*Original URL: [https://medium.com/@saniyainayath/found-stored-xss-in-a-production-workflow-77cce165cb04?source=search_post---------41-----------------------------------](https://medium.com/@saniyainayath/found-stored-xss-in-a-production-workflow-77cce165cb04?source=search_post---------41-----------------------------------)*
