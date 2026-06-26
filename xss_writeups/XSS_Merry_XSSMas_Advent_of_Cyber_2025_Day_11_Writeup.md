# XSS — Merry XSSMas | Advent of Cyber 2025 Day 11 | Writeup

> **Author**: Debmalya Mondal
> **Published**: Dec 11, 2025

---

## TRYHACKME WRITEUP

## Unwrapping the Mechanics of Cross‑Site Scripting Attacks

![Debmalya Mondal](https://miro.medium.com/v2/resize:fill:32:32/1*tSFQNmx2ZZofpypkFsb2dQ.png)

3

Listen

Share

Access the room: https://tryhackme.com/room/xss-aoc2025-c5j8b1m4t6

![image](https://miro.medium.com/v2/resize:fit:700/0*sCutERhymggIeDoo)

After last year’s automation and tech modernisation, Santa’s workshop got a new makeover. McSkidy has a secure message portal where you can contact her directly with any questions or concerns. However, lately, the logs have been lighting up with unusual activity, ranging from odd messages to suspicious search terms. Even Santa’s letters appear to be scripts or random code. Your mission, should you choose to accept it: dig through the logs, uncover the mischief, and figure out who’s trying to mess with McSkidy.

## Learning Objectives

- Understand how XSS works
- Learn to prevent XSS attacks

## Step-by-Step Walkthrough

### Initial Setup

Start the target machine and AttackBox as instructed

![image](https://miro.medium.com/v2/resize:fit:700/1*lgm3ThHh01T5esjaVKzBEg.png)

Access the web application at http://MACHINE_IP using the browser in the AttackBox

![image](https://miro.medium.com/v2/resize:fit:700/1*ZeWScI_rkzm6C--ZTwLpxg.png)

Familiarize yourself with the web app’s interface, including the search section and message form.

## So, what exactly is XSS?

Cross-Site Scripting (XSS) is a critical web application vulnerability that enables attackers to inject malicious code, typically JavaScript, into input fields whose content is rendered to other users, such as forms or comment sections in blogs. When applications fail to properly validate or escape user input, the submitted data may be executed as code instead of being treated as harmless text.

This can lead to severe consequences, including the theft of credentials, website defacement, and user impersonation. XSS attacks are categorized into several types based on their execution method and impact. This discussion focuses specifically on Reflected XSS, where the injected code is immediately reflected back to the user via the application’s response, and Stored XSS, where the malicious payload is permanently stored on the target server and served to users over time.

## Understanding Reflected XSS

Reflected XSS occurs when the injected script is immediately reflected in the response.

Search for a term like gift.

![image](https://miro.medium.com/v2/resize:fit:700/1*SeppOXUa0XNiHqeCeq0OFA.png)

Craft a malicious payloadand add the payload to the search bar and click “Search Messages”: <script>alert('Reflected Meow Meow')</script>

![image](https://miro.medium.com/v2/resize:fit:700/1*sDCBlIi-n8HwIM3fk8NLiA.png)

If an alert box appears, the application is vulnerable to reflected XSS.

After finding the vulnerability, we discovered our first flag.

THM{Evil_Bunny}

![image](https://miro.medium.com/v2/resize:fit:700/1*7f2I-7b2QcYdfsNhHwg7Qw.png)

![image](https://miro.medium.com/v2/resize:fit:700/1*U-LQBF5ZPvCf3Y2aeHdByg.png)

The system log also identifies the XSS payload script.

### Understanding Stored XSS

Stored XSS occurs when the malicious script is saved on the server and loaded for every user who views the affected page.

## Get Debmalya Mondal’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

Use a message form to submit a comment.

![image](https://miro.medium.com/v2/resize:fit:700/1*_OSMJ5tKIhugqIuGSF_ZMA.png)

![image](https://miro.medium.com/v2/resize:fit:700/1*HEIeoZaseL_PHyS08293Jw.png)

Now we will craft a malicious payload and Submit the it as a message:

<script>alert('Stored Meow Meow')</script>

![image](https://miro.medium.com/v2/resize:fit:700/1*gMo1Mil94xt4vndyssMW7A.png)

![image](https://miro.medium.com/v2/resize:fit:700/1*fN2GUxhB3i67ynLX_X6tEg.png)

Now every time the page is reloaded, the alert box will display, indicating successful exploitation of stored XSS.

![image](https://miro.medium.com/v2/resize:fit:700/1*6TEeRMW3M-5XfuI5syCaGw.png)

After confirming successful exploitation of stored XSS we finally found our 2nd Flag!!!

THM{Evil_Stored_Egg}

![image](https://miro.medium.com/v2/resize:fit:700/1*YOd0ibtHhVDGpube8QBEUA.png)

The system log has detected the XSS payload threat and flagged it.

## Answers of the THM Lab

Which type of XSS attack requires payloads to be persisted on the backend?

Stored.

What’s the reflected XSS flag?

THM{Evil_Bunny}.

What’s the stored XSS flag?

THM{Evil_Stored_Egg}.

## Preventing XSS Attacks

- Disable Dangerous Rendering Paths: Instead of using innerHTML, use textContent to treat input as text and parse it for HTML.
- Make Cookies Inaccessible to JS: Set session cookies with the HttpOnly, Secure, and SameSite attributes to reduce the impact of XSS attacks.
- Sanitize Input/Output and Encode: Sanitize and encode all user-supplied data to prevent security vulnerabilities. Remove or escape any elements that could be interpreted as executable code, such as scripts, event handlers, or JavaScript URLs, while preserving safe formatting.

## Key Takeaways

- XSS vulnerabilities can be exploited to execute malicious scripts on a user’s browser, leading to various security issues such as stealing session cookies, triggering fake login popups, and defacing pages.
- Reflected XSS requires the user to click on a link with a malicious payload, while stored XSS persists on the server and affects all users who view the affected page.
- Preventing XSS attacks involves disabling dangerous rendering paths, making cookies inaccessible to JavaScript, and sanitizing and encoding user-supplied data.​

## Join Advent of Cyber 2025

TryHackMe | Advent of Cyber 2025: Free 24-Day Cyber Security Challenge



---
*Original URL: [https://medium.com/@devdebug/xss-merry-xssmas-advent-of-cyber-2025-day-11-writeup-51ead6368176?source=search_post---------124-----------------------------------](https://medium.com/@devdebug/xss-merry-xssmas-advent-of-cyber-2025-day-11-writeup-51ead6368176?source=search_post---------124-----------------------------------)*
