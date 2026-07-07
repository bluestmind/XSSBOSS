# 📌🚀Tryhackme | Advent Of Cyber 2025 | Day 11 | XSS — Merry XSSMas | Walkthrough🔥👉

> **Author**: Sudarshan Patel
> **Published**: Dec 11, 2025

---

![Sudarshan Patel](https://miro.medium.com/v2/resize:fill:32:32/1*y4z_vBLh5AzRc5Dhnbq3mA.jpeg)

4

Listen

Share

Learn about types of XSS vulnerabilities and how to prevent them.

Thanks for checking out this walkthrough of “TryHackMe | Advent Of Cyber 2025 | Day 11 | XSS — Merry XSSMas”. In this writeup, we’re going to break down the different types of XSS vulnerabilities you’ll see in the wild and how to actually defend against them — not just tick boxes.

Huge shout-out to TryHackMe and the module author for putting together another solid, hands-on challenge that lets us sharpen real-world web security skills instead of just reading theory.

To my subscribers, readers, and followers: thanks for riding along with me on this journey. Whether you’re here to learn, to compare flags, or to level up your bug bounty game, I appreciate you taking the time to read, view, and support these walkthroughs and blogs. Let’s dive in and make “Merry XSSMas” a little less merry for vulnerable apps.

## 👉The Story

![image](https://miro.medium.com/v2/resize:fit:700/1*KhysV6pIKeBhB48kfqx5yA.png)

## Task 1

## Introduction

After last year’s automation and tech modernisation, Santa’s workshop got a new makeover. McSkidy has a secure message portal where you can contact her directly with any questions or concerns. However, lately, the logs have been lighting up with unusual activity, ranging from odd messages to suspicious search terms. Even Santa’s letters appear to be scripts or random code. Your mission, should you choose to accept it: dig through the logs, uncover the mischief, and figure out who’s trying to mess with McSkidy.

## Learning Objectives

- Understand how XSS works
- Learn to prevent XSS attacks

## Task 2

## Leave the Cookies, Take the Payload

## Equipment Check

For today’s room we will be using a the web app found under http://TARGET-IP. You can use the browser of your AttackBox to navigate to it. You will see a page as shown below:

![image](https://miro.medium.com/v2/resize:fit:700/1*fTeClLMRitOMxEZMmcyDJw.png)

Let’s review some key material regarding potential attacks on websites like this portal, specifically Cross-Site Scripting (XSS).

XSS is a web application vulnerability that lets attackers (or evil bunnies) inject malicious code (usually JavaScript) into input fields that reflect content viewed by other users (e.g., a form or a comment in a blog). When an application doesn’t properly validate or escape user input, that input can be interpreted as code rather than harmless text. This results in malicious code that can steal credentials, deface pages, or impersonate users. Depending on the result, there are various types of XSS. In today’s task, we focus on Reflected XSS and Stored XSS.

## Reflected XSS

You see reflected variants when the injection is immediately projected in a response. Imagine a toy search function in an online toy store, you search via:

https://trygiftme.thm/search?term=gift

But imagine you send this to your friend who is looking for a gift for their nephew (please don’t do this):

https://trygiftme.thm/search?term=<script>alert( atob("VEhNe0V2aWxfQnVubnl9") )</script>

If your friend clicks on the link, it will execute code instead.

Impact

You could act, view information, or modify information that your friend or any user could do, view, or access. It’s usually exploited via phishing to trick users into clicking a link with malicious code injected.

## Stored XSS

A Stored XSS attack occurs when malicious script is saved on the server and then loaded for every user who views the affected page. Unlike Reflected XSS, which targets individual victims, Stored XSS becomes a “set-and-forget” attack, anyone who loads the page runs the attacker’s script.

To understand how this works, let’s use the example of a simple blog where users can submit comments that get displayed below each post.

## Normal Comment Submission

![image](https://miro.medium.com/v2/resize:fit:700/1*Zxfl4hSXmPSBsrUEuCgGpw.png)

The server stores this information and displays it whenever someone visits that blog post.

## Malicious Comment Submission (Stored XSS Example)

If the application does not sanitize or filter input, an attacker can submit JavaScript instead of a comment:

![image](https://miro.medium.com/v2/resize:fit:700/1*pbXD0Y3SCT6IjUek5zqIDw.png)

Because the comment is saved in the database, every user who opens that blog post will automatically trigger the script.

This lets the attacker run code as if they were the victim in order to perform malicious actions such as:

- Steal session cookies
- Trigger fake login popups
- Deface the page

## Protecting against XSS

Each service is different, and requires a well-thought-out, secure design and implementation plan, but key practices you can implement are:

- Disable dangerous rendering raths: Instead of using the innerHTML property, which lets you inject any content directly into HTML, use the textContent property instead, it treats input as text and parses it for HTML.
- Make cookies inaccessible to JS: Set session cookies with the HttpOnly, Secure, and SameSite attributes to reduce the impact of XSS attacks.
- Sanitise input/output and encode:
- In some situations, applications may need to accept limited HTML input — for example, to allow users to include safe links or basic formatting. However it’s critical to sanitize and encode all user-supplied data to prevent security vulnerabilities. Sanitising and encoding removes or escapes any elements that could be interpreted as executable code, such as scripts, event handlers, or JavaScript URLs while preserving safe formatting.

To exploit XSS vulnerabilities, we need some type of input field to inject code. There is a search section, let’s start there.

## Exploiting Reflected XSS

To exploit reflected XSS, we can use test payloads to check if the app runs the code injected. If you want to test more advanced payloads, there are cheat sheets online that you can use to craft them. For now, we’ll pick the following payload:

## Get Sudarshan Patel’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

<script>alert('Reflected Meow Meow')</script>

Inject the code by adding the payload to the search bar and clicking “ Search Messages”. If it shows the alert text, we have confirmed reflected XSS. So, what happened?

- The search input is reflected directly in the results without encoding
- The browser interprets your HTML/JavaScript as executable code
- An alert box appeared, demonstrating successful XSS execution

You can track the behaviour and how the system interprets your actions by checking the “ System Logs” tab at the bottom of the page:

![image](https://miro.medium.com/v2/resize:fit:700/1*XoyVIL-vqMVhau5krxw75w.png)

Now that we have confirmed reflected XSS, let’s investigate if it’s susceptible to stored XSS. This vector must be different, as it needs to be persisted. Looking at the website, we can see that you are able to send messages, which are stored on the server for McSkidy to view later (as opposed to searching, which is stored temporarily on the client side).

Navigate to the message form, and enter the malicious payload we used before (others work too):

<script>alert('Stored Meow Meow')</script>

Click the “ Send Message” button. Because messages are stored on the server, every time you navigate to the site or reload, the alert will display.

## Wrapping Up

So it’s confirmed! The site is vulnerable to XSS; it’s no wonder that unusual payloads have been detected in the logs. The team will now harden the site to prevent future malicious code from being injected.

A
nswer the questions below

Question:

What type of XSS attack requires payloads to be persisted on the backend?

Answer: stored

Please read the above theory section carefully to get the answer to this question.

Question:

What’s the reflected XSS flag?

Answer: THM{Evil_Bunny}

To get the answer to this question, just paste the attached payload in the theory section in the search box as shown in the below screenshots:

![image](https://miro.medium.com/v2/resize:fit:3016/1*dWxLIEfXtsDVjTAXlbvlXQ.png)

![image](https://miro.medium.com/v2/resize:fit:1482/1*oDL-0GrlHCzScjg7qTUhSw.png)

![image](https://miro.medium.com/v2/resize:fit:1488/1*zvik8ySD63h3fsAMrMtNmA.png)

![image](https://miro.medium.com/v2/resize:fit:1506/1*DdUIEAxzCbAjobo_CW2aag.png)

Question:

What’s the stored XSS flag?

Answer: THM{Evil_Stored_Egg}

Please refer to the theory section and copy-paste the payload in the second searchbox. Please do also refer to the below screenshots for a clear understanding:

![image](https://miro.medium.com/v2/resize:fit:1510/1*ypkuwrLBoa1fXY8tfHWKew.png)

![image](https://miro.medium.com/v2/resize:fit:1498/1*FE0EdT0K78IhM0C3MQ9qVg.png)

![image](https://miro.medium.com/v2/resize:fit:700/1*2mWrYlOWm-vf3-UEPmhBhA.png)

If you made it this far through Day 11 — Merry XSSMas, respect. You’ve just reinforced your understanding of reflected and stored XSS, and more importantly, how to spot and prevent them in real environments — exactly the mindset you need as a bug bounty hunter or security engineer.

Big thanks again to TryHackMe and the author of this Advent of Cyber module for giving us another lab that actually builds practical skill, not just badges.

To all my subscribers, readers, and followers: thank you for reading, viewing, and subscribing to my walkthroughs, writeups, and blogs. Your support is what keeps me grinding, testing, and sharing more content like this. If this helped you, share it with someone who’s still sleeping on XSS — and I’ll catch you in the next room.

Happy hacking, and see you in the next writeup. 🔍📊

Stay curious, keep learning🕵️‍♂️

Crafted by: Sudarshan Patel 👨‍💻
Connect with me on LinkedIn: Sudarshan Patel 🔗
Follow my Tweets: @loneliestwolf3



---
*Original URL: [https://medium.com/@sudarshan.defcon/tryhackme-advent-of-cyber-2025-day-11-xss-merry-xssmas-walkthrough-c2511de9c318?source=search_post---------110-----------------------------------](https://medium.com/@sudarshan.defcon/tryhackme-advent-of-cyber-2025-day-11-xss-merry-xssmas-walkthrough-c2511de9c318?source=search_post---------110-----------------------------------)*
