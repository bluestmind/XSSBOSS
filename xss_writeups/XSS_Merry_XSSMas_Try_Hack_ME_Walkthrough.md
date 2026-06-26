# XSS — Merry XSSMas |Try Hack ME Walkthrough

> **Author**: Fazal
> **Published**: Dec 11, 2025

---

![Fazal](https://miro.medium.com/v2/resize:fill:32:32/1*FjQKe0-QeZvQotbq_SAYyQ.jpeg)

2

Listen

Share

The Story

![image](https://miro.medium.com/v2/resize:fit:700/0*AHuVp8GQ9AeKrB4b.png)

After last year’s automation and tech modernisation, Santa’s workshop got a new makeover. McSkidy has a secure message portal where you can contact her directly with any questions or concerns. However, lately, the logs have been lighting up with unusual activity, ranging from odd messages to suspicious search terms. Even Santa’s letters appear to be scripts or random code. Your mission, should you choose to accept it: dig through the logs, uncover the mischief, and figure out who’s trying to mess with McSkidy.

## Learning Objectives

- Understand how XSS works
- Learn to prevent XSS attacks

## Connecting to the Machine

Before moving forward, review the questions in the connection card shown below:

![image](https://miro.medium.com/v2/resize:fit:700/0*eAFtF-b1DC2Pc9B5.png)

Start your target machine by clicking the Start Machine button below. The machine will need about 2 minutes to fully boot. Additionally, start your AttackBox by clicking the Start AttackBox button below. The AttackBox will start in split view. In case you can not see it, click the Show Split View button at the top of the page.

Task 2 — Leave the Cookies, Take the Payload

## Equipment Check

For today’s room we will be using a the web app found under http://10.49.133.87. You can use the browser of your AttackBox to navigate to it. You will see a page as shown below:

![image](https://miro.medium.com/v2/resize:fit:700/0*Fr0tfDyBEGYk0RW1.png)

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

```
POST /post/comment HTTP/1.1
Host: tgm.review-your-gifts.thm
```

```
postId=3
name=Tony Baritone
email=tony@normal-person-i-swear.net
comment=This gift set my carpet on fire but my kid loved it!
```

The server stores this information and displays it whenever someone visits that blog post.

## Malicious Comment Submission (Stored XSS Example)

If the application does not sanitize or filter input, an attacker can submit JavaScript instead of a comment:

```
POST /post/comment HTTP/1.1
Host: tgm.review-your-gifts.thm
```

```
postId=3
name=Tony Baritone
email=tony@normal-person-i-swear.net
comment=<script>alert(atob("VEhNe0V2aWxfU3RvcmVkX0VnZ30="))</script> + "This gift set my carpet on fire but my kid loved it!"
```

Because the comment is saved in the database, every user who opens that blog post will automatically trigger the script.

## Get Fazal’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

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

<script>alert('Reflected Meow Meow')</script>

Inject the code by adding the payload to the search bar and clicking “ Search Messages”. If it shows the alert text, we have confirmed reflected XSS. So, what happened?

- The search input is reflected directly in the results without encoding
- The browser interprets your HTML/JavaScript as executable code
- An alert box appeared, demonstrating successful XSS execution

You can track the behaviour and how the system interprets your actions by checking the “ System Logs” tab at the bottom of the page:

![image](https://miro.medium.com/v2/resize:fit:700/0*alKU942wR0emzlTb.png)

Now that we have confirmed reflected XSS, let’s investigate if it’s susceptible to stored XSS. This vector must be different, as it needs to be persisted. Looking at the website, we can see that you are able to send messages, which are stored on the server for McSkidy to view later (as opposed to searching, which is stored temporarily on the client side).

Navigate to the message form, and enter the malicious payload we used before (others work too):

<script>alert('Stored Meow Meow')</script>

Click the “ Send Message” button. Because messages are stored on the server, every time you navigate to the site or reload, the alert will display.

## Wrapping Up

So it’s confirmed! The site is vulnerable to XSS; it’s no wonder that unusual payloads have been detected in the logs. The team will now harden the site to prevent future malicious code from being injected.

Steps to Complete this room

- This room is about the XSS(cross-site scripting), in this attack the attacker mostly targeted on the input fields,where by us of javascript codes to maniplate the request into intended way, so to find the flags need find out the two types xss attack which explained in the task(reflected and stored).
- Lets find the reflected XSS attack , in the website given a search field box,in that write the js code like which will show on the website (“<script>alert(“hello you are hacked”)</script>”), by putting this it show that text on the website when you click on the submit button.

![image](https://miro.medium.com/v2/resize:fit:700/1*d_Vmqw3j6sPtfjKskE-ABQ.png)

![image](https://miro.medium.com/v2/resize:fit:700/1*-VsoCQOPadIzsVIejyKJ_g.png)

![image](https://miro.medium.com/v2/resize:fit:700/1*OuVQ6viC0seV7QjlYIfbjg.png)

3.Now lets find the stored xss in the website , if stored xss attack need work in the website it need storing text like thing like comment section, where it will be showed to everyone how open the website,lets use same js script here two , but this time in the message box given below of the search message,(“<script>alert(“hello you are hacked”)</script>”),now the message is saved in the database.

![image](https://miro.medium.com/v2/resize:fit:700/1*O0V0d2o4HFEa4lbMe7ZFBA.png)

![image](https://miro.medium.com/v2/resize:fit:700/1*jGwVDjc4xYsW4feDAObfjQ.png)

![image](https://miro.medium.com/v2/resize:fit:700/1*3MQynyP6i_z3XK9-4cc1Ug.png)

```
Which type of XSS attack requires payloads to be persisted on the backend?
sorted

What's the reflected XSS flag?
THM{Evil_Bunny}

What's the stored XSS flag?
THM{Evil_Stored_Egg}
```

[DAY-10] SOC Alert Triaging — Tinsel Triage |Try Hack Me walkthrough
[DAY-12] Phishing — Phishmas Greetings

Follow Me:

I’m active here — if you like my work, follow me on the platforms you use:

Instagram: https://www.instagram.com/.fazal07.

LinkedIn: https://www.linkedin.com/in/fazal-shaikk/

GitHub: https://github.com/shaikfazal-del

Medium: https://medium.com/@fazal-sec

If you want more content like this, follow me on any of these — don’t miss the next piece.



---
*Original URL: [https://medium.com/@fazal-sec/xss-merry-xssmas-try-hack-me-walkthrough-e2c6ad72c2fc?source=search_post---------114-----------------------------------](https://medium.com/@fazal-sec/xss-merry-xssmas-try-hack-me-walkthrough-e2c6ad72c2fc?source=search_post---------114-----------------------------------)*
