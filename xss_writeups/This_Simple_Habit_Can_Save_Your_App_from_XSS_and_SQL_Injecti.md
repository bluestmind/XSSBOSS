# This Simple Habit Can Save Your App from XSS and SQL Injection Attacks

> **Author**: CodeByUmar
> **Published**: Nov 15, 2025

---

Member-only story

## It’s not about new frameworks or tools; it’s about writing code that never trusts anything you didn’t create yourself.

![CodeByUmar](https://miro.medium.com/v2/resize:fill:64:64/1*vjFe2I18KAEfLTTJKyDC0Q.jpeg)

52

1

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:700/1*fc1y3c5E1z755Cy59-Qt3w.png)

## Free Read No Paywall

Hey 👋, not a Medium member?
You can read this full article for free here: 👉 Read

## Introduction: The Habit Developers Forget

A few years ago, I built a small internal dashboard for a client. It worked fine for months until someone reported that opening a page triggered random pop-ups.

No server crashes, no logs, no suspicious users. Just a pop-up.

After digging through code, I realized what had happened: a single form field was being stored and rendered without validation or escaping. A script tag was inserted, and it executed in every browser that opened the page.

That’s all it took, one careless assumption that user input was safe.

The problem wasn’t the framework. It wasn’t the database.
It was me forgetting a simple habit: validate and sanitize every single piece of data.



---
*Original URL: [https://medium.com/skillstuff/this-simple-habit-can-save-your-app-from-xss-and-sql-injection-attacks-f169999deae2?source=search_post---------148-----------------------------------](https://medium.com/skillstuff/this-simple-habit-can-save-your-app-from-xss-and-sql-injection-attacks-f169999deae2?source=search_post---------148-----------------------------------)*
