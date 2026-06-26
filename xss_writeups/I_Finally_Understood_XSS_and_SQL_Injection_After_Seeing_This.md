# I Finally Understood XSS and SQL Injection After Seeing This Demo

> **Author**: CodeByUmar
> **Published**: Nov 19, 2025

---

Member-only story

## A hands-on demo that makes the mechanics of XSS and SQL injection impossible to forget and shows the exact fixes you should apply today.

![CodeByUmar](https://miro.medium.com/v2/resize:fill:64:64/1*vjFe2I18KAEfLTTJKyDC0Q.jpeg)

57

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:700/1*ZWMUsGRAdd-v6lGrfYg5DQ.png)

## Free Read No Paywall

Hey 👋, not a Medium member?
You can read this full article for free here: 👉 Read

## Introduction

I used to explain XSS and SQL injection with diagrams and slides. People would nod, jot notes, then go back to code and never change habits.

Everything clicked the day I built a tiny vulnerable app and then exploited it in a controlled demo. Seeing the payload run in the browser and watching a crafted input leak rows from the database turned abstract warnings into obvious anti-patterns.

This article walks through that exact demo: the vulnerable code (frontend + backend), how the exploit works step-by-step, and the fixes you apply immediately. You will learn:

- The minimal vulnerable code that makes XSS and SQLi possible
- How attackers craft payloads and why those payloads succeed
- Safe, copy-paste fixes (server-side and client-side)



---
*Original URL: [https://medium.com/skillstuff/i-finally-understood-xss-and-sql-injection-after-seeing-this-demo-77bbd292d86b?source=search_post---------143-----------------------------------](https://medium.com/skillstuff/i-finally-understood-xss-and-sql-injection-after-seeing-this-demo-77bbd292d86b?source=search_post---------143-----------------------------------)*
