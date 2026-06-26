# bug“Bug Bounty Bootcamp #16: Stored & Blind XSS — The ‘Time Bomb’ and ‘Message in a Bottle’ of Web Hacking”

> **Author**: Aman Sharma
> **Published**: Jan 15, 2026

---

Member-only story

## One poisons a page for every visitor. The other lies in wait for an admin. Learn how to plant these high-impact XSS payloads and prove they work, even when you can’t see the explosion.

![Aman Sharma](https://miro.medium.com/v2/da:true/resize:fill:64:64/0*gTsmBWudIxLcZoel)

81

Listen

Share

Free link

![image](https://miro.medium.com/v2/resize:fit:700/1*LLPqknx-kFjF8XIxgZBYDw.jpeg)

You’ve mastered finding and exploiting reflected XSS. Now, we level up to more dangerous variants: Stored (Persistent) XSS and Blind XSS. These aren’t one-time tricks; they’re payloads you implant into a system, where they wait to trigger against other users — sometimes against high-privileged victims like administrators. Finding these is a hallmark of an advanced hunter and often commands higher bounties.

## Stored XSS: The Poison in the Well

A Stored XSS vulnerability occurs when an attacker’s malicious input is saved by the application (in a database, file system, etc.) and then served to other users in their normal browsing.

Classic Example: A Blog Comment

- You post a comment containing an XSS payload: <script>alert('Hacked')</script>.
- The server saves this comment to its…



---
*Original URL: [https://medium.com/the-first-digit/bug-bounty-bootcamp-16-stored-blind-xss-the-time-bomb-and-message-in-a-bottle-of-web-fc4366929393?source=search_post---------79-----------------------------------](https://medium.com/the-first-digit/bug-bounty-bootcamp-16-stored-blind-xss-the-time-bomb-and-message-in-a-bottle-of-web-fc4366929393?source=search_post---------79-----------------------------------)*
