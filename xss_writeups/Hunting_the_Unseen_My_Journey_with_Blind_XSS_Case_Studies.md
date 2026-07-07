# Hunting the Unseen: My Journey with Blind XSS (Case Studies)

> **Author**: elcezeri
> **Published**: Dec 24, 2025

---

![elcezeri](https://miro.medium.com/v2/resize:fill:32:32/1*2eJqXfp4TQ1hPcVQpcEZfw.jpeg)

13

1

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:700/1*gj4Bzafw2MeD61qtrJVu5w.png)

Most bug bounty hunters start their journey with reflected XSS — you enter a payload, press enter, and wait for that sweet alert box. But what if the execution happens hours, days, or even weeks later, in a place you can’t even see? Welcome to the world of Blind XSS.

## What is Blind XSS?

Blind XSS is a specialized form of Stored XSS. It occurs when your malicious payload is saved by the server and executed in a different part of the application usually an administrative panel or a log viewer. You don’t see the result immediately because the “victim” is typically an admin or a support agent reviewing your data.

Friend Link

## Get elcezeri’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

Common Hunting Grounds:

- Contact Us Forms: Feedback fields or message boxes.
- Support Tickets: Chat logs or ticket descriptions.
- Registration Fields: “Project Description” or “About Me” sections.
- Email Addresses: Sometimes even the email field itself can be a vector.

Since you can’t see the execution, you need a “callback” server. These tools notify you when your script is triggered:

- XSSReport (My personal favorite)
- XSS Hunter
- BXSS Hunter

## Case Study 1: The Patience Game ($$$)

On redacted-target.com, after trying IDORs and SQLis with no luck, I found a feedback form. I grabbed a payload from my BXSS dashboard

![image](https://miro.medium.com/v2/resize:fit:613/1*ApoLUPJlZkOt0ZHIjaL1-w.png)

I filled the name, address, and message fields with different variations. One hour later, my phone buzzed. An admin had opened their dashboard to review my feedback, sending me their Full Cookies, IP Address, and User-Agent. Lesson: Never underestimate a simple “Contact Us” page.

## Case Study 2: The Encode Bypass Trick ($$$)

On another program, the contact form was rejecting my payloads. It felt like a basic WAF or filter. Instead of giving up, I URL encoded my payload.

- Trick: If <script> is blocked, try hex encoding or double encoding. A week later, I received the notification. The server decoded the input before rendering it in the internal judging tool. Bypass successful.

![image](https://miro.medium.com/v2/resize:fit:254/1*ZK2ZD2X6pi6y_WxjBVfa7g.png)

## Case Study 3: The Registration Field

Recently, I tested a registration form at https://redacted.com/register. I submitted a payload in the Project Description field. Two days later, the payload triggered. The referer URL was: https://target.com/projects/targetdescriPtionhad essentially "phished" the judging panel’s session!

![image](https://miro.medium.com/v2/resize:fit:225/1*DzARXzcD8Fb5AcyMvFIwhg.png)

## Tips for Hunters

- Don’t Expect Instant Gratification: Blind XSS is about playing the long game.
- Payload Everything: Every input field that an admin might see is a potential goldmine.
- The Email Trick: If a site lists a contact email, try sending a mail with a payload in the “From Name” or “Subject” line. You never know which internal mail-renderer will execute it.

- X: xelcezeri
- LinkedIn: Samet Yiğit

Thank you for reading, and stay safe in the digital world :)



---
*Original URL: [https://medium.com/@xelcezeri/hunting-the-unseen-my-journey-with-blind-xss-case-studies-abf1c8c8fac9?source=search_post---------101-----------------------------------](https://medium.com/@xelcezeri/hunting-the-unseen-my-journey-with-blind-xss-case-studies-abf1c8c8fac9?source=search_post---------101-----------------------------------)*
