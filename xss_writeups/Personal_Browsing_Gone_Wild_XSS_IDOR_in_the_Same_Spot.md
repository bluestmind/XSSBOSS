# Personal Browsing Gone Wild: XSS + IDOR in the Same Spot

> **Author**: Josekutty Kunnelthazhe Binu
> **Published**: Dec 26, 2025

---

![Josekutty Kunnelthazhe Binu](https://miro.medium.com/v2/resize:fill:32:32/1*_S2MEdAtTYjXtlUeI5PWzA.jpeg)

165

1

Listen

Share

It’s been a while since I wrote my last article! I hope all my fellow hunters and infosec friends are doing great.

![image](https://miro.medium.com/v2/resize:fit:400/1*GomB-D_pMXsOQpM1fE6VJQ.gif)

It’s 26th december 2025 today. Even though I planned to hunt on some targets I was not in the right mood.

![image](https://miro.medium.com/v2/resize:fit:500/1*SyjSppLbs4rwvr5A8rrpRQ.gif)

So I thought to write something to keep myself engaged. Also if its helping someone I will be happy.

Recently, while browsing some websites for personal reasons, my testing instincts kicked in (as always). Even when I’m not actively hunting, I can’t help but notice certain things URL patterns, redirects, and request structures.

![image](https://miro.medium.com/v2/resize:fit:480/1*V8ulZS8-RCnj5rRnLrX4qQ.gif)

Whether I’m booking train tickets or checking movie schedules, I have this habit of observing every detail in the browser, even without Burp Suite running!

As usual, I tried a few payloads on reflected pages, but nothing interesting popped up. Then I moved on to exploring the career section of one site. I noticed an option to upload a CV (PDF or DOC) as part of the user profile. That immediately grabbed my attention.

![image](https://miro.medium.com/v2/resize:fit:442/1*KE7IWcdhMQD-INtZNDO8XQ.png)

I decided to upload a PDF containing a basic XSS payload (more about this payload later in the article). Once uploaded, the platform provided a feature to view the uploaded resume directly from the web interface — and that’s where things got interesting.

![image](https://miro.medium.com/v2/resize:fit:700/1*rjrrgC5EeOHbDYA_M60AFQ.png)

Another tip, when testing if you don’t have an option to open the file you uploaded, try to right click on the file and try to open in a new tab, or somehow you need to find the path where the file is uploaded.

Upon clicking “View Uploaded Resume”, my payload successfully triggered, and the XSS pop-up appeared. At this point, I knew there was stored XSS happening through the uploaded file.

![image](https://miro.medium.com/v2/resize:fit:700/1*s5acEAocokhspHm2oyqMAQ.png)

## Digging Deeper: The Curious URL

I don’t know how many of you noticed the url in the previous url image, the url was something like this:

https://www.xyz.com/xyz/media/user_details/431879/resume.pdf

My first thought that numeric part (431879) looks like a user ID or some identifier related to stored files.

## Get Josekutty Kunnelthazhe Binu’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

Out of curiosity (and as a common security instinct), I tried changing the ID to 431878. That returned a 404 Not Found.

![image](https://miro.medium.com/v2/resize:fit:700/1*XXBQOoTDaITWm8Lf6ekflw.png)

![image](https://miro.medium.com/v2/resize:fit:320/1*yMbpZkUbUcbFaMvOhYhZeA.gif)

To analyze it systematically, I captured the request in Burp Suite and used Intruder to fuzz the numeric value, iterating IDs between 430000 and 440000.

![image](https://miro.medium.com/v2/resize:fit:700/1*VvCDJ8u9e0FwSWwAen3ubA.png)

As expected, I saw multiple 404 responses, but then some 200 OKs appeared in the results.

![image](https://miro.medium.com/v2/resize:fit:700/1*2ig21nOUVBUSWJ-CMa46iQ.png)

On reviewing those successful responses in the browser, I was shocked to find that other users’ resumes were accessible simply by manipulating the ID.

![image](https://miro.medium.com/v2/resize:fit:1351/1*fBRzHrdkks6nhObJIKNDdw.png)

![image](https://miro.medium.com/v2/resize:fit:1365/1*I1w7mjqqqyuUPHwhV2oCdg.png)

![image](https://miro.medium.com/v2/resize:fit:1365/1*A26-r3LvqlSE7OobDiw-vw.png)

At this point, it was clear there was an Insecure Direct Object Reference (IDOR) vulnerability.

![image](https://miro.medium.com/v2/resize:fit:500/1*aAUqgpcS_JlWJBWULYACqg.gif)

It allowed anyone to access other users’ private files by modifying the numeric identifier in the URL.

## Impact

This kind of issue is serious. A combination of Stored XSS and IDOR means:

- Attackers could potentially upload malicious files.
- Sensitive personal documents (like resumes) could be exposed to unauthorized users.

If you guys wants to download the xss injected pdf file, go to https://gist.github.com/GugSaas/3e12c57cf22f745d009e31266f441e07 and download it…

So that's it, I hope you guys got something helpful. I find this so easy to exploit. Hopefully, it helps someone notice similar patterns during their own hunts.

![image](https://miro.medium.com/v2/resize:fit:500/1*a-IWWioMtV2ZOslqd1IpVA.gif)

I’m definitely not a big writer or anything, just another random dude poking around the internet for bugs. So until we see again, happy hunting and take care!



---
*Original URL: [https://medium.com/@josekuttykunnelthazhebinu/personal-browsing-gone-wild-xss-idor-in-the-same-spot-6ab3e0ea6190?source=search_post---------97-----------------------------------](https://medium.com/@josekuttykunnelthazhebinu/personal-browsing-gone-wild-xss-idor-in-the-same-spot-6ab3e0ea6190?source=search_post---------97-----------------------------------)*
