# Stored XSS via uploaded SVG in group chat

> **Author**: HBlack Ghost
> **Published**: Nov 8, 2025

---

Top highlight

![HBlack Ghost](https://miro.medium.com/v2/resize:fill:32:32/1*RJY7UjbXCEHzBOBSVwUGxw.jpeg)

107

2

Listen

Share

بسم الله الرحمن الرحيم
اللَّهُمَّ صَلِّ عَلَى مُحَمَّدٍ وَعَلَى آلِ مُحَمَّدٍ

Hello Hunter, how are you?
I hope you’re doing well. After spending a long time focused on my pentesting work, I’m finally back to bug hunting. Guess what? I found a stored XSS in a group chat that redirects victims to a malicious site. Let me tell you the story behind this bug.

After having a cup of coffee yeah, coffee I became a rich man, haha. While I was searching for a new program, I found this site let’s hack site, bro. When I signed in, I discovered a fantastic feature a group chat where you join a group and chat with other people.

Okay, let’s hack this: after searching for privilege escalation or BAC bugs, I couldn’t find any. Then I saw a juicy feature file upload. Ooooh, let’s go for it!

I tried to upload an XSS payload to this feature using an SVG file.

![image](https://miro.medium.com/v2/resize:fit:700/1*5RPLaArAZwkAJYsrRpwtBg.png)

it’s working without any filter

![image](https://miro.medium.com/v2/resize:fit:364/1*zjxf5CzH6gLhsvdHftDZXQ.png)

Let’s try a payload that can extract cookies but this site opens the SVG from the browser cache so that we haven’t any cookies

## Get HBlack Ghost’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

Note : blob URLs let websites handle files or data locally in the browser without uploading them to a server.

![image](https://miro.medium.com/v2/resize:fit:700/1*hWL9UIyFWqyGiy3Xwddhhw.png)

Let’s brainstorm ways to bypass this obstacle and have an impact on victims or carry out malicious attacks.

After a few minutes, I had a payload that forces victims to a malicious site. I tried to upload the XSS payload to this feature using an SVG file that contained the payload.

![image](https://miro.medium.com/v2/resize:fit:700/1*ujQmyXxZ57_1SgHngwC_EA.png)

Guess what this payload is working well, and I was able to force the victim to a malicious site.

![image](https://miro.medium.com/v2/resize:fit:320/1*UXl_0Z236TWahVfUTXQ88Q.gif)

Here We Go Triaged bug :

![image](https://miro.medium.com/v2/resize:fit:700/1*D89QacHQ3s5wF4AbSPNLMA.png)

وابللللللع 🔥😎

LinkedIn Profile : https://www.linkedin.com/in/pt-ahmed-alaa/

YouTube Channel : https://www.youtube.com/@PT-ahmed-alaa

والسلام عليكم ورحمه الله وبركاته



---
*Original URL: [https://medium.com/@HBlackGhost/stored-xss-via-uploaded-svg-in-group-chat-b45f182b2e33?source=search_post---------131-----------------------------------](https://medium.com/@HBlackGhost/stored-xss-via-uploaded-svg-in-group-chat-b45f182b2e33?source=search_post---------131-----------------------------------)*
