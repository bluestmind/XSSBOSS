# How I Discovered Account Takeover (ATO) via XSS and Open redirect

> **Author**: JEETPAL
> **Published**: May 20, 2026

---

![JEETPAL](https://miro.medium.com/v2/resize:fill:32:32/1*3UJihM4VvA-DeZOgGnYqLg.jpeg)

80

1

3

Listen

Share

Hello Everyone,

Today, I want to share my experience of discovering an account takeover (ATO) vulnerability through XSS and Open redirect. Let’s dive right in!

So, hunting starts with a random program selection let call it example.xyz.It is a crypto platform.

I started hunting with enumerating subdomain and checking if there is any possible subdomain takeover but there is nothing found.

## Get JEETPAL’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

I use my Wayback URLs to grab previous URL’s from the example.xyzand started hunting manually. I visited the signup page and started the registration process while registering on the site I notice a parameter called callbackUrl

```
https://example.xyz/sign-in?callbackUrl=
```

I decided to test this parameter with an open redirect payload.

```
https://example.xyz/sign-in?callbackUrl=https://example.xyz@evil.com
```

and this Open redirect works. After the signin. I was redirected to the evil.com. but this wasn’t sufficient for higher impact the max could go up to P3 /P4 so I decide to test for a xss. I use many payloads but the tags <>were filter out from the payload. So, I decided to use different payload i.e

```
javascript:alert(document.cookie)
```

and this one worked successfully I was able to pop-up an alert with session cookies. from here we can get those cookies into our server and use them.

![image](https://miro.medium.com/v2/resize:fit:700/1*OtJnir_CbvUjbjCXp0byrA.png)

After this I prepared a report to submit to the program. and after few days I got a reply from the program manager.

![image](https://miro.medium.com/v2/resize:fit:700/1*VzpHaBo5vOrMj_v959GVGw.png)

The report considers as duplicate of a 2024 report submitted by someone else on the platform.

Thank you for reading if you enjoy it clap 50 times

New articles Dropping soon

Connect with me
Linkedin: https://www.linkedin.com/in/jeet-pal-22601a290/
Instagram: https://www.instagram.com/jeetpal.2007/
X/Twitter: https://x.com/Mr_mars_hacker



---
*Original URL: [https://medium.com/bugbountywriteup/how-i-discovered-account-takeover-ato-via-xss-and-open-redirect-36f640760451?source=search_post---------1-----------------------------------](https://medium.com/bugbountywriteup/how-i-discovered-account-takeover-ato-via-xss-and-open-redirect-36f640760451?source=search_post---------1-----------------------------------)*
