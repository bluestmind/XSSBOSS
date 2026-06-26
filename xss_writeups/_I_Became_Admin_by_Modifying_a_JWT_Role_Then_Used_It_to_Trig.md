# 🎯 I Became Admin by Modifying a JWT Role — Then Used It to Trigger Stored XSS on Clinic Staff

> **Author**: k4yd0_
> **Published**: Jan 20, 2026

---

![k4yd0_](https://miro.medium.com/v2/resize:fill:32:32/1*YzeAqLaebG1Swo1_4FkxKQ.jpeg)

20

Listen

Share

Yo, it’s k4yd0_ ,
and this one was wild.

![image](https://miro.medium.com/v2/resize:fit:700/0*XsLMmvXgyUtkoLJ2.jpg)

While testing a clinic web application, I ended up finding two serious vulnerabilities that chained perfectly together:

- Weak JWT signing secret → full admin access
- Stored XSS in uploaded PDF → admin compromise

This wasn’t a UI bug.
This wasn’t visual-only.

This was full privilege escalation + medical data exposure.

## It Started With JWT

I was testing the authentication flow like usual.

![image](https://miro.medium.com/v2/resize:fit:700/1*uXkVy4NrwK7oK0oTIyHvog.png)

After login, I checked the session token and noticed the app was using a JWT.

Decoded it on jwt.io and saw something like:

```
{
  "id": 9482,
  "email": "user@test.com",
  "role": 4
}
```

Role 4 = normal user.

Out of curiosity, I changed it to:

```
"role": 1
```

(role 1 = admin)

Re-signed the token…

❌ invalid signature.

So I tried brute-forcing the signing secret.

![image](https://miro.medium.com/v2/resize:fit:700/1*3bxoqKhpEnRVRFS6LWUZvQ.png)

And that’s when I found it.

## 💀 The JWT Secret Was Literally:

```
devsec1990
```

No rotation.
No randomness.
No environment-based secret.

Just:

```
HMAC secret = "devsec1990"
```

At that moment I already knew where this was going.

## Boom Moment

I forged my own JWT:

```
{
  "email": "user@test.com",
  "role": 1
}
```

Signed it using:

```
HS256
secret: devsec1990
```

![image](https://miro.medium.com/v2/resize:fit:700/1*v0XM3luDSnPyKMSJoPAZ6A.png)

Then replaced my Authorization header:

```
Authorization: Bearer <eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InVzZXJAdGVzdC5jb20iLCJyb2xlIjoxfQ.1flFl8OpAws88BHzp_iy3ThD4z2t1qS52-A-SQQOQ6s>
```

Reloaded the app.

And suddenly…

Admin dashboard loaded.

No error.
No redirect.
No verification.

Just full admin access.

## What Admin Access Gave Me

With role = 1, I could:

- View all users
- Read private medical documents
- Download uploaded files
- Edit user information
- Change emails
- Reset passwords
- Delete reservations
- Fully take over accounts

This is a clinic system.

Meaning:

- medical documents
- health history
- personal data
- PII
- patient files

Everything was exposed.

## Then I Asked Myself…

If I can read any uploaded document as admin…

What happens if a document is malicious?

So I tested it.

When I saw myself logged in as an admin, I started thinking about what normal users cannot access.

As a regular user, I could upload documents — but I couldn’t view how they were rendered for staff or admins.
So if I uploaded a malicious PDF with XSS, there was no way for me to know whether it actually executed or not.

That’s where the admin access gave me a huge advantage.

## Testing the Upload Feature

During registration, users are asked to upload documents (medical files, IDs, PDFs, etc.).

So I created a normal user account — no admin role, nothing special.

During upload, I submitted a PDF containing JavaScript.

Yes , a PDF XSS payload.

Example:

![image](https://miro.medium.com/v2/resize:fit:700/1*n9lzjUK9bsququlragPuzA.png)

Upload succeeded.

## Get k4yd0_’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

No validation.
No sanitization.
No file inspection.

## Second Boom Moment

I logged back into my admin account (role = 1).

Opened the uploaded document.

And instantly…

XSS executed in admin context.

![image](https://miro.medium.com/v2/resize:fit:700/1*zEoop2KbadXRmTQrmTV17A.png)

JavaScript ran inside:

- admin session
- authenticated domain
- full privileges

Meaning:

- session hijacking
- admin token theft
- backend API abuse
- full system compromise

## What This Means in Real Life

Any attacker could:

Register as a normal user
Upload a malicious PDF
Wait for staff / admin / doctor to open it

And once they do…

💀 the entire clinic system is compromised.

No phishing emails needed.
No user interaction tricks.

Just upload → wait → pwn.

## Combined Impact

This chain allowed:

- Weak JWT secret → admin privilege escalation
- Admin access → view all medical files
- Stored XSS → execute JS on staff/admin
- Account takeover of internal users
- Exposure of sensitive healthcare data
- Full compromise of the platform

This is why the issue was rated Critical (9.1).

## Root Causes

## JWT Issues

- Static secret (devsec1990)
- No rotation
- No environment separation
- Trusting client-controlled claims (role)

## File Upload Issues

- No PDF sanitization
- No content inspection
- No JS stripping
- Admin viewing untrusted user uploads

## How This Should Be Fixed

- Use strong, random JWT secrets
- Rotate secrets regularly
- Never trust role claims from JWT alone
- Enforce server-side authorization
- Sanitize PDFs or convert to safe formats
- Never render user documents in privileged contexts

## Final Thoughts

This bug wasn’t about payloads.

It wasn’t about scanners.

It was about logic.

One weak secret:

```
devsec1990
```

Was enough to:

- become admin
- read medical records
- upload malicious files
- compromise staff accounts
- destroy trust in a healthcare system

Always test:

- JWT secrets
- role claims
- file uploads
- admin document viewers

Because when these bugs chain together…

the impact multiplies fast.

Update: The vulnerability was confirmed by the security team and officially resolved with a Critical (9.1) severity. Always feels good seeing logic bugs taken seriously.

![image](https://miro.medium.com/v2/1*n6_rfcXT6ehuvuKic1XA1w.png)

Note: This screenshot refers only to the weak JWT signing secret vulnerability.
The stored XSS was a separate issue and was reported independently.
I chained both vulnerabilities together only to better demonstrate real-world impact and help uncover additional security issues

![image](https://miro.medium.com/v2/resize:fit:249/1*3ISvL_emckXRYOL-9O_Wsw.png)

Until next time,
— k4yd0_



---
*Original URL: [https://medium.com/@k4yd0_/i-became-admin-by-modifying-a-jwt-role-then-used-it-to-trigger-stored-xss-on-clinic-staff-5febefff191c?source=search_post---------81-----------------------------------](https://medium.com/@k4yd0_/i-became-admin-by-modifying-a-jwt-role-then-used-it-to-trigger-stored-xss-on-clinic-staff-5febefff191c?source=search_post---------81-----------------------------------)*
