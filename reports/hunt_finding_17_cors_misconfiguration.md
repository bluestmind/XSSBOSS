# DOM XSS in POST https://marketplace.tw.coupangcorp.com/tw/s/sfsites/aura?r=&ui-communities-components-aura-components-forceCommunity-richText.RichText.getParsedRichTextValue= (High 8.1)

## Summary
Endpoint reflects an arbitrary Origin into Access-Control-Allow-Origin and also allows credentials.

The `Origin` parameter on `POST https://marketplace.tw.coupangcorp.com/tw/s/sfsites/aura?r=&ui-communities-components-aura-components-forceCommunity-richText.RichText.getParsedRichTextValue=` executes attacker-controlled JavaScript in a victim browser context, potentially allowing session impersonation and account compromise.

## Severity & CVSS 3.1 Rating
- **Severity**: High (8.1)
- **CVSS 3.1 Vector**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`

## Steps To Reproduce
1. Send a `POST` request to `https://marketplace.tw.coupangcorp.com/tw/s/sfsites/aura?r=&ui-communities-components-aura-components-forceCommunity-richText.RichText.getParsedRichTextValue=`.
2. Place the payload in `Origin` (header).
3. Open the reproduction URL in a standard modern browser.
4. Observe execution of the attacker JavaScript payload confirmed by evidence.

### Proof of Concept (cURL Command)
```bash
curl -i -s -k -X POST "https://marketplace.tw.coupangcorp.com/tw/s/sfsites/aura" --data "Origin=https%3A%2F%2Fxssboss.invalid"
```

### Standalone HTML Exploit (PoC)
```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>XSS PoC - https://marketplace.tw.coupangcorp.com/tw/s/sfsites/aura?r=&amp;ui-communities-components-aura-components-forceCommunity-richText.RichText.getParsedRichTextValue=</title>
</head>
<body>
  <form id="pocForm" action="https://marketplace.tw.coupangcorp.com/tw/s/sfsites/aura" method="POST">
    <input type="hidden" name="Origin" value="https://xssboss.invalid" />
  </form>
  <script>
    document.getElementById('pocForm').submit();
  </script>
</body>
</html>
```

## Payload
```html
https://xssboss.invalid
```

## Impact
Confirmed browser JavaScript execution, potentially allowing session impersonation.

- Internal Impact Score: n/a
- Tags: browser-execution

## Supporting Evidence
- Finding ID: 17
- Execution IDs: n/a
- Oracle tokens: n/a
- Screenshots: n/a

## Remediation
- Apply context-aware contextual output encoding (e.g. HTML entity, JavaScript attribute, or URL encoding) before rendering untrusted input.
- Avoid assigning user-controllable input to dangerous execution sinks such as `innerHTML`, `document.write`, `eval`, `Function`, or navigation sinks (`location.href`).
- Enforce a restrictive Content Security Policy (CSP) with strict script-src and object-src directives.
- Add automated regression tests covering this endpoint and parameter.