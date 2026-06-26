# Securing the Edges: A Practical Way to Handle XSS in Modern Apps

> **Author**: Dogukan Batal
> **Published**: Mar 31, 2026

---

![Dogukan Batal](https://miro.medium.com/v2/resize:fill:32:32/1*YKEC2FeEdADG99vnwlop9A.jpeg)

5

Listen

Share

Modern frameworks like React or Vue protect us from many XSS attacks by default. They escape values automatically and make common mistakes harder to do.

But in real applications, security problems don’t disappear — they move to the edges.

These “edges” are places where we step outside the default safety:

- Rendering HTML
- Setting dynamic attributes
- Allowing custom styles
- Injecting data into scripts

In this post, we’ll look at these problems and how to solve them in a practical way using a context-aware approach.

![image](https://miro.medium.com/v2/resize:fit:700/1*R-3_f7SCHyWsw_JUAjVQUw.png)

## 1. Raw HTML injection (e.g. React’s dangerouslySetInnerHTML)

Sometimes we need to render HTML:

```
<div dangerouslySetInnerHTML={{ __html: content }} />
```

If this content is not sanitized, it can execute code:

```
<img src="x" onerror="alert(1)">
```

## Common Approaches

- Escaping everything → breaks valid HTML
- Regex filtering → unsafe and incomplete
- DOM-based sanitizers → safer but often heavy (especially in SSR)

## A More Practical Approach

A better solution is to sanitize HTML structurally:

- Remove dangerous tags (script, etc.)
- Strip unsafe attributes (onerror, onclick)
- Keep safe markup intact

With Jaga, this happens at the template level.
Instead of treating HTML as a string, it parses and filters it before rendering, so unsafe nodes never reach the output.

## 2. The Attribute Problem

Escaping does not protect attributes:

```
<a href={userInput}>Click</a>
```

If userInput is:

```
javascript:alert(1)
```

the browser will execute it.

## Why This Happens

Escaping focuses on characters.
But this problem is about meaning, not characters.

## Safer Strategy

A safer approach is:

- Detect the context (URL)
- Allow only safe protocols (https, mailto)
- Block everything else

Jaga handles this by recognizing that href is a URL context.
It inspects the value, normalizes it, and blocks dangerous protocols like javascript: or obfuscated variants before rendering.

## 3. CSS Injection

CSS is often ignored as a security risk.

```
<div style={userStyle}></div>
```

If uncontrolled, attackers can inject:

```
background: url("javascript:alert(1)");
```

or even obfuscated values:

```
color: \6a avascript:alert(1);
```

## Why CSS Is Hard

- It has its own syntax and parsing rules
- It allows functions like url()
- It supports escaping tricks

## Safer Strategy

A more reliable solution:

- Parse CSS properly
- Allow only safe properties (like color, margin)
- Block dangerous values and functions

Jaga uses a small lexical CSS sanitizer.
It tokenizes the style string and only allows a safe subset of properties and values, rejecting anything that doesn’t match expected patterns.

## 4. Server-Side Rendering (SSR)

Modern apps often run on the server (Next.js, etc.).

## Get Dogukan Batal’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

Many sanitization libraries depend on the browser DOM, which creates issues:

- Extra dependencies like jsdom
- Higher memory usage
- Slower execution

## Safer Strategy

In SSR environments, it helps to use tools that:

- Don’t require a DOM
- Work the same in browser and server
- Stay lightweight

Jaga follows this model.
It does not rely on DOM APIs and works the same way in Node, Bun, Deno, and the browser, which simplifies usage in full-stack apps.

Jaga follows this model. It does not rely on DOM APIs and works the same way in Node, Bun, Deno, and the browser. It is a zero-dependency library, which means it won’t bloat your project or create supply-chain risks. Additionally, it includes a Smart Minifier that reduces the size of your HTML without breaking spaces in tags like <pre> or <textarea>, giving you a small performance boost in SSR.

## 5. Script Context and JSON Injection

Injecting data into scripts can also be dangerous:

```
<script>
  window.__STATE__ = ${data}
</script>
```

If data contains:

```
"</script><script>alert(1)</script>"
```

it can break out of the script and execute code.

## Safer Strategy

To prevent this:

- Encode JSON safely
- Escape dangerous sequences like </script>

Jaga provides a helper for this (j.json()), which serializes data and safely escapes script-breaking sequences. This ensures the data stays inside the script context.Furthermore, it is compatible with Trusted Types. This means it can return objects that modern browsers trust, helping you follow strict Content Security Policy (CSP) rules without extra effort.

## 6. Putting It Together: Context-Aware Security

Across all these examples, one pattern appears:

Security depends on context.

Different places need different rules:

- HTML → sanitize structure
- Attributes → validate meaning (URLs)
- CSS → restrict properties and values
- Scripts → encode safely

Instead of handling each case manually, a context-aware system applies the right protection automatically.

In practice, using a tool like Jaga means:

- Less manual validation
- Fewer edge-case bugs
- More consistent security across the app

## Quick Summary

Raw HTML

- Risk: Script execution
- General Solution: HTML sanitization
- With Jaga: Structural sanitizer that removes unsafe tags and attributes

Attributes (href / src)

- Risk: javascript: injection
- General Solution: URL validation and protocol allowlisting
- With Jaga: Detects URL context and blocks unsafe protocols automatically

CSS

- Risk: Malicious styles and hidden injections
- General Solution: CSS parsing + property/value allowlist
- With Jaga: Lexical CSS sanitizer that filters unsafe tokens

Script / JSON

- Risk: Script breakout (</script>)
- General Solution: Safe JSON encoding
- With Jaga: j.json() escapes dangerous sequences safely

SSR (Server-Side Rendering)

- Risk: Heavy dependencies and DOM requirements
- General Solution: DOM-free sanitization tools
- With Jaga: Zero-dependency, works in Node, Bun, Deno, and browser

Performance & Compatibility

- Risk: Heavy dependencies and strict browser security policies (CSP).
- With Jaga: Zero-dependency architecture, Trusted Types support for modern browsers, and an integrated Smart Minifier for faster page loads.

## Conclusion

Frameworks give us a strong foundation, but they don’t cover everything.

The real risks live at the edges:

- Raw HTML
- Attributes
- CSS
- Script injection

Solving these problems requires more than escaping — it requires understanding context.

By applying context-aware rules — and using tools that enforce them consistently — we can make these edge cases much safer without adding too much complexity.

## A Note on Implementation

In my case, dealing with all these edge cases repeatedly led me to build a small library called Jaga.

It’s a zero-dependency, context-aware templating tool that applies the ideas in this post:

- HTML sanitization
- URL filtering
- CSS allowlisting
- Safe JSON encoding
- Trusted Types compliance for modern browser security
- Integrated smart minification for better performance

It’s not the only way to solve these problems, but it shows how a single, consistent layer can reduce many common XSS risks across different contexts.

If you’re dealing with similar edge cases, it might give you a practical starting point — or at least a reference for how to approach the problem.



---
*Original URL: [https://medium.com/@dgknbtl/securing-the-edges-a-practical-way-to-handle-xss-in-modern-apps-21bab25f9de1?source=search_post---------50-----------------------------------](https://medium.com/@dgknbtl/securing-the-edges-a-practical-way-to-handle-xss-in-modern-apps-21bab25f9de1?source=search_post---------50-----------------------------------)*
