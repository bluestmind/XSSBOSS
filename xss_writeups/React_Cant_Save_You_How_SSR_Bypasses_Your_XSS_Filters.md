# React Can’t Save You: How SSR Bypasses Your XSS Filters

> **Author**: Vamsi Krishna Kodimela
> **Published**: Feb 17, 2026

---

Member-only story

![Vamsi Krishna Kodimela](https://miro.medium.com/v2/resize:fill:64:64/1*0W9ETspNkuZ8QfNhcBSpJg.png)

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:700/1*9TQTAP8S2sJ1htolBWZehw.png)

You build a Next.js application, rigorously sanitize inputs, and rely on React’s built-in XSS protections.

An attacker updates their profile bio to: Hello! </script><script>alert('pwned')</script> Visitors to that profile are immediately hit with a malicious script, or the page crashes entirely (a White Screen of Death).

The Catch: Your React components are perfectly secure. The attacker bypassed React by attacking the raw HTML before React even loaded.

## The Mechanism: The Vulnerable Hydration Bridge

- The SSR Requirement: In Server-Side Rendering (SSR), the server generates the initial HTML so the user sees the page instantly.
- The Hydration Process: For React to wake up and make the page interactive, it needs the server’s initial data.
- The Bridge: Frameworks pass this data by serializing the state and embedding it directly into the HTML document, usually inside a <script> tag.
- The Fatal Flaw: If your server naively uses standard JSON.stringify() to embed this data, the browser's HTML parser gets confused.
- The Execution: The browser reads top-to-bottom. When it hits the </script> string inside the bio, it assumes the data block is finished. It…



---
*Original URL: [https://medium.com/frontend-simplified/react-cant-save-you-how-ssr-bypasses-your-xss-filters-7e20637d88cc?source=search_post---------63-----------------------------------](https://medium.com/frontend-simplified/react-cant-save-you-how-ssr-bypasses-your-xss-filters-7e20637d88cc?source=search_post---------63-----------------------------------)*
