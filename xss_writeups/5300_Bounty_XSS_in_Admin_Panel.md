# $5,300 Bounty: XSS in Admin Panel

> **Author**: Monika sharma
> **Published**: Nov 25, 2025

---

## How a simple HTML editor turned into an attacker’s playground

![Monika sharma](https://miro.medium.com/v2/da:true/resize:fill:32:32/0*Tv4b4p5mb6J3IJwD)

72

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:700/1*j7_iuBYNaolM9-ZpqBFLyw.png)

### Introduction

I recently read this Shopify XSS bug report, and in this article I’ll explain it to you in a very simple way so even beginners can understand it easily.

Cross-Site Scripting (XSS) bugs still show up on many websites even the ones that are very secure. Shopify a huge e-commerce platform used by millions of people also had one such issue.

We’ll talk about a stored XSS vulnerability found in Shopify’s admin panel by researcher Ashketchum (ID: 1147433). The bug happened because Shopify’s Rich Text Editor allowed attackers to insert JavaScript code inside product and collection descriptions.

### What We’ll Cover

In this write-up, we’ll explore:

- What a Stored XSS vulnerability is
- How Hunter discovered the issue in Shopify’s admin interface
- Step-by-step reproduction of the bug
- The potential impact of this vulnerability
- How you can find similar bugs in other targets
- A quick automation approach to detect such flaws

### Understanding Stored XSS

Stored XSS (also known as persistent XSS) occurs when a malicious script is permanently stored on the target server for example, in a database, comment field, or product description.
When another user (or admin) loads the page the injected script executes in their browser, allowing attackers to steal cookies, session tokens, or perform actions on behalf of the victim.

Unlike Reflected XSS, which requires tricking a user into clicking a crafted link, Stored XSS can automatically execute whenever the page is loaded making it far more dangerous.

### Discovery and Context

Shopify updated their bug bounty policy to include Rich Text Editor (RTE)-based XSS vulnerabilities. Researcher immediately began testing the new scope and noticed potential injection points inside Shopify’s admin/product and admin/collections pages.

He found that by switching to the HTML view in the product description editor, he could directly insert malicious JavaScript payloads and Shopify’s sanitization filters didn’t catch them.

### Steps to Reproduce

Target: /admin/product

Step 1. Navigate to

```
https://your-store.myshopify.com/admin/products?selectedView=all
```

Step 2. Click on Add Product

Step 3. Enter any value in the “Title” field

Step 4. On the right-hand side of the description box, click “Show HTML”

Step 5. Insert the following payloads:

```
"><img src=x onerror=alert(document.domain)>
"><img src=x onerror=alert(document.cookie)>
```

Step 6. Click on Save

The XSS payload will execute on subsequent page loads

![image](https://miro.medium.com/v2/resize:fit:700/1*t4pOam_5tBsW62pNuTR1wg.png)

Target: /admin/collections

Step 1. Navigate to

```
https://your-store.myshopify.com/admin/collections
```

Step 2. Click Create Collection

## Get Monika sharma’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

Step 3. Add a title of your choice

Step 4. Again, click “Show HTML” in the description editor

Step 5. Paste the same payloads:

```
"><img src=x onerror=alert(document.domain)>
"><img src=x onerror=alert(document.cookie)>
```

Step 6. Save and reload the collection

The stored XSS triggers instantly when the admin reopens the collection.

![image](https://miro.medium.com/v2/resize:fit:700/1*rBhag1SoSloDFYeIFZ7mKw.png)

### Impact

A successful stored XSS in Shopify’s admin panel is severe.

An attacker could:

- Steal admin session cookies, hijacking accounts
- Execute arbitrary actions as the logged-in admin
- Add or remove products, alter store settings, or steal sensitive merchant data
- Chain XSS with CSRF or privilege escalation for full account takeover

Essentially, it provided a gateway for complete control over a Shopify store.

### How to Find Similar Vulnerabilities

If you’re into bug hunting, especially in SaaS platforms that use WYSIWYG or Rich Text Editors, here’s how you can look for similar bugs:

Manual Testing

- Look for HTML editor toggle buttons in admin panels or form inputs.
- Switch to HTML view and inject common payloads like:

```
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<script>alert(document.domain)</script>
```

3. Save and reload the page to check if the payload persists.

### Automated Detection Command Example

You can use tools like DalFox, XSStrike, or Nuclei to automate XSS checks.

Example (using DalFox with a URL list):

```
cat urls.txt | dalfox pipe --deep-domxss --output result.txt
```

Or using Nuclei for stored XSS templates:

```
nuclei -l urls.txt -t cves/xss -o stored_xss_results.txt
```

These tools scan parameters and payload reflection behavior automatically.

### Conclusion

This vulnerability is a great example of how even mature platforms like Shopify can have blind spots in sanitization logic especially when new features like Rich Text Editors are introduced.
It highlights why bug bounty programs evolve their scope over time and why creative hunters like ashketchum keep finding gold in unexpected places.

If you’re hunting for similar issues, focus on HTML editors, content fields, or Markdown converters that allow user input these are often rich grounds for persistent XSS.

☕ Thank You! If you enjoyed this breakdown and learned something new, consider supporting my work — buy me a coffee: https://buymeacoffee.com/monikaak47



---
*Original URL: [https://medium.com/meetcyber/5-300-bounty-xss-in-admin-panel-06e403984a68?source=search_post---------144-----------------------------------](https://medium.com/meetcyber/5-300-bounty-xss-in-admin-panel-06e403984a68?source=search_post---------144-----------------------------------)*
