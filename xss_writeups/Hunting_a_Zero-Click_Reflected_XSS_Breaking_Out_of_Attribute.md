# Hunting a Zero-Click Reflected XSS: Breaking Out of Attributes in WordPress Search

> **Author**: Maverick
> **Published**: Jan 1, 2026

---

![Maverick](https://miro.medium.com/v2/resize:fill:32:32/1*QYqepfC4M8bax1iIoAGNqw.jpeg)

128

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:603/1*nJ86UpOowpQCfjT022sxGQ.png)

As a security researcher, one of the most satisfying finds is a zero-click vulnerability something that executes malicious code the moment a victim loads the page, with no interaction required. Recently, I discovered exactly that: a reflected Cross-Site Scripting (XSS) vulnerability in the search functionality of a public-facing WordPress site.

This wasn’t a stored XSS that persists forever, but a reflected one delivered via a crafted URL. What made it dangerous? The proof-of-concept (PoC) triggered JavaScript execution instantly on page load, turning a simple shared link into a potential phishing or session hijacking vector.

In this write-up, I’ll break down the vulnerability, the payload, why it worked, the impact, and most importantly how developers can prevent it. (The issue was reported responsibly, deemed out-of-scope for the program’s bounty due to it being on the marketing site, but appears to have been fixed shortly after.)

## The Vulnerability: Attribute Breakout in the Search Input

WordPress sites commonly use the ?s= parameter for search queries (e.g., / ?s=keyword). Themes often repopulate the search box on the results page like this:

```
<input type="search" name="s" value="<?php echo $_GET['s']; ?>">
```

If the input isn’t properly escaped for HTML attributes (using something like esc_attr() in PHP), an attacker can break out of the value attribute and inject new ones.

Many sinks escape text content (like the <h1>Results for “…` heading), but forget the input field itself a classic oversight.

## The Payload: Zero-Click Execution with autofocus + onfocus

```
?s=" autofocus onfocus=alert(1) x="
```

![image](https://miro.medium.com/v2/resize:fit:700/1*27Hq8Qs8jm9tM40gLHX8tw.png)

Here’s how it breaks down:

- The “ closes the value attribute prematurely.
- autofocus — a valid HTML attribute that forces the browser to focus the input on page load.
- onfocus=alert(1) — an event handler that fires when the input gains focus.
- x=” — a dummy attribute to balance the syntax and prevent rendering errors.

Resulting injected HTML:

```
<input type="search" value="" autofocus onfocus="alert(1)" x="">
```

Boom: Page loads → input auto-focuses → onfocus triggers → alert(1) pops instantly.

## Get Maverick’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

No clicks, no hovers pure zero-click.

## Impact: Why This Matters

- Arbitrary JS execution in the site’s origin.
- Easy social engineering: “Hey, check this search result on [site]” → victim clicks link → code runs.
- Potential for:
- Stealing non-HttpOnly cookies/sessions.
- Phishing overlays.
- Keylogging.
- Defacement (visual changes).
- Even on a marketing site, it erodes trust and could target partners/customers.

Reflected XSS is often underrated, but zero-click variants elevate it to high severity.

## Timeline & Responsible Disclosure

- Discovered and PoC’d with screenshot evidence.
- Reported via the company’s bug bounty platform.
- Triaged as High severity but out-of-scope (program focuses on core product, excludes WordPress marketing site and standard WP issues).
- No bounty, but that’s fine safety first.

## Final Thoughts

Finding executable XSS never gets old especially zero-click ones that feel like magic. Shoutout to the team for the quick (implicit) fix and running a program.

If you’re hunting WordPress sites, check those search fields! Happy hunting ! 🚀



---
*Original URL: [https://medium.com/bugbountywriteup/hunting-a-zero-click-reflected-xss-breaking-out-of-attributes-in-wordpress-search-70071a099dd3?source=search_post---------70-----------------------------------](https://medium.com/bugbountywriteup/hunting-a-zero-click-reflected-xss-breaking-out-of-attributes-in-wordpress-search-70071a099dd3?source=search_post---------70-----------------------------------)*
