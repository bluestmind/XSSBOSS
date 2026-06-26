# Why strip_tags() Does Not Protect You From XSS in PHP/Laravel

> **Author**: Hafiq Iqmal
> **Published**: Apr 7, 2026

---

Member-only story

## A False Sense of Security That Your Code Probably Has Right Now

![Hafiq Iqmal](https://miro.medium.com/v2/resize:fill:64:64/1*HJ2yEKm0RYklE3IoZBwf6g.jpeg)

35

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:700/1*d86Q5KGsmHn0SOL1BpCoaA.png)

Developers in countless PHP applications believe that sanitizing user input with strip_tags() prevents XSS attacks. It doesn't. The function removes HTML and PHP tags from a string, but it leaves attributes intact. An attacker doesn't need script tags to execute JavaScript. They just need an event handler, a javascript: protocol in a URL, or an SVG element with embedded code. Most developers never discover this vulnerability until something goes wrong.

strip_tags() gives you a false sense of security while leaving the door wide open. This article explains why, shows you real payloads that strip_tags() misses, and walks you through the proper defenses.

## What strip_tags() Actually Does

The PHP function strip_tags() removes HTML and PHP tags from a string. If you pass it the whitelist parameter, it removes everything except the tags you explicitly allow. That seems reasonable on the surface.

Here’s the problem: it only removes tags. It does not process, validate, or escape HTML attributes.

```
$userInput = '<img src=x onerror="alert(\'XSS\')">';
echo strip_tags($userInput);
// Output: (empty…
```



---
*Original URL: [https://medium.com/bugbountywriteup/why-strip-tags-does-not-protect-you-from-xss-in-php-laravel-c97d0e805213?source=search_post---------19-----------------------------------](https://medium.com/bugbountywriteup/why-strip-tags-does-not-protect-you-from-xss-in-php-laravel-c97d0e805213?source=search_post---------19-----------------------------------)*
