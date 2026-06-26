# Clobbering DOM Attributes to Bypass HTML Filters and Trigger DOM-Based XSS

> **Author**: Bash Overflow
> **Published**: Feb 1, 2026

---

Member-only story

## How DOM property collisions quietly break client-side HTML sanitization.

![Bash Overflow](https://miro.medium.com/v2/resize:fill:64:64/1*JoM8_WC11wsYSOwkJ1oqxQ.png)

13

1

Listen

Share

🔓 Free Link

![Clobbering DOM Attributes to Bypass HTML Filters and Trigger DOM-Based XSS](https://miro.medium.com/v2/resize:fit:700/1*JkwGsa83BLtDtpAh4DSJAA.jpeg)

## Table of Contents

- Summary of the Vulnerability
- Proof of Concept (PoC)
- Impact

## Summary of the Vulnerability

This lab demonstrates a subtle but powerful form of DOM-based XSS that arises from unsafe assumptions about DOM properties rather than from classic script injection. The application allows users to post comments containing a restricted subset of “safe” HTML. On the surface, this appears well-defended: dangerous attributes are filtered, and event handlers such as onclick or onfocus are supposed to be removed.

The core issue lies in how the client-side sanitization logic inspects HTML attributes. The filtering library relies on the DOM attributes property to enumerate and validate which attributes are present on an element. However, the DOM itself is mutable. By injecting an element with an id or name that collides with the attributes property, an attacker can clobber that property entirely.



---
*Original URL: [https://medium.com/meetcyber/clobbering-dom-attributes-to-bypass-html-filters-and-trigger-dom-based-xss-cc2afb437bde?source=search_post---------59-----------------------------------](https://medium.com/meetcyber/clobbering-dom-attributes-to-bypass-html-filters-and-trigger-dom-based-xss-cc2afb437bde?source=search_post---------59-----------------------------------)*
