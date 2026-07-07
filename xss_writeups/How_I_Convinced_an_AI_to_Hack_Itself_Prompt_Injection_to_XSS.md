# How I Convinced an AI to Hack Itself: Prompt Injection to XSS 🕷️

> **Author**: Mahendra Purbia (Mah3Sec)
> **Published**: Jan 21, 2026

---

Member-only story

![Mahendra Purbia (Mah3Sec)](https://miro.medium.com/v2/resize:fill:32:32/1*IdwfJb3VERWXm77PHKIHNQ.jpeg)

15

1

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:700/1*kBtimrLO7-F01pFsvuHXWA.png)

## Free Link🔗

## TL;DR

Found XSS in an AI chat feature by manipulating the AI to generate malicious JavaScript. The AI became my unwilling accomplice in hacking the application. Spider-Sense: activated 🕸️

## The Discovery

Testing an enterprise web app (let’s call it Target-X), I found their AI chat assistant. This wasn’t some developer-focused coding AI — this was a productivity assistant for meetings, scheduling, and general workplace tasks (think Copilot for Outlook vibes).

Important Context: This AI was specifically designed to NOT generate code, scripts, or technical payloads. It’s supposed to help you write meeting notes, not write XSS payloads.

Like any researcher with trust issues, I immediately tried injecting in my messages.

```
Me: <script>alert('XSS')</script>
```

Result: Properly escaped. User input was sanitized. ✅

But then I thought… what if I manipulate the AI to generate the payload for me, even though it’s not supposed to?

## The Attack: 2 Days of AI Gaslighting

## Day 1: Normal Conversation (Building Trust)



---
*Original URL: [https://medium.com/bugbountywriteup/how-i-convinced-an-ai-to-hack-itself-prompt-injection-to-xss-%EF%B8%8F-dab60010e40d?source=search_post---------69-----------------------------------](https://medium.com/bugbountywriteup/how-i-convinced-an-ai-to-hack-itself-prompt-injection-to-xss-%EF%B8%8F-dab60010e40d?source=search_post---------69-----------------------------------)*
