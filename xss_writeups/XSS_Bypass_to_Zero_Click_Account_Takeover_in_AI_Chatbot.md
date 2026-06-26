# XSS Bypass to Zero Click Account Takeover in AI Chatbot

> **Author**: Rahul Singh Chauhan
> **Published**: Mar 11, 2026

---

Member-only story

![Rahul Singh Chauhan](https://miro.medium.com/v2/resize:fill:64:64/1*6Zw9HGzZfk5gtMih8eoTxA.jpeg)

38

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:700/0*yh0itrE1sXMf7LxC)

Hi everyone, in this article, I’ll walk through a recent penetration test I conducted against a custom-built AI chatbot. As usual, we’ll cover:

- The application overview
- The high-level architecture
- The vulnerability
- The exploit

This assessment was conducted as a black-box test, meaning no source code access, no architectural documentation, and no internal visibility — only what an external attacker would see.

## Application Overview

Let’s call the company A.Corp.

Instead of integrating a third-party chatbot, A.Corp built their own AI assistant from scratch:

- The model was trained in-house.
- The user interface was custom-built.
- The guardrails and safety controls were implemented internally.

## Overview

Riding on the AI wave, this company, had come up with an AI chatbot. Unlike the ones in the market, the had created one for themselves, which means —

- It was an in-house trained model.
- They had created the UI themselves
- The guardrails were also created by their team



---
*Original URL: [https://medium.com/bugbountywriteup/xss-bypass-to-zero-click-account-takeover-in-ai-chatbot-a19acee8266f?source=search_post---------39-----------------------------------](https://medium.com/bugbountywriteup/xss-bypass-to-zero-click-account-takeover-in-ai-chatbot-a19acee8266f?source=search_post---------39-----------------------------------)*
