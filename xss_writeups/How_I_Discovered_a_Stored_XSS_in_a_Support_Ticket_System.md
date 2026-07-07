# How I Discovered a Stored XSS in a Support Ticket System

> **Author**: Bharath Kalyan
> **Published**: Apr 4, 2026

---

![Bharath Kalyan](https://miro.medium.com/v2/resize:fill:32:32/1*ijTL1e3P6jyMPIpmOgBF-g.jpeg)

75

1

Listen

Share

While testing a web application’s support feature, I came across a Stored Cross-Site Scripting (XSS) vulnerability in an unexpected place — the comment section of support tickets.

At first, everything looked normal. But a simple comment field turned into a powerful attack vector.

![image](https://miro.medium.com/v2/resize:fit:660/1*__emwrawxpcJt2b3ly_Qcg.jpeg)

## Understanding Stored XSS (Technical View)

Stored XSS occurs when:

- User-controlled input is persisted in backend storage (database)
- The application later retrieves and embeds this data into HTML
- The browser interprets it as executable code instead of data

This usually happens due to:

- Lack of output encoding
- Improper or no input sanitization

## Application Workflow Analysis

The vulnerable flow:

- User submits a support ticket
- Backend stores ticket details + comments in database
- When the ticket is opened:

- Server fetches stored comments
- Injects them directly into HTML response
- Browser renders content

## Steps to Reproduce

- Authenticate into the application
- Navigate to Support → Raise Ticket → Report Bug
- Submit a valid ticket
- Open the ticket from Raised Requests
- Inject payload in comment:

```
<img src=x onerror=alert(document.cookie)>
```

6. Submit and reload/view the ticket

![image](https://miro.medium.com/v2/resize:fit:700/1*ZDz53MSErTu0SjzKwdlDCg.png)

## Conclusion

This finding shows that even small features like comment sections can lead to serious vulnerabilities.

## Get Bharath Kalyan’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

Never ignore:

- Comment fields
- Feedback forms
- Internal features

Because sometimes…
the smallest input box leads to the biggest bug.

“Keep testing. Keep breaking. That’s how you learn.”

connect with me LinkedIn , Twitter

Happy hacking :)…..



---
*Original URL: [https://medium.com/@bharathkalyan11/how-i-discovered-a-stored-xss-in-a-support-ticket-system-01ec5ff75515?source=search_post---------16-----------------------------------](https://medium.com/@bharathkalyan11/how-i-discovered-a-stored-xss-in-a-support-ticket-system-01ec5ff75515?source=search_post---------16-----------------------------------)*
