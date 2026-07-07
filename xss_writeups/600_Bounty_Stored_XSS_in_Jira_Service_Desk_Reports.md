# $600 Bounty: Stored XSS in Jira Service Desk Reports

> **Author**: Monika sharma
> **Published**: Nov 24, 2025

---

## How a simple “Question” field turned into a Stored XSS that executed inside Jira’s admin reports

![Monika sharma](https://miro.medium.com/v2/da:true/resize:fill:32:32/0*Tv4b4p5mb6J3IJwD)

33

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:700/1*aKlz0E8xOQK98blD8e61yQ.png)

### Introduction

Cross-Site Scripting (XSS) vulnerabilities continue to appear in even the most robust enterprise products. This report highlights how a stored XSS in Atlassian Jira Service Management allowed a non-authenticated user to inject malicious JavaScript code that later executed in an administrator’s context all by using the public Service Desk Widget.

In this write-up, we’ll discuss:

- What this vulnerability was
- How the researcher found and exploited it
- The impact it had on administrators
- How you can test for similar stored XSS vulnerabilities in widget-based products

### Vulnerability Type

- Stored Cross-Site Scripting (XSS) Non-Authenticated to Admin
- Category: Web Application
- VRT Classification: Cross-Site Scripting > Stored > Non-Privileged User to Anyone

This vulnerability occurs when unescaped input is stored on the server and later rendered within the web application in an unsafe manner. In this case, the malicious input was injected into a user-facing widget form and was later displayed in the Reports Requests Resolved section viewed by admins.

### How the Researcher Found It

The researcher tested Jira’s public Service Desk widget, which allows customers to ask questions or create requests without needing authentication.

By inserting a crafted XSS payload in the “Question” field, the researcher demonstrated that the malicious code persisted across backend processes and finally executed when viewed by an admin in the Reports dashboard.

Steps to Reproduce

Step 1. Enable the Service Desk Widget

As an admin, enable and configure the Service Desk widget for public access.

URL Example:

https://<yourdomain>.atlassian.net/servicedesk/admin/<project>/addon/com.atlassian.servicedesk.embedded__settings

![image](https://miro.medium.com/v2/resize:fit:700/1*IisV4tphJvm-WEWDNVvK1Q.png)

Step 2. Inject the Payload

Once the widget is live, any user (even without login) can ask a question.

In the “What is your question?” field, enter the payload:

```
norwin"><img src="x" onerror="alert(document.domain)"></img>
```

![image](https://miro.medium.com/v2/resize:fit:700/1*49bGq4ttRLTzS9cWjULnCg.png)

This payload gets stored in the system as part of the user’s question.

Step 3. Admin Resolves the Request

When the admin opens the submitted question, it appears normal. The admin then marks the question as resolved.

![image](https://miro.medium.com/v2/resize:fit:700/1*2Woj_gM629fcRS9gsBtEjg.png)

![image](https://miro.medium.com/v2/resize:fit:700/1*RgIib40Qyzh-dmHYFDr31A.png)

Step 4. Visit “Requests Resolved” in Reports

## Get Monika sharma’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

Now, when the admin navigates to:

```
/jira/servicedesk/projects/<project>/reports/kb-requests-resolved
```

and clicks on the “Requests Resolved” graph, the stored payload executes in the admin’s browser context.

![image](https://miro.medium.com/v2/resize:fit:700/1*Pq8HU7RIHhmAQBBSJ5yHHA.png)

### Impact

- Privilege Escalation: The attacker could execute JavaScript in the admin’s browser.
- Session Hijacking: Potential theft of session cookies or CSRF tokens.
- Defacement / Redirects: Could modify the UI or trick admins into performing unintended actions.
- Persistent Exploitation: Since this was stored XSS, it triggered each time the report was viewed.

This vulnerability was particularly dangerous because it required no authentication just a public form submission.

### How You Can Find Similar Bugs

Stored XSS in enterprise widgets and integrations is more common than you’d think. Here’s a simple methodology to detect them:

- Identify Input Points:

Find all public forms, widgets, or support tools that allow user input (especially if embedded in other dashboards).

2. Inject Payloads:

Use simple, harmless payloads to detect reflection or storage:

```
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<script>alert(1)</script>
```

3. Track Persistence:

Check where your payload appears emails, dashboards, reports, or analytics sections.

4. Test Different Roles:

See how the data is displayed for higher-privileged users (like admins or analysts).

5. Automate Monitoring:

Use Burp Collaborator or DOM Invader to catch triggered payloads.

### Additional Insights

- Widget-based attack surfaces are often ignored in testing, but they’re rich in stored XSS possibilities.
- Always test where user input ends up not just where it’s entered.
- Stored XSS often hides in secondary views like reports, exports, or analytics dashboards.

### Conclusion

A simple “question” field turned into a powerful stored XSS vector — proving once again that even trusted SaaS platforms can have blind spots.

This bug was responsibly reported and fixed, earning the researcher a $600 bounty.

If you’re testing similar helpdesk or CRM products, pay close attention to:

- Input fields connected to public widgets
- Data visualizations or admin reports displaying user content
- HTML contexts where sanitization is weak or missing

☕ Liked this write-up? If it helped you understand stored XSS better or inspired your next bug hunt

buy me a coffee and keep the research alive ❤️ https://buymeacoffee.com/monikaak47



---
*Original URL: [https://medium.com/bugbountywriteup/600-bounty-stored-xss-in-jira-service-desk-reports-22bad0f8120d?source=search_post---------147-----------------------------------](https://medium.com/bugbountywriteup/600-bounty-stored-xss-in-jira-service-desk-reports-22bad0f8120d?source=search_post---------147-----------------------------------)*
