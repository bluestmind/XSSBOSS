# Reflected Cross-Site Scripting (XSS)

> **Author**: Manoj Kumar Chaudhary
> **Published**: May 27, 2026

---

![Manoj Kumar Chaudhary](https://miro.medium.com/v2/resize:fill:32:32/1*ACkKwi0s5ni3iBzkYpB72w.jpeg)

2

Listen

Share

Reflected Cross-Site Scripting (XSS) is a type of injection attack where malicious JavaScript code is injected into a website. When a user visits the affected web page, the JavaScript code executes and its input is reflected in the user’s browser. Reflected XSS can be found on this domain which allows an attacker to create a crafted URL which when opened by a user will execute arbitrary JavaScript within that user’s browser in the context of this domain.

When an attacker can control code that is executed within a user’s browser, they are able to carry out any actions that the user is able to perform, including accessing any of the user’s data and modifying information within the user’s permissions. This can result in modification, deletion, or theft of data, including accessing or deleting files, or stealing session cookies which an attacker could use to hijack a user’s session.

Business Impact

Reflected XSS could lead to data theft through the attacker’s ability to manipulate data through their access to the application, and their ability to interact with other users, including performing other malicious attacks, which would appear to originate from a legitimate user. These malicious actions could also result in reputational damage for the business through the impact to customers trust.

Steps to Reproduce

## Get Manoj Kumar Chaudhary’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

1.Go to example.com in browser

2.In search bar url input the payload of XSS: “><img src/onerror=prompt(document.cookie)>
https://corporate.mattel.com/search-results?q=%27%22%3E%3Cimg%20src/onerror=prompt(document.cookie)%3E

3.And Reflected Cross-Site Scripting (XSS) execute shows cookie popup

Impact
When a user visits the affected web page, the JavaScript code executes and its input is reflected in the user’s browser. Reflected XSS can be found on this domain which allows an attacker to create a crafted URL which when opened by a user will execute arbitrary JavaScript within that user’s browser in the context of this domain.

When the user clicks the malicious URL, it sends an HTTP request to a server with the user’s cookie which the attacker can use to hijack the user/admin account through what’s called session hijacking.

![image](https://miro.medium.com/v2/resize:fit:700/1*vsNZfvBod2cyg4nvhHZqvw.png)



---
*Original URL: [https://medium.com/@Manojchy/reflected-cross-site-scripting-xss-0f0c291a6f7a?source=search_post---------10-----------------------------------](https://medium.com/@Manojchy/reflected-cross-site-scripting-xss-0f0c291a6f7a?source=search_post---------10-----------------------------------)*
