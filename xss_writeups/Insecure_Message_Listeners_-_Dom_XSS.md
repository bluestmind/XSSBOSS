# Insecure Message Listeners -> Dom XSS

> **Author**: phlmox
> **Published**: Mar 11, 2026

---

![phlmox](https://miro.medium.com/v2/resize:fill:32:32/1*kIjyouTSom-cF_AxoScWYQ.jpeg)

4

Listen

Share

In this writeup, I will write about a recent finding in my bug bounty session. I have been hunting on this target for more than a year and have reported a few critical and high severity issues. When it feels like all bugs have been exhausted, reading JavaScript files can often help uncover more.

Everything started when I noticed one route in the app ( Let’s call it /my-route ) using an iframe to display the content from frame.redacted.com.

![image](https://miro.medium.com/v2/resize:fit:700/1*2vfMjFxa2CzDF50eThbhOA.jpeg)

The main web app has the X-Frame-Options header set to DENY, as expected. This setting prevents attackers from embedding the web app in an iframe from a third-party context and in the frame.redacted.com app, the X-Frame-Options header should be set to SAMEORIGIN in order to prevent attackers from fetching the page in an iframe from other origins. Another solution is to use Content-Security-Policy header to set who can iframe the app. This solution might be useful for allowing iframe from third party apps. However the developers chose neither. The page on the frame.redacted.com was frameable by anyone because of the lack of an X-Frame-Options header.

We don’t care about the contents of the iframe actually. What we care about is how this iframe and its ancestor (the page that embedded it) is communicating. There is a Javascript file app.js loaded in the frame.redacted.com. This script contains a bunch of functions, configurations, etc… but most importantly message listeners. Since this script is loaded on frame.redacted.com, this page will listen for messages from its ancestor to perform different kinds of actions.

![image](https://miro.medium.com/v2/resize:fit:700/1*5wMw_wO_ZCTJwac8klQ0lQ.jpeg)

Message listeners which are not meant to be public, must check the message sender’s origin to make sure only allowed origins can communicate. However, it is also important to implement these security controls properly. Some origin checks can be flawed:

```
.indexOf('redacted.com')>-1 // -> redacted.com.attacker.com returns 0
.startsWith('redacted.com') // -> redacted.com.attacker.com returns true
.endsWith('redacted.com') // -> attacker-redacted.com returns true
```

After reading the message listeners in the target Javascript file, one message listener caught my attention.

```
var t = document.createElement("a");
window.addEventListener("message", function(e) {
    e.origin.startsWith(h.a.angularHost) && e.data && e.data.type && (e.data.type.includes("routingToBB") && e.data.payload.path ? (t.href = e.data.payload.path, document.getElementsByClassName("header-right")[0].appendChild(t), t.click()) : e.data.type.includes("toBB"))
})
```

Let’s inspect what this message listener does:

- We have predefined anchor element ‘t’ which will be used later.
- When a message sent to this page, this message listener will be triggered along with the other message listeners.

The code block first checks the sender origin.

```
e.origin.startsWith(h.a.angularHost)
```

But as you can see this is the flawed check of origin control as I showed in the example above. So it’s easy to bypass this part by creating a domain such as redacted.com.attacker.com that contains the trusted string. So the final PoC will work on redacted.com.attacker.com which is owned by me.

## Get phlmox’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

After bypassing the security check, code checks for the required payload parameters. It checks if data exists, if the data type exists and the data’s type includes the keyword ‘routingToBB’. As you may have guessed, the purpose of this listener is to redirect the user. Then it checks if the path parameter is defined in the payload. If all the conditions are met, this block will be executed next:

```
(t.href = e.data.payload.path, document.getElementsByClassName("header-right")[0].appendChild(t), t.click())
```

This is the sink we were looking for. It sets the path parameter as the href attribute of the anchor element, it appends the element to the page and then automatically click on it.

If we put javascript:alert(1) as path parameter, this Javascript will be executed in the frame.redacted.com without any user interaction.

Here is the PoC for the exploit flow:

![image](https://miro.medium.com/v2/resize:fit:700/1*_NOFbvaXlPxdB3oks2nr9Q.png)

And the alert popup for proof of concept:

![image](https://miro.medium.com/v2/resize:fit:700/1*3Zv5zZ_xLNGFCOb_hfiVGg.png)

Note: You might think this is also possible by calling window.open after a button click and then sending the payload to the opened window, but it isn’t. The frame.redacted.com page closes itself if it is not embedded.

I didn’t report it as just a simple alert popup. Instead, I demonstrated how it could be used to perform malicious actions on behalf of the user. The frame.redacted.com domain was trusted by the API server and the application was using a session cookie instead of an authorization header. All of this allowed me to send authorized API requests on behalf of the victim by using the Javascript fetch function with credentials attribute set to “include”.

I got some help from the AI to write Javascript code for me to get all critical information from the API routes and send it to an attacker controlled server.

![image](https://miro.medium.com/v2/resize:fit:700/1*WeWqOA0AEZv2IW9Qm6o3FQ.png)

Thanks for reading.



---
*Original URL: [https://medium.com/@phlmox/insecure-message-listeners-dom-xss-6e5b43b4b915?source=search_post---------48-----------------------------------](https://medium.com/@phlmox/insecure-message-listeners-dom-xss-6e5b43b4b915?source=search_post---------48-----------------------------------)*
