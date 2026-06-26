# I Put an XSS Payload as My Contact Name, and a Bank Paid the Price

> **Author**: Barengsinau
> **Published**: May 25, 2026

---

![Barengsinau](https://miro.medium.com/v2/da:true/resize:fill:32:32/0*g3SFIsjV64HNuGmD)

11

1

Listen

Share

How a curious experiment inspired by Wi-Fi SSIDs led me to discover a XSS vulnerability in one of Indonesia’s banking apps

I changed my phone contact name to an XSS payload after reading an article from Om YoKo Kho about XSS via Wi-Fi SSID names. Out of curiosity, I tested it against several apps, including a banking app in Indonesia, and the payload triggered inside one of its features. This allowed me to exfiltrate sensitive data stored in localStorage, including the victim's full name, username, simSerialNumber, phonenum, bank account number, sessionID, session token, tokenRASP, favorite recipient accounts, and more. I reported the issue responsibly, received no response, and later discovered it had been quietly fixed.
On the other hand, the same bank is now (when this article is posted) reportedly involved in a data breach incident by Triple X hacking group, I felt it was important to share this story.

![image](https://miro.medium.com/v2/resize:fit:700/1*Yx3Rhey3mW90mdRgq32YVA.png)

## Behind the Scene, How I Got Into This

Around 2021 or 2022 *I forgot what the exact years, I found an interesting article about how XSS (Cross-Site Scripting) can be triggered through a Wi-Fi SSID name. The idea was simple but elegant: if an application renders a network name without sanitization, setting your router’s SSID to something like <script>alert(1)</script> could trigger JavaScript execution in the victim's browser or app.
That article makes me think.
”If SSID names can carry XSS payloads… what about other user-controlled strings that apps blindly trust?”

Contact names. Phone numbers. Email subjects. These are all strings that originate from user input and often flow across systems without being treated as untrusted data.
So I did what any curious security enthusiast would do, I opened my phone, went to my contacts, and renamed one of my entries to:

```
"><svg onload=alert(1)>
```

Then I started testing apps.

Most apps handled it fine. But when I opened one of Indonesia’s banking apps, navigated to a feature that interacts with phone contacts, specifically a transfer / favorite recipient feature that reads my contact list to pre-fill data, and there it was. The payload fired.

## What Is XSS?

Cross-Site Scripting (XSS) is a web security vulnerability that allows an attacker to inject malicious scripts into content that is then viewed by other users. When a browser renders that content, the injected script executes in the context of the victim’s session.

There are three main types:

- Reflected XSS: The payload is embedded in a URL and reflected back in the response immediately. [portswigger]
- Stored XSS: The payload is saved to the server (or local storage) and executed whenever the content is loaded. [portswigger]
- DOM-based XSS: The payload is processed by the browser’s JavaScript engine without going to the server. [portswigger]

In this case, the application has reflected the input (after load from the Contact Name) into the pop-up webview (each time the user opens the contact name feature in the apps). When the Contact name contains client-side scripts (such as javascript), the pop-up will trigger scripts that can trigger XSS vulnerabilities.

## Is XSS Possible in a Mobile App?

This is a question many people ask (including me before I do some research), and the short answer is: yes, sometimes.
Modern mobile apps, especially fintech or banking apps, are not always built entirely in native code. Many use hybrid architectures that mix native components with web-rendered content:
- WebViews: Embedded browsers inside an app that render HTML/CSS/JS
- React Native / Flutter Web: Frameworks that use JavaScript bridges
- In-app browsers: Custom browser tabs for specific features

When these webview-rendered pages handle user data (like contact names, recipient details, or transaction histories) without proper output encoding, XSS is just as dangerous as in a regular browser.
it can be worse in mobile contexts because:

- Users trust mobile apps implicitly: they don’t inspect URLs or check certificates the same way.
- localStorage in WebViews often holds sensitive data: session tokens, cached user info, account numbers.

## PoC (Piye Om Carane a.k.a Proof of Concept)

To complete the explanation, there are few things that must be done to reproduce this issue. Here are the steps that need to be prepared:

- Create a contact phone using the payload
Create a contact phone with simple JavaScript as the name. For example: "><svg onload=alert(1)> *the purpose of this script is to trigger a popup warning with “1” as a character.
- Trigger the Feature
I opened the banking app and navigated to the transfer feature, which pulls contact names from the device to suggest recipients. The app read my contact list, picked up the payload-laden contact name, and rendered it inside a WebView component.

![image](https://miro.medium.com/v2/resize:fit:425/1*EU9TxmcdPNwjcwVFcTovdA.png)

3. Payload Executes
The onerror event fired. My attacker server received a GET request with base64-encoded data. When decoded, the payload had successfully exfiltrated some interesting information.

![image](https://miro.medium.com/v2/resize:fit:700/1*f2wEJCmQuSTFVAQynwSBsQ.png)

### Wait, Isn’t This Just Self-XSS?

Great question. And yes, at first glance, it looks like one.
Self-XSS is when only the attacker can trigger the payload, which makes it low-severity since you can’t really harm anyone else. But this case is a little bit different, and here’s why.

The payload lives in a contact name on the device. That means any attacker who can plant that contact name on a victim’s phone can trigger the XSS when the victim opens the banking app. And planting a contact is easier but trickier than you’d think.

Here’s a realistic attack chain:
1. Send a malicious contact file (.vcf) Attackers can craft a .vcf (vCard) file where the contact name contains the XSS payload, then send it to the victim via WhatsApp, email, or SMS. One tap to save, and the payload is now on their device.

## Get Barengsinau’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

2. Physical access If an attacker has brief physical access to an unlocked phone (a friend, a colleague, a stranger at a café), adding or editing a contact takes less than 10 seconds. The victim would have no reason to suspect their contacts have been tampered with.

3. Social Engineering the trigger Once the payload contact is saved, the attacker doesn’t need to do anything else on the device. They just need to convince the victim to open the banking app and navigate to the transfer/favorite recipient feature.

This could be like this:

- “Hey, can you transfer me some money?”
- “Hey, can you help me to check this feature?”
- Anything that naturally prompts the victim to use that feature

4. Silent data exfiltration The moment the victim opens the affected feature, the payload fires silently in the background. The victim sees nothing unusual. Their session token, account number, name, and favorite recipients are already on their way to the attacker’s server.

## Reporting Timeline

- November 2022:
Discovered the vulnerability and confirmed the impact, but had no idea who to report it to. The bank had no public security contact, no bug bounty program, nothing.

![image](https://miro.medium.com/v2/resize:fit:700/1*m9pma9d06lwey6y5b3-C_w.png)

- June 2025:
Almost 3 years later, the vulnerability still exists, and I finally found an email address to report security issues to the company. I sent a detailed report with the full proof of concept and impact analysis.

![image](https://miro.medium.com/v2/resize:fit:700/1*6eGwGX_oKOfVUjCzLM2P2Q.png)

- Q4 2025:
Decided to recheck the app, and the bug was gone. Fixed. Silently. No reply. No acknowledgment. No thank you. The report was seemingly read and acted upon, but I was left completely in the dark.
- May 2026:
News surfaced that the company had suffered a data breach by Triple X hacking group. I haven’t been able to independently verify the validity of the breach at the time of writing, but it’s what prompted me to finally publish this write-up.

*Psst, another info. at the time this article was written, they do more strict restriction until the app could not be opened on Android devices with Developer Mode enabled, even though it’s not a rooted device.

![image](https://miro.medium.com/v2/resize:fit:700/1*YHXPQSA1DlDzZxXVqs8glg.png)

## Lesson Learned

### For Developers

- Never trust user-controlled input: contact names, email subjects, URLs, and any external data source must be treated as untrusted
- Sanitize and encode output: use context-aware output encoding before rendering data in HTML, JavaScript, or attributes
- WebViews need the same security treatment as browsers: set proper CSP headers, disable JavaScript if not needed, and avoid setAllowFileAccess(true)

### For Security Researchers

- Think creatively about input vectors: not just form fields. Contact names, Wi-Fi SSIDs, Bluetooth device names, and clipboard content are all potential entry points.
- Mobile apps are not immune: always check for WebView components when testing mobile apps
- Test localStorage exposure: always check what sensitive data is stored client-side
- Document everything: screenshot, screen record, note timestamps. You’ll need it for the report

## Final Thoughts

What started as idle curiosity, “what if I name my contact like an XSS payload?” turned into a discovery of a real, exploitable vulnerability in a production banking application.

The vulnerability has been fixed. The bank never said a word.

I’m writing this now because I believe the security community deserves to know this attack scenario, developers need to be reminded that every string is a potential attack vector, and users deserve better from the apps that hold their financial lives.

You can find another bank write-up story that I have discovered in a previous post:
- Accessed bank admin panel
- Bank Database Configuration leaked

Stay curious. Stay responsible.

Tags: #cybersecurity #xss #bugbounty #mobileapp #infosec #webview #indonesia #banking #responsiblebdisclosure #appsecurity #penetrationtesting



---
*Original URL: [https://medium.com/@barengsinau45/i-put-an-xss-payload-as-my-contact-name-and-a-bank-paid-the-price-05504b8c4dfe?source=search_post---------6-----------------------------------](https://medium.com/@barengsinau45/i-put-an-xss-payload-as-my-contact-name-and-a-bank-paid-the-price-05504b8c4dfe?source=search_post---------6-----------------------------------)*
