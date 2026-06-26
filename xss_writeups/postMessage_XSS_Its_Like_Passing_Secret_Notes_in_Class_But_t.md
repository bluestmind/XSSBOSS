# postMessage` XSS: It’s Like Passing Secret Notes in Class… But the Whole School Can Read Them** 📝➡️🔓

> **Author**: Shady Farouk
> **Published**: Nov 11, 2025

---

![Shady Farouk](https://miro.medium.com/v2/resize:fill:32:32/1*Pwa3mzdAXYIzn22wjtlucw.jpeg)

3

Listen

Share

Hey team, let’s talk about one of the web’s sneakiest vulnerabilities: the `postMessage` XSS. If you’ve ever used `window.postMessage()`, you know it’s a fantastic way for different windows, iframes, or tabs to chat with each other, even if they’re from different domains. It’s like a secure messaging app for your browser tabs!

**But here’s the problem:** Our code often acts like an overly trusting friend who believes every piece of gossip they hear. 😬

#### **The “Secret Note” Analogy, Gone Wrong**

Imagine your main website (Window A) is waiting for a secret note from your payment iframe (Window B). You’ve agreed on a secret handshake (the origin).

A trustworthy message looks like this:

```javascript

// From the trusted iframe

trustedIframe.postMessage(‘{ “user”: “cool_guy”, “action”: “paymentComplete” }’, ‘https://your-trusted-site.com’);

```

But what happens when a malicious website (Window C, run by “Eve the Eavesdropper”) also sends a note? Your site, if not careful, might just read it and do exactly what it says!

```javascript

// From EVIL WINDOW! 🦹‍♀️

evilWindow.postMessage(‘{ “user”: “<img src=x onerror=stealYourCookies()>” }’, ‘*’);

```

If your event listener isn’t checking who sent the note, it will happily render that malicious HTML and execute the script. **Congratulations, you’ve just been Rickrolled by an XSS.** 🎷🐛

#### **Where We Go Wrong: The Usual Suspects**

We often write event listeners that are a little too… welcoming. Here’s the “bad code” we’re all guilty of writing at 2 AM:

```javascript

// DANGER ZONE! 🚨 Why is this bad? Let’s count the ways!

window.addEventListener(‘message’, (event) => {

. // 1. We didn’t check the sender’s identity! Who are you?!

. // 2. We’re directly injecting the data. YOLO!

. document.getElementById(‘messageDisplay’).innerHTML = event.data;

});

```

This code is the digital equivalent of shouting, “I’ll do whatever you say!” into a crowded room. Not a great strategy.

#### **How to Be a Security Bouncer 🕶️**

We need to turn our code from a naive intern into a paranoid bouncer with a strict guest list. Here’s the checklist:

- **Verify the Origin (`event.origin`):** This is the most crucial step. Before you even look at the message, check the ID of the person handing you the note.

. ```javascript

## Get Shady Farouk’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

. window.addEventListener(‘message’, (event) => {

. // Is this message from a friend we trust?

. const trustedOrigins = [‘https://my-trusted-app.com’, ‘https://my-other-site.net’];

. if (!trustedOrigins.includes(event.origin)) {

. return; // Go away, stranger!

. }

. // … rest of your code

. });

. ```

2. **Validate the *Content* of the Message:** Don’t just trust the data because it came from a “trusted” origin. What if that origin was itself compromised? Always validate the structure and content of the message before using it.

. ```javascript

. // Example: We expect a specific format

. if (typeof event.data !== ‘object’ || !event.data.action) {

. return; // This message is gibberish. Ignore it.

. }

. ```

3. **Use `event.source` for Extra Paranoia:** You can also check the `event.source` property to ensure it’s the specific window you expected to hear from.

4. **Never Use `*` as a Target Origin When Sending:** When *you* send a message, always specify the exact target origin, not the wildcard `*`. It’s like addressing an envelope properly instead of just yelling the message down the street.

. ```javascript

. // Good 👍

. otherWindow.postMessage(myData, ‘https://specific-trusted-domain.com’);

. // Bad 👎 (Unless you *want* the whole internet to listen)

. otherWindow.postMessage(myData, ‘*’);

. ```

#### **Conclusion: Trust, But Verify!**

The `postMessage` API is powerful, but with great power comes great responsibility… to not accidentally create a gaping security hole.

So next time you’re implementing it, ask yourself: **”Is my code a gullible puppy or a seasoned security guard?”** 🐶🆚💂

Let’s all commit to writing code that’s a little less trusting. Your users’ data will thank you!

Stay safe out there! 🛡️

![image](https://miro.medium.com/v2/resize:fit:700/1*BcdTx7BDYbqBksLkhjp3yw@2x.jpeg)



---
*Original URL: [https://medium.com/@shadyfarouk1986/postmessage-xss-its-like-passing-secret-notes-in-class-but-the-whole-school-can-read-them-842c113b61dc?source=search_post---------154-----------------------------------](https://medium.com/@shadyfarouk1986/postmessage-xss-its-like-passing-secret-notes-in-class-but-the-whole-school-can-read-them-842c113b61dc?source=search_post---------154-----------------------------------)*
