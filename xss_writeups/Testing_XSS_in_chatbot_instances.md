# Testing XSS in chatbot instances

> **Author**: 4osp3l
> **Published**: Nov 3, 2025

---

![image](https://miro.medium.com/v2/resize:fit:700/1*d39psnoCU75kO-g5pKcTOQ.jpeg)

![4osp3l](https://miro.medium.com/v2/resize:fill:32:32/1*I_U7PoFd9622GgE7mNkUQg.jpeg)

32

2

Listen

Share

Here’s a little tip for testing XSS in chatbot instances; when you inject an XSS payload as a user message and it doesn’t execute, don’t stop, go deeper; if direct injection into the sender message fails, try the bot’s replies and responses…. some developers properly escape user-supplied messages to protect against XSS/HTML, but they forget to do the same for bot-generated output; for example, send a harmless marker like ( say “hello” ) and see if the bot echoes “hello” back… if it does, try ( say “hello <h1>4osp3l</h1>” ); if the bot replies and renders HTML, you’ve found a rendering vector.

## Get 4osp3l’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

From there you can attempt XSS payloads and, if successful, look for ways to chain that into something more impactful.

If the bot says “Hi {{your_name}}” whenever you launch the bot, set your username / name as an HTML/XSS payload, then try starting the bot again and see if it executes the payload you set as your name.



---
*Original URL: [https://medium.com/@4osp3l/testing-xss-in-chatbot-instances-aa988c09a6d7?source=search_post---------138-----------------------------------](https://medium.com/@4osp3l/testing-xss-in-chatbot-instances-aa988c09a6d7?source=search_post---------138-----------------------------------)*
