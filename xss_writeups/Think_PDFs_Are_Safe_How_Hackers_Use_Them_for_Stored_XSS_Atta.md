# Think PDFs Are Safe? How Hackers Use Them for Stored XSS Attacks

> **Author**: Tushar Suryawanshi
> **Published**: Dec 2, 2025

---

![Tushar Suryawanshi](https://miro.medium.com/v2/resize:fill:32:32/1*v3-j6h9Cos0iUNxNsasCtw.jpeg)

1

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:700/1*wR1BMnNTHFSsapeNGGayIQ.jpeg)

Cross-Site Scripting (XSS) is a well-known web application vulnerability that allows attackers to inject malicious code into pages viewed by unsuspecting users. It can lead to session hijacking, credential theft, redirection to malicious sites, and even full account takeover.
While most developers associate XSS with JavaScript injected through HTML inputs, file uploads — specifically PDF files — are an often overlooked and risky attack surface.

PDFs are widely used for sharing reports, invoices, resumes, and documents. But many people don’t realize that PDFs can embed JavaScript, interactive objects, and active content. When such a malicious PDF is uploaded and later rendered in the browser, it can execute attacker-controlled code, resulting in a stored XSS attack.

## Get Tushar Suryawanshi’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

This blog walks through how XSS can occur via PDF uploads, how attackers exploit it, and what developers can implement to prevent it.

## How XSS via PDF Uploads Works

- An attacker uploads a PDF containing embedded malicious JavaScript.
- The application stores the file and makes it available to other users.
- When a victim opens the PDF in the browser (via iframe, embed, or direct view), the JavaScript runs automatically, executing in the context of the web application.
- This can lead to theft of cookies, tokens, sensitive data, or unauthorized actions using the victim’s account.

## Why is this possible?

- PDF files can contain JavaScript (/JavaScript or /JS tags).
- Many PDF readers, especially browser-based viewers, still support limited script execution.
- Weak file validation allows attackers to upload PDFs that are actually HTML or contain malicious scripting elements.
- Some applications serve uploaded files inline, increasing the probability of execution.

## Reproduction Steps

- Navigate to Browse Files → Upload.
- Select a malicious PDF from your local system containing embedded JavaScript.
- The web UI confirms that the file was uploaded successfully.
- Open the file in a new browser tab.
- As soon as the PDF loads, the JavaScript executes — demonstrating how stored XSS can be triggered via file upload.

![image](https://miro.medium.com/v2/resize:fit:700/1*ZoQgtjhpaJPyL-wVsMV9_w.png)

![image](https://miro.medium.com/v2/resize:fit:700/1*A1I3BFdmcsOco_HKj4CSHw.png)

## Impact of XSS via PDF Upload

- User impersonation
- Execution of any action the victim can perform
- Unauthorized access to sensitive user data
- Credential theft (username/password/session tokens
- Website defacement
- Embedding trojan-like functionality
- Full compromise of high-privilege accounts (e.g., admins)

Stored XSS through a PDF upload is especially dangerous because every user who views the uploaded file becomes a victim.

## Preventing XSS via PDF File Uploads

Mitigating this attack requires addressing both file security and content security configuration

## 1. Strict File Type Validation

Applications must enforce:

- MIME type validation (application/pdf)
- Magic number checks (verify file header)
- Whitelist-based filtering (allow only trusted formats)

Do not rely solely on file extensions, as attackers can rename .html or .js to .pdf.

## 2. Sanitize or Remove Active Content from PDFs

Before storing or serving files:

- Inspect and sanitize PDFs for embedded JavaScript
- Use tools like: PDF sanitizers;pdfid / pdf-parser
- Strip /JS, /JavaScript, /OpenAction, and other active objects

If sanitization isn’t feasible, disable inline preview and force PDF downloads.

## 3. Serve Uploaded Files with Safe Headers

Always deliver uploaded PDFs using:

```
Content-Disposition: attachment;
X-Content-Type-Options: nosniff;
Content-Type: application/pdf;
```

This prevents inline rendering and blocks JavaScript execution inside the browser.

## 4. Implement a Strong Content Security Policy (CSP)

A properly configured CSP can drastically reduce impact:

```
Content-Security-Policy: script-src 'self'; object-src 'none';
```

This prevents execution of scripts loaded from inside PDFs or external sources.

## 5. Ensure Users View PDFs in Updated, Secure Readers

Using outdated or vulnerable PDF readers increases the risk of script execution.
Encourage or enforce the use of modern PDF viewers that disable JavaScript by default.

## Conclusion

Stored XSS via PDF file upload is a subtle yet powerful attack vector that many development teams overlook. Because PDFs are generally trusted formats, malicious payloads embedded within them can easily bypass poorly implemented upload validations.

By enforcing strong file validation, sanitizing PDFs, using secure headers, keeping PDF readers updated, and applying a robust Content Security Policy, developers can significantly reduce the risk of PDF-based XSS attacks.

Security is not just about validating inputs — it’s about validating everything users upload or interact with.



---
*Original URL: [https://medium.com/@tushar_rs_/think-pdfs-are-safe-how-hackers-use-them-for-stored-xss-attacks-043f2c208c37?source=search_post---------129-----------------------------------](https://medium.com/@tushar_rs_/think-pdfs-are-safe-how-hackers-use-them-for-stored-xss-attacks-043f2c208c37?source=search_post---------129-----------------------------------)*
