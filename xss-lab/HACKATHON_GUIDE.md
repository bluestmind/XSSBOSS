# XSSBOSS - Hackathon Presentation & Demo Guide

Welcome to the **AI for Security** Hackathon! This guide ensures you are fully prepared to run a flawless demonstration of **XSSBOSS** on your laptop and present it effectively to the judges.

---

## 💡 The Pitch Strategy (3-Minute Presentation)

### 1. The Problem
Traditional vulnerability scanners (like standard DAST scanners) are **blind and noisy**:
* They send thousands of generic payloads (like `<script>alert(1)</script>`) which are immediately blocked by Web Application Firewalls (WAFs).
* They don't understand the **context** of where inputs are reflected (e.g., inside an unquoted HTML attribute vs. inside a JSON block).
* They cannot verify if an injection actually *executed*, leading to high false-positive rates.

### 2. The Solution: XSSBOSS
XSSBOSS is an **Agentic, Self-Correcting XSS Vulnerability Assessment Platform**:
* **Context & Filter Profiler**: It dynamically probes target endpoints to map reflection contexts and discover what keywords/characters the WAF blocks.
* **Grammar & Mutation Engine**: It generates context-aware bypass payloads using mutation rules (SVG namespaces, SMIL animations, backtick tagged template literals, case variations).
* **Feedback Loop (Oracle)**: It executes candidates in a real headless browser using custom instrumentation and a local callback server (Oracle), closing the loop only when the payload actually runs JS in the DOM.
* **Premium Reporting**: It exports a full campaign audit complete with triaged PoC links, DOM snapshots, and screenshots.

---

## 🛠️ Local Demo Orchestration (Zero Network Dependencies)

Everything is pre-configured to run **100% offline** on your laptop, isolation-safe:
* Playwright binaries are located in the local `.playwright-browsers` folder.
* Celery tasks run synchronously in-process (`CELERY_TASK_ALWAYS_EAGER=True`), removing the need for a Redis broker.
* A Python virtual environment (`.venv`) hosts all dependencies locally.

### Start the Demo
Simply run the launcher script from the root of `xss-lab/`:

```bat
run_hackathon_demo.bat
```

This will automatically:
1. Reset the local SQLite database.
2. Seed the database with the pre-configured **XSS Boss Hard Local Lab** target.
3. Start the **Oracle Callback Server** on `http://127.0.0.1:8001`.
4. Start the **FastAPI Control Plane Backend** on `http://127.0.0.1:8000`.
5. Start the **Hard Mock Target Lab** (hosting strict WAF filter endpoints) on `http://127.0.0.1:8099`.
6. Launch the **React Web UI** on `http://127.0.0.1:3000`.

---

## 🖥️ Live Demo Walkthrough (Step-by-Step)

Follow this sequence to WOW the judges in under 2 minutes:

### Step 1: Open the Console
Go to `http://localhost:3000` in your web browser. You'll be greeted by the premium, dark-mode, glassmorphic XSSBOSS dashboard.

### Step 2: Load the Hard Lab Target
1. Go to the **Recon & Vuln Scan** section from the sidebar.
2. Click on the pre-seeded campaign in the **Previous runs** list.
3. Show the target details: `http://127.0.0.1:8099/hard/extreme-filter` (a target with severe sanitization blocking `script`, `onerror`, `onload`, `javascript`, parentheses `()`, and quotes `'"'`).

### Step 3: Trigger the Scan
1. Click **Run recon + vuln scan**.
2. Explain the **agentic cycle** as the console updates:
   * *"The analyzer first detects the reflection context (HTML Text)."*
   * *"The profiler probes the input filter and identifies that parentheses, quotes, and standard onload/onerror attributes are forbidden."*
   * *"The fuzzer adapts by choosing an SVG SMIL `<animate>` element, bypassing parentheses with backticks, and prioritizing the allowed `onbegin` handler."*
3. Watch the findings pop up in **real-time** on the screen!

### Step 4: Show the Finding Evidence
1. Navigate to the **Findings Database** tab.
2. Expand the `extreme_filter_bypass` vulnerability finding.
3. Show the exact working payload:
   ```html
   <svg><animate onbegin=__XSS__`TOKEN` attributeName=x></svg>
   ```
4. Show the **DOM Snapshot** and **Screenshot** confirming execution.
5. Highlight the advanced report generated at the end of the scan under `xss-lab/reports/` (available in HTML and Markdown).

---

## 🏆 Key Features to Highlight to Judges
* **Zero False Positives**: We only report a vulnerability if the JavaScript callback server (Oracle) correlates a unique token execution in the browser.
* **Stealth Evader Engine**: Demonstrates defensive evasion (homoglyph variation, character set encoding, and namespace wrapping).
* **Burp Suite Integration**: Show the Burp Montoya extension code in `xss-lab/extensions/` to prove enterprise utility.
* **Full Local Portability**: Runs fully self-contained on your machine during offline presentations.
