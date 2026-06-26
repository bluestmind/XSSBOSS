# XSSBOSS

> An advanced, feedback-driven security fuzzer designed to identify and verify Cross-Site Scripting (XSS) vulnerabilities with 100% accuracy and zero false positives.

XSSBOSS is a state-of-the-art DAST tool that treats vulnerability discovery as a feedback loop. Instead of spraying generic static payloads, it dynamically analyzes target sanitization rules, maps reflection syntax contexts, breeds optimized mutations, and verifies execution inside real headless browsers connected to a callback oracle.

---

## 🚀 Key Features

*   **Context-Aware Detection**: Parses input reflections into 5 distinct contexts (`HTML_TEXT`, `ATTR_QUOTED`, `ATTR_UNQUOTED`, `JS_STRING`, `EVENT_HANDLER`) to formulate target-specific breakouts.
*   **Active WAF Profiling**: Probes filter behavior to detect blocked keywords (`script`, `onerror`) or characters (`(`, `)`, `'`, `"`, `` ` ``) before launching campaign fuzzer threads.
*   **Genetic Mutation Engine**: Evolved mutation strategies targeting WAF bypasses (Recursive nesting, HTML Entity protocol encoding, Unicode homoglyphs, and tag-free template literal rewrites).
*   **Zero False Positives**: Uses unique cryptographic tokens embedded in payloads. An issue is logged only when a browser-level execution hook triggers a callback to the Oracle server.
*   **Automation-First Design**: Auto-forwards verified bugs to Burp Suite Repeater/Issues queue and generates clean Markdown/HTML compliance reports.

---

## 🛠️ System Architecture

```
                       ┌─────────────────────────┐
                       │    Target Web App       │
                       └────────────┬────────────┘
                                    │ (Injected Payload)
                                    ▼
┌──────────────────┐    ┌─────────────────────────┐    ┌─────────────────────┐
│  Adaptive Fuzzer ├───>│ Stealth Browser Instance├───>│ Oracle Server       │
│  (Genetics/WAF)  │    │ (DOM Instrumentation)   │    │ (Token Correlation) │
└──────────────────┘    └─────────────────────────┘    └──────────┬──────────┘
                                                                  │
                                                                  ▼
                                                       ┌─────────────────────┐
                                                       │ Burp Queue & Reports│
                                                       └─────────────────────┘
```

---

## ⚙️ Quick Start

### 1. Prerequisites
Ensure you have **Python 3.10+** and **Node.js** (for browser binaries) installed.

### 2. Installation
Clone the repository and run the setup script to initialize the project environment and dependencies:
```bash
git clone https://github.com/bluestmind/XSSBOSS.git
cd XSSBOSS
# Initialize virtual environment and install requirements
setup_backend.bat
```

### 3. Run the Local Test Lab
To test the engine locally, start the vulnerable hard mock target and the oracle callback server:

*   **Terminal 1**: Start the target local app:
    ```bash
    python xss-lab/hard_mock_target.py
    ```
*   **Terminal 2**: Start the oracle server:
    ```bash
    set PYTHONPATH=.
    python xss-lab/oracle_server/main.py
    ```
*   **Terminal 3**: Launch the fuzzer campaign and E2E verifier:
    ```bash
    set PYTHONPATH=.
    python xss-lab/tools/run_hard_lab_e2e.py --skip-controls --reset
    ```

---

## 📄 License & Disclaimer
This project is created for authorized penetration testing, security auditing, and educational use only. Inspecting systems without prior consent is illegal.
