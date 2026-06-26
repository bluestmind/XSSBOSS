"""Smoke-test the LLM service query and bypass guide parsing pipeline."""
import sys
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Setup environment variables to match E2E run
os.environ.setdefault("DATABASE_URL", f"sqlite:///{(ROOT / 'xssboss.db').as_posix()}")
os.environ.setdefault("CELERY_TASK_ALWAYS_EAGER", "True")
os.environ.setdefault("ORACLE_SERVER_URL", "http://127.0.0.1:8001")
os.environ.setdefault("API_HOST", "127.0.0.1")
os.environ.setdefault("PYTHONPATH", str(ROOT))

from backend_api.services.llm_service import LLMService, ChatGPTBrowserClient

def main():
    print("[*] Initializing LLM Service test query...")
    token = "LLMTESTSEDTok"
    context_type = "HTML_TEXT"
    filter_profile = {
        "blocked_tokens": ["<script", "</script", "javascript:", "onerror", "srcdoc", "expression("],
        "allowed_tokens": ["svg", "details", "ontoggle", "onbegin", "onfocus"],
        "normalization_behavior": ["case_normalized"],
        "waf_detected": False,
        "sanitizer_detected": True,
        "csp_rules": {
            "allow_inline_scripts": True,
            "allow_event_handlers": True,
            "allow_javascript_urls": False,
        },
    }

    try:
        print(f"[*] Querying LLMService for context={context_type}...")
        payloads = LLMService.generate_evasion_payloads(
            context_type=context_type,
            token=token,
            filter_profile=filter_profile,
            allow_fallback=False  # Force LLM generation without fallback to heuristics
        )
        print(f"\n[+] Success! Generated {len(payloads)} payloads using benign developer tutorial guide:")
        for idx, p in enumerate(payloads[:10], 1):
            print(f"  {idx}. {p}")
            
    except Exception as e:
        print(f"\n[!] LLM Service query failed: {e}")
        
    finally:
        print("[*] Closing browser session driver...")
        if ChatGPTBrowserClient._driver:
            try:
                ChatGPTBrowserClient._driver.quit()
                print("[+] Browser driver stopped successfully.")
            except Exception as close_err:
                print(f"[!] Warning: failed to quit driver: {close_err}")

if __name__ == "__main__":
    main()
