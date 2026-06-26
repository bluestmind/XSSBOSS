import sys
import os

# Ensure the root directory is on PYTHONPATH
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from backend_api.services.llm_service import LLMService
from backend_api.config import settings

def main():
    print("=" * 75)
    print("             XSS BOSS - LLM & BYPASS FLAG INTEGRATION FAST TEST")
    print("=" * 75)
    print(f"[*] Configuration Status:")
    print(f"    - USE_BROWSER_CHATGPT: {settings.USE_BROWSER_CHATGPT}")
    print(f"    - OPENAI_API_KEY:      {bool(settings.OPENAI_API_KEY)}")
    print(f"    - LLM_ENABLED:         {settings.LLM_ENABLED} ({settings.LLM_MODEL})")
    print("-" * 75)

    # Simulated filter profile and telemetry logs
    context_type = "HTML_TEXT"
    token = "test_telemetry_token_123"
    filter_profile = {
        "blocked_tokens": ["<script", "alert", "parentheses", "(", ")"],
        "normalization_behavior": ["brackets_stripped", "quotes_escaped"]
    }
    telemetry_logs = {
        "console": [{"text": "Uncaught SyntaxError: Unexpected token '('"}],
        "errors": ["Uncaught SyntaxError: Unexpected token '(' in inline event handler"]
    }

    print("[*] Simulating Target Context & WAF Blockers:")
    print(f"    - Reflection Context:   {context_type}")
    print(f"    - Blocked Tokens/Chars: {filter_profile['blocked_tokens']}")
    print(f"    - Normalization:        {filter_profile['normalization_behavior']}")
    print(f"    - Telemetry Error:      {telemetry_logs['errors'][0]}")
    print("-" * 75)
    
    print("[+] Triggering LLM Evasion Service (No Fallbacks)...")
    try:
        payloads = LLMService.generate_evasion_payloads(
            context_type=context_type,
            token=token,
            filter_profile=filter_profile,
            telemetry_logs=telemetry_logs,
            allow_fallback=False  # Disable fallback to strictly verify LLM connection
        )
        
        print(f"\n[+] SUCCESS! Generated {len(payloads)} adaptive bypass payloads:")
        for idx, payload in enumerate(payloads, 1):
            print(f"    {idx}. {payload}")
            
    except Exception as e:
        print(f"\n[!] LLM Evasion Generation Failed: {e}")
        print("[*] Troubleshooting tips:")
        print("    1. If using Browser ChatGPT, ensure Chrome is not already locked by another process.")
        print("    2. If using OpenAI API, ensure OPENAI_API_KEY is defined in config.py or environment.")
        print("    3. If using Ollama, ensure your local Ollama server is running (ollama serve).")
    print("=" * 75)

if __name__ == "__main__":
    main()
