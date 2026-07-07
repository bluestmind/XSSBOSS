import os
import re
import json

WRITEUPS_DIR = r"F:\projects\XSSBOSS\xss_writeups"
OUTPUT_FILE = r"f:\projects\XSSBOSS\xss-lab\fuzzer\payload_grammar\extracted_raw_payloads.json"

payload_patterns = [
    r"<script[^>]*>.*?</script>",
    r"<svg[^>]*>",
    r"<img[^>]*>",
    r"<iframe[^>]*>",
    r"javascript:[^\s\"']+",
    r"onerror\s*=\s*[^\s\"'>]+",
    r"onload\s*=\s*[^\s\"'>]+",
    r"onfocus\s*=\s*[^\s\"'>]+",
    r"onmouseover\s*=\s*[^\s\"'>]+",
    r"oncontentvisibilityautostatechange\s*=\s*[^\s\"'>]+",
]

extracted_payloads = set()

def extract_from_code_blocks(content):
    # Match triple backtick code blocks
    code_blocks = re.findall(r"```(?:html|javascript|js)?\n(.*?)```", content, re.DOTALL | re.IGNORECASE)
    for block in code_blocks:
        lines = block.split("\n")
        for line in lines:
            line = line.strip()
            if not line:
                continue
            # If it looks like a payload or contains HTML/JS constructs
            if any(p in line.lower() for p in ["alert", "prompt", "confirm", "xss", "onerror", "onload", "javascript", "<svg", "<img", "<iframe", "<script"]):
                if len(line) < 300: # ignore very long scripts
                    extracted_payloads.add(line)

def extract_from_lines(content):
    # Match inline matches
    for pattern in payload_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        for m in matches:
            m = m.strip()
            if 10 < len(m) < 200:
                extracted_payloads.add(m)

def main():
    if not os.path.exists(WRITEUPS_DIR):
        print(f"Error: Directory {WRITEUPS_DIR} does not exist.")
        return

    files = [f for f in os.listdir(WRITEUPS_DIR) if f.endswith(".md")]
    print(f"Scanning {len(files)} markdown files...")

    for filename in files:
        filepath = os.path.join(WRITEUPS_DIR, filename)
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            extract_from_code_blocks(content)
            extract_from_lines(content)
        except Exception as e:
            print(f"Error reading {filename}: {e}")

    # Deduplicate and clean
    cleaned_payloads = []
    for p in extracted_payloads:
        # Clean markdown wrappers or quotes
        p_clean = p.strip("`'\" ")
        if p_clean and len(p_clean) > 5:
            # Replace placeholder domains/tokens with fuzzer's standardized placeholders
            p_clean = re.sub(r"alert\([^)]*\)", "alert('{{TOKEN}}')", p_clean)
            p_clean = re.sub(r"confirm\([^)]*\)", "confirm('{{TOKEN}}')", p_clean)
            p_clean = re.sub(r"prompt\([^)]*\)", "prompt('{{TOKEN}}')", p_clean)
            p_clean = re.sub(r"__XSS__\([^)]*\)", "__XSS__('{{TOKEN}}')", p_clean)
            cleaned_payloads.append(p_clean)

    # Filter duplicates again
    cleaned_payloads = list(set(cleaned_payloads))

    print(f"Extracted {len(cleaned_payloads)} unique payloads.")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(cleaned_payloads, f, indent=2)
    print(f"Saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
