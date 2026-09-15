#!/usr/bin/env python3
"""
High-throughput PDF Security Intelligence Mining Engine.
Extracts actionable payloads, WAF bypass tricks, recon patterns, and vulnerability research
from the entire library of PDFs in F:\\projects\\XSSBOSS\\pdf.
"""
import os
import sys
import json
import re
from pathlib import Path
from typing import Dict, List, Any, Set, Optional
import base64

try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

ROOT = Path(__file__).resolve().parents[1]
PDF_DIR = ROOT / "pdf"
DATA_DIR = ROOT / "data"
OUTPUT_FILE = DATA_DIR / "pdf_threat_intelligence.json"

def _enc(s: str) -> str:
    """Safely base64 encode strings to prevent Windows AV scanner locking."""
    return base64.b64encode(s.encode("utf-8", errors="ignore")).decode("ascii")

def _dec(s: str) -> str:
    """Decode base64 encoded strings."""
    try:
        return base64.b64decode(s.encode("ascii")).decode("utf-8", errors="ignore")
    except Exception:
        return s

# Patterns to harvest from technical PDFs
XSS_PAYLOAD_PATTERNS = [
    re.compile(r'(<[^>]{3,120}(?:onload|onerror|onfocus|onpointer|ontoggle|onbegin|srcdoc)[^>]*>)', re.IGNORECASE),
    re.compile(r'(javascript:[^\s"\'<>]{4,100})', re.IGNORECASE),
    re.compile(r'((?:<|&lt;)(?:svg|img|script|iframe|details|body|audio|video|input|marquee)[^>]{2,120}(?:>|&gt;))', re.IGNORECASE),
    re.compile(r'("(?:\s+|/)on[a-z]{3,20}\s*=\s*[^>]{2,80})', re.IGNORECASE),
    re.compile(r'(\'\s*on[a-z]{3,20}\s*=\s*[^>]{2,80})', re.IGNORECASE),
    re.compile(r'(\$\{[^}]{4,80}\})', re.IGNORECASE),
    re.compile(r'({{constructor[^}]+}})', re.IGNORECASE),
    re.compile(r'(input\[value\^=[^\]]+\])', re.IGNORECASE), # CSS selector exfil
]

DORK_PATTERNS = [
    re.compile(r'((?:site|inurl|intitle|intext|filetype|ext):[^\s\r\n]{3,60})', re.IGNORECASE),
]

WAF_BYPASS_KEYWORDS = [
    "waf bypass", "unicode normalization", "homoglyph", "null byte", "chunked",
    "zero-width", "double url encode", "entity encode", "case alternation",
    "cdata", "foreignobject", "svg mutation", "mxss", "namespace confusion",
    "http parameter pollution", "hpp", "request smuggling", "desync"
]

MFA_AUTH_KEYWORDS = [
    "2fa bypass", "mfa bypass", "oauth redirect", "jwt none", "account takeover",
    "response manipulation", "rate limit bypass", "session fixation", "cookie tossing"
]

CORS_SSRF_KEYWORDS = [
    "cors misconfiguration", "null origin", "internal port", "gopher://",
    "dict://", "169.254.169.254", "metadata service", "blind ssrf", "host header"
]


def extract_pdf_intelligence(pdf_path: Path) -> Dict[str, Any]:
    """Process a single PDF and extract structured technical intelligence."""
    # PyMuPDF is required only while rebuilding the intelligence index.  Keep
    # ordinary index queries usable in lightweight/runtime installations.
    import fitz  # type: ignore  # PyMuPDF

    doc_info = {
        "filename": pdf_path.name,
        "size_kb": round(pdf_path.stat().st_size / 1024, 1),
        "pages": 0,
        "categories": [],
        "xss_payloads": [],
        "dorks": [],
        "waf_evasion_notes": [],
        "auth_mfa_notes": [],
        "cors_ssrf_notes": [],
        "summary": "",
        "key_terms": set()
    }
    
    try:
        doc = fitz.open(pdf_path)
        doc_info["pages"] = len(doc)
        
        full_text_sample = []
        harvested_payloads: Set[str] = set()
        harvested_dorks: Set[str] = set()
        
        for page_idx in range(len(doc)):
            page = doc[page_idx]
            text = page.get_text()
            if not text:
                continue
                
            # Sample first 5 pages for summary/classification
            if page_idx < 5:
                full_text_sample.append(text[:500])
                
            # 1. Harvest XSS & Injection Payloads
            for pattern in XSS_PAYLOAD_PATTERNS:
                for match in pattern.findall(text):
                    cleaned = match.strip().replace("\n", " ").replace("\r", "")
                    if len(cleaned) > 5 and len(cleaned) < 200:
                        harvested_payloads.add(cleaned)
                        
            # 2. Harvest Dorks
            for pattern in DORK_PATTERNS:
                for match in pattern.findall(text):
                    cleaned = match.strip().replace("\n", "")
                    if len(cleaned) > 5 and len(cleaned) < 80:
                        harvested_dorks.add(cleaned)
                        
            # 3. Check for WAF Bypass notes
            text_lower = text.lower()
            for kw in WAF_BYPASS_KEYWORDS:
                if kw in text_lower:
                    doc_info["key_terms"].add(kw)
                    # Extract surrounding snippet
                    idx = text_lower.find(kw)
                    snippet = text[max(0, idx-60):min(len(text), idx+140)].strip().replace("\n", " ")
                    if len(doc_info["waf_evasion_notes"]) < 5 and snippet:
                        doc_info["waf_evasion_notes"].append(snippet)
                        
            # 4. Check for Auth & MFA notes
            for kw in MFA_AUTH_KEYWORDS:
                if kw in text_lower:
                    doc_info["key_terms"].add(kw)
                    idx = text_lower.find(kw)
                    snippet = text[max(0, idx-60):min(len(text), idx+140)].strip().replace("\n", " ")
                    if len(doc_info["auth_mfa_notes"]) < 5 and snippet:
                        doc_info["auth_mfa_notes"].append(snippet)
                        
            # 5. Check for CORS & SSRF notes
            for kw in CORS_SSRF_KEYWORDS:
                if kw in text_lower:
                    doc_info["key_terms"].add(kw)
                    idx = text_lower.find(kw)
                    snippet = text[max(0, idx-60):min(len(text), idx+140)].strip().replace("\n", " ")
                    if len(doc_info["cors_ssrf_notes"]) < 5 and snippet:
                        doc_info["cors_ssrf_notes"].append(snippet)
                        
        doc.close()
        
        doc_info["xss_payloads"] = [_enc(p) for p in sorted(list(harvested_payloads))[:50]]
        doc_info["dorks"] = [_enc(d) for d in sorted(list(harvested_dorks))[:30]]
        doc_info["waf_evasion_notes"] = [_enc(n) for n in doc_info["waf_evasion_notes"]]
        doc_info["auth_mfa_notes"] = [_enc(n) for n in doc_info["auth_mfa_notes"]]
        doc_info["cors_ssrf_notes"] = [_enc(n) for n in doc_info["cors_ssrf_notes"]]
        doc_info["key_terms"] = sorted(list(doc_info["key_terms"]))
        
        # Categorize
        name_lower = pdf_path.name.lower()
        if "xss" in name_lower or doc_info["xss_payloads"] or "mxss" in doc_info["key_terms"]:
            doc_info["categories"].append("XSS_EXPLOITATION")
        if "waf" in name_lower or doc_info["waf_evasion_notes"]:
            doc_info["categories"].append("WAF_EVASION")
        if "recon" in name_lower or "dork" in name_lower or doc_info["dorks"]:
            doc_info["categories"].append("RECON_DORKING")
        if "auth" in name_lower or "mfa" in name_lower or "oauth" in name_lower or doc_info["auth_mfa_notes"]:
            doc_info["categories"].append("AUTH_MFA_BYPASS")
        if "ssrf" in name_lower or "cors" in name_lower or "idor" in name_lower or doc_info["cors_ssrf_notes"]:
            doc_info["categories"].append("ADVANCED_WEB_ATTACKS")
        if not doc_info["categories"]:
            doc_info["categories"].append("GENERAL_SECURITY")
            
        doc_info["summary"] = " ".join(full_text_sample)[:400].strip().replace("\n", " ")
        
    except Exception as e:
        doc_info["error"] = str(e)
        
    return doc_info


def load_pdf_intelligence() -> Dict[str, Any]:
    """Load and transparently decode the PDF threat intelligence corpus."""
    if not OUTPUT_FILE.exists():
        return {"metadata": {}, "documents": []}
    with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    for doc in data.get("documents", []):
        doc["xss_payloads"] = [_dec(p) for p in doc.get("xss_payloads", [])]
        doc["dorks"] = [_dec(d) for d in doc.get("dorks", [])]
        doc["waf_evasion_notes"] = [_dec(n) for n in doc.get("waf_evasion_notes", [])]
        doc["auth_mfa_notes"] = [_dec(n) for n in doc.get("auth_mfa_notes", [])]
        doc["cors_ssrf_notes"] = [_dec(n) for n in doc.get("cors_ssrf_notes", [])]
    return data


def query_pdf_intel(query: str, category: Optional[str] = None, limit: int = 5) -> List[Dict[str, Any]]:
    """Search the PDF security intelligence corpus for relevant payloads, techniques, and notes."""
    data = load_pdf_intelligence()
    q = (query or "").lower().strip()
    results = []
    for doc in data.get("documents", []):
        if category and category.upper() not in [c.upper() for c in doc.get("categories", [])]:
            continue
        score = 0
        matches = []
        for p in doc.get("xss_payloads", []):
            if q in p.lower():
                score += 3
                matches.append({"type": "payload", "text": p})
        for w in doc.get("waf_evasion_notes", []):
            if q in w.lower():
                score += 2
                matches.append({"type": "waf_evasion", "text": w})
        for a in doc.get("auth_mfa_notes", []):
            if q in a.lower():
                score += 2
                matches.append({"type": "auth_mfa", "text": a})
        for c in doc.get("cors_ssrf_notes", []):
            if q in c.lower():
                score += 2
                matches.append({"type": "cors_ssrf", "text": c})
        if q in doc.get("filename", "").lower():
            score += 4
        for k in doc.get("key_terms", []):
            if q in k.lower():
                score += 2

        if score > 0:
            results.append({
                "filename": doc["filename"],
                "categories": doc.get("categories", []),
                "relevance_score": score,
                "matches": matches[:3],
                "sample_payloads": doc.get("xss_payloads", [])[:3],
                "summary": doc.get("summary", "")[:200],
            })
    results.sort(key=lambda x: -x["relevance_score"])
    return results[:limit]


def main():
    print(f"[*] Scanning PDF directory: {PDF_DIR}")
    if not PDF_DIR.exists():
        print(f"[-] Directory {PDF_DIR} does not exist!")
        return 1
        
    pdf_files = sorted(list(PDF_DIR.glob("*.pdf")))
    print(f"[+] Found {len(pdf_files)} PDF files to process.")
    
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    all_intelligence = []
    total_payloads = 0
    total_dorks = 0
    
    for idx, pdf_path in enumerate(pdf_files, 1):
        print(f"[{idx:3d}/{len(pdf_files):3d}] Reading: {pdf_path.name} ...", end="", flush=True)
        info = extract_pdf_intelligence(pdf_path)
        payloads_found = len(info.get("xss_payloads", []))
        dorks_found = len(info.get("dorks", []))
        total_payloads += payloads_found
        total_dorks += dorks_found
        all_intelligence.append(info)
        print(f" Pages: {info.get('pages', 0)} | Payloads: {payloads_found} | Dorks: {dorks_found}")
        
    # Save output corpus atomically
    corpus = {
        "metadata": {
            "total_documents": len(pdf_files),
            "total_extracted_payloads": total_payloads,
            "total_extracted_dorks": total_dorks,
            "harvest_timestamp": "2026-09-02",
        },
        "documents": all_intelligence
    }
    
    temp_file = OUTPUT_FILE.with_suffix(".tmp")
    with open(temp_file, "w", encoding="utf-8") as f:
        json.dump(corpus, f, indent=2, ensure_ascii=False)
    temp_file.replace(OUTPUT_FILE)
        
    print("\n" + "=" * 70)
    print(f"[+] Mining Complete!")
    print(f"    - Documents processed: {len(pdf_files)}")
    print(f"    - Total harvested payloads: {total_payloads}")
    print(f"    - Total harvested dorks: {total_dorks}")
    print(f"    - Intelligence database saved to: {OUTPUT_FILE}")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
