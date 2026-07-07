"""Automated Proof-of-Concept (PoC) Generator and Sanitizer.

Generates standalone HTML exploits, cURL commands, and Python verification scripts
suitable for professional bug bounty submissions (HackerOne, Bugcrowd).
"""
import html
import re
import urllib.parse
from typing import Dict, Any, Optional


class PoCGenerator:
    """Generate standalone PoC artifacts and sanitize reproduction steps."""

    @staticmethod
    def generate_html_poc(
        method: str,
        url: str,
        param_name: str,
        payload: str,
        title: str = "XSS Boss PoC Exploit"
    ) -> str:
        """Generate a standalone, self-executing HTML PoC exploit."""
        method = (method or "GET").upper()
        escaped_title = html.escape(title)
        escaped_payload = html.escape(payload)

        parsed = urllib.parse.urlparse(url)
        base_endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if method == "GET":
            # Build query parameters
            query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            query_params[param_name] = [payload]
            exploit_query = urllib.parse.urlencode(
                [(k, v[0] if isinstance(v, list) else v) for k, v in query_params.items()],
                doseq=True
            )
            target_exploit_url = f"{base_endpoint}?{exploit_query}"

            return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{escaped_title}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 40px; background: #0d1117; color: #c9d1d9; }}
    .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 24px; max-width: 700px; margin: 0 auto; box-shadow: 0 8px 24px rgba(0,0,0,0.5); }}
    h1 {{ color: #58a6ff; font-size: 20px; margin-top: 0; }}
    p {{ font-size: 14px; line-height: 1.6; color: #8b949e; }}
    .btn {{ display: inline-block; background: #238636; color: #ffffff; padding: 10px 20px; border-radius: 6px; text-decoration: none; font-weight: bold; margin-top: 15px; }}
    .btn:hover {{ background: #2ea043; }}
    pre {{ background: #090d13; padding: 12px; border-radius: 6px; overflow-x: auto; color: #79c0ff; border: 1px solid #21262d; font-size: 13px; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>{escaped_title}</h1>
    <p>This standalone Proof of Concept demonstrates client-side JavaScript execution via parameter <code>{html.escape(param_name)}</code>.</p>
    <pre>{html.escape(target_exploit_url)}</pre>
    <a href="{html.escape(target_exploit_url)}" class="btn" target="_blank">Click Here to Launch Exploit</a>
  </div>
  <script>
    // Automatic navigation after 2 seconds
    setTimeout(function() {{
      window.location.href = {json_escape_url(target_exploit_url)};
    }}, 2000);
  </script>
</body>
</html>"""

        else:
            # POST form auto-submission
            return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{escaped_title}</title>
</head>
<body>
  <form id="pocForm" action="{html.escape(base_endpoint)}" method="POST">
    <input type="hidden" name="{html.escape(param_name)}" value="{escaped_payload}" />
  </form>
  <script>
    document.getElementById('pocForm').submit();
  </script>
</body>
</html>"""

    @staticmethod
    def generate_curl_command(
        method: str,
        url: str,
        param_name: str,
        payload: str,
        headers: Optional[Dict[str, str]] = None
    ) -> str:
        """Generate clean, copy-pasteable curl reproduction command."""
        method = (method or "GET").upper()
        headers = headers or {}

        parsed = urllib.parse.urlparse(url)
        base_endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if method == "GET":
            query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            query_params[param_name] = [payload]
            encoded_query = urllib.parse.urlencode(
                [(k, v[0] if isinstance(v, list) else v) for k, v in query_params.items()]
            )
            full_url = f"{base_endpoint}?{encoded_query}"
            
            cmd = f'curl -i -s -k -X GET "{full_url}"'
            for h_name, h_val in headers.items():
                cmd += f' -H "{h_name}: {h_val}"'
            return cmd

        else:
            cmd = f'curl -i -s -k -X POST "{base_endpoint}"'
            for h_name, h_val in headers.items():
                cmd += f' -H "{h_name}: {h_val}"'
            
            post_data = urllib.parse.urlencode({param_name: payload})
            cmd += f' --data "{post_data}"'
            return cmd

    @staticmethod
    def sanitize_markdown_report(text: str) -> str:
        """Remove broken markdown archaeology, raw debug fragments, and malformed URLs inside code blocks."""
        if not text:
            return ""

        # Remove markdown link syntax inside backticks or code blocks
        # e.g., `[https://target.com](https://target.com)` -> `https://target.com`
        text = re.sub(r'`\[([^\]]+)\]\([^\)]+\)`', r'`\1`', text)

        # Remove repetitive broken scanner fragments like 'svgsvg', 'javascriptjavascript'
        text = re.sub(r'\b(svg){2,}\b', 'svg', text, flags=re.IGNORECASE)
        text = re.sub(r'\b(javascript){2,}\b', 'javascript', text, flags=re.IGNORECASE)

        # Fix multiple blank lines
        text = re.sub(r'\n{3,}', '\n\n', text)
        return text.strip()


def json_escape_url(url: str) -> str:
    import json
    return json.dumps(url)
