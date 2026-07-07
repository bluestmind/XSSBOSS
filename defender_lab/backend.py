import html
import json
import logging
from fastapi import FastAPI, Query, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("defender-site")

app = FastAPI(title="Defender Shield - Security Lab")

# CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for logs, guestbook messages, and CSP reports
request_logs: List[Dict[str, Any]] = []
csp_reports: List[Dict[str, Any]] = []
vulnerable_messages: List[Dict[str, str]] = [{"name": "Admin", "message": "Welcome to the insecure guestbook!"}]
secure_messages: List[Dict[str, str]] = [{"name": "SecAdmin", "message": "Welcome to the protected guestbook!"}]

def log_request(method: str, path: str, ip: str, status: str, details: str = ""):
    """Helper to record request logs for the dashboard console."""
    request_logs.insert(0, {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "method": method,
        "path": path,
        "ip": ip,
        "status": status,
        "details": details
    })
    # Keep only the last 30 logs
    if len(request_logs) > 30:
        request_logs.pop()

def _page(title: str, body: str, csp_header: Optional[str] = None, extra_headers: bool = False) -> HTMLResponse:
    """Return a styled HTML document with optional security headers."""
    html_content = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>{html.escape(title)}</title>
  <style>
    body {{ font-family: sans-serif; background-color: #0b0f19; color: #f3f4f6; margin: 24px; line-height: 1.5; }}
    .box {{ border: 1px solid #1f2937; background-color: #111827; padding: 20px; margin: 15px 0; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
    h1 {{ color: #6366f1; border-bottom: 2px solid #1f2937; padding-bottom: 10px; }}
    a {{ color: #38bdf8; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 0.85em; font-weight: bold; }}
    .badge-secure {{ background-color: #065f46; color: #34d399; }}
    .badge-vulnerable {{ background-color: #7f1d1d; color: #fca5a5; }}
    pre {{ background-color: #030712; padding: 10px; border-radius: 6px; overflow-x: auto; border: 1px solid #1f2937; }}
    input, button {{ padding: 8px 12px; border-radius: 6px; border: 1px solid #374151; background-color: #1f2937; color: white; }}
    button {{ background-color: #4f46e5; border: none; cursor: pointer; }}
    button:hover {{ background-color: #4338ca; }}
  </style>
</head>
<body>
  {body}
</body>
</html>"""

    headers = {}
    if csp_header:
        headers["Content-Security-Policy"] = csp_header
    if extra_headers:
        headers["X-Content-Type-Options"] = "nosniff"
        headers["X-Frame-Options"] = "DENY"
        headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        headers["X-XSS-Protection"] = "0"  # Explicitly disable legacy XSS auditor to enforce modern CSP

    return HTMLResponse(content=html_content, headers=headers)

# --- 1. React Dashboard Front-End ---
@app.get("/")
def get_dashboard(request: Request):
    """Serves the main command-center dashboard page."""
    log_request("GET", "/", request.client.host, "Allowed", "Serves React Dashboard")
    # Read the template file
    template_path = Path(__file__).parent / "templates" / "index.html"
    try:
        with open(template_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse("<h3>Dashboard template not found. Please create f:/projects/XSSBOSS/defender_lab/templates/index.html</h3>")

# --- 2. API Endpoints ---
@app.get("/api/logs")
def get_logs(request: Request):
    """API for the React frontend to fetch live logs."""
    return JSONResponse({
        "logs": request_logs,
        "csp_reports": csp_reports,
        "vulnerable_messages": vulnerable_messages,
        "secure_messages": secure_messages
    })

@app.post("/api/csp-report")
async def csp_report(request: Request):
    """Receives CSP violation reports."""
    try:
        body = await request.body()
        data = json.loads(body)
        report = data.get("csp-report", {})
        csp_reports.insert(0, {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "blocked_uri": report.get("blocked-uri"),
            "violated_directive": report.get("violated-directive"),
            "original_policy": report.get("original-policy"),
            "source_file": report.get("source-file"),
            "line_number": report.get("line-number")
        })
        if len(csp_reports) > 30:
            csp_reports.pop()
        logger.warning(f"CSP VIOLATION REPORTED: {report.get('blocked-uri')} violated {report.get('violated-directive')}")
        log_request("POST", "/api/csp-report", request.client.host, "Blocked (CSP)", f"Violation: {report.get('blocked-uri')}")
        return JSONResponse({"status": "ok"})
    except Exception as e:
        logger.error(f"Error handling CSP report: {e}")
        return JSONResponse({"status": "error", "message": str(e)}, status_code=400)

@app.post("/api/guestbook/vulnerable")
def submit_vuln_guestbook(request: Request, name: str = Form(...), message: str = Form(...)):
    """Insecure message submission."""
    vulnerable_messages.append({"name": name, "message": message})
    log_request("POST", "/api/guestbook/vulnerable", request.client.host, "Allowed (Unescaped)", f"Saved stored XSS by {name}")
    return JSONResponse({"status": "success"})

@app.post("/api/guestbook/secure")
def submit_secure_guestbook(request: Request, name: str = Form(...), message: str = Form(...)):
    """Secure message submission with sanitization."""
    escaped_name = html.escape(name)
    escaped_message = html.escape(message)
    secure_messages.append({"name": escaped_name, "message": escaped_message})
    log_request("POST", "/api/guestbook/secure", request.client.host, "Allowed (Sanitized)", f"Saved sanitized msg by {escaped_name}")
    return JSONResponse({"status": "success"})

# --- 3. Vulnerable Playground Endpoints ---
@app.get("/vulnerable/html")
def vulnerable_html(request: Request, q: str = Query("")):
    """Directly reflects q in the HTML."""
    log_request("GET", f"/vulnerable/html?q={q[:15]}...", request.client.host, "VULNERABLE", "HTML Reflection")
    body = f"""
    <a href="/">&larr; Back to Command Center</a>
    <h1>HTML Context: Vulnerable reflection</h1>
    <span class="badge badge-vulnerable">Vulnerable</span>
    <div class="box">
        <p>Your search returned: <strong>{q}</strong></p>
    </div>
    """
    return _page("Vulnerable Search", body)

@app.get("/vulnerable/attr")
def vulnerable_attr(request: Request, name: str = Query("")):
    """Reflects name inside a quoted attribute."""
    log_request("GET", f"/vulnerable/attr?name={name[:15]}...", request.client.host, "VULNERABLE", "Attribute Reflection")
    body = f"""
    <a href="/">&larr; Back to Command Center</a>
    <h1>Attribute Context: Vulnerable reflection</h1>
    <span class="badge badge-vulnerable">Vulnerable</span>
    <div class="box">
        <p>Edit Profile:</p>
        <input type="text" value="{name}" style="width: 100%; max-width: 400px;" />
    </div>
    """
    return _page("Vulnerable Attribute", body)

@app.get("/vulnerable/js")
def vulnerable_js(request: Request, term: str = Query("")):
    """Reflects term inside a script tag."""
    log_request("GET", f"/vulnerable/js?term={term[:15]}...", request.client.host, "VULNERABLE", "Script Reflection")
    body = f"""
    <a href="/">&larr; Back to Command Center</a>
    <h1>Script Context: Vulnerable reflection</h1>
    <span class="badge badge-vulnerable">Vulnerable</span>
    <div class="box">
        <p id="output">Waiting for JavaScript execution...</p>
    </div>
    <script>
        const reflectedTerm = "{term}";
        document.getElementById("output").textContent = "Parsed JS term: " + reflectedTerm;
    </script>
    """
    return _page("Vulnerable JS String", body)

@app.get("/vulnerable/dom")
def vulnerable_dom(request: Request, next: str = Query("")):
    """DOM XSS using client-side innerHTML assignment."""
    log_request("GET", f"/vulnerable/dom?next={next[:15]}...", request.client.host, "VULNERABLE", "DOM Client reflection")
    body = f"""
    <a href="/">&larr; Back to Command Center</a>
    <h1>DOM Context: Vulnerable client-side reflection</h1>
    <span class="badge badge-vulnerable">Vulnerable</span>
    <div class="box">
        <p>Rendered via innerHTML:</p>
        <div id="output-sink">Loading URL parameter...</div>
    </div>
    <script>
        setTimeout(function() {{
            const urlParams = new URLSearchParams(window.location.search);
            const nextParam = urlParams.get('next') || '';
            document.getElementById("output-sink").innerHTML = nextParam;
        }}, 100);
    </script>
    """
    return _page("Vulnerable DOM Sink", body)

# --- 4. Secure Defender Endpoints ---
@app.get("/secure/html")
def secure_html(request: Request, q: str = Query("")):
    """Reflects q with HTML escaping."""
    log_request("GET", f"/secure/html?q={q[:15]}...", request.client.host, "PROTECTED", "HTML Escaping")
    escaped_q = html.escape(q)
    body = f"""
    <a href="/">&larr; Back to Command Center</a>
    <h1>HTML Context: Protected reflection</h1>
    <span class="badge badge-secure">Secure (HTML Encoded)</span>
    <div class="box">
        <p>Your search returned: <strong>{escaped_q}</strong></p>
    </div>
    """
    # Enforce strict headers and CSP
    csp = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none';"
    return _page("Secure Search", body, csp_header=csp, extra_headers=True)

@app.get("/secure/attr")
def secure_attr(request: Request, name: str = Query("")):
    """Reflects name inside a quoted attribute with HTML attribute escaping."""
    log_request("GET", f"/secure/attr?name={name[:15]}...", request.client.host, "PROTECTED", "Attribute Escaping")
    escaped_name = html.escape(name, quote=True)
    body = f"""
    <a href="/">&larr; Back to Command Center</a>
    <h1>Attribute Context: Protected reflection</h1>
    <span class="badge badge-secure">Secure (Attribute Encoded)</span>
    <div class="box">
        <p>Edit Profile:</p>
        <input type="text" value="{escaped_name}" style="width: 100%; max-width: 400px;" />
    </div>
    """
    csp = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none';"
    return _page("Secure Attribute", body, csp_header=csp, extra_headers=True)

@app.get("/secure/js")
def secure_js(request: Request, term: str = Query("")):
    """Reflects term inside a script tag using JSON serialization to block breakouts."""
    log_request("GET", f"/secure/js?term={term[:15]}...", request.client.host, "PROTECTED", "JS Serialization")
    # Neutralize script tags by escaping </script> using json.dumps
    safe_term = json.dumps(term).replace("</", "<\\/")
    body = f"""
    <a href="/">&larr; Back to Command Center</a>
    <h1>Script Context: Protected reflection</h1>
    <span class="badge badge-secure">Secure (JSON Encoded)</span>
    <div class="box">
        <p id="output">Waiting for JavaScript execution...</p>
    </div>
    <script>
        const reflectedTerm = {safe_term};
        document.getElementById("output").textContent = "Parsed JS term: " + reflectedTerm;
    </script>
    """
    csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; object-src 'none';"
    return _page("Secure JS String", body, csp_header=csp, extra_headers=True)

@app.get("/secure/dom")
def secure_dom(request: Request, next: str = Query("")):
    """DOM XSS blocked via textContent rendering and CSP Trusted Types requirement."""
    log_request("GET", f"/secure/dom?next={next[:15]}...", request.client.host, "PROTECTED", "Trusted Types / textContent")
    body = f"""
    <a href="/">&larr; Back to Command Center</a>
    <h1>DOM Context: Protected DOM reflection</h1>
    <span class="badge badge-secure">Secure (textContent & CSP)</span>
    <div class="box">
        <p>Rendered safely via textContent:</p>
        <div id="output-sink">Loading URL parameter...</div>
    </div>
    <script>
        setTimeout(function() {{
            const urlParams = new URLSearchParams(window.location.search);
            const nextParam = urlParams.get('next') || '';
            // Safe DOM insertion using textContent
            document.getElementById("output-sink").textContent = nextParam;
        }}, 100);
    </script>
    """
    # Enforce strict CSP with Trusted Types requirement
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "require-trusted-types-for 'script'; "
        "report-uri /api/csp-report;"
    )
    return _page("Secure DOM Sink", body, csp_header=csp, extra_headers=True)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8085, log_level="info")
