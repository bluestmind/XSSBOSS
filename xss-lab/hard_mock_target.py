"""Hard local XSS target for end-to-end scanner testing.

This app is intentionally vulnerable and should only be bound locally.
It gives XSS Boss a mix of real executable cases and safe controls.
"""
import html
import json
import re

from fastapi import FastAPI, Form, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse


app = FastAPI(title="XSS Boss Hard Local Lab")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _page(title: str, body: str, extra_head: str = "") -> HTMLResponse:
    """Return a small HTML document."""
    return HTMLResponse(
        f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>{html.escape(title)}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; line-height: 1.45; }}
    .box {{ border: 1px solid #ccc; padding: 12px; margin: 12px 0; }}
    @keyframes x {{ from {{ opacity: .99; }} to {{ opacity: 1; }} }}
  </style>
  {extra_head}
</head>
<body>
  <h1>{html.escape(title)}</h1>
  {body}
</body>
</html>"""
    )


def _casefold_filter(value: str) -> str:
    """A deliberately naive filter that blocks common XSS tokens only."""
    blocked = [
        r"<\s*/?\s*script\b",
        r"javascript\s*:",
        r"onerror",
        r"srcdoc",
        r"expression\s*\(",
    ]
    filtered = value
    for pattern in blocked:
        filtered = re.sub(pattern, "", filtered, flags=re.IGNORECASE)
    return filtered


def _safe_js_string(value: str) -> str:
    """Encode a JS string and neutralize HTML parser script end tags."""
    return json.dumps(value).replace("</", "<\\/")


@app.get("/")
def index():
    """Human-readable route catalog."""
    routes = [
        ("GET", "/hard/html?q=", "raw HTML reflection"),
        ("GET", "/hard/filter-bypass?q=", "naive filter bypass reflection"),
        ("GET", "/hard/extreme-filter?q=", "extreme filter bypass (no quotes/parentheses)"),
        ("GET", "/hard/attr-quoted?name=", "quoted attribute breakout"),
        ("GET", "/hard/attr-unquoted?probe=", "unquoted attribute breakout"),
        ("GET", "/hard/js-string?term=", "JavaScript string breakout"),
        ("GET", "/hard/event?handler=", "event handler JavaScript context"),
        ("GET", "/hard/json-script?data=", "JSON-in-script breakout"),
        ("GET", "/hard/dom-sink?next=", "delayed DOM innerHTML sink"),
        ("GET", "/hard/post-message", "postMessage to innerHTML sink"),
        ("GET", "/hard/prototype-pollution", "query/hash prototype pollution gadget"),
        ("GET", "/hard/dom-clobber?q=", "DOM clobbering named-property gadget"),
        ("GET", "/hard/trusted-types?next=", "Trusted Types/CSP telemetry route"),
        ("POST", "/hard/post-body note=", "form body reflection"),
        ("POST", "/hard/post-json message=", "JSON body reflection"),
        ("GET", "/hard/safe-html?q=", "escaped safe control"),
        ("GET", "/hard/safe-js?term=", "JS encoded safe control"),
    ]
    items = "\n".join(
        f"<li><code>{method} {html.escape(path)}</code> - {html.escape(desc)}</li>"
        for method, path, desc in routes
    )
    return _page("XSS Boss Hard Local Lab", f"<ul>{items}</ul>")


@app.get("/hard/html")
def hard_html(q: str = Query("")):
    """Raw HTML reflection: should be easy for HTML_TEXT payloads."""
    return _page(
        "Hard Case: Raw HTML",
        f"""
<div class="box">
  <p>Search result:</p>
  <div id="html-reflection">{q}</div>
</div>
""",
    )


@app.get("/hard/filter-bypass")
def hard_filter_bypass(q: str = Query("")):
    """Naive filter bypass case: common tokens fail, alternate events survive."""
    filtered = _casefold_filter(q)
    return _page(
        "Hard Case: Naive Filter Bypass",
        f"""
<div class="box">
  <p>Filtered result:</p>
  <div id="filtered-reflection">{filtered}</div>
</div>
""",
    )


@app.get("/hard/extreme-filter")
def hard_extreme_filter(q: str = Query("")):
    """Extreme filter: blocks quotes (', "), parentheses ((), ()), and common keywords (script, onerror, onload).
    Bypassed using backticks, svg animate, and alternative event attributes!
    """
    blocked = ["script", "onerror", "onload", "javascript", "(", ")", "'", "\""]
    filtered = q
    for token in blocked:
        filtered = re.sub(re.escape(token), "", filtered, flags=re.IGNORECASE)
    return _page(
        "Extreme Case: Stringent Filter Bypass",
        f"""
<div class="box">
  <p>Result under strict filter:</p>
  <div id="extreme-reflection">{filtered}</div>
</div>
""",
    )


@app.get("/hard/attr-quoted")
def hard_attr_quoted(name: str = Query("")):
    """Quoted attribute reflection."""
    return _page(
        "Hard Case: Quoted Attribute",
        f"""
<div class="box">
  <label for="name-input">Name</label>
  <input id="name-input" value="{name}" placeholder="quoted attribute">
</div>
""",
    )


@app.get("/hard/attr-unquoted")
def hard_attr_unquoted(probe: str = Query("")):
    """Unquoted attribute reflection on an image with an invalid source."""
    return _page(
        "Hard Case: Unquoted Attribute",
        f"""
<div class="box">
  <img id="probe-image" src=x data-probe={probe} alt="broken image probe">
</div>
""",
    )


@app.get("/hard/js-string")
def hard_js_string(term: str = Query("")):
    """JavaScript string reflection."""
    return _page(
        "Hard Case: JavaScript String",
        f"""
<div class="box" id="js-output">Waiting for script...</div>
<script>
  const reflectedTerm = "{term}";
  document.getElementById('js-output').textContent = reflectedTerm;
</script>
""",
    )


@app.get("/hard/event")
def hard_event(handler: str = Query("")):
    """Event handler attribute with a synthetic event to remove user interaction."""
    return _page(
        "Hard Case: Event Handler",
        f"""
<div class="box">
  <button id="event-button" onpointerenter="{handler}">Synthetic pointer target</button>
</div>
<script>
  setTimeout(function() {{
    var button = document.getElementById('event-button');
    button.dispatchEvent(new PointerEvent('pointerenter', {{ bubbles: true }}));
  }}, 50);
</script>
""",
    )


@app.get("/hard/json-script")
def hard_json_script(data: str = Query("")):
    """JSON script tag reflection that is vulnerable to HTML parser breakouts."""
    return _page(
        "Hard Case: JSON Script Breakout",
        f"""
<script id="boot-state" type="application/json">{{"profile":"{data}"}}</script>
<div class="box" id="boot-output">State loaded</div>
""",
    )


@app.get("/hard/dom-sink")
def hard_dom_sink():
    """Client-side DOM sink fed by query string."""
    return _page(
        "Hard Case: Delayed DOM Sink",
        """
<div class="box" id="sink">DOM sink waiting...</div>
<script>
  setTimeout(function() {
    var value = new URLSearchParams(location.search).get('next') || '';
    document.getElementById('sink').innerHTML = value;
  }, 75);
</script>
""",
    )


@app.get("/hard/post-message")
def hard_post_message():
    """postMessage source flowing to innerHTML."""
    return _page(
        "Hard Case: postMessage DOM Sink",
        """
<div class="box" id="message-sink">Waiting for message...</div>
<script>
  window.addEventListener('message', function(event) {
    var value = event.data;
    if (typeof value !== 'string') {
      value = value && (value.html || value.content || value.message || value.data || JSON.stringify(value));
    }
    document.getElementById('message-sink').innerHTML = value || '';
  });
</script>
""",
    )


@app.get("/hard/post-message-origin-weak")
def hard_post_message_origin_weak():
    """postMessage sink guarded by flawed startsWith/endsWith origin checks."""
    return _page(
        "Hard Case: Weak postMessage Origin Check",
        """
<div class="box" id="message-sink">Waiting for trusted message...</div>
<script>
  window.addEventListener('message', function(event) {
    var origin = event.origin || '';
    var expectedOrigin = location.origin;
    var expectedHost = location.host;
    if (!(origin.startsWith(expectedOrigin) && origin.endsWith(expectedHost))) {
      document.getElementById('message-sink').textContent = 'Blocked origin: ' + origin;
      return;
    }

    var value = event.data;
    if (typeof value !== 'string') {
      value = value && (value.html || value.content || value.message || value.data || JSON.stringify(value));
    }
    document.getElementById('message-sink').innerHTML = value || '';
  });
</script>
""",
    )


@app.get("/hard/prototype-pollution")
def hard_prototype_pollution():
    """Prototype pollution gadget that reads inherited config.html."""
    return _page(
        "Hard Case: Prototype Pollution Gadget",
        """
<div class="box" id="pollution-sink">Prototype config waiting...</div>
<script>
  function assignPath(root, key, value) {
    var parts = key.replace(/\\]/g, '').split(/[.\\[]/).filter(Boolean);
    var current = root;
    for (var i = 0; i < parts.length - 1; i++) {
      var part = parts[i];
      if (!current[part]) current[part] = {};
      current = current[part];
    }
    current[parts[parts.length - 1]] = value;
  }

  var params = new URLSearchParams(location.search);
  if (location.hash.length > 1) {
    new URLSearchParams(location.hash.slice(1)).forEach(function(value, key) {
      params.append(key, value);
    });
  }
  params.forEach(function(value, key) {
    assignPath({}, key, value);
  });

  var config = {};
  if (config.html) {
    document.getElementById('pollution-sink').innerHTML = config.html;
  }
</script>
""",
    )


@app.get("/hard/dom-clobber")
def hard_dom_clobber(q: str = Query("")):
    """DOM clobbering gadget that trusts a named global property."""
    return _page(
        "Hard Case: DOM Clobbering",
        f"""
<div class="box" id="clobber-zone">{q}</div>
<script>
  setTimeout(function() {{
    if (window.redirectTo && redirectTo.href && redirectTo.href.indexOf('javascript:') === 0) {{
      setTimeout(redirectTo.href.slice('javascript:'.length), 0);
    }}
  }}, 50);
</script>
""",
    )


@app.get("/hard/trusted-types")
def hard_trusted_types(next: str = Query("")):
    """Trusted Types/CSP route for telemetry checks."""
    response = _page(
        "Hard Case: Trusted Types Telemetry",
        f"""
<div class="box" id="tt-sink">Trusted Types route</div>
<script>
  try {{
    document.getElementById('tt-sink').innerHTML = "{next}";
  }} catch (err) {{
    console.log('Trusted Types blocked assignment', err && err.message);
  }}
</script>
""",
    )
    response.headers["Content-Security-Policy"] = "require-trusted-types-for 'script'; trusted-types default"
    return response


@app.post("/hard/post-body")
def hard_post_body(note: str = Form("")):
    """POST form reflection."""
    return _page(
        "Hard Case: POST Body",
        f"""
<div class="box">
  <p>Saved note:</p>
  <div id="note-output">{note}</div>
</div>
""",
    )


@app.post("/hard/post-json")
async def hard_post_json(request: Request):
    """POST JSON reflection inside a script block."""
    payload = await request.json()
    message = str(payload.get("message", ""))
    return _page(
        "Hard Case: POST JSON",
        f"""
<script>
  window.__hardJsonMessage = "{message}";
</script>
<div class="box">JSON accepted</div>
""",
    )


@app.get("/hard/safe-html")
def safe_html(q: str = Query("")):
    """Escaped HTML control: should reflect but not execute."""
    return _page(
        "Safe Control: Escaped HTML",
        f"""
<div class="box">
  <p>Escaped result:</p>
  <div id="safe-html">{html.escape(q)}</div>
</div>
""",
    )


@app.get("/hard/safe-js")
def safe_js(term: str = Query("")):
    """Safely encoded JavaScript string control."""
    encoded = _safe_js_string(term)
    return _page(
        "Safe Control: Encoded JavaScript",
        f"""
<div class="box" id="safe-js-output"></div>
<script>
  const safeTerm = {encoded};
  document.getElementById('safe-js-output').textContent = safeTerm;
</script>
""",
    )


stored_db = {"message": "Hello"}

@app.post("/hard/stored-post")
def hard_stored_post(msg: str = Form("")):
    """Submit payload to stored memory database."""
    stored_db["message"] = msg
    return JSONResponse({"status": "success", "message": "Saved"})


@app.get("/hard/stored-view")
def hard_stored_view():
    """Retrieve stored memory database and reflect it into HTML."""
    msg = stored_db.get("message", "")
    return _page(
        "Hard Case: Stored XSS View",
        f"""
<div class="box">
  <p>Stored Message:</p>
  <div id="stored-msg">{msg}</div>
</div>
"""
    )


@app.get("/hard/wizard")
def hard_wizard():
    """Multi-step interactive wizard page requiring stateful action chains."""
    return _page(
        "Hard Case: Interactive Wizard",
        """
<div class="box" id="wizard-container">
  <h3>Step 1: User Profile</h3>
  <label for="step1-input">username:</label>
  <input id="step1-input" type="text" placeholder="Enter username">
  <button id="submit-step1" onclick="goToStep2()">Next</button>
</div>

<script>
  var username = "";
  function goToStep2() {
    username = document.getElementById('step1-input').value;
    document.getElementById('wizard-container').innerHTML = `
      <h3>Step 2: Custom Status</h3>
      <label for="step2-input">Status Message:</label>
      <input id="step2-input" type="text" placeholder="Enter status message">
      <button id="submit-step2" onclick="goToStep3()">Finish</button>
    `;
  }
  function goToStep3() {
    var status = document.getElementById('step2-input').value;
    document.getElementById('wizard-container').innerHTML = `
      <h3>Step 3: Summary</h3>
      <p>User <strong>` + username + `</strong> status message:</p>
      <div id="wizard-sink"></div>
    `;
    // Vulnerable sink reflecting status input
    document.getElementById('wizard-sink').innerHTML = status;
  }
</script>
        """
    )


@app.get("/health")
def health():
    """Health endpoint for scripts."""
    return JSONResponse({"status": "ok", "service": "hard-local-lab"})


@app.get("/hard/reset-state")
def hard_reset_state():
    """Reset the mock target server memory databases."""
    global stored_db
    stored_db = {"message": "Hello"}
    return JSONResponse({"status": "success", "message": "State reset successfully"})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("hard_mock_target:app", host="127.0.0.1", port=8099, log_level="info")
