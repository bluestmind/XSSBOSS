"""Login-form auto-discovery + end-to-end authenticated-session proof.

Unit-tests the zero-config selector discovery, then drives the real `authenticate_selenium`
login logic against a fake authenticated site (login form -> session -> behind-login sink) to
prove the whole chain works together, including the human-escalation guardrails — the part the
existing unit tests do not cover.
"""
import pytest

from backend_api.services.auth_session_service import (
    AuthSessionService,
    HumanInterventionRequired,
)

ORIGIN = "http://authlab.test"

LOGIN_HTML = """
<html><body><h1>Sign in</h1>
<form action="/session">
  <input id="user" name="username" type="text">
  <input id="pass" name="password" type="password">
  <button id="go" type="submit">Log in</button>
</form></body></html>
"""
DASH_HTML = '<html><body><h1>Welcome, admin</h1><a href="/logout">Logout</a></body></html>'
HOME_HTML = '<html><body><a href="/dashboard">Dashboard</a></body></html>'
MFA_HTML = '<html><body><h1>Verify your identity</h1><p>Enter the verification code</p></body></html>'


# --------------------------------------------------------------- discovery units

def test_discover_login_form_by_id():
    sel = AuthSessionService.discover_login_form(LOGIN_HTML)
    assert sel == {
        "username_selector": "#user",
        "password_selector": "#pass",
        "submit_selector": "#go",
    }


def test_discover_login_form_by_name_when_no_id():
    html = """
    <form><input name="email" type="text"><input name="pass" type="password">
    <input type="submit" value="go"></form>
    """
    sel = AuthSessionService.discover_login_form(html)
    assert sel["username_selector"] == "input[name='email']"
    assert sel["password_selector"] == "input[name='pass']"
    assert "submit" in sel["submit_selector"]


def test_discover_prefers_username_hinted_field():
    # Two text inputs before password; the identity-hinted one should win.
    html = """
    <form><input name="search" type="text"><input id="login_email" type="text">
    <input name="password" type="password"><button type="submit">x</button></form>
    """
    sel = AuthSessionService.discover_login_form(html)
    assert sel["username_selector"] == "#login_email"


def test_discover_returns_none_without_password_field():
    assert AuthSessionService.discover_login_form("<form><input name=q></form>") is None


# --------------------------------------------------------------- fake auth site

class _FakeEl:
    def __init__(self, driver, selector):
        self._d, self._sel = driver, selector

    def clear(self):
        pass

    def send_keys(self, value):
        self._d._type(self._sel, value)

    def click(self):
        self._d._click(self._sel)


class FakeAuthDriver:
    """A minimal Selenium-shaped driver modeling a login form + behind-login reflected sink."""

    def __init__(self, valid_user, valid_pass, mfa=False):
        self.valid = (valid_user, valid_pass)
        self.mfa = mfa
        self.authenticated = False
        self.current_url = ORIGIN + "/"
        self.page_source = HOME_HTML
        self._typed = {}

    # --- selenium API surface used by authenticate_selenium ---
    def execute_cdp_cmd(self, *_a, **_k):
        return {}

    def add_cookie(self, _cookie):
        pass

    def execute_script(self, *_a, **_k):
        return None

    def get_cookies(self):
        return [{"name": "session", "value": "sess-xyz"}] if self.authenticated else []

    def find_element(self, _by, selector):
        return _FakeEl(self, selector)

    def get(self, url):
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        path, query = parsed.path or "/", parsed.query
        if path in ("/login", "/session"):
            self.current_url = ORIGIN + "/login"
            self.page_source = MFA_HTML if self.mfa else LOGIN_HTML
        elif path == "/dashboard":
            if self.authenticated:
                self.current_url, self.page_source = ORIGIN + "/dashboard", DASH_HTML
            else:
                self.current_url = ORIGIN + "/login"
                self.page_source = MFA_HTML if self.mfa else LOGIN_HTML
        elif path.startswith("/search"):
            if self.authenticated:
                q = parse_qs(query).get("q", [""])[0]
                self.current_url = ORIGIN + "/search"
                self.page_source = f"<html><body><div>Results for {q}</div></body></html>"
            else:
                self.current_url, self.page_source = ORIGIN + "/login", LOGIN_HTML
        else:
            self.current_url, self.page_source = ORIGIN + "/", HOME_HTML

    # --- fake form behavior ---
    def _type(self, selector, value):
        s = selector.lower()
        if "pass" in s:
            self._typed["password"] = value
        else:
            self._typed["username"] = value

    def _click(self, _selector):
        if self._typed.get("username") == self.valid[0] and self._typed.get("password") == self.valid[1]:
            self.authenticated = True
            self.current_url, self.page_source = ORIGIN + "/dashboard", DASH_HTML
        else:
            self.current_url, self.page_source = ORIGIN + "/login", LOGIN_HTML


# --------------------------------------------------------------- end-to-end chain

def _auth_info(password="hunter2"):
    # NOTE: no selectors declared -> exercises auto-discovery.
    return {
        "login": {"url": "/login", "username": "admin", "password": password, "wait_seconds": 0},
        "health_check_url": "/dashboard",
    }


def test_e2e_login_then_reach_behind_login_sink():
    driver = FakeAuthDriver("admin", "hunter2")
    result = AuthSessionService.authenticate_selenium(driver, ORIGIN + "/", _auth_info())

    # 1. It detected the auth wall, auto-discovered the form, logged in, and is authenticated.
    assert result["authenticated"] is True
    assert driver.authenticated is True
    assert "session" in result["cookies"]

    # 2. The behind-login sink is now reachable and reflects our probe with the live session.
    driver.get(ORIGIN + "/search?q=XSSPROBE_9f3")
    assert "XSSPROBE_9f3" in driver.page_source


def test_e2e_wrong_credentials_escalate_to_human():
    driver = FakeAuthDriver("admin", "hunter2")
    with pytest.raises(HumanInterventionRequired):
        AuthSessionService.authenticate_selenium(driver, ORIGIN + "/", _auth_info(password="WRONG"))
    assert driver.authenticated is False


def test_e2e_mfa_challenge_escalates_to_human():
    driver = FakeAuthDriver("admin", "hunter2", mfa=True)
    with pytest.raises(HumanInterventionRequired):
        AuthSessionService.authenticate_selenium(driver, ORIGIN + "/", _auth_info())


def test_e2e_explicit_selectors_also_work():
    info = _auth_info()
    info["login"].update({"username_selector": "#user", "password_selector": "#pass", "submit_selector": "#go"})
    driver = FakeAuthDriver("admin", "hunter2")
    result = AuthSessionService.authenticate_selenium(driver, ORIGIN + "/", info)
    assert result["authenticated"] is True
