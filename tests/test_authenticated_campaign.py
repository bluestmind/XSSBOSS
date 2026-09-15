"""End-to-end unit coverage for authenticated, stateful campaign operation."""
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from backend_api.models.base import Base
from backend_api.models.experiment import Experiment, ExperimentStatus, ExperimentStrategy
from backend_api.models.endpoint import Endpoint
from backend_api.models.run_state import RunStage, RunStageName, RunStageStatus
from backend_api.models.target import Target
from backend_api.schemas.endpoint import EndpointResponse
from backend_api.services.auth_session_service import (
    AuthConfigurationError,
    AuthSessionService,
    HumanInterventionRequired,
)
from backend_api.services.fuzzing_service import FuzzingService
from backend_api.services.human_intervention_service import HumanInterventionService
from backend_api.services.recon_service import ReconService
from backend_api.services.stored_xss_verifier import StoredXSSVerifier
from browser_workers.executor import BrowserExecutor


AUTH_INFO = {
    "default_identity": "author",
    "revisit_identities": ["admin"],
    "identities": {
        "author": {
            "role": "user",
            "headers": {"Authorization": "Bearer author-token"},
            "cookies": {"session": "author-cookie"},
            "login": {
                "url": "/login",
                "username": "author@example.test",
                "password": "correct horse",
            },
            "health_check_url": "/account",
        },
        "admin": {
            "role": "admin",
            "cookies": {"session": "admin-cookie"},
            "login": {
                "url": "/login",
                "username": "admin@example.test",
                "password": "battery staple",
            },
        },
    },
}


def _db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def test_legacy_and_multi_identity_request_material():
    legacy = {"Authorization": "Bearer old", "Cookie": "sid=one; theme=dark"}
    context = AuthSessionService.request_context(legacy)
    assert context["Authorization"] == "Bearer old"
    assert context["Cookie"] == "sid=one; theme=dark"

    author = AuthSessionService.request_context(AUTH_INFO, "author", {"X-Request": "yes"})
    assert author["Authorization"] == "Bearer author-token"
    assert author["Cookie"] == "session=author-cookie"
    assert author["X-Request"] == "yes"
    assert AuthSessionService.identity_labels(AUTH_INFO) == ["author", "admin"]
    with pytest.raises(AuthConfigurationError, match="Unknown"):
        AuthSessionService.material(AUTH_INFO, "missing")


def test_auth_api_view_redacts_credentials_and_sessions():
    public = AuthSessionService.sanitize_public(AUTH_INFO)
    author = public["identities"]["author"]
    assert author["headers"]["Authorization"] == "***configured***"
    assert author["cookies"] == "***configured***"
    assert author["login"]["password"] == "***configured***"
    assert "correct horse" not in str(public)
    assert "author-token" not in str(public)


def test_auth_wall_and_challenge_detection():
    assert AuthSessionService.is_auth_wall(status_code=401, final_url="https://app.test/")
    assert AuthSessionService.is_auth_wall(final_url="https://app.test/login?next=/account")
    assert AuthSessionService.challenge_reason("Complete the hCaptcha to continue") == "captcha"
    assert not AuthSessionService.is_auth_wall(status_code=200, final_url="https://app.test/account")
    assert AuthSessionService.operational_barrier_reason(429, "") == "target rate limit or temporary ban"
    assert AuthSessionService.operational_barrier_reason(403, "Cloudflare Ray ID: 123") == "WAF or anti-bot block"
    assert AuthSessionService.challenge_reason("<script>const captcha = true</script><main>Welcome</main>") is None


def test_declared_stored_render_edges_are_scoped():
    auth = {
        **AUTH_INFO,
        "workflows": [{
            "name": "draft",
            "identity": "author",
            "steps": [],
            "submit_pattern": "*/drafts/new*",
            "render_urls": ["/drafts", "/admin/moderation"],
        }],
    }
    assert AuthSessionService.stored_render_urls(
        auth, "https://app.test/drafts/new", "https://app.test"
    ) == ["https://app.test/drafts", "https://app.test/admin/moderation"]


class _Element:
    def __init__(self, driver, submit=False):
        self.driver = driver
        self.submit = submit
        self.value = ""

    def clear(self):
        self.value = ""

    def send_keys(self, value):
        self.value += str(value)

    def click(self):
        if self.submit:
            self.driver.current_url = "https://app.test/dashboard"
            self.driver.page_source = "<main>Welcome</main>"
            self.driver.logged_in = True


class _SeleniumDriver:
    def __init__(self, challenge=False):
        self.current_url = "about:blank"
        self.page_source = ""
        self.challenge = challenge
        self.logged_in = False
        self.headers = {}
        self.cookies = []

    def execute_cdp_cmd(self, name, payload):
        if name == "Network.setExtraHTTPHeaders":
            self.headers = payload["headers"]

    def get(self, url):
        if self.challenge:
            self.current_url = url
            self.page_source = "<div>Please complete CAPTCHA</div>"
        elif self.logged_in:
            self.current_url = url
            self.page_source = "<main>Welcome</main>"
        elif url.endswith("/account") or url.rstrip("/") == "https://app.test":
            self.current_url = "https://app.test/login?next=/account"
            self.page_source = '<form>Sign in<input name="password"></form>'
        else:
            self.current_url = url
            self.page_source = '<form>Sign in<input name="password"></form>'

    def add_cookie(self, cookie):
        self.cookies.append(cookie)

    def execute_script(self, *args):
        return None

    def find_element(self, by, selector):
        return _Element(self, submit="submit" in selector)

    def get_cookies(self):
        rows = [{"name": item["name"], "value": item["value"]} for item in self.cookies]
        if self.logged_in:
            rows.append({"name": "session", "value": "renewed-cookie"})
        return rows


def test_selenium_login_renews_and_captures_session(monkeypatch):
    monkeypatch.setattr("backend_api.services.auth_session_service.time.sleep", lambda _: None)
    driver = _SeleniumDriver()
    state = AuthSessionService.authenticate_selenium(driver, "https://app.test", AUTH_INFO, "author")
    assert state["authenticated"] is True
    assert state["cookies"]["session"] == "renewed-cookie"
    assert driver.headers == {}
    assert state["header_auth_omitted"] is True
    assert driver.current_url == "https://app.test/dashboard"


class _RouteRequest:
    def __init__(self, url):
        self.url = url
        self.headers = {"Authorization": "stale", "Accept": "text/html"}


class _HeaderRoute:
    def __init__(self, url):
        self.request = _RouteRequest(url)
        self.forwarded = None

    def fallback(self, *, headers):
        self.forwarded = headers


class _HeaderContext:
    def __init__(self):
        self.callback = None

    def route(self, pattern, callback):
        self.callback = callback

    def unroute(self, pattern, callback):
        if self.callback is callback:
            self.callback = None


def test_playwright_headers_are_bound_to_exact_authorized_origins():
    context = _HeaderContext()
    AuthSessionService.bind_playwright_headers(
        context,
        "https://app.test",
        {"Authorization": "Bearer secret"},
        ["https://api.app.test:8443"],
    )

    first_party = _HeaderRoute("https://app.test/account")
    context.callback(first_party)
    assert first_party.forwarded["Authorization"] == "Bearer secret"

    approved = _HeaderRoute("https://api.app.test:8443/v1")
    context.callback(approved)
    assert approved.forwarded["Authorization"] == "Bearer secret"

    third_party = _HeaderRoute("https://cdn.invalid/bundle.js")
    context.callback(third_party)
    assert "Authorization" not in third_party.forwarded
    assert third_party.forwarded["Accept"] == "text/html"


def test_allowed_auth_origins_reject_wildcards_and_paths():
    with pytest.raises(AuthConfigurationError, match="exact HTTP"):
        AuthSessionService.material({
            "headers": {"Authorization": "x"},
            "allowed_auth_origins": ["https://*.app.test"],
        })
    with pytest.raises(AuthConfigurationError, match="exact HTTP"):
        AuthSessionService.material({
            "headers": {"Authorization": "x"},
            "allowed_auth_origins": ["https://app.test/private"],
        })


def test_selenium_challenge_escalates_without_guessing(monkeypatch):
    monkeypatch.setattr("backend_api.services.auth_session_service.time.sleep", lambda _: None)
    with pytest.raises(HumanInterventionRequired, match="challenge"):
        AuthSessionService.authenticate_selenium(
            _SeleniumDriver(challenge=True), "https://app.test", AUTH_INFO, "author"
        )


class _Response:
    status = 200


class _PlaywrightPage:
    def __init__(self):
        self.url = "about:blank"
        self._content = "<main>Welcome</main>"
        self._console = None

    def goto(self, url):
        self.url = url
        if url.endswith("/view") and self._console:
            self._console(type("Message", (), {"text": "XSS Oracle: Execution detected token-123"})())
        return _Response()

    def content(self):
        return self._content

    def on(self, event, callback):
        if event == "console":
            self._console = callback

    def evaluate(self, script, arg=None):
        return None

    def wait_for_timeout(self, milliseconds):
        return None

    def fill(self, selector, value):
        return None

    def click(self, selector):
        self.url = "https://app.test/dashboard"

    def press(self, selector, key):
        return None

    def wait_for_selector(self, selector):
        return None


class _PlaywrightContext:
    def __init__(self):
        self.page = _PlaywrightPage()
        self.cookie_rows = []
        self.scripts = []

    def add_cookies(self, rows):
        self.cookie_rows.extend(rows)

    def add_init_script(self, script):
        self.scripts.append(script)

    def cookies(self):
        return self.cookie_rows

    def new_page(self):
        return self.page

    def set_default_navigation_timeout(self, value):
        return None

    def set_default_timeout(self, value):
        return None

    def close(self):
        return None


class _PlaywrightBrowser:
    def __init__(self):
        self.contexts = []

    def new_context(self, **kwargs):
        context = _PlaywrightContext()
        self.contexts.append(context)
        return context


def test_playwright_identity_and_cross_account_revisit():
    browser = _PlaywrightBrowser()
    executor = BrowserExecutor()
    executor.browser = browser
    admin_spec = AuthSessionService.material(AUTH_INFO, "admin").browser_spec()
    results = executor._execute_cross_identity_revisits(
        "https://app.test/view",
        "https://app.test",
        "token-123",
        [admin_spec],
    )
    assert results == [{
        "identity": "admin",
        "oracle_hit": True,
        "final_url": "https://app.test/view",
    }]
    assert browser.contexts[0].cookie_rows[0]["value"] == "admin-cookie"


def test_recon_injects_target_identity_into_endpoint():
    db = _db()
    target = Target(
        name="Authenticated app",
        base_url="https://app.test",
        tenant_id=1,
        scope_tags={"allowed_hosts": ["app.test"]},
        auth_info=AUTH_INFO,
    )
    db.add(target)
    db.commit()
    endpoint = ReconService.create_endpoint_from_request(
        db,
        target.id,
        "GET",
        "https://app.test/profile?q=one",
        {"headers": {"X-Captured": "yes"}, "query": {"q": "one"}},
    )
    assert endpoint.auth_context["Authorization"] == "Bearer author-token"
    assert endpoint.auth_context["Cookie"] == "session=author-cookie"
    assert endpoint.auth_context["X-Captured"] == "yes"


def test_target_authentication_is_encrypted_at_rest():
    db = _db()
    target = Target(
        name="Encrypted app",
        base_url="https://app.test",
        tenant_id=1,
        auth_info=AUTH_INFO,
    )
    db.add(target)
    db.commit()
    target_id = target.id
    raw = db.execute(text("SELECT auth_info FROM targets WHERE id = :id"), {"id": target_id}).scalar_one()
    assert "correct horse" not in raw
    assert "author-token" not in raw
    assert "__xssboss_encrypted_v1__" in raw
    db.expire_all()
    assert db.query(Target).filter(Target.id == target_id).one().auth_info == AUTH_INFO


def test_endpoint_live_session_is_encrypted_and_redacted():
    db = _db()
    target = Target(name="Encrypted endpoint", base_url="https://app.test", tenant_id=1)
    db.add(target)
    db.flush()
    endpoint = Endpoint(
        target_id=target.id,
        method="GET",
        url_pattern="https://app.test/account",
        auth_context={"Authorization": "Bearer live-token", "Cookie": "session=live-cookie"},
    )
    db.add(endpoint)
    db.commit()

    raw = db.execute(
        text("SELECT auth_context FROM endpoints WHERE id = :id"), {"id": endpoint.id}
    ).scalar_one()
    assert "live-token" not in raw
    assert "live-cookie" not in raw
    assert "__xssboss_encrypted_v1__" in raw

    public = EndpointResponse.model_validate(endpoint).model_dump()
    assert public["auth_context"]["Authorization"] == "***configured***"
    assert public["auth_context"]["Cookie"] == "***configured***"


def test_stored_verifier_defaults_to_all_configured_identities():
    roles = StoredXSSVerifier._normalize_roles(None, AUTH_INFO)
    assert [role["label"] for role in roles] == ["author", "admin"]
    assert roles[1]["auth_spec"]["role"] == "admin"
    assert "admin-cookie" in roles[1]["auth_context"]["Cookie"]


def test_intervention_queue_pauses_deduplicates_and_resumes():
    db = _db()
    target = Target(name="App", base_url="https://app.test", tenant_id=1)
    db.add(target)
    db.flush()
    experiment = Experiment(
        target_id=target.id,
        name="Auth run",
        strategy=ExperimentStrategy.QUICK_LIGHT,
        status=ExperimentStatus.RUNNING,
        limits={},
        started_at=datetime.now(UTC),
    )
    db.add(experiment)
    db.flush()
    stage = RunStage(
        experiment_id=experiment.id,
        name=RunStageName.RECON,
        status=RunStageStatus.RUNNING,
    )
    db.add(stage)
    db.commit()

    first = HumanInterventionService.raise_intervention(
        db,
        experiment.id,
        kind="authentication_challenge",
        reason="MFA required",
        identity="admin",
        url="https://app.test/mfa",
    )
    duplicate = HumanInterventionService.raise_intervention(
        db,
        experiment.id,
        kind="authentication_challenge",
        reason="MFA required again",
        identity="admin",
    )
    assert duplicate["id"] == first["id"]
    assert experiment.status == ExperimentStatus.PAUSED
    assert stage.status == RunStageStatus.PENDING
    assert len(HumanInterventionService.list_open(db, experiment.id)) == 1

    HumanInterventionService.resolve(db, experiment.id, first["id"], "fresh session supplied")
    assert experiment.status == ExperimentStatus.RUNNING
    assert HumanInterventionService.list_open(db, experiment.id) == []


def test_endpoint_diversity_order_round_robins_families():
    endpoints = [
        type("Endpoint", (), {"id": 1, "method": "GET", "url_pattern": "https://app.test/users/list?page="})(),
        type("Endpoint", (), {"id": 2, "method": "GET", "url_pattern": "https://app.test/users/list?sort="})(),
        type("Endpoint", (), {"id": 3, "method": "GET", "url_pattern": "https://app.test/admin/audit"})(),
    ]
    ordered = FuzzingService._diversity_order(endpoints)
    assert {ordered[0].id, ordered[1].id} == {1, 3}
    assert ordered[2].id == 2
