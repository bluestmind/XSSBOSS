"""Program-scope engine: asset parsing, bounty/severity prioritization, and Burp scope export."""
from backend_api.services.program_scope import ProgramScope, ScopeAsset

SCOPE_TAGS = {
    "handle": "oppo_bbp",
    "offers_bounties": True,
    "in_scope": [
        {"asset_identifier": "*.oppo.com", "asset_type": "WILDCARD", "eligible_for_bounty": True, "max_severity": "critical"},
        {"asset_identifier": "https://login.starbucks.co.jp", "asset_type": "URL", "eligible_for_bounty": True, "max_severity": "high"},
        {"asset_identifier": "api.test.com", "asset_type": "DOMAIN", "eligible_for_bounty": False, "max_severity": "medium"},
        {"asset_identifier": "com.oppo.app", "asset_type": "GOOGLE_PLAY_APP_ID", "eligible_for_bounty": True, "max_severity": "critical"},
    ],
    "out_of_scope": [
        {"asset_identifier": "blog.oppo.com", "asset_type": "URL"},
        {"asset_identifier": "*.honeypot.oppo.com", "asset_type": "WILDCARD"},
    ],
}


def test_parses_rich_assets():
    ps = ProgramScope.from_scope_tags(SCOPE_TAGS)
    assert ps.handle == "oppo_bbp" and ps.offers_bounties is True
    assert len(ps.in_scope) == 4
    wildcard = ps.in_scope[0]
    assert wildcard.is_wildcard and wildcard.host == "oppo.com"
    assert wildcard.max_severity == "critical" and wildcard.eligible_for_bounty


def test_web_assets_skip_mobile_app_ids():
    ps = ProgramScope.from_scope_tags(SCOPE_TAGS)
    hosts = {a.host for a in ps.web_assets()}
    assert hosts == {"oppo.com", "login.starbucks.co.jp", "api.test.com"}  # play-store id dropped


def test_worklist_prioritizes_bounty_then_severity():
    ps = ProgramScope.from_scope_tags(SCOPE_TAGS)
    order = [a.host for a in ps.worklist()]
    # critical bounty wildcard, then high bounty concrete, then non-bounty medium last.
    assert order == ["oppo.com", "login.starbucks.co.jp", "api.test.com"]


def test_non_bounty_program_ignores_bounty_tiering():
    tags = dict(SCOPE_TAGS, offers_bounties=False)
    ps = ProgramScope.from_scope_tags(tags)
    order = [a.host for a in ps.worklist()]
    # Pure severity order now (critical, high, medium).
    assert order == ["oppo.com", "login.starbucks.co.jp", "api.test.com"]


def test_to_burp_scope_include_exclude_regexes():
    ps = ProgramScope.from_scope_tags(SCOPE_TAGS)
    burp = ps.to_burp_scope()
    inc = {r["host"] for r in burp["target"]["scope"]["include"]}
    exc = {r["host"] for r in burp["target"]["scope"]["exclude"]}
    assert r"^(?:[^.]+\.)+oppo\.com$" in inc       # wildcard -> subdomains only
    assert r"^login\.starbucks\.co\.jp$" in inc    # exact host anchored
    assert r"^api\.test\.com$" in inc
    assert r"^blog\.oppo\.com$" in exc             # out-of-scope -> exclude
    assert r"^(?:[^.]+\.)+honeypot\.oppo\.com$" in exc
    assert burp["target"]["scope"]["advanced_mode"] is True


def test_burp_include_prefixes_for_extension():
    ps = ProgramScope.from_scope_tags(SCOPE_TAGS)
    prefixes = ps.burp_include_prefixes()
    assert "https://oppo.com/" not in prefixes
    assert "https://login.starbucks.co.jp/" in prefixes


def test_burp_exports_fail_closed_for_path_prefixes_and_query_rules():
    ps = ProgramScope.from_scope_tags({
        "in_scope": [
            {"asset_identifier": "https://app.example.test/app", "asset_type": "URL"},
            {"asset_identifier": "https://api.example.test/search?tenant=allowed", "asset_type": "URL"},
            {"asset_identifier": "https://root.example.test", "asset_type": "URL"},
        ],
    })

    scope = ps.to_burp_scope()["target"]["scope"]
    assert {item["host"] for item in scope["include"]} == {
        r"^app\.example\.test$",
        r"^root\.example\.test$",
    }
    assert ps.burp_include_prefixes() == ["https://root.example.test/"]


def test_same_host_exclusion_disables_unscoped_automated_crawl():
    ps = ProgramScope.from_scope_tags({
        "in_scope": [{"asset_identifier": "https://app.example.test", "asset_type": "URL"}],
        "out_of_scope": [
            {"asset_identifier": "https://app.example.test/admin", "asset_type": "URL"},
            {"asset_identifier": "https://other.example.test/private", "asset_type": "URL"},
        ],
    })

    assert ps.has_host_exclusions("https://app.example.test/")
    assert not ps.has_host_exclusions("https://unrelated.example.test/")


def test_wildcard_does_not_authorize_apex_and_requires_observed_subdomain():
    ps = ProgramScope.from_scope_tags({
        "in_scope": [{"asset_identifier": "*.example.test", "asset_type": "WILDCARD"}],
    })

    assert not ps.contains_url("https://example.test/")
    assert ps.contains_url("https://a.example.test/path")
    assert ps.concrete_worklist() == []
    resolved = ps.concrete_worklist([
        "https://example.test/",
        "https://a.example.test/observed?x=1",
    ])
    assert [item.seed_url for item in resolved] == ["https://a.example.test/"]


def test_path_scope_and_exclusion_are_preserved_in_burp_rules():
    ps = ProgramScope.from_scope_tags({
        "in_scope": [
            {"asset_identifier": "https://app.example.test/app", "asset_type": "URL"},
            {"asset_identifier": "https://app.example.test/api/v1/*", "asset_type": "URL"},
        ],
        "out_of_scope": [
            {"asset_identifier": "https://app.example.test/app/admin", "asset_type": "URL"},
        ],
    })

    assert ps.contains_url("https://app.example.test/app/profile")
    assert not ps.contains_url("https://app.example.test/app/admin/users")
    assert not ps.contains_url("https://app.example.test/other")
    rules = ps.to_burp_scope()["target"]["scope"]
    files = {item["file"] for item in rules["include"]}
    assert files == {r"^/app(?:/.*)?$", r"^/api/v1/.*$"}
    assert rules["exclude"][0]["file"] == r"^/app/admin(?:/.*)?$"


def test_string_items_and_web_targets_fallback():
    tags = {"handle": "x", "offers_bounties": True, "in_scope": [], "web_targets": ["a.com", "*.b.com"]}
    ps = ProgramScope.from_scope_tags(tags)
    assert {a.host for a in ps.web_assets()} == {"a.com", "b.com"}


def test_summary():
    ps = ProgramScope.from_scope_tags(SCOPE_TAGS)
    s = ps.summary()
    assert s["web_assets"] == 3
    assert s["bounty_eligible_assets"] == 2
    assert s["exclusions"] == 2
    assert s["top_priority"][0] == "oppo.com"


def test_empty_scope_is_safe():
    ps = ProgramScope.from_scope_tags(None)
    assert ps.web_assets() == [] and ps.worklist() == []
    assert ps.to_burp_scope()["target"]["scope"]["include"] == []
