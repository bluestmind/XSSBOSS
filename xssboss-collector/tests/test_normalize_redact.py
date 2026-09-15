from __future__ import annotations

from xsscollector.normalize import canonical_url, endpoint_fingerprint, extract_parameters, flatten_json
from xsscollector.redact import Redactor


def test_dynamic_path_and_query_values_normalize() -> None:
    first = "https://EXAMPLE.com:443/api/users/123?b=two&a=one#fragment"
    second = "https://example.com/api/users/999?a=changed&b=changed"
    assert canonical_url(first) == "https://example.com/api/users/{path_id_3}?a=&b="
    assert endpoint_fingerprint("get", first) == endpoint_fingerprint("GET", second)


def test_extracts_nested_json_query_path_and_cookie_names() -> None:
    params = extract_parameters(
        "POST", "https://example.com/users/123?view=full",
        {"Content-Type": "application/json", "Cookie": "sid=secret; theme=dark"},
        {"profile": {"email": "a@example.com"}, "roles": ["admin"]},
    )
    identities = {(name, location) for name, location, _, _ in params}
    assert ("view", "query") in identities
    assert ("profile.email", "json") in identities
    assert ("roles[]", "json") in identities
    assert ("sid", "cookie") in identities
    assert any(location == "path" for _, location in identities)


def test_redactor_removes_secrets_and_query_values() -> None:
    redactor = Redactor(["authorization"], ["token", "password"])
    assert redactor.headers_map({"Authorization": "Bearer secret", "Accept": "json"})["Authorization"] == "[REDACTED]"
    assert "supersecret" not in redactor.url("https://example.com/?token=supersecret&mode=full")
    assert redactor.structured({"password": "hello", "safe": "value"}) == {"password": "[REDACTED]", "safe": "value"}
    text = redactor.text('<input type="hidden" name="token" value="abc123"><script>const x={"password":"hello world"}</script>')
    assert "abc123" not in text
    assert "hello world" not in text
