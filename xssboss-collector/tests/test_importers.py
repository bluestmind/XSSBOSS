from __future__ import annotations

import base64
import json
from pathlib import Path

from xsscollector.importers import import_burp, import_har, import_openapi, import_urls


def test_har_import_decodes_and_structures(tmp_path: Path) -> None:
    path = tmp_path / "capture.har"
    path.write_text(json.dumps({"log": {"entries": [{
        "time": 12.5,
        "request": {"method": "POST", "url": "https://example.com/api?x=1", "headers": [{"name": "Content-Type", "value": "application/json"}], "postData": {"mimeType": "application/json", "text": "{\"name\":\"value\"}"}},
        "response": {"status": 201, "headers": [{"name": "Content-Type", "value": "application/json"}], "content": {"text": base64.b64encode(b'{"ok":true}').decode(), "encoding": "base64"}}
    }]}}), encoding="utf-8")
    record = import_har(path)[0]
    assert record.body == {"name": "value"}
    assert record.response_body == b'{"ok":true}'
    assert record.response_status == 201


def test_burp_import_handles_base64(tmp_path: Path) -> None:
    request = base64.b64encode(b"GET /a?x=1 HTTP/1.1\r\nHost: example.com\r\nCookie: sid=secret\r\n\r\n").decode()
    path = tmp_path / "burp.xml"
    path.write_text(f"<items><item><url>https://example.com/a?x=1</url><method>GET</method><status>200</status><request base64='true'>{request}</request></item></items>", encoding="utf-8")
    record = import_burp(path)[0]
    assert record.headers["Cookie"] == "sid=secret"
    assert record.response_status == 200


def test_url_and_openapi_imports(tmp_path: Path) -> None:
    urls = tmp_path / "urls.txt"
    urls.write_text("# comment\nhttps://example.com/a\n", encoding="utf-8")
    assert [record.url for record in import_urls(urls)] == ["https://example.com/a"]
    spec = tmp_path / "openapi.json"
    spec.write_text(json.dumps({"openapi": "3.1.0", "servers": [{"url": "https://example.com"}], "paths": {"/users": {"get": {"parameters": [{"name": "limit", "in": "query", "schema": {"type": "integer"}}]}, "post": {"requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"profile": {"type": "object", "properties": {"email": {"type": "string"}}}}}}}}}}}}), encoding="utf-8")
    records = import_openapi(spec)
    assert {record.method for record in records} == {"GET", "POST"}
    assert any(item["name"] == "limit" for record in records for item in record.metadata["declared_parameters"])
    assert any(item["name"] == "profile.email" for record in records for item in record.metadata["declared_parameters"])
