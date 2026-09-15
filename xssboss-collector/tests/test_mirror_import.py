from __future__ import annotations

import json

import pytest

from xsscollector.mirror_import import import_mirror, import_uploaded_mirror


def test_import_mirror_reconstructs_urls_and_uses_manifest(tmp_path) -> None:
    root = tmp_path / "mirror"
    host = root / "example.com"
    (host / "assets").mkdir(parents=True)
    (host / "index.html").write_text("<script src='/assets/app.js'></script>", encoding="utf-8")
    (host / "assets" / "app.js").write_text("document.body.innerHTML = location.hash", encoding="utf-8")
    (host / "assets" / "photo.jpg").write_bytes(b"ignored binary")
    (root / "manifest.json").write_text(json.dumps([
        {"url": "https://example.com/assets/app.js?v=7", "path": "example.com/assets/app.js"}
    ]), encoding="utf-8")

    records = list(import_mirror(root, "https://example.com/", max_files=10))
    assert [record.url for record in records] == [
        "https://example.com/assets/app.js?v=7", "https://example.com/"
    ]
    assert all(record.source == "mirror-import" for record in records)
    assert records[0].metadata == {"mirror_path": "example.com/assets/app.js", "manifest_mapped": True}


def test_uploaded_mirror_is_bounded_and_rejects_traversal() -> None:
    records = import_uploaded_mirror([
        ("site/index.html", b"<h1>Safe</h1>"),
        ("site/app.css", b"body{}"),
        ("site/image.png", b"ignored"),
    ], "https://example.com/", max_files=2)
    assert len(records) == 2
    with pytest.raises(ValueError, match="invalid relative"):
        import_uploaded_mirror([("../escape.js", b"alert(1)")], "https://example.com/")
