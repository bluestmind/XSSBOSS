"""Source-aware, bounded JavaScript dependency inventory tests."""
from __future__ import annotations

import socket

from analysis_engine.vulnerable_library_scanner import VulnerableLibraryScanner as Scanner


def test_scan_retains_findings_for_multiple_versions_of_one_library():
    content = (
        '<script src="/vendor/jquery-1.6.4.min.js"></script>'
        '<script src="/vendor/jquery-3.4.1.min.js"></script>'
    )

    instances = Scanner.detect_library_instances(content)
    assert {(item.library, item.version) for item in instances} == {
        ("jquery", "1.6.4"),
        ("jquery", "3.4.1"),
    }

    findings = Scanner.scan(content)
    assert any(f.version == "1.6.4" and f.ref == "CVE-2011-4969" for f in findings)
    assert any(f.version == "3.4.1" and f.ref == "CVE-2020-11022" for f in findings)
    # The same advisory on two loaded versions is two useful observations, not one collapsed row.
    assert sum(f.ref == "CVE-2020-11022" for f in findings) == 2


def test_url_only_artifact_evidence_is_supported_and_passive(monkeypatch):
    attempted_connections = []

    def fail_if_called(*args, **kwargs):
        attempted_connections.append((args, kwargs))
        raise AssertionError("dependency inventory must not perform network I/O")

    monkeypatch.setattr(socket, "create_connection", fail_if_called)
    findings = Scanner.scan_artifact(
        "https://cdn.example.test/assets/jquery-3.4.1.min.js?access_token=do-not-return",
        "",
    )

    assert attempted_connections == []
    assert {f.ref for f in findings} == {"CVE-2020-11022"}
    assert {f.source for f in findings} == {"script_url"}
    assert all(len(f.source_fingerprint) == 20 for f in findings)


def test_url_query_and_credentials_are_not_version_evidence():
    secret_version_decoy = (
        "https://jquery-1.6.4:password@cdn.example.test/assets/application.js"
        "?file=jquery-1.6.4.js#jquery-1.6.4"
    )
    encoded_path = "https://cdn.example.test/assets/jquery%2D3.4.1.min.js"

    assert Scanner.scan_artifact(secret_version_decoy, "") == []
    assert {item.version for item in Scanner.scan_artifact(encoded_path, "")} == {"3.4.1"}


def test_modern_angular_version_is_not_classified_as_angularjs_csti():
    instances = Scanner.detect_library_instances("", "https://cdn.example.test/angular-17.3.0.js")

    assert [(item.library, item.version) for item in instances] == [("angular", "17.3.0")]
    assert Scanner.scan_artifact("https://cdn.example.test/angular-17.3.0.js", "") == []


def test_duplicate_evidence_is_collapsed_per_library_version_and_source():
    banner = "/*! jQuery v1.12.4 */"
    instances = Scanner.detect_library_instances(banner + banner + banner)
    assert [(item.library, item.version, item.source) for item in instances] == [
        ("jquery", "1.12.4", "content")
    ]

    findings = Scanner.scan(banner + banner)
    keys = {
        (f.library, f.version, f.source, f.source_fingerprint, f.ref)
        for f in findings
    }
    assert len(findings) == len(keys) == 3


def test_url_and_content_are_distinct_evidence_sources():
    instances = Scanner.detect_library_instances(
        "/*! jQuery v3.4.1 */",
        script_url="https://cdn.example.test/jquery-3.4.1.min.js",
    )
    assert {(item.library, item.version, item.source) for item in instances} == {
        ("jquery", "3.4.1", "script_url"),
        ("jquery", "3.4.1", "content"),
    }


def test_inventory_and_findings_are_bounded_for_adversarial_version_spam():
    content = "\n".join(
        f"/*! jquery v1.0.{patch} */" for patch in range(Scanner.MAX_LIBRARY_INSTANCES * 3)
    )
    instances = Scanner.detect_library_instances(content)
    findings = Scanner.scan(content)

    assert len(instances) == Scanner.MAX_VERSIONS_PER_LIBRARY_SOURCE
    assert len(instances) <= Scanner.MAX_LIBRARY_INSTANCES
    assert len(findings) <= Scanner.MAX_FINDINGS


def test_serialized_evidence_never_contains_url_secrets_or_raw_bundle_content():
    secret = "SUPER_SECRET_71f0"
    url = f"https://user:{secret}@cdn.example.test/lodash-4.17.11.js?token={secret}#{secret}"
    content = f"/*! lodash v4.17.11 */ const privateValue = '{secret}';"

    instances = Scanner.detect_library_instances(content, script_url=url)
    findings = Scanner.scan_artifact(url, content)
    serialized = repr([item.to_dict() for item in instances]) + repr(
        [finding.to_dict() for finding in findings]
    )

    assert secret not in serialized
    assert "privateValue" not in serialized
    assert all(item.source in {"script_url", "content"} for item in instances)


def test_legacy_dictionary_view_still_returns_one_version_per_library():
    content = "jquery-1.6.4.min.js jquery-3.4.1.min.js angular-1.5.8.js"
    assert Scanner.detect_libraries(content) == {"jquery": "1.6.4", "angular": "1.5.8"}
