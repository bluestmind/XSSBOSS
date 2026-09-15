"""Vulnerable JS library scanner — detection, version matching, payload boosts."""
from analysis_engine.vulnerable_library_scanner import VulnerableLibraryScanner as V


def _refs(findings):
    return {f.ref for f in findings}


def test_detects_old_jquery_from_filename():
    html = '<script src="/assets/jquery-1.6.4.min.js"></script>'
    libs = V.detect_libraries(html)
    assert libs.get("jquery") == "1.6.4"
    findings = V.scan(html)
    # 1.6.4 is below every jQuery threshold in the DB.
    assert "CVE-2011-4969" in _refs(findings) and "CVE-2020-11022" in _refs(findings)
    assert len(findings) == 4


def test_patched_jquery_has_no_findings():
    html = '<script src="/vendor/jquery-3.5.1.min.js"></script>'
    assert V.detect_libraries(html)["jquery"] == "3.5.1"
    assert V.scan(html) == []


def test_angular_cdn_path_version_and_csti():
    html = '<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.5.8/angular.min.js"></script>'
    assert V.detect_libraries(html)["angular"] == "1.5.8"
    findings = V.scan(html)
    assert "CSTI" in _refs(findings)                       # always-flagged for AngularJS
    assert "csti_angular" in V.payload_boosts(findings)    # boosts the CSTI payloads for it


def test_angular_inline_banner():
    assert V.detect_libraries("/* AngularJS v1.5.8 */")["angular"] == "1.5.8"


def test_bootstrap_and_handlebars():
    assert "CVE-2019-8331" in _refs(V.scan('<script src="/js/bootstrap-3.3.7.min.js">'))
    assert "CVE-2019-19919" in _refs(V.scan("/*! Handlebars v4.0.11 */"))


def test_jquery_ui_does_not_pollute_jquery():
    html = '<script src="/lib/jquery-ui-1.12.1.min.js"></script>'
    libs = V.detect_libraries(html)
    assert libs.get("jquery-ui") == "1.12.1"
    assert "jquery" not in libs        # the -ui match must not also register bare jquery


def test_clean_page_is_empty():
    assert V.scan("<html><body>no libraries here</body></html>") == []
    assert V.detect_libraries("") == {}


def test_findings_sorted_severity_first():
    html = '<script src="/angular-1.5.8.js"></script><script src="/jquery-3.4.9.js"></script>'
    findings = V.scan(html)
    sevs = [f.severity for f in findings]
    # high (angular) should come before medium (jquery)
    assert sevs.index("high") < sevs.index("medium")
