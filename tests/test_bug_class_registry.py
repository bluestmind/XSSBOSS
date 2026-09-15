"""Bug-class registry — enumerates the vuln subsystems beyond XSS and stays pluggable."""
from backend_api.services.bug_class_registry import BugClass, BugClassRegistry


def test_ships_the_known_bug_classes():
    keys = set(BugClassRegistry.keys())
    # XSS plus the auditor suite that already runs inside every experiment.
    for expected in ["xss", "cors", "sqli", "ssrf", "open_redirect", "crlf", "path_traversal"]:
        assert expected in keys, f"{expected} missing from registry"
    assert len(BugClassRegistry.all()) >= 10


def test_get_and_kind_split():
    xss = BugClassRegistry.get("xss")
    assert xss and xss.kind == "fuzz"
    auditors = BugClassRegistry.auditors()
    assert all(b.kind == "auditor" for b in auditors)
    assert "cors" in {b.key for b in auditors}
    assert "xss" not in {b.key for b in auditors}   # xss is the fuzzer, not an auditor


def test_new_subsystem_is_one_line_register():
    before = len(BugClassRegistry.all())
    BugClassRegistry.register(BugClass(
        "prototype_pollution", "Prototype Pollution",
        "Client-side prototype pollution gadget chains.",
        "backend_api.services.auditors.proto.ProtoAuditor", "auditor", "high",
    ))
    try:
        assert len(BugClassRegistry.all()) == before + 1
        assert BugClassRegistry.get("prototype_pollution").default_severity == "high"
    finally:
        BugClassRegistry._REGISTRY.pop("prototype_pollution", None)  # keep the shared registry clean


def test_recon_only_leads_are_not_misrepresented_as_active_auditors():
    assert BugClassRegistry.get("idor_bola").kind == "research"
    assert BugClassRegistry.get("csrf").kind == "research"
    assert BugClassRegistry.get("graphql_auth").kind == "research"
    assert "idor_bola" not in {bug.key for bug in BugClassRegistry.auditors()}
