"""Safety invariants for advanced payload families enabled in autonomous mode."""
from fuzzer.mutation_engine import MutationEngine


def test_advanced_environment_probes_use_canaries_not_destructive_actions():
    seed = "<svg onload=__XSS__('safe-token')>"
    payloads = []
    for generator in (
        MutationEngine.apply_cookie_tossing,
        MutationEngine.apply_some_taint_theft,
        MutationEngine.apply_webview_sandbox_escape,
        MutationEngine.apply_cache_poisoning_bypass,
        MutationEngine.apply_webview_ipc_escape,
        MutationEngine.apply_postmessage_window_name_escape,
    ):
        payloads.extend(generator(seed))

    rendered = "\n".join(payloads).lower()
    forbidden = (
        ".exec(", "runtime').getmethod", "calculator", "cmd:'id'",
        "attacker.com", "document.body.innerhtml", "session_id=",
        "document.cookie=", "eval(decodeuri", "setinterval(",
    )
    assert "__xss__('safe-token')" in rendered
    for marker in forbidden:
        assert marker not in rendered
