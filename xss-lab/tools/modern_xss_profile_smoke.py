"""Smoke-test modern XSS probe profile generation."""
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOKEN = "MODERNLABTOKEN"
TARGET_URL = "http://127.0.0.1:8099/hard/post-message-origin-weak"


def main() -> int:
    sys.path.insert(0, str(ROOT))

    from backend_api.utils.modern_xss_profiles import ModernXSSProfiles
    from backend_api.utils.js_parser import JSParser

    post_message = ModernXSSProfiles.generate_post_message_probes(TARGET_URL, TOKEN)
    expanded_post_message = ModernXSSProfiles.expand_post_message_origin_modes(
        post_message,
        TARGET_URL,
        ["none", "starts_ends", "exact"],
        serve_http=True,
    )
    pollution = ModernXSSProfiles.generate_prototype_pollution_probes(
        "http://127.0.0.1:8099/hard/prototype-pollution",
        TOKEN,
    )
    clobbering = ModernXSSProfiles.generate_dom_clobbering_payloads(TOKEN)
    mxss = ModernXSSProfiles.generate_sanitizer_mxss_payloads(TOKEN)
    fingerprint = ModernXSSProfiles.fingerprint_html(
        """
        <script>
          angular.module('app', []);
          window.addEventListener('message', e => sink.innerHTML = e.data);
          trustedTypes.createPolicy('default', { createHTML: x => x });
          DOMPurify.sanitize('<b>x</b>');
        </script>
        <div ng-app v-html="content" dangerouslySetInnerHTML></div>
        """,
        {
            "Content-Security-Policy": "require-trusted-types-for 'script'; trusted-types default app-policy; script-src 'strict-dynamic'"
        },
    )
    signals = JSParser.find_modern_dom_signals(
        """
        window.addEventListener('message', function(event) {
          sink.innerHTML = event.data;
        });
        Object.assign(config, userInput);
        if (window.redirectTo.href) setTimeout(window.redirectTo.href.slice(11), 0);
        options.template = location.hash;
        """
    )

    failures = []
    checks = [
        ("post_message", len(post_message) >= 1 and TOKEN in post_message[0]["poc_html"]),
        (
            "post_message_origin_modes",
            len(expanded_post_message) == len(post_message) * 3
            and {"none", "starts_ends", "exact"}.issubset(
                {item["post_message_origin_mode"] for item in expanded_post_message}
            )
            and all(item["serve_http"] for item in expanded_post_message)
            and any(
                item.get("fake_message_origin", "").startswith("http://127.0.0.1:8099")
                for item in expanded_post_message
                if item["post_message_origin_mode"] == "starts_ends"
            ),
        ),
        ("prototype_pollution", len(pollution) >= 20 and any("__proto__" in item["target_url"] for item in pollution)),
        ("dom_clobbering", len(clobbering) >= 4 and any("redirectTo" in item["payload"] for item in clobbering)),
        ("sanitizer_mxss", len(mxss) >= 5 and all(TOKEN in item["payload"] for item in mxss)),
        ("framework_fingerprint", any(item["name"] == "angularjs" for item in fingerprint["frameworks"])),
        ("trusted_types_fingerprint", fingerprint["trusted_types"]["required"]),
        ("sanitizer_fingerprint", any(item["name"] == "dompurify" for item in fingerprint["sanitizers"])),
        ("dom_source_signals", len(signals["sources"]) >= 2),
        ("dom_clobbering_gadget_signals", len(signals["dom_clobbering_gadgets"]) >= 1),
        ("prototype_pollution_gadget_signals", len(signals["prototype_pollution_gadgets"]) >= 1),
    ]

    print("[+] Modern XSS profile smoke")
    for name, passed in checks:
        print(f"[{'PASS' if passed else 'FAIL'}] {name}")
        if not passed:
            failures.append(name)

    print("")
    print(f"post_message_profiles={len(post_message)}")
    print(f"expanded_post_message_profiles={len(expanded_post_message)}")
    print(f"prototype_pollution_profiles={len(pollution)}")
    print(f"dom_clobbering_payloads={len(clobbering)}")
    print(f"sanitizer_mxss_payloads={len(mxss)}")
    print(f"frameworks={[item['name'] for item in fingerprint['frameworks']]}")
    print(f"sanitizers={[item['name'] for item in fingerprint['sanitizers']]}")
    print(f"trusted_type_policies={fingerprint['trusted_types']['policy_names']}")
    print(f"source_signals={len(signals['sources'])}")
    print(f"clobbering_gadgets={len(signals['dom_clobbering_gadgets'])}")
    print(f"prototype_gadgets={len(signals['prototype_pollution_gadgets'])}")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
