from backend_api.utils.tokenizer import Tokenizer


def test_replace_token_updates_html_entity_encoded_token():
    old_token = "HARDE2ESEEDTOKEN"
    new_token = "fresh-token_123"
    encoded_old = "".join(f"&#{ord(char)};" for char in old_token)
    payload = f'<a href="javascript:parent.__XSS__(&quot;{encoded_old}&quot;)">'

    replaced = Tokenizer.replace_token(payload, old_token, new_token)

    assert old_token not in replaced
    assert encoded_old not in replaced
    assert "".join(f"&#{ord(char)};" for char in new_token) in replaced


def test_placeholder_round_trip_preserves_encoded_token_styles():
    token = "seed-token"
    new_token = "next_token"
    forms = [
        "".join(f"&#{ord(char)};" for char in token),
        "".join(f"&#x{ord(char):x};" for char in token),
        "".join(f"\\x{ord(char):02x}" for char in token),
        "".join(f"\\u{ord(char):04x}" for char in token),
        "".join(f"%{ord(char):02X}" for char in token),
    ]
    payload = "|".join(forms)

    normalized = Tokenizer.replace_token_with_placeholders(payload, token)
    replaced = Tokenizer.replace_placeholders_with_token(normalized, new_token)

    assert token not in replaced
    assert "".join(f"&#{ord(char)};" for char in new_token) in replaced
    assert "".join(f"\\x{ord(char):02x}" for char in new_token) in replaced
    assert "".join(f"%{ord(char):02X}" for char in new_token) in replaced
