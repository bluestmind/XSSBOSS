"""Authenticated-at-rest JSON storage for credentials and live sessions."""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from sqlalchemy.types import JSON, TypeDecorator


_MARKER = "__xssboss_encrypted_v1__"


def _fernet():
    from cryptography.fernet import Fernet
    from backend_api.config import settings

    digest = hashlib.sha256(settings.SECRET_KEY.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_json_value(value: Any) -> Any:
    if value is None or (isinstance(value, dict) and _MARKER in value):
        return value
    plaintext = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return {_MARKER: _fernet().encrypt(plaintext).decode("ascii")}


def decrypt_json_value(value: Any) -> Any:
    if value is None or not isinstance(value, dict) or _MARKER not in value:
        return value
    try:
        plaintext = _fernet().decrypt(str(value[_MARKER]).encode("ascii"))
        return json.loads(plaintext.decode("utf-8"))
    except Exception as error:
        raise RuntimeError(
            "Unable to decrypt authentication data. Verify that SECRET_KEY has not changed."
        ) from error


class EncryptedJSON(TypeDecorator):
    """Keep a JSON-compatible ciphertext envelope while exposing normal Python values."""

    impl = JSON
    cache_ok = True

    def process_bind_param(self, value, dialect):
        return encrypt_json_value(value)

    def process_result_value(self, value, dialect):
        return decrypt_json_value(value)
