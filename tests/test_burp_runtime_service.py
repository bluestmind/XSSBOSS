"""Tests for safe official Burp Desktop lifecycle management."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from backend_api.services.burp_runtime_service import BurpRuntimeService


def test_jar_and_launcher_validation(tmp_path):
    non_jar = tmp_path / "not_a_jar.txt"
    non_jar.write_bytes(b"txt")
    with pytest.raises(RuntimeError, match="must reference a JAR"):
        BurpRuntimeService._official_jar(str(non_jar))
    with pytest.raises(RuntimeError, match="does not exist"):
        BurpRuntimeService._official_jar("C:/non_existent_burp.jar")

    valid_jar = tmp_path / "main.jar"
    valid_jar.write_bytes(b"jar")
    assert BurpRuntimeService._official_jar(str(valid_jar)) == valid_jar.resolve()


def test_windows_launcher_uses_javaw_and_jar(tmp_path):
    jar = tmp_path / "main.jar"
    javaw = tmp_path / "javaw.exe"
    proj = tmp_path / "test.burp"
    jar.write_bytes(b"jar")
    javaw.write_bytes(b"exe")
    proj.write_bytes(b"burp")
    process = SimpleNamespace(pid=321, poll=lambda: None)

    with patch("backend_api.services.burp_runtime_service.os.name", "nt"), patch(
        "backend_api.services.burp_runtime_service.settings.BURP_PROJECT_FILE", str(proj)
    ), patch(
        "backend_api.services.burp_runtime_service.subprocess.Popen", return_value=process
    ) as popen:
        returned = BurpRuntimeService._launch(javaw, jar, ["-Xmx2g"])

    assert returned.pid == 321
    command = popen.call_args.args[0]
    assert command == [str(javaw), "-Xmx2g", "-jar", str(jar), f"--project-file={proj.resolve()}"]


def test_already_ready_burp_returns_without_launch(tmp_path):
    jar = tmp_path / "main.jar"
    javaw = tmp_path / "javaw.exe"
    jar.write_bytes(b"jar")
    javaw.write_bytes(b"exe")

    with patch.object(BurpRuntimeService, "api_ready", return_value=True), patch.object(
        BurpRuntimeService,
        "process_state",
        return_value={"running": True, "pid": 7, "process_name": "javaw.exe"},
    ), patch.object(BurpRuntimeService, "_launch") as launch, patch(
        "backend_api.services.burp_runtime_service.settings.BURP_EXECUTABLE", str(jar)
    ), patch(
        "backend_api.services.burp_runtime_service.settings.BURP_JAVA_EXECUTABLE", str(javaw)
    ):
        result = BurpRuntimeService.ensure_available("http://127.0.0.1:13337")
        assert result["status"] == "ready"
        assert result["started"] is False
    launch.assert_not_called()


def test_api_readiness_supports_legacy_key_path():
    unauthorized = SimpleNamespace(status_code=401)
    ready = SimpleNamespace(status_code=200)
    client = MagicMock()
    client.get.side_effect = [unauthorized, ready]
    context = MagicMock()
    context.__enter__.return_value = client

    with patch(
        "backend_api.services.burp_runtime_service.httpx.Client", return_value=context
    ):
        assert BurpRuntimeService.api_ready(
            "http://127.0.0.1:13337", "key with/slash"
        )

    assert client.get.call_args_list[1].args[0].endswith(
        "/key%20with%2Fslash/v0.1/scan"
    )


def test_api_readiness_rejects_remote_hosts():
    with patch("backend_api.services.burp_runtime_service.httpx.Client") as client:
        assert not BurpRuntimeService.api_ready("https://burp.example.test", "secret")
    client.assert_not_called()
