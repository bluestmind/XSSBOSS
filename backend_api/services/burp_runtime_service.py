""" local lifecycle management for an official Burp Desktop process."""
from __future__ import annotations

import os
from pathlib import Path
import shlex
import subprocess
import threading
import time
from typing import Any, Optional
from urllib.parse import quote, urlparse

import httpx
import psutil

from backend_api.config import settings
from backend_api.utils.logger import logger


class BurpRuntimeService:
    """Start Burp through Java(TM) ``javaw.exe`` and avoid duplicate GUIs."""

    _launch_lock = threading.Lock()


    @staticmethod
    def _official_jar(path_value: Optional[str]) -> Path:
        if not path_value:
            raise RuntimeError("BURP_EXECUTABLE is required when BURP_AUTO_START is enabled")
        path = Path(path_value).expanduser().resolve()
        if path.suffix.lower() != ".jar":
            raise RuntimeError("BURP_EXECUTABLE must reference a JAR file (.jar)")
        if not path.is_file():
            raise RuntimeError(f"Configured Burp JAR does not exist: {path}")
        return path

    @staticmethod
    def _javaw(path_value: Optional[str]) -> Path:
        if not path_value:
            raise RuntimeError("BURP_JAVA_EXECUTABLE must point to javaw.exe or java.exe")
        path = Path(path_value).expanduser().resolve()
        if not path.is_file():
            raise RuntimeError(f"Configured Java launcher does not exist: {path}")
        return path



    @staticmethod
    def process_state(jar_path: Path) -> dict[str, Any]:
        expected = str(jar_path).replace("\\", "/").lower()
        jar_name = jar_path.name.lower()
        for process in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                proc_name = (process.info.get("name") or "").lower()
                if "java" not in proc_name:
                    continue
                command = " ".join(process.info.get("cmdline") or [])
                normalized = command.replace("\\", "/").lower()
                if expected in normalized or jar_name in normalized or "burpsuite" in normalized:
                    return {
                        "running": True,
                        "pid": process.info.get("pid"),
                        "process_name": process.info.get("name"),
                    }
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                continue
        return {"running": False, "pid": None, "process_name": None}

    @staticmethod
    def api_ready(api_url: str, api_key: Optional[str] = None) -> bool:
        parsed = urlparse(api_url)
        if (parsed.hostname or "").lower() not in {"127.0.0.1", "localhost", "::1"}:
            return False
        base_url = api_url.rstrip("/")
        endpoints = [f"{base_url}/v0.1/scan"]
        if api_key:
            endpoints.append(f"{base_url}/{quote(api_key, safe='')}/v0.1/scan")
        endpoints.append(f"{base_url}/v0.1/knowledge_base/issue_definitions")
        if api_key:
            endpoints.append(f"{base_url}/{quote(api_key, safe='')}/v0.1/knowledge_base/issue_definitions")
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        try:
            with httpx.Client(
                timeout=1.5,
                verify=not settings.ALLOW_INSECURE_TLS,
                trust_env=False,
            ) as client:
                for endpoint in endpoints:
                    response = client.get(endpoint, headers=headers)
                    if 200 <= response.status_code < 300 or (response.status_code == 400 and "expecting an identifier" in response.text):
                        return True
            return False
        except httpx.HTTPError:
            return False

    @staticmethod
    def _launch(javaw_path: Path, jar_path: Path, extra_args: list[str]) -> subprocess.Popen:
        jar_dir = jar_path.parent
        app_args = []
        project_file = getattr(settings, "BURP_PROJECT_FILE", None)
        if project_file:
            p_path = Path(project_file).expanduser().resolve()
            if p_path.is_file():
                app_args.append(f"--project-file={p_path}")

        # If launching main.jar loader, configure the required JVM open flags and agent
        if jar_path.name.lower() == "main.jar":
            desktop_jar = jar_dir / "burpsuite_desktop_v2026.4.3.jar"
            if not desktop_jar.exists():
                candidates = list(jar_dir.glob("burpsuite*.jar"))
                if candidates:
                    desktop_jar = candidates[0]
            if desktop_jar.exists():
                command = [
                    str(javaw_path),
                    "--add-opens=java.desktop/javax.swing=ALL-UNNAMED",
                    "--add-opens=java.base/java.lang=ALL-UNNAMED",
                    "--add-opens=java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED",
                    "--add-opens=java.base/jdk.internal.org.objectweb.asm.tree=ALL-UNNAMED",
                    "--add-opens=java.base/jdk.internal.org.objectweb.asm.Opcodes=ALL-UNNAMED",
                    f"-javaagent:{jar_path.name}",
                    "-noverify",
                    *extra_args,
                    "-jar",
                    str(desktop_jar.name),
                    *app_args,
                ]
            else:
                command = [str(javaw_path), *extra_args, "-jar", str(jar_path), *app_args]
        else:
            command = [str(javaw_path), *extra_args, "-jar", str(jar_path), *app_args]

        kwargs: dict[str, Any] = {
            "cwd": str(jar_dir),
            "close_fds": True,
        }
        if os.name == "nt":
            kwargs["creationflags"] = (
                subprocess.CREATE_NEW_PROCESS_GROUP
            )
        logger.info("Starting Burp Desktop with Java(TM) javaw.exe")
        return subprocess.Popen(command, **kwargs)

    @staticmethod
    def ensure_available(
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout_seconds: Optional[float] = None,
    ) -> dict[str, Any]:
        """Start one local official Burp process and wait for its REST service."""
        api_url = api_url or settings.BURP_API_URL
        parsed = urlparse(api_url)
        if (parsed.hostname or "").lower() not in {"127.0.0.1", "localhost", "::1"}:
            raise RuntimeError("Burp auto-start is allowed only for a local REST API URL")

        jar_path = BurpRuntimeService._official_jar(settings.BURP_EXECUTABLE)
        javaw_path = BurpRuntimeService._javaw(settings.BURP_JAVA_EXECUTABLE)

        configured_timeout = (
            settings.BURP_STARTUP_TIMEOUT_SECONDS
            if timeout_seconds is None
            else timeout_seconds
        )
        timeout = max(0.5, min(300.0, float(configured_timeout)))
        extra_args = shlex.split(settings.BURP_STARTUP_ARGS) if getattr(settings, "BURP_STARTUP_ARGS", None) else []

        with BurpRuntimeService._launch_lock:
            state = BurpRuntimeService.process_state(jar_path)
            if BurpRuntimeService.api_ready(api_url, api_key):
                return {
                    "status": "ready",
                    "started": False,
                    "pid": state["pid"],
                    "launcher": state["process_name"],
                    "jar": str(jar_path),
                }
            process = None
            if not state["running"]:
                process = BurpRuntimeService._launch(javaw_path, jar_path, extra_args)
                state = {
                    "running": True,
                    "pid": process.pid,
                    "process_name": javaw_path.name,
                }

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if BurpRuntimeService.api_ready(api_url, api_key):
                return {
                    "status": "ready",
                    "started": process is not None,
                    "pid": state["pid"],
                    "launcher": str(javaw_path),
                    "jar": str(jar_path),
                }
            if process is not None and process.poll() is not None:
                raise RuntimeError(f"Burp exited during startup with code {process.returncode}")
            time.sleep(0.5)
        raise RuntimeError(
            f"Burp process is running but REST API did not become ready at {api_url} "
            f"within {timeout:g} seconds"
        )
