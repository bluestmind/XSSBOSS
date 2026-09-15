"""Durable program-run checkpoints — resume a program hunt from where it stopped.

The fuzzing layer is already restart-safe (``RunStage`` + pending ``TestCase``s), but the
program-level cursor — *which assets of a program are already done* — lived only in memory. If the
tool crashed or was killed mid-program, that cursor was lost. This persists each asset's outcome as
it completes, so a resumed run skips finished assets, keeps the running totals, and continues with
the remaining request budget.

``JsonCheckpointStore`` writes one small JSON file per run key (durable across process restarts).
``MemoryCheckpointStore`` is the in-process equivalent used in tests.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Dict, Protocol


class CheckpointStore(Protocol):
    def load(self, key: str) -> Dict[str, dict]: ...           # host -> outcome dict
    def record(self, key: str, host: str, outcome: dict) -> None: ...
    def finalize(self, key: str, report: dict) -> None: ...
    def reset(self, key: str) -> None: ...


class MemoryCheckpointStore:
    """In-process checkpoint store (tests / ephemeral runs)."""

    def __init__(self) -> None:
        self._outcomes: Dict[str, Dict[str, dict]] = {}
        self.reports: Dict[str, dict] = {}

    def load(self, key: str) -> Dict[str, dict]:
        return dict(self._outcomes.get(key, {}))

    def record(self, key: str, host: str, outcome: dict) -> None:
        self._outcomes.setdefault(key, {})[host] = outcome

    def finalize(self, key: str, report: dict) -> None:
        self.reports[key] = report

    def reset(self, key: str) -> None:
        self._outcomes.pop(key, None)
        self.reports.pop(key, None)


class JsonCheckpointStore:
    """Durable checkpoint store: one JSON file per run key, written atomically."""

    def __init__(self, directory: str) -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _safe(key: str) -> str:
        return re.sub(r"[^A-Za-z0-9_.-]", "_", str(key)) or "run"

    def _path(self, key: str) -> Path:
        return self.dir / f"{self._safe(key)}.json"

    def _read(self, key: str) -> dict:
        path = self._path(key)
        if not path.exists():
            return {"outcomes": {}, "report": None}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {"outcomes": {}, "report": None}

    def _write(self, key: str, data: dict) -> None:
        path = self._path(key)
        # Atomic write: temp file in the same dir, then replace.
        fd, tmp = tempfile.mkstemp(dir=str(self.dir), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f)
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    def load(self, key: str) -> Dict[str, dict]:
        return dict(self._read(key).get("outcomes", {}))

    def record(self, key: str, host: str, outcome: dict) -> None:
        data = self._read(key)
        data.setdefault("outcomes", {})[host] = outcome
        self._write(key, data)

    def finalize(self, key: str, report: dict) -> None:
        data = self._read(key)
        data["report"] = report
        self._write(key, data)

    def reset(self, key: str) -> None:
        path = self._path(key)
        if path.exists():
            path.unlink()
