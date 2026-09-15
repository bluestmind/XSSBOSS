"""Content-addressed, compressed evidence with atomic writes."""

from __future__ import annotations

import gzip
import hashlib
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    sha256: str
    relative_path: str
    size: int
    stored_size: int
    mime_type: str


class EvidenceStore:
    def __init__(self, root: Path, compress: bool = True):
        self.root = root
        self.compress = compress
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, body: bytes, mime_type: str = "application/octet-stream") -> EvidenceRef:
        digest = hashlib.sha256(body).hexdigest()
        suffix = ".evidence.gz" if self.compress else ".evidence"
        relative = Path(digest[:2]) / digest[2:4] / f"{digest}{suffix}"
        destination = self.root / relative
        payload = gzip.compress(body, compresslevel=6, mtime=0) if self.compress else body
        if not destination.exists():
            destination.parent.mkdir(parents=True, exist_ok=True)
            fd, temporary = tempfile.mkstemp(prefix=".evidence-", dir=destination.parent)
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, destination)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        return EvidenceRef(digest, relative.as_posix(), len(body), len(payload), mime_type)

    def get(self, reference: str) -> bytes:
        path = (self.root / reference).resolve()
        if self.root.resolve() not in path.parents:
            raise ValueError("evidence path escapes its configured root")
        data = path.read_bytes()
        return gzip.decompress(data) if path.suffix == ".gz" else data

