"""Safe, offline import of website mirrors as security-analysis evidence."""

from __future__ import annotations

import json
import mimetypes
from collections.abc import Iterable, Iterator
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote, urljoin, urlsplit

from .models import RequestRecord

MIRROR_EXTENSIONS = {
    ".html", ".htm", ".xhtml", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
    ".css", ".json", ".map", ".xml", ".svg", ".txt", ".webmanifest",
}


def import_mirror(
    directory: str | Path,
    base_url: str,
    manifest: str | Path | None = None,
    *,
    max_files: int = 500,
    max_file_bytes: int = 2_000_000,
) -> Iterator[RequestRecord]:
    """Read security-relevant text assets from a mirror; never execute or serve them."""
    root = Path(directory).resolve()
    if not root.is_dir():
        raise ValueError("mirror path must be a directory")
    _validate_base_url(base_url)
    manifest_path = Path(manifest).resolve() if manifest else _find_manifest(root)
    mappings = _manifest_mappings(manifest_path) if manifest_path else {}
    count = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink() or path.suffix.lower() not in MIRROR_EXTENSIONS:
            continue
        resolved = path.resolve()
        if root not in resolved.parents or (manifest_path and resolved == manifest_path):
            continue
        count += 1
        if count > max_files:
            raise ValueError(f"mirror file count exceeds max_pages ({max_files})")
        size = path.stat().st_size
        if size > max_file_bytes:
            raise ValueError(f"{path.relative_to(root)} exceeds max_response_bytes ({max_file_bytes:,})")
        relative = path.relative_to(root).as_posix()
        yield mirror_record(relative, path.read_bytes(), base_url, mappings)
    if not count:
        raise ValueError("mirror contains no supported HTML, CSS, JS/TS, JSON, XML, SVG, map, or text files")


def import_uploaded_mirror(
    files: Iterable[tuple[str, bytes]],
    base_url: str,
    *,
    max_files: int = 500,
) -> list[RequestRecord]:
    """Build mirror records from already bounded dashboard uploads."""
    _validate_base_url(base_url)
    uploaded = [(_safe_relative_name(name), body) for name, body in files]
    first_parts = {PurePosixPath(name).parts[0] for name, _ in uploaded if len(PurePosixPath(name).parts) > 1}
    if len(first_parts) == 1 and all(len(PurePosixPath(name).parts) > 1 for name, _ in uploaded):
        uploaded = [("/".join(PurePosixPath(name).parts[1:]), body) for name, body in uploaded]
    mappings: dict[str, str] = {}
    for name, body in uploaded:
        if PurePosixPath(name.replace("\\", "/")).name.lower() in {"manifest.json", "asset-manifest.json", "url-manifest.json", "_cloner_report.txt"}:
            mappings.update(_manifest_mappings_text(body.decode("utf-8", errors="replace")))
    records: list[RequestRecord] = []
    for name, body in uploaded:
        safe = _safe_relative_name(name)
        if Path(safe).suffix.lower() not in MIRROR_EXTENSIONS:
            continue
        if PurePosixPath(safe).name.lower() in {"manifest.json", "asset-manifest.json", "url-manifest.json", "_cloner_report.txt"}:
            continue
        records.append(mirror_record(safe, body, base_url, mappings))
        if len(records) > max_files:
            raise ValueError(f"mirror file count exceeds max_pages ({max_files})")
    if not records:
        raise ValueError("folder contains no supported security-relevant text files")
    return records


def mirror_record(relative: str, body: bytes, base_url: str, mappings: dict[str, str]) -> RequestRecord:
    safe = _safe_relative_name(relative)
    source_url = _mapped_url(safe, mappings) or _reconstruct_url(safe, base_url)
    return RequestRecord(
        "GET", source_url, "mirror-import", response_status=200,
        response_headers={"Content-Type": _content_type(safe)}, response_body=body,
        metadata={"mirror_path": safe, "manifest_mapped": bool(_mapped_url(safe, mappings))},
    )


def _reconstruct_url(relative: str, base_url: str) -> str:
    parsed = urlsplit(base_url)
    parts = list(PurePosixPath(relative).parts)
    host_index = next((index for index, part in enumerate(parts) if part.lower() == parsed.netloc.lower()), None)
    if host_index is not None:
        parts = parts[host_index + 1:]
        root = f"{parsed.scheme}://{parsed.netloc}/"
    else:
        root = base_url.rstrip("/") + "/"
    encoded = "/".join(quote(part, safe="!$&'()+,;=@[]~") for part in parts)
    if parts and parts[-1].lower() in {"index.html", "index.htm", "index.xhtml"}:
        encoded = "/".join(encoded.split("/")[:-1]) + "/"
    return urljoin(root, encoded)


def _find_manifest(root: Path) -> Path | None:
    for name in ("manifest.json", "asset-manifest.json", "url-manifest.json", "_cloner_report.txt"):
        candidate = root / name
        if candidate.is_file() and not candidate.is_symlink():
            return candidate.resolve()
    return None


def _manifest_mappings(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise FileNotFoundError(path)
    text = path.read_text(encoding="utf-8", errors="replace")
    return _manifest_mappings_text(text)


def _manifest_mappings_text(text: str) -> dict[str, str]:
    pairs: list[tuple[str, str]] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        for line in text.splitlines():
            for separator in (" -> ", "\t"):
                if separator in line:
                    left, right = (part.strip() for part in line.split(separator, 1))
                    if _looks_url(left):
                        pairs.append((right, left))
                    elif _looks_url(right):
                        pairs.append((left, right))
                    break
    else:
        pairs.extend(_json_pairs(data))
    return {_safe_relative_name(local): url for local, url in pairs if _looks_url(url)}


def _json_pairs(value: Any) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    if isinstance(value, dict):
        url = next((value.get(key) for key in ("url", "source_url", "original_url") if isinstance(value.get(key), str)), None)
        local = next((value.get(key) for key in ("path", "file", "local_path", "saved_as") if isinstance(value.get(key), str)), None)
        if url and local:
            pairs.append((local, url))
        for key, item in value.items():
            if _looks_url(str(key)) and isinstance(item, str):
                pairs.append((item, str(key)))
            elif _looks_url(str(item)) and isinstance(key, str):
                pairs.append((key, str(item)))
            elif isinstance(item, (dict, list)):
                pairs.extend(_json_pairs(item))
    elif isinstance(value, list):
        for item in value:
            pairs.extend(_json_pairs(item))
    return pairs


def _mapped_url(relative: str, mappings: dict[str, str]) -> str | None:
    normalized = relative.replace("\\", "/").lstrip("./")
    candidates = (normalized, "/".join(PurePosixPath(normalized).parts[1:]))
    return next((mappings[item] for item in candidates if item in mappings), None)


def _content_type(name: str) -> str:
    suffix = Path(name).suffix.lower()
    if suffix in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}:
        return "application/javascript"
    if suffix == ".map":
        return "application/source-map+json"
    if suffix == ".webmanifest":
        return "application/manifest+json"
    return mimetypes.guess_type(name)[0] or "text/plain"


def _safe_relative_name(value: str) -> str:
    raw = str(value).replace("\\", "/").strip()
    path = PurePosixPath(raw)
    if not raw or path.is_absolute() or (len(raw) > 1 and raw[1] == ":") or ".." in path.parts:
        raise ValueError("mirror contains an invalid relative file name")
    return path.as_posix()


def _validate_base_url(value: str) -> None:
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise ValueError("mirror base URL must be an absolute HTTP(S) URL")


def _looks_url(value: str) -> bool:
    parsed = urlsplit(value)
    return parsed.scheme.lower() in {"http", "https"} and bool(parsed.netloc)
