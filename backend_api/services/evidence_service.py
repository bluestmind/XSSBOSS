"""Register immutable hashes for evidence produced by workers."""
import hashlib
import json
import re
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sqlalchemy.orm import Session

from backend_api.models.evidence import EvidenceArtifact
from backend_api.config import settings
from backend_api.utils.log_serializer import (
    parse_execution_logs,
    safe_unparsed_execution_log_text,
    sanitize_execution_logs,
)
from backend_api.utils.runtime_lineage_evidence import (
    normalize_runtime_lineage_evidence,
)


class EvidenceService:
    REDACTION_POLICY_VERSION = "2026-09-08.1"
    _SENSITIVE_NAMES = {
        "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key",
        "password", "passwd", "secret", "token", "api_key", "apikey", "access_token",
        "refresh_token", "session", "sessionid", "csrf", "xsrf", "jwt",
    }

    @classmethod
    def _redact_value(cls, value, key: str = ""):
        normalized_key = str(key).lower().replace("-", "_")
        if normalized_key in {name.replace("-", "_") for name in cls._SENSITIVE_NAMES}:
            return "[REDACTED]"
        if isinstance(value, dict):
            return {str(name): cls._redact_value(item, str(name)) for name, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [cls._redact_value(item, key) for item in value]
        if isinstance(value, str):
            value = re.sub(r"(?i)(authorization|proxy-authorization|cookie|set-cookie|password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|session(?:id)?|csrf|xsrf|jwt)\\s*[:=]\\s*[^\\r\\n&,;]+", r"\1=[REDACTED]", value)
            return cls._redact_url(value)
        return value

    @classmethod
    def _redact_url(cls, value: str) -> str:
        try:
            parsed = urlsplit(value)
            if not parsed.scheme or not parsed.netloc:
                return value
            query = urlencode([
                (key, "[REDACTED]" if key.lower().replace("-", "_") in {name.replace("-", "_") for name in cls._SENSITIVE_NAMES} else item)
                for key, item in parse_qsl(parsed.query, keep_blank_values=True)
            ], doseq=True)
            return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))
        except (TypeError, ValueError):
            return value

    @staticmethod
    def _persist(experiment_id: int, kind: str, digest: str, content: bytes) -> str:
        safe_kind = "".join(char if char.isalnum() or char in "-_" else "_" for char in kind)
        root = Path(settings.EVIDENCE_DIR).resolve()
        relative = Path(str(experiment_id)) / safe_kind / f"{digest}.evidence"
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            try:
                with destination.open("xb") as handle:
                    handle.write(content)
            except FileExistsError:
                pass
        return relative.as_posix()

    @staticmethod
    def _canonical_json(value) -> bytes:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")

    @staticmethod
    def _redacted_request(request_data: dict) -> dict:
        return EvidenceService._redact_value(dict(request_data or {}))

    @staticmethod
    def register_bytes(
        db: Session,
        experiment_id: int,
        execution_id: Optional[int],
        kind: str,
        content: bytes,
        uri: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> EvidenceArtifact:
        digest = hashlib.sha256(content).hexdigest()
        source_uri = uri
        stored_uri = EvidenceService._persist(experiment_id, kind, digest, content)
        artifact_metadata = dict(metadata or {})
        if source_uri:
            artifact_metadata.setdefault("source_uri", source_uri)
        artifact = db.query(EvidenceArtifact).filter_by(
            experiment_id=experiment_id, kind=kind, sha256=digest
        ).first()
        if artifact is None:
            artifact = EvidenceArtifact(
                experiment_id=experiment_id,
                execution_id=execution_id,
                kind=kind,
                uri=stored_uri,
                sha256=digest,
                size_bytes=len(content),
                artifact_metadata=artifact_metadata or None,
            )
            db.add(artifact)
        elif execution_id and artifact.execution_id is None:
            artifact.execution_id = execution_id
        if artifact.uri != stored_uri:
            artifact.uri = stored_uri
        db.commit()
        return artifact

    @staticmethod
    def resolve_verified_path(artifact: EvidenceArtifact) -> Path:
        """Resolve an immutable artifact without permitting absolute or traversal paths."""
        root = Path(settings.EVIDENCE_DIR).resolve()
        if not artifact.uri:
            raise FileNotFoundError("Artifact has no stored content")
        relative = Path(artifact.uri)
        if relative.is_absolute():
            raise PermissionError("Absolute artifact paths are not downloadable")
        path = (root / relative).resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise PermissionError("Artifact path escapes the evidence store") from exc
        if not path.is_file():
            raise FileNotFoundError("Artifact content is missing")
        result = EvidenceService.verify_artifact(artifact)
        if not result["valid"]:
            raise ValueError("Artifact integrity verification failed")
        return path

    @staticmethod
    def register_execution(
        db: Session,
        execution,
        request_data: Optional[dict] = None,
        result: Optional[dict] = None,
    ) -> list[EvidenceArtifact]:
        artifacts = []
        experiment_id = execution.test_case.experiment_id
        if request_data is not None:
            artifacts.append(EvidenceService.register_bytes(
                db,
                experiment_id,
                execution.id,
                "request",
                EvidenceService._canonical_json(EvidenceService._redacted_request(request_data)),
                metadata={
                    "canonical": "json",
                    "credentials_redacted": True,
                    "redaction_policy_version": EvidenceService.REDACTION_POLICY_VERSION,
                },
            ))
        if result is not None:
            response = {
                "status_code": result.get("status_code"),
                "headers": EvidenceService._redact_value(result.get("headers") or {}),
                "final_url": EvidenceService._redact_url(str(result.get("final_url") or "")),
                "oracle_hit": bool(result.get("oracle_hit")),
            }
            artifacts.append(EvidenceService.register_bytes(
                db,
                experiment_id,
                execution.id,
                "response",
                EvidenceService._canonical_json(response),
                metadata={"canonical": "json", "redaction_policy_version": EvidenceService.REDACTION_POLICY_VERSION},
            ))
            result_logs = sanitize_execution_logs(
                result.get("logs"),
                test_case_id=execution.test_case_id,
                attempt_no=execution.attempt_no,
            )
            response_posture = result_logs.get("response_posture")
            if isinstance(response_posture, dict):
                artifacts.append(EvidenceService.register_bytes(
                    db,
                    experiment_id,
                    execution.id,
                    "response_posture",
                    EvidenceService._canonical_json(
                        EvidenceService._redact_value(response_posture)
                    ),
                    metadata={
                        "canonical": "json",
                        "schema_version": str(response_posture.get("schema_version") or "unknown")[:80],
                        "redaction_policy_version": EvidenceService.REDACTION_POLICY_VERSION,
                    },
                ))
            runtime_coverage = result_logs.get("runtime_code_coverage")
            if isinstance(runtime_coverage, dict):
                artifacts.append(EvidenceService.register_bytes(
                    db,
                    experiment_id,
                    execution.id,
                    "runtime_code_coverage",
                    EvidenceService._canonical_json(
                        EvidenceService._redact_value(runtime_coverage)
                    ),
                    metadata={
                        "canonical": "json",
                        "schema_version": str(
                            runtime_coverage.get("schema_version") or "unknown"
                        )[:80],
                        "source_free": True,
                        "redaction_policy_version": EvidenceService.REDACTION_POLICY_VERSION,
                    },
                ))
            raw_lineage = (
                result_logs.get("runtime_lineage")
                if isinstance(result_logs.get("runtime_lineage"), dict)
                else result_logs.get("runtime_causal_lineage")
            )
            runtime_lineage = normalize_runtime_lineage_evidence(
                raw_lineage,
                test_case_id=execution.test_case_id,
                attempt_no=execution.attempt_no,
            )
            if runtime_lineage is not None:
                artifacts.append(EvidenceService.register_bytes(
                    db,
                    experiment_id,
                    execution.id,
                    "runtime_lineage",
                    EvidenceService._canonical_json(runtime_lineage),
                    metadata={
                        "canonical": "json",
                        "schema_version": runtime_lineage["schema_version"],
                        "value_free": True,
                        "redaction_policy_version": EvidenceService.REDACTION_POLICY_VERSION,
                    },
                ))
            dom_differential = result_logs.get("dom_marker_differential")
            if isinstance(dom_differential, dict):
                artifacts.append(EvidenceService.register_bytes(
                    db,
                    experiment_id,
                    execution.id,
                    "dom_marker_differential",
                    EvidenceService._canonical_json(
                        EvidenceService._redact_value(dom_differential)
                    ),
                    metadata={
                        "canonical": "json",
                        "schema_version": str(
                            dom_differential.get("schema_version") or "unknown"
                        )[:80],
                        "content_free": True,
                        "redaction_policy_version": EvidenceService.REDACTION_POLICY_VERSION,
                    },
                ))
        if execution.logs:
            parsed_execution_logs = parse_execution_logs(execution.logs)
            safe_execution_logs = sanitize_execution_logs(
                parsed_execution_logs,
                test_case_id=execution.test_case_id,
                attempt_no=execution.attempt_no,
            )
            execution_log_content = (
                EvidenceService._canonical_json(
                    EvidenceService._redact_value(safe_execution_logs)
                )
                if parsed_execution_logs
                else str(EvidenceService._redact_value(
                    safe_unparsed_execution_log_text(execution.logs)
                )).encode("utf-8", errors="replace")
            )
            artifacts.append(EvidenceService.register_bytes(
                db,
                experiment_id,
                execution.id,
                "execution_log",
                execution_log_content,
                metadata={"redaction_policy_version": EvidenceService.REDACTION_POLICY_VERSION, "sensitive_artifact": True},
            ))
        if execution.dom_snapshot:
            artifacts.append(EvidenceService.register_bytes(
                db,
                experiment_id,
                execution.id,
                "dom_snapshot",
                str(EvidenceService._redact_value(execution.dom_snapshot)).encode("utf-8", errors="replace"),
                metadata={"redaction_policy_version": EvidenceService.REDACTION_POLICY_VERSION, "sensitive_artifact": True},
            ))
        if execution.screenshot_path:
            path = Path(execution.screenshot_path).resolve()
            if path.is_file():
                artifacts.append(EvidenceService.register_bytes(
                    db,
                    experiment_id,
                    execution.id,
                    "screenshot",
                    path.read_bytes(),
                    uri=str(path),
                    metadata={"sensitive_artifact": True, "redaction_policy_version": EvidenceService.REDACTION_POLICY_VERSION},
                ))
        return artifacts

    @staticmethod
    def verify_artifact(artifact: EvidenceArtifact) -> dict:
        path = Path(artifact.uri) if artifact.uri else None
        if path is not None and not path.is_absolute():
            path = Path(settings.EVIDENCE_DIR).resolve() / path
        elif path is not None:
            path = path.resolve()
        if path is None or not path.is_file():
            return {
                "artifact_id": artifact.id,
                "kind": artifact.kind,
                "valid": False,
                "error": "missing_content",
            }
        content = path.read_bytes()
        actual_hash = hashlib.sha256(content).hexdigest()
        valid = actual_hash == artifact.sha256 and len(content) == artifact.size_bytes
        return {
            "artifact_id": artifact.id,
            "kind": artifact.kind,
            "valid": valid,
            "expected_sha256": artifact.sha256,
            "actual_sha256": actual_hash,
            "expected_size": artifact.size_bytes,
            "actual_size": len(content),
        }

    @staticmethod
    def verify_all(db: Session) -> dict:
        results = [
            EvidenceService.verify_artifact(artifact)
            for artifact in db.query(EvidenceArtifact).order_by(EvidenceArtifact.id).all()
        ]
        valid = sum(1 for result in results if result["valid"])
        return {
            "total": len(results),
            "valid": valid,
            "invalid": len(results) - valid,
            "passed": bool(results) and valid == len(results),
            "results": results,
        }

    @staticmethod
    def link_finding(db: Session, finding_id: int, execution_ids: list[int]) -> None:
        if not execution_ids:
            return
        db.query(EvidenceArtifact).filter(
            EvidenceArtifact.execution_id.in_(execution_ids)
        ).update({EvidenceArtifact.finding_id: finding_id}, synchronize_session=False)
        db.commit()

    @staticmethod
    def descriptors(db: Session, execution_ids: list[int]) -> list[dict]:
        if not execution_ids:
            return []
        return [
            {
                "kind": artifact.kind,
                "sha256": artifact.sha256,
                "size_bytes": artifact.size_bytes,
                "uri": artifact.uri,
            }
            for artifact in db.query(EvidenceArtifact)
            .filter(EvidenceArtifact.execution_id.in_(execution_ids))
            .order_by(EvidenceArtifact.id)
            .all()
        ]
