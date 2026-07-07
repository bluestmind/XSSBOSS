"""Register immutable hashes for evidence produced by workers."""
import hashlib
import json
from pathlib import Path
from typing import Optional

from sqlalchemy.orm import Session

from backend_api.models.evidence import EvidenceArtifact
from backend_api.config import settings


class EvidenceService:
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
        redacted = dict(request_data or {})
        sensitive = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key"}
        headers = {
            key: ("[REDACTED]" if str(key).lower() in sensitive else value)
            for key, value in (redacted.get("headers") or {}).items()
        }
        redacted["headers"] = headers
        if redacted.get("cookies"):
            redacted["cookies"] = {key: "[REDACTED]" for key in redacted["cookies"]}
        return redacted

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
                metadata={"canonical": "json", "credentials_redacted": True},
            ))
        if result is not None:
            response = {
                "status_code": result.get("status_code"),
                "headers": result.get("headers") or {},
                "final_url": result.get("final_url"),
                "oracle_hit": bool(result.get("oracle_hit")),
            }
            artifacts.append(EvidenceService.register_bytes(
                db,
                experiment_id,
                execution.id,
                "response",
                EvidenceService._canonical_json(response),
                metadata={"canonical": "json"},
            ))
        if execution.logs:
            artifacts.append(EvidenceService.register_bytes(
                db,
                experiment_id,
                execution.id,
                "execution_log",
                str(execution.logs).encode("utf-8", errors="replace"),
            ))
        if execution.dom_snapshot:
            artifacts.append(EvidenceService.register_bytes(
                db,
                experiment_id,
                execution.id,
                "dom_snapshot",
                execution.dom_snapshot.encode("utf-8", errors="replace"),
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
