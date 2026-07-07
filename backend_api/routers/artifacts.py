"""Tenant-scoped, integrity-checked evidence downloads."""
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from backend_api.db.session import get_db
from backend_api.models.evidence import EvidenceArtifact
from backend_api.services.evidence_service import EvidenceService


router = APIRouter(prefix="/artifacts", tags=["artifacts"])

_MEDIA_TYPES = {
    "campaign_report_html": "text/html; charset=utf-8",
    "campaign_report_markdown": "text/markdown; charset=utf-8",
    "dom_snapshot": "text/html; charset=utf-8",
    "execution_log": "text/plain; charset=utf-8",
    "request": "application/json",
    "response": "application/json",
    "screenshot": "image/png",
}


def _download_response(artifact: EvidenceArtifact) -> FileResponse:
    try:
        path = EvidenceService.resolve_verified_path(artifact)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    metadata = artifact.artifact_metadata or {}
    filename = metadata.get("filename") or Path(path).name
    headers = {
        "Cache-Control": "private, immutable, max-age=31536000",
        "ETag": f'"{artifact.sha256}"',
        "Content-Security-Policy": (
            "default-src 'none'; style-src 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; img-src 'self' data:; "
            "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
        ),
    }
    return FileResponse(
        path=path,
        media_type=metadata.get("media_type") or _MEDIA_TYPES.get(artifact.kind, "application/octet-stream"),
        filename=filename,
        content_disposition_type="inline",
        headers=headers,
    )


@router.get("/{artifact_id}/download")
def download_artifact(artifact_id: int, db: Session = Depends(get_db)):
    """Download an artifact only when the authenticated tenant owns its experiment."""
    artifact = db.query(EvidenceArtifact).filter(EvidenceArtifact.id == artifact_id).first()
    if artifact is None:
        raise HTTPException(status_code=404, detail="Artifact not found")
    return _download_response(artifact)
