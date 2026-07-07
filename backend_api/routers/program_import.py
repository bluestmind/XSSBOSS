"""Bug bounty program import routes."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend_api.db.session import get_db
from backend_api.schemas.program_import import ProgramImportRequest, ProgramImportResponse
from backend_api.services.program_import_service import ProgramImportService

router = APIRouter(prefix="/program-imports", tags=["program-imports"])


@router.post("/bug-bounty", response_model=ProgramImportResponse)
def import_bug_bounty_programs(
    request: ProgramImportRequest,
    db: Session = Depends(get_db),
):
    """Import HackerOne and YesWeHack programs into the target registry."""
    try:
        return ProgramImportService(db).import_programs(request)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
