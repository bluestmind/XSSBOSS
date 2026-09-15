"""HackerOne Scraper API Router."""
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend_api.db.session import get_db
from backend_api.services.hackerone_scraper_service import HackerOneScraperService

router = APIRouter(prefix="/hackerone", tags=["hackerone"])


class HackerOneSyncRequest(BaseModel):
    handles: Optional[List[str]] = None
    bounty_only: bool = True
    limit: int = 50
    tenant_id: int = 1


class HackerOneExportRequest(BaseModel):
    bounty_only: bool = False
    query: Optional[str] = None
    format: str = "json"  # json or csv


@router.get("/programs")
def list_programs(
    bounty_only: bool = Query(default=False, description="Filter for bounty-offering programs only"),
    query: Optional[str] = Query(default=None, description="Search by program name or handle"),
    asset_type: Optional[str] = Query(default=None, description="Filter by asset type (URL, DOMAIN, etc.)"),
    limit: Optional[int] = Query(default=100, description="Max programs to return"),
) -> Dict[str, Any]:
    """Search and list public HackerOne bug bounty programs and scopes."""
    try:
        programs = HackerOneScraperService.fetch_all_programs(
            bounty_only=bounty_only,
            query=query,
            asset_type=asset_type,
            limit=limit,
        )
        return {
            "status": "success",
            "count": len(programs),
            "programs": programs,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/programs/{handle}")
def get_program_details(handle: str) -> Dict[str, Any]:
    """Get complete scope and details for a specific HackerOne program."""
    prog = HackerOneScraperService.fetch_program_by_handle(handle)
    if not prog:
        raise HTTPException(status_code=404, detail=f"Program @{handle} not found")
    return {"status": "success", "program": prog}


@router.post("/sync")
def sync_programs(
    req: HackerOneSyncRequest,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Sync and import HackerOne programs into the active XSS Boss target database."""
    try:
        res = HackerOneScraperService.bulk_sync_to_database(
            db=db,
            handles=req.handles,
            bounty_only=req.bounty_only,
            limit=req.limit,
            tenant_id=req.tenant_id,
        )
        return res
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/export")
def export_programs(req: HackerOneExportRequest) -> Any:
    """Export scraped HackerOne programs and scopes in JSON or CSV format."""
    programs = HackerOneScraperService.fetch_all_programs(
        bounty_only=req.bounty_only,
        query=req.query,
    )
    exported = HackerOneScraperService.export_programs(programs, export_format=req.format)
    if req.format.lower() == "csv":
        return Response(content=exported, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=hackerone_scopes.csv"})
    return Response(content=exported, media_type="application/json")
