"""Parameters router."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional

from backend_api.db.session import get_db
from backend_api.models.param import Param
from backend_api.schemas.param import ParamResponse

router = APIRouter(prefix="/params", tags=["params"])


@router.get("/", response_model=List[ParamResponse])
def list_params(
    endpoint_id: Optional[int] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """List parameters, optionally filtered by endpoint."""
    query = db.query(Param)
    if endpoint_id:
        query = query.filter(Param.endpoint_id == endpoint_id)
    return query.order_by(Param.id.asc()).offset(skip).limit(limit).all()


@router.get("/dictionary")
def get_learned_dictionary(
    category: Optional[str] = None,
    query: Optional[str] = None
):
    """Get the self-improving parameter vocabulary across all bug bounty programs."""
    from backend_api.services.learned_dictionary_service import LearnedDictionaryService
    items = LearnedDictionaryService.get_all(category=category, query=query)
    redirect_count = sum(1 for i in items if i.get("category") == "redirect")
    search_count = sum(1 for i in items if i.get("category") == "search_query")
    jsonp_count = sum(1 for i in items if i.get("category") == "jsonp_callback")
    debug_count = sum(1 for i in items if i.get("category") == "debug_privileged")

    return {
        "total_count": len(items),
        "categories": {
            "redirect": redirect_count,
            "search_query": search_count,
            "jsonp_callback": jsonp_count,
            "debug_privileged": debug_count,
            "other": len(items) - (redirect_count + search_count + jsonp_count + debug_count),
        },
        "items": items,
    }


@router.post("/dictionary")
def add_custom_parameter(payload: dict):
    """Add or update a custom parameter in the self-improving dictionary."""
    param_name = payload.get("param_name") or payload.get("name")
    category = payload.get("category")
    source = payload.get("source") or "custom_user_rule"

    if not param_name:
        raise HTTPException(status_code=400, detail="param_name is required")

    from backend_api.services.learned_dictionary_service import LearnedDictionaryService
    item = LearnedDictionaryService.register_parameter(
        name=param_name,
        category=category,
        source=source,
        is_custom=True
    )
    return {"message": f"Successfully registered parameter '{param_name}' into dictionary", "item": item}


@router.delete("/dictionary/{param_name}")
def delete_learned_parameter(param_name: str):
    """Remove a parameter from the learned dictionary."""
    from backend_api.services.learned_dictionary_service import LearnedDictionaryService
    deleted = LearnedDictionaryService.delete_param(param_name)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Parameter '{param_name}' not found")
    return {"message": f"Parameter '{param_name}' removed from dictionary"}


@router.get("/{param_id}", response_model=ParamResponse)
def get_param(param_id: int, db: Session = Depends(get_db)):
    """Get a parameter by ID."""
    param = db.query(Param).filter(Param.id == param_id).first()
    if not param:
        raise HTTPException(status_code=404, detail=f"Param {param_id} not found")
    return param

