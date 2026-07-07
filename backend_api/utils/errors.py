"""Error handling utilities."""
from fastapi import HTTPException, status
from typing import Any, Dict, Optional


class XSSBossException(HTTPException):
    """Base exception for XSS Boss API."""
    
    def __init__(
        self,
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail: Any = None,
        headers: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(status_code=status_code, detail=detail, headers=headers)


class NotFoundError(XSSBossException):
    """Resource not found exception."""
    
    def __init__(self, resource: str, resource_id: Any):
        detail = f"{resource} with id {resource_id} not found"
        super().__init__(status_code=status.HTTP_404_NOT_FOUND, detail=detail)


class ValidationError(XSSBossException):
    """Validation error exception."""
    
    def __init__(self, detail: str):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


class ConflictError(XSSBossException):
    """Resource conflict exception."""
    
    def __init__(self, detail: str):
        super().__init__(status_code=status.HTTP_409_CONFLICT, detail=detail)

