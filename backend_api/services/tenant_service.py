"""Tenant provisioning and token authentication."""
import hashlib
import json

from sqlalchemy.orm import Session

from backend_api.config import settings
from backend_api.models.tenant import Tenant


class TenantService:
    @staticmethod
    def token_hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @staticmethod
    def configured_tokens() -> dict[str, str]:
        configured: dict[str, str] = {}
        if settings.API_AUTH_TOKEN:
            configured["default"] = settings.API_AUTH_TOKEN
        if settings.TENANT_API_TOKENS.strip():
            parsed = json.loads(settings.TENANT_API_TOKENS)
            if not isinstance(parsed, dict):
                raise RuntimeError("TENANT_API_TOKENS must be a JSON object of slug to token")
            configured.update({str(slug): str(token) for slug, token in parsed.items()})
        return configured

    @staticmethod
    def provision_configured(db: Session) -> None:
        for slug, token in TenantService.configured_tokens().items():
            tenant = db.query(Tenant).filter(Tenant.slug == slug).first()
            if tenant is None:
                tenant = Tenant(slug=slug, name=slug.replace("-", " ").title())
                db.add(tenant)
            tenant.api_token_hash = TenantService.token_hash(token)
            tenant.is_active = True
        db.commit()

    @staticmethod
    def authenticate(db: Session, token: str) -> Tenant | None:
        if not token:
            return None
        return db.query(Tenant).filter(
            Tenant.api_token_hash == TenantService.token_hash(token),
            Tenant.is_active.is_(True),
        ).first()
