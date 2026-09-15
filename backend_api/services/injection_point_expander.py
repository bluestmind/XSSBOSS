"""Injection-point expander — the xsscrapy borrow: test headers, cookies, and path, not just params.

XSSBOSS's request layer (``RequestBuilder`` / ``FilterProfiler``) is already fully location-aware
(query/body/json/header/cookie/path), and the browser executor can inject headers (CDP
``setExtraHTTPHeaders``) and cookies. The only missing piece was that recon never *seeded* those as
injection points — so reflected XSS via ``User-Agent`` / ``Referer`` / ``X-Forwarded-*`` / cookies /
URL path was invisible. This seeds them so the existing smart pipeline (context detection → SMT →
oracle) tests them exactly like query params.

Non-reflecting header points are naturally pruned by context detection, so this widens coverage
without exploding the request budget on dead surface.
"""
from __future__ import annotations

from typing import List

from sqlalchemy.orm import Session

from backend_api.models.endpoint import Endpoint
from backend_api.models.param import Param
from backend_api.utils.logger import logger

# The reflected-XSS header surface, highest-value first (echoed by error pages, analytics, WAFs).
HEADER_POINTS: List[str] = ["User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host"]
# A probe cookie whose value the app may reflect.
COOKIE_POINTS: List[str] = ["xssboss_probe"]


class InjectionPointExpander:
    """Seeds header / cookie / path injection points for an endpoint (idempotent)."""

    @staticmethod
    def seed_for_endpoint(
        db: Session,
        endpoint_id: int,
        *,
        include_headers: bool = True,
        include_cookies: bool = True,
        include_path: bool = True,
    ) -> int:
        endpoint = db.query(Endpoint).filter(Endpoint.id == endpoint_id).first()
        if not endpoint:
            return 0
        existing = {
            (p.name.lower(), p.location)
            for p in db.query(Param).filter(Param.endpoint_id == endpoint_id).all()
        }
        to_add: List[Param] = []

        if include_headers:
            for name in HEADER_POINTS:
                if (name.lower(), "header") not in existing:
                    to_add.append(Param(endpoint_id=endpoint_id, name=name, location="header"))
        if include_cookies:
            for name in COOKIE_POINTS:
                if (name.lower(), "cookie") not in existing:
                    to_add.append(Param(endpoint_id=endpoint_id, name=name, location="cookie"))
        # Path injection only makes sense for a path-templated URL (recon marks these with {…}).
        if include_path and "{" in (endpoint.url_pattern or "") and "}" in (endpoint.url_pattern or ""):
            import re
            for name in re.findall(r"\{(\w+)\}", endpoint.url_pattern):
                if (name.lower(), "path") not in existing:
                    to_add.append(Param(endpoint_id=endpoint_id, name=name, location="path"))

        if not to_add:
            return 0
        db.add_all(to_add)
        try:
            db.commit()
        except Exception as e:
            db.rollback()
            logger.warning(f"Injection-point seeding failed for endpoint {endpoint_id}: {e}")
            return 0
        logger.info(f"Seeded {len(to_add)} header/cookie/path injection point(s) for endpoint {endpoint_id}")
        return len(to_add)
