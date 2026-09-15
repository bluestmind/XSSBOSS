"""Autonomous stored-flow discovery (plant -> render edge mapping).

Closes the remaining autonomy gap for stored / second-order XSS: instead of an operator
*declaring* which pages to revisit after submitting to a form, this engine *discovers* those
edges empirically. It plants a unique **inert canary** (a plain marker, never a payload) through
each input source, re-crawls the surface once, and attributes each surfaced canary back to its
source — yielding proven ``submit-here -> renders-there`` edges that feed ``StoredXSSVerifier``.

Design guarantees:
* **Safe by construction** — discovery uses benign alphanumeric canaries with no HTML/JS
  metacharacters. Exploitation payloads are only ever sent later, by ``StoredXSSVerifier``, and
  only on edges proven here.
* **Request-efficient** — plant a distinct canary per source in one pass, then observe all render
  candidates in one pass: ``O(sources + renders)`` requests, not ``O(sources x renders)`` — which
  matters under the scanner's hard request cap.
* **Decoupled / testable** — the core :meth:`discover` takes injected ``submit_fn`` / ``render_fn``
  so it runs without a browser or DB; the thin :meth:`discover_for_target` wrapper wires it to the
  live authenticated request path.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

# Submit an inert canary into (endpoint_id, param_id); return True if the submission went through.
SubmitFn = Callable[[int, int, str], bool]
# Fetch the rendered text/HTML of a render-candidate endpoint (authenticated in the live wiring).
RenderFn = Callable[[int], Optional[str]]

_CANARY_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"


@dataclass(frozen=True)
class SourceCandidate:
    """An input source a canary can be planted into."""
    endpoint_id: int
    param_id: int
    label: str = ""


@dataclass
class DiscoveredEdge:
    """A proven plant->render relationship."""
    source_endpoint_id: int
    param_id: int
    canary: str
    render_endpoint_ids: List[int] = field(default_factory=list)
    snippets: Dict[int, str] = field(default_factory=dict)  # render_endpoint_id -> surrounding text

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_endpoint_id": self.source_endpoint_id,
            "param_id": self.param_id,
            "canary": self.canary,
            "render_endpoint_ids": list(self.render_endpoint_ids),
            "snippets": dict(self.snippets),
        }


class StoredFlowDiscovery:
    """Discovers stored plant->render edges by benign canary correlation."""

    CANARY_PREFIX = "wfd"          # workflow-discovery marker; inert on purpose
    SNIPPET_RADIUS = 40

    @classmethod
    def make_canary(cls, rand_bytes: int = 8) -> str:
        """Return an inert, unique canary — alphanumerics only, no HTML/JS metacharacters."""
        body = "".join(secrets.choice(_CANARY_ALPHABET) for _ in range(rand_bytes))
        return f"{cls.CANARY_PREFIX}{body}"

    @classmethod
    def _snippet(cls, haystack: str, canary: str) -> str:
        idx = haystack.find(canary)
        if idx < 0:
            return ""
        start = max(0, idx - cls.SNIPPET_RADIUS)
        end = min(len(haystack), idx + len(canary) + cls.SNIPPET_RADIUS)
        return haystack[start:end]

    @classmethod
    def discover(
        cls,
        sources: Sequence[SourceCandidate],
        render_endpoint_ids: Sequence[int],
        submit_fn: SubmitFn,
        render_fn: RenderFn,
        *,
        max_sources: int = 50,
        max_renders: int = 100,
    ) -> List[DiscoveredEdge]:
        """Plant one canary per source, observe every render candidate once, and map the edges.

        Only sources whose submission succeeds are planted. A source whose canary surfaces on no
        render candidate yields an edge with an empty ``render_endpoint_ids`` (recorded so the
        caller knows it was tried and is not a stored source).
        """
        planted: List[DiscoveredEdge] = []
        canary_to_edge: Dict[str, DiscoveredEdge] = {}

        # Pass 1: plant a distinct canary per source.
        for source in list(sources)[:max_sources]:
            canary = cls.make_canary()
            try:
                ok = bool(submit_fn(source.endpoint_id, source.param_id, canary))
            except Exception:
                ok = False
            if not ok:
                continue
            edge = DiscoveredEdge(
                source_endpoint_id=source.endpoint_id,
                param_id=source.param_id,
                canary=canary,
            )
            planted.append(edge)
            canary_to_edge[canary] = edge

        if not canary_to_edge:
            return planted

        # Pass 2: observe every render candidate once; attribute surfaced canaries to their source.
        for render_id in list(dict.fromkeys(render_endpoint_ids))[:max_renders]:
            try:
                body = render_fn(render_id)
            except Exception:
                body = None
            if not body:
                continue
            for canary, edge in canary_to_edge.items():
                if canary in body:
                    if render_id not in edge.render_endpoint_ids:
                        edge.render_endpoint_ids.append(render_id)
                        edge.snippets[render_id] = cls._snippet(body, canary)

        return planted

    @classmethod
    def confirmed_edges(cls, edges: Sequence[DiscoveredEdge]) -> List[DiscoveredEdge]:
        """Only edges that actually surfaced somewhere — the ones worth handing to StoredXSSVerifier."""
        return [e for e in edges if e.render_endpoint_ids]

    # ------------------------------------------------------------------ live wiring

    @classmethod
    def discover_for_target(
        cls,
        db: Any,
        target_id: int,
        sources: Sequence[SourceCandidate],
        render_endpoint_ids: Sequence[int],
        *,
        identity: Optional[str] = None,
        max_sources: int = 50,
        max_renders: int = 100,
    ) -> List[DiscoveredEdge]:
        """Best-effort wrapper that binds the core to the live authenticated request path.

        Builds ``submit_fn`` from ``StoredXSSVerifier._submit_payload`` and ``render_fn`` from an
        authenticated GET. Every endpoint and credential merge is revalidated here so a stale
        caller cannot expand program scope.
        """
        from backend_api.models.endpoint import Endpoint
        from backend_api.models.target import Target

        target = db.query(Target).filter(Target.id == target_id).first()
        auth_info = target.auth_info if target else None

        def submit_fn(endpoint_id: int, param_id: int, value: str) -> bool:
            try:
                from backend_api.models.param import Param
                from backend_api.services.stored_xss_verifier import StoredXSSVerifier
                endpoint = db.query(Endpoint).filter(Endpoint.id == endpoint_id).first()
                param = db.query(Param).filter(Param.id == param_id).first()
                from backend_api.utils.scope_guard import is_endpoint_in_scope
                if (
                    not endpoint
                    or not param
                    or endpoint.target_id != target_id
                    or param.endpoint_id != endpoint.id
                    or not is_endpoint_in_scope(endpoint)
                ):
                    return False
                request_context = None
                try:
                    from backend_api.services.auth_session_service import AuthSessionService
                    request_context = AuthSessionService.request_context_for_url(
                        auth_info,
                        endpoint.url_pattern,
                        target.base_url,
                        identity,
                        endpoint.auth_context or {},
                    )
                except Exception:
                    request_context = None
                StoredXSSVerifier._submit_payload(
                    endpoint=endpoint, param=param, payload=value, request_context=request_context
                )
                return True
            except Exception:
                return False

        def render_fn(endpoint_id: int) -> Optional[str]:
            try:
                import httpx
                from backend_api.services.auth_session_service import AuthSessionService
                endpoint = db.query(Endpoint).filter(Endpoint.id == endpoint_id).first()
                from backend_api.utils.scope_guard import is_endpoint_in_scope
                if (
                    not endpoint
                    or endpoint.target_id != target_id
                    or not is_endpoint_in_scope(endpoint)
                ):
                    return None
                url = getattr(endpoint, "url_pattern", None) or getattr(endpoint, "url", None)
                if not url:
                    return None
                headers = {}
                try:
                    headers = AuthSessionService.request_context_for_url(
                        auth_info,
                        url,
                        target.base_url,
                        identity,
                        endpoint.auth_context or {},
                    )
                except Exception:
                    pass
                from backend_api.utils.stealth import get_http_proxy_kwargs
                proxy_kwargs = get_http_proxy_kwargs(rotated=True)
                from backend_api.config import settings
                from backend_api.utils.rate_limiter import rate_limited_call
                with httpx.Client(
                    timeout=8,
                    verify=not settings.ALLOW_INSECURE_TLS,
                    follow_redirects=False,
                    **proxy_kwargs,
                ) as client:
                    response = rate_limited_call(
                        url,
                        lambda: client.get(url, headers=headers),
                    )
                barrier = AuthSessionService.response_intervention_reason(
                    status_code=response.status_code,
                    final_url=str(response.url),
                    body_text=response.text,
                    login_url_patterns=(
                        AuthSessionService.material(auth_info, identity).login_url_patterns
                        if auth_info else ()
                    ),
                )
                if barrier:
                    return None
                return response.text if response.status_code == 200 else None
            except Exception:
                return None

        return cls.discover(
            sources, render_endpoint_ids, submit_fn, render_fn,
            max_sources=max_sources, max_renders=max_renders,
        )
