"""FastAPI application entry point."""
import os
import re
import threading
import time
import uuid
os.environ["no_proxy"] = "localhost,127.0.0.1,::1"
os.environ["NO_PROXY"] = "localhost,127.0.0.1,::1"

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.responses import PlainTextResponse
from fastapi.exceptions import RequestValidationError
from backend_api.config import settings
from backend_api.routers import artifacts, contexts, endpoints, experiments, filters, modern, oracle, params, program_import, research, results, scans, sinks, targets, test_cases, verification, burp
from backend_api.db.base import init_db
from backend_api.utils.logger import logger, setup_logging
from backend_api.utils.errors import XSSBossException
from sqlalchemy import text

_metrics_lock = threading.Lock()
_request_counts: dict[tuple[str, int], int] = {}
_request_duration_seconds = 0.0
_duration_buckets = (0.05, 0.1, 0.3, 1.0, 5.0)
_route_duration_counts: dict[str, int] = {}
_route_duration_sums: dict[str, float] = {}
_route_duration_buckets: dict[tuple[str, float], int] = {}

# Setup logging
setup_logging()


def _route_group(path: str) -> str:
    return path.split("/")[3] if path.startswith("/api/v1/") else "system"


def _record_request_metric(path: str, status_code: int, duration: float) -> None:
    global _request_duration_seconds
    route_group = _route_group(path)
    with _metrics_lock:
        key = (route_group, status_code)
        _request_counts[key] = _request_counts.get(key, 0) + 1
        _request_duration_seconds += duration
        _route_duration_counts[route_group] = _route_duration_counts.get(route_group, 0) + 1
        _route_duration_sums[route_group] = _route_duration_sums.get(route_group, 0.0) + duration
        for boundary in _duration_buckets:
            if duration <= boundary:
                bucket_key = (route_group, boundary)
                _route_duration_buckets[bucket_key] = _route_duration_buckets.get(bucket_key, 0) + 1


def _apply_response_security(response, request_id: str):
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


def _append_request_audit(request: Request, audit_request_id: str, status_code: int, duration: float) -> None:
    if not hasattr(request.state, "tenant_id"):
        return
    try:
        from backend_api.db.base import SessionLocal
        from backend_api.services.audit_service import AuditService

        audit_event = dict(
            tenant_id=request.state.tenant_id,
            request_id=audit_request_id,
            actor=request.state.tenant_slug,
            method=request.method,
            path=request.url.path,
            status_code=status_code,
            duration_ms=duration * 1000,
            client_ip=request.client.host if request.client else None,
        )
        if settings.AUDIT_MODE.lower() == "celery":
            AuditService.enqueue(**audit_event)
        else:
            audit_db = SessionLocal()
            try:
                AuditService.record(audit_db, **audit_event)
            finally:
                audit_db.close()
    except Exception as audit_error:
        logger.error("Failed to append request audit event: %s", audit_error)


def _finish_early_response(request: Request, response, request_id: str, audit_request_id: str, started: float):
    duration = time.perf_counter() - started
    _record_request_metric(request.url.path, response.status_code, duration)
    _append_request_audit(request, audit_request_id, response.status_code, duration)
    return _apply_response_security(response, request_id)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize and clean up application resources."""
    logger.info("Starting XSS Boss API...")
    try:
        settings.validate_runtime()
        init_db()
        from backend_api.db.base import SessionLocal
        from backend_api.services.tenant_service import TenantService

        provisioning_db = SessionLocal()
        try:
            TenantService.provision_configured(provisioning_db)
        finally:
            provisioning_db.close()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}", exc_info=True)
        raise

    yield

    logger.info("Shutting down XSS Boss API...")


app = FastAPI(
    title="XSS Boss API",
    description="Human-in-the-loop XSS hunting system",
    version="1.0.0",
    lifespan=lifespan,
)


@app.middleware("http")
async def security_and_observability(request: Request, call_next):
    """Authenticate production API traffic and attach correlation telemetry."""
    global _request_duration_seconds
    candidate_request_id = request.headers.get("x-request-id", "")
    request_id = candidate_request_id if re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", candidate_request_id) else str(uuid.uuid4())
    audit_request_id = f"{request_id[:43]}-{uuid.uuid4().hex[:20]}"
    started = time.perf_counter()
    protected = request.url.path.startswith(settings.API_PREFIX) or request.url.path.startswith(("/reports", "/screenshots"))
    oracle_callback = request.url.path.startswith(f"{settings.API_PREFIX}/oracle")
    from backend_api.services.tenant_service import TenantService
    auth_required = bool(TenantService.configured_tokens()) and protected and not oracle_callback
    tenant_context_token = None
    if auth_required and request.method != "OPTIONS":
        authorization = request.headers.get("authorization", "")
        bearer = authorization[7:] if authorization.lower().startswith("bearer ") else ""
        supplied = bearer or request.headers.get("x-api-key", "")
        from backend_api.db.base import SessionLocal
        from backend_api.tenancy import current_tenant_id

        auth_db = SessionLocal()
        try:
            tenant = TenantService.authenticate(auth_db, supplied)
        finally:
            auth_db.close()
        if tenant is None:
            response = JSONResponse(
                status_code=401,
                content={"detail": "Missing or invalid API credentials", "request_id": request_id},
                headers={"X-Request-ID": request_id},
            )
            return _finish_early_response(request, response, request_id, audit_request_id, started)
        request.state.tenant_id = tenant.id
        request.state.tenant_slug = tenant.slug
        try:
            from backend_api.services.quota_service import QuotaService

            quota_allowed, quota_count, quota_limit = QuotaService.allow_request(tenant)
        except Exception as quota_error:
            if settings.ENVIRONMENT.lower() == "production":
                logger.error("Tenant quota backend unavailable: %s", quota_error)
                response = JSONResponse(
                    status_code=503,
                    content={"detail": "Quota service unavailable", "request_id": request_id},
                    headers={"X-Request-ID": request_id},
                )
                return _finish_early_response(request, response, request_id, audit_request_id, started)
            quota_allowed, quota_count, quota_limit = True, 0, 0
        if not quota_allowed:
            response = JSONResponse(
                status_code=429,
                content={"detail": "Tenant API quota exceeded", "request_id": request_id},
                headers={
                    "X-Request-ID": request_id,
                    "X-RateLimit-Limit": str(quota_limit),
                    "X-RateLimit-Remaining": "0",
                },
            )
            return _finish_early_response(request, response, request_id, audit_request_id, started)
        tenant_context_token = current_tenant_id.set(tenant.id)

    try:
        response = await call_next(request)
    finally:
        if tenant_context_token is not None:
            from backend_api.tenancy import current_tenant_id

            current_tenant_id.reset(tenant_context_token)
    duration = time.perf_counter() - started
    _record_request_metric(request.url.path, response.status_code, duration)
    if auth_required:
        _append_request_audit(request, audit_request_id, response.status_code, duration)
    if auth_required and 'quota_limit' in locals() and quota_limit:
        response.headers["X-RateLimit-Limit"] = str(quota_limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, quota_limit - quota_count))
    return _apply_response_security(response, request_id)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if settings.ENVIRONMENT.lower() != "production":
    # Legacy local-only paths. Production artifacts are served exclusively by
    # tenant-scoped, hash-verifying API routes.
    from fastapi.staticfiles import StaticFiles

    workspace_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for route, directory_name in (("/screenshots", "screenshots"), ("/reports", "reports")):
        directory = os.path.join(workspace_root, directory_name)
        os.makedirs(directory, exist_ok=True)
        app.mount(route, StaticFiles(directory=directory), name=directory_name)


# Error handlers
@app.exception_handler(XSSBossException)
async def xssboss_exception_handler(request: Request, exc: XSSBossException):
    """Handle XSS Boss exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail}
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle validation errors."""
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.errors()}
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"}
    )


# Include routers
app.include_router(targets.router, prefix=settings.API_PREFIX)
app.include_router(endpoints.router, prefix=settings.API_PREFIX)
app.include_router(params.router, prefix=settings.API_PREFIX)
app.include_router(program_import.router, prefix=settings.API_PREFIX)
app.include_router(contexts.router, prefix=settings.API_PREFIX)
app.include_router(sinks.router, prefix=settings.API_PREFIX)
app.include_router(filters.router, prefix=settings.API_PREFIX)
app.include_router(modern.router, prefix=settings.API_PREFIX)
app.include_router(experiments.router, prefix=settings.API_PREFIX)
app.include_router(test_cases.router, prefix=settings.API_PREFIX)
app.include_router(artifacts.router, prefix=settings.API_PREFIX)
app.include_router(research.router, prefix=settings.API_PREFIX)
app.include_router(verification.router, prefix=settings.API_PREFIX)
app.include_router(results.router, prefix=settings.API_PREFIX)
app.include_router(oracle.router, prefix=settings.API_PREFIX)
app.include_router(scans.router, prefix=settings.API_PREFIX)
app.include_router(burp.router, prefix=settings.API_PREFIX)

@app.get("/")
def root():
    """Root endpoint."""
    return {
        "name": "XSS Boss API",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
        "health": "/health"
    }


@app.get("/health")
def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "XSS Boss API"
    }


@app.get("/ready")
def readiness():
    """Verify dependencies required to accept new durable work."""
    from backend_api.db.session import SessionLocal

    checks = {"database": False, "redis": settings.ORCHESTRATION_MODE.lower() != "celery"}
    db = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
        checks["database"] = True
    finally:
        db.close()
    if settings.ORCHESTRATION_MODE.lower() == "celery":
        try:
            import redis

            checks["redis"] = bool(redis.Redis.from_url(settings.REDIS_URL).ping())
        except Exception:
            checks["redis"] = False
    ready = all(checks.values())
    return JSONResponse(status_code=200 if ready else 503, content={"ready": ready, "checks": checks})


@app.get("/metrics", response_class=PlainTextResponse)
def metrics():
    """Expose low-cardinality Prometheus metrics without target data leakage."""
    with _metrics_lock:
        lines = [
            "# HELP xssboss_http_requests_total HTTP requests by route group and status.",
            "# TYPE xssboss_http_requests_total counter",
        ]
        for (route_group, status_code), count in sorted(_request_counts.items()):
            lines.append(
                f'xssboss_http_requests_total{{route="{route_group}",status="{status_code}"}} {count}'
            )
        lines.extend([
            "# HELP xssboss_http_request_duration_seconds_total Total request processing time.",
            "# TYPE xssboss_http_request_duration_seconds_total counter",
            f"xssboss_http_request_duration_seconds_total {_request_duration_seconds:.6f}",
        ])
        lines.extend([
            "# HELP xssboss_http_request_duration_seconds Request latency by low-cardinality route group.",
            "# TYPE xssboss_http_request_duration_seconds histogram",
        ])
        for route_group in sorted(_route_duration_counts):
            for boundary in _duration_buckets:
                count = _route_duration_buckets.get((route_group, boundary), 0)
                lines.append(
                    f'xssboss_http_request_duration_seconds_bucket{{route="{route_group}",le="{boundary:g}"}} {count}'
                )
            count = _route_duration_counts[route_group]
            lines.append(
                f'xssboss_http_request_duration_seconds_bucket{{route="{route_group}",le="+Inf"}} {count}'
            )
            lines.append(
                f'xssboss_http_request_duration_seconds_sum{{route="{route_group}"}} '
                f'{_route_duration_sums[route_group]:.6f}'
            )
            lines.append(f'xssboss_http_request_duration_seconds_count{{route="{route_group}"}} {count}')
    try:
        from redis import Redis

        redis_client = Redis.from_url(settings.REDIS_URL)
        lines.extend([
            "# HELP xssboss_queue_depth Ready messages by durable queue.",
            "# TYPE xssboss_queue_depth gauge",
        ])
        for queue in ("orchestration", "browser", "audit", "maintenance"):
            lines.append(f'xssboss_queue_depth{{queue="{queue}"}} {redis_client.llen(queue)}')
        lines.append("xssboss_dependency_up{dependency=\"redis\"} 1")
    except Exception:
        lines.append("xssboss_dependency_up{dependency=\"redis\"} 0")

    try:
        from datetime import UTC, datetime
        from sqlalchemy import func
        from backend_api.db.base import SessionLocal
        from backend_api.models.experiment import Experiment, ExperimentStatus
        from backend_api.models.run_state import RunStage, RunStageStatus
        from backend_api.models.test_case import TestCase, TestCaseStatus

        metrics_db = SessionLocal()
        try:
            lines.extend([
                "# HELP xssboss_runs Runs by terminal/current status.",
                "# TYPE xssboss_runs gauge",
            ])
            for run_status, count in metrics_db.query(
                Experiment.status, func.count(Experiment.id)
            ).group_by(Experiment.status).all():
                lines.append(f'xssboss_runs{{status="{run_status.value}"}} {count}')
            active_case_leases = metrics_db.query(func.count(TestCase.id)).filter(
                TestCase.status == TestCaseStatus.RUNNING,
                TestCase.lease_expires_at > datetime.now(UTC),
            ).scalar()
            stale_case_leases = metrics_db.query(func.count(TestCase.id)).filter(
                TestCase.status == TestCaseStatus.RUNNING,
                TestCase.lease_expires_at <= datetime.now(UTC),
            ).scalar()
            stale_stage_leases = metrics_db.query(func.count(RunStage.id)).filter(
                RunStage.status == RunStageStatus.RUNNING,
                RunStage.lease_expires_at <= datetime.now(UTC),
            ).scalar()
            now = datetime.now(UTC)
            oldest_queued = metrics_db.query(func.min(TestCase.created_at)).filter(
                TestCase.status.in_([TestCaseStatus.PENDING, TestCaseStatus.QUEUED])
            ).scalar()
            oldest_active_run = metrics_db.query(func.min(Experiment.started_at)).filter(
                Experiment.status.in_([ExperimentStatus.PENDING, ExperimentStatus.RUNNING])
            ).scalar()
            queued_age = max(0.0, (now - oldest_queued).total_seconds()) if oldest_queued else 0.0
            active_run_age = max(0.0, (now - oldest_active_run).total_seconds()) if oldest_active_run else 0.0
            lines.extend([
                "# HELP xssboss_execution_leases Browser execution leases by state.",
                "# TYPE xssboss_execution_leases gauge",
                f'xssboss_execution_leases{{state="active"}} {active_case_leases}',
                f'xssboss_execution_leases{{state="stale"}} {stale_case_leases}',
                f'xssboss_stage_leases{{state="stale"}} {stale_stage_leases}',
                "# HELP xssboss_oldest_queued_case_age_seconds Age of the oldest unclaimed browser case.",
                "# TYPE xssboss_oldest_queued_case_age_seconds gauge",
                f"xssboss_oldest_queued_case_age_seconds {queued_age:.3f}",
                "# HELP xssboss_oldest_active_run_age_seconds Age of the oldest active scan run.",
                "# TYPE xssboss_oldest_active_run_age_seconds gauge",
                f"xssboss_oldest_active_run_age_seconds {active_run_age:.3f}",
                "xssboss_dependency_up{dependency=\"database\"} 1",
            ])
        finally:
            metrics_db.close()
    except Exception:
        lines.append("xssboss_dependency_up{dependency=\"database\"} 0")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend_api.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.API_RELOAD,
        log_level=settings.LOG_LEVEL.lower()
    )
