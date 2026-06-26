"""FastAPI application entry point."""
import os
os.environ["no_proxy"] = "localhost,127.0.0.1,::1"
os.environ["NO_PROXY"] = "localhost,127.0.0.1,::1"

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from backend_api.config import settings
from backend_api.routers import contexts, endpoints, experiments, filters, modern, oracle, params, program_import, results, scans, sinks, targets, test_cases, verification, burp
from backend_api.db.base import init_db
from backend_api.utils.logger import logger, setup_logging
from backend_api.utils.errors import XSSBossException

# Setup logging
setup_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize and clean up application resources."""
    logger.info("Starting XSS Boss API...")
    try:
        init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}", exc_info=True)

    yield

    logger.info("Shutting down XSS Boss API...")


app = FastAPI(
    title="XSS Boss API",
    description="Human-in-the-loop XSS hunting system",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi.staticfiles import StaticFiles
import os
workspace_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
screenshots_dir = os.path.join(workspace_root, "screenshots")
if not os.path.exists(screenshots_dir):
    os.makedirs(screenshots_dir, exist_ok=True)
app.mount("/screenshots", StaticFiles(directory=screenshots_dir), name="screenshots")


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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend_api.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.API_RELOAD,
        log_level=settings.LOG_LEVEL.lower()
    )
