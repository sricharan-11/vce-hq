"""FastAPI application factory.

Creates and configures the FastAPI application with all routes,
middleware, and startup/shutdown lifecycle hooks.
"""

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from vce_hq.api.middleware import RequestLoggingMiddleware
from vce_hq.api.routes import analyze, credentials, health, knowledge, webhooks, finops, trace
from vce_hq.api.scheduler import start_scheduler
from vce_hq.config import settings


def create_app() -> FastAPI:
    """Create and configure the FastAPI application.

    Returns:
        A fully configured FastAPI instance ready to serve.
    """
    # Configure logging
    _configure_logging()

    app = FastAPI(
        title="VCE-HQ",
        description=(
            "Multi-tenant AI-powered infrastructure operations advisor. "
            "Ingests observability signals, routes them through specialized "
            "LLM agents, and delivers root-cause analyses, answers to queries and remediation playbooks (if required)"
        ),
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # ── Middleware ─────────────────────────────────────────────
    # Order matters: outermost middleware runs first.

    # CORS — permissive for v1 (tighten in production)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Request logging
    app.add_middleware(RequestLoggingMiddleware)

    # ── Routes ────────────────────────────────────────────────
    app.include_router(health.router)
    app.include_router(webhooks.router)
    app.include_router(analyze.router)
    app.include_router(knowledge.router)
    app.include_router(credentials.router)
    app.include_router(finops.router)
    app.include_router(trace.router)

    # ── Frontend ──────────────────────────────────────────────
    @app.get("/", include_in_schema=False)
    async def root():
        return RedirectResponse(url="/ui/")

    app.mount("/ui", StaticFiles(directory="frontend", html=True), name="frontend")

    # ── Lifecycle Events ──────────────────────────────────────

    @app.on_event("startup")
    async def on_startup() -> None:
        logger = logging.getLogger(__name__)
        logger.info(
            "VCE-HQ starting | model=%s embedding=%s data_dir=%s",
            settings.llm_model, settings.embedding_model, settings.data_dir,
        )
        app.state.scheduler = start_scheduler()

    @app.on_event("shutdown")
    async def on_shutdown() -> None:
        logger = logging.getLogger(__name__)
        logger.info("VCE-HQ shutting down")
        if hasattr(app.state, "scheduler"):
            app.state.scheduler.shutdown()

    return app


def _configure_logging() -> None:
    """Configure structured logging based on settings."""
    log_level = getattr(logging, settings.log_level, logging.INFO)

    if settings.log_format == "json":
        fmt = '{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","message":"%(message)s"}'
    else:
        fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

    logging.basicConfig(level=log_level, format=fmt, force=True)

    # Quiet noisy third-party loggers
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
