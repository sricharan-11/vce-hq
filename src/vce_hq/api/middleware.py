"""FastAPI middleware for logging, tenant tagging, and request timing."""

import logging
import time
import uuid

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from vce_hq.config import settings

logger = logging.getLogger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Logs every request with tenant ID, method, path, status, and duration.

    Adds structured fields for observability:
        - request_id: Unique ID per request for tracing
        - tenant_id: From X-Tenant-ID header (if present)
        - method: HTTP method
        - path: Request path
        - status_code: Response status
        - duration_ms: Request processing time
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        request_id = str(uuid.uuid4())[:8]
        tenant_id = request.headers.get("X-Tenant-ID", "anonymous")
        start_time = time.monotonic()

        # Attach request ID to response headers for client-side tracing
        try:
            response = await call_next(request)
        except Exception:
            duration_ms = (time.monotonic() - start_time) * 1000
            logger.error(
                "request_failed | request_id=%s tenant=%s method=%s path=%s duration_ms=%.1f",
                request_id, tenant_id, request.method, request.url.path, duration_ms,
            )
            raise

        duration_ms = (time.monotonic() - start_time) * 1000
        response.headers["X-Request-ID"] = request_id

        logger.info(
            "request_completed | request_id=%s tenant=%s method=%s path=%s status=%d duration_ms=%.1f",
            request_id, tenant_id, request.method, request.url.path,
            response.status_code, duration_ms,
        )

        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Set OWASP-recommended browser security headers on every response.

    Includes:
        - Content-Security-Policy         → blocks inline JS + arbitrary connect-src
        - X-Content-Type-Options: nosniff → stops MIME sniffing on served assets
        - X-Frame-Options: DENY           → belt-and-braces alongside CSP frame-ancestors
        - Referrer-Policy: no-referrer    → avoids leaking `/analyze?…` paths to CDNs
        - Strict-Transport-Security       → only when the request already came in via HTTPS
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)
        if not settings.security_headers_enabled:
            return response

        response.headers.setdefault("Content-Security-Policy", settings.content_security_policy)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

        # Only advertise HSTS when the browser is already talking to us over TLS —
        # otherwise the header is ignored anyway and it hides local http dev issues.
        if request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https":
            response.headers.setdefault(
                "Strict-Transport-Security",
                f"max-age={settings.hsts_max_age_seconds}; includeSubDomains",
            )

        return response
