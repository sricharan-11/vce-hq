"""FastAPI middleware for logging, tenant tagging, and request timing."""

import logging
import time
import uuid

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

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
