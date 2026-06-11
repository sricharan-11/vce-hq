"""Health check endpoint."""

from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/health", summary="Health check")
async def health_check() -> dict:
    """Return service health status.

    This endpoint does not require authentication or tenant headers.
    Used by load balancers and monitoring systems.
    """
    return {"status": "healthy", "service": "vce-hq", "version": "1.0.0"}
