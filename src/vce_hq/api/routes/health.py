import functools
import subprocess
from typing import Dict
from fastapi import APIRouter

router = APIRouter(tags=["health"])


@functools.lru_cache(maxsize=1)
def get_git_commit() -> Dict[str, str]:
    """Retrieve git commit information of the current deployment."""
    try:
        # Format: %H (hash), %h (abbrev hash), %an (author name), %ad (author date), %s (subject)
        output = subprocess.check_output(
            ["git", "log", "-1", "--format=%H%n%h%n%an%n%ad%n%s"],
            stderr=subprocess.DEVNULL,
            text=True
        ).strip().split("\n")

        if len(output) >= 5:
            return {
                "commit": output[0],
                "abbreviated_commit": output[1],
                "author": output[2],
                "date": output[3],
                "subject": output[4]
            }
        elif len(output) > 0 and output[0]:
            return {"commit": output[0]}
    except Exception:
        pass
    return {"commit": "unknown", "error": "Could not retrieve git commit details"}


@router.get("/health", summary="Health check")
async def health_check() -> Dict[str, str]:
    """Return service health status.

    This endpoint does not require authentication or tenant headers.
    Used by load balancers and monitoring systems.
    """
    return {"status": "healthy", "service": "vce-hq", "version": "1.0.0"}


@router.get("/commitcode", summary="Commit code")
async def commit_code() -> Dict[str, str]:
    """Return git commit details of the current deployment."""
    return get_git_commit()

