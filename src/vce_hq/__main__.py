"""VCE-HQ entry point.

Run with:
    python -m vce_hq
    # or
    uvicorn vce_hq.api.app:create_app --factory --host 0.0.0.0 --port 8000
"""

import uvicorn

from vce_hq.api.app import create_app
from vce_hq.config import settings


def main() -> None:
    """Start the VCE-HQ server."""
    app = create_app()
    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()
