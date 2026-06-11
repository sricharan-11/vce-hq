"""FastAPI dependency injection.

Provides request-scoped dependencies for tenant isolation:
    - Tenant ID extraction from headers
    - Per-tenant database connections
    - Per-tenant service instances (STM, LTM, embedding, vault)

All dependencies are designed for FastAPI's ``Depends()`` system,
enabling clean testability and automatic cleanup.
"""

import sqlite3
from typing import Annotated, Generator

from fastapi import Depends, Header, HTTPException, status

from vce_hq.config import Settings, get_settings
from vce_hq.db.connection import create_connection
from vce_hq.db.long_term import LongTermMemory
from vce_hq.db.short_term import ShortTermMemory
from vce_hq.embeddings.service import EmbeddingService
from vce_hq.vault.manager import CredentialManager


def get_tenant_id(
    x_tenant_id: Annotated[str, Header(description="Tenant identifier")],
) -> str:
    """Extract and validate the tenant ID from the request header.

    Every API request MUST include an ``X-Tenant-ID`` header.
    This enforces tenant isolation at the API boundary.

    Args:
        x_tenant_id: The tenant ID header value.

    Returns:
        The validated tenant ID string.

    Raises:
        HTTPException: If the header is missing or empty.
    """
    if not x_tenant_id or not x_tenant_id.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="X-Tenant-ID header is required",
        )
    # Sanitize: only allow alphanumeric, hyphens, and underscores
    sanitized = x_tenant_id.strip()
    if not all(c.isalnum() or c in "-_" for c in sanitized):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="X-Tenant-ID must contain only alphanumeric characters, hyphens, and underscores",
        )
    return sanitized


import threading

# Thread-safe per-tenant connection cache.
# SQLite in WAL mode (set in create_connection) supports concurrent readers
# with a single writer, and check_same_thread=False is already configured.
# Connections are reused across requests for the same tenant to avoid:
#   - SQLite file open (disk I/O)
#   - 3 PRAGMAs per open
#   - sqlite-vec C extension load
#   - 8+ CREATE TABLE IF NOT EXISTS DDL statements
_conn_lock = threading.Lock()
_conn_cache: dict[str, sqlite3.Connection] = {}


def get_db_connection(
    tenant_id: Annotated[str, Depends(get_tenant_id)],
    app_settings: Annotated[Settings, Depends(get_settings)],
) -> Generator[sqlite3.Connection, None, None]:
    """Provide a tenant-scoped database connection (pooled).

    Connections are created on first access and reused across requests
    for the same tenant. This avoids the overhead of loading the
    sqlite-vec C extension and running schema migrations on every request.

    Yields:
        An open SQLite connection with sqlite-vec loaded.
    """
    db_path = app_settings.tenant_db_path(tenant_id)
    cache_key = str(db_path)

    with _conn_lock:
        if cache_key not in _conn_cache:
            _conn_cache[cache_key] = create_connection(db_path)

    yield _conn_cache[cache_key]
    # Connection is NOT closed — reused across the process lifetime.


def get_stm(
    conn: Annotated[sqlite3.Connection, Depends(get_db_connection)],
) -> ShortTermMemory:
    """Provide a tenant-scoped Short-Term Memory instance."""
    return ShortTermMemory(conn)


def get_ltm(
    conn: Annotated[sqlite3.Connection, Depends(get_db_connection)],
) -> LongTermMemory:
    """Provide a tenant-scoped Long-Term Memory instance."""
    return LongTermMemory(conn)


# Module-level singleton: avoids re-calling genai.configure() and
# creating new HTTP connection pools on every request.
_embedding_service: EmbeddingService | None = None


def get_embedding_service() -> EmbeddingService:
    """Provide the shared embedding service (singleton).

    The embedding service is stateless and safe to share across tenants.
    A single instance is reused for the lifetime of the process to avoid
    re-initializing the Google SDK and HTTP clients on every request.
    """
    global _embedding_service
    if _embedding_service is None:
        _embedding_service = EmbeddingService()
    return _embedding_service


def get_credential_manager(
    conn: Annotated[sqlite3.Connection, Depends(get_db_connection)],
    tenant_id: Annotated[str, Depends(get_tenant_id)],
) -> CredentialManager:
    """Provide a tenant-scoped credential manager."""
    return CredentialManager(conn, tenant_id)
