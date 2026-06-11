"""Credential management API endpoints (The Vault).

CRUD operations for tenant credentials. Credential values are
hashed on store and never returned in API responses. The tenant
must provide the credential value at the time of verification
or rotation.

Security notes:
    - Credential values are hashed with SHA-256 + per-tenant salt
    - Plaintext values are never persisted or logged
    - List endpoints return metadata only (name, provider, dates)
    - Constant-time comparison is used for verification
"""

import logging
import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from vce_hq.api.dependencies import get_credential_manager, get_db_connection, get_settings, get_tenant_id
from vce_hq.config import Settings
from vce_hq.vault.inventory import schedule_inventory_capture
from vce_hq.vault.manager import CredentialManager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/credentials", tags=["vault"])


# ── Request/Response Schemas ──────────────────────────────────

class StoreCredentialRequest(BaseModel):
    """Request to store a new credential."""
    name: str = Field(
        ..., min_length=1, max_length=200,
        description="Human-readable label for this credential",
        examples=["AWS Production Read-Only"],
    )
    provider: str = Field(
        ..., min_length=1, max_length=50,
        description="Cloud provider identifier",
        examples=["aws", "gcp", "azure"],
    )
    credential_value: str = Field(
        ..., min_length=1,
        description="The credential value (API key, JSON, etc.). Will be hashed immediately.",
    )


class RotateCredentialRequest(BaseModel):
    """Request to rotate an existing credential."""
    new_value: str = Field(
        ..., min_length=1,
        description="The new credential value. Will replace the existing hash.",
    )


class VerifyCredentialRequest(BaseModel):
    """Request to verify a credential value against the stored hash."""
    credential_value: str = Field(
        ..., min_length=1,
        description="The credential value to verify.",
    )


class CredentialResponse(BaseModel):
    """Credential metadata returned by the API (never includes the value or hash)."""
    credential_id: str
    name: str
    provider: str
    created_at: str
    last_rotated: str | None = None
    inventory_status: str = "unknown"  # 'capturing' | 'ready' | 'unknown'


class VerifyResponse(BaseModel):
    """Response from credential verification."""
    name: str
    verified: bool


# ── Endpoints ─────────────────────────────────────────────────

@router.post(
    "/",
    response_model=CredentialResponse,
    summary="Store a new credential",
    status_code=status.HTTP_201_CREATED,
)
async def store_credential(
    request: StoreCredentialRequest,
    tenant_id: Annotated[str, Depends(get_tenant_id)],
    vault: Annotated[CredentialManager, Depends(get_credential_manager)],
    app_settings: Annotated[Settings, Depends(get_settings)],
) -> CredentialResponse:
    """Store a new credential (hashed + encrypted) and trigger inventory capture."""
    try:
        credential = vault.store_credential(
            name=request.name,
            provider=request.provider,
            credential_value=request.credential_value,
        )
    except Exception as e:
        if "UNIQUE constraint" in str(e):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A credential with name '{request.name}' already exists",
            )
        raise

    # ── Trigger background inventory sweep ──────────────────────
    # Non-blocking: the HTTP response returns immediately while the
    # sweep runs in a background asyncio task.
    db_path = str(app_settings.tenant_db_path(tenant_id))
    schedule_inventory_capture(
        tenant_id=tenant_id,
        credential_name=request.name,
        provider=request.provider,
        credential_value=request.credential_value,
        db_path=db_path,
    )

    return CredentialResponse(
        credential_id=credential.credential_id,
        name=credential.name,
        provider=credential.provider,
        created_at=credential.created_at.isoformat(),
        last_rotated=None,
        inventory_status="capturing",
    )


@router.get(
    "/",
    response_model=list[CredentialResponse],
    summary="List all credentials",
)
async def list_credentials(
    vault: Annotated[CredentialManager, Depends(get_credential_manager)],
) -> list[CredentialResponse]:
    """List all credentials for this tenant (metadata only, no values or hashes)."""
    credentials = vault.list_credentials()
    return [
        CredentialResponse(
            credential_id=c.credential_id,
            name=c.name,
            provider=c.provider,
            created_at=c.created_at.isoformat() if hasattr(c.created_at, 'isoformat') else str(c.created_at),
            last_rotated=c.last_rotated.isoformat() if c.last_rotated and hasattr(c.last_rotated, 'isoformat') else c.last_rotated,
        )
        for c in credentials
    ]


@router.post(
    "/{name}/verify",
    response_model=VerifyResponse,
    summary="Verify a credential",
)
async def verify_credential(
    name: str,
    request: VerifyCredentialRequest,
    vault: Annotated[CredentialManager, Depends(get_credential_manager)],
) -> VerifyResponse:
    """Verify a credential value against the stored hash."""
    verified = vault.verify_credential(name, request.credential_value)
    return VerifyResponse(name=name, verified=verified)


@router.put(
    "/{name}/rotate",
    response_model=dict,
    summary="Rotate a credential",
)
async def rotate_credential(
    name: str,
    request: RotateCredentialRequest,
    vault: Annotated[CredentialManager, Depends(get_credential_manager)],
) -> dict:
    """Rotate a credential's value (re-hash with new value)."""
    rotated = vault.rotate_credential(name, request.new_value)
    if not rotated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Credential '{name}' not found",
        )
    return {"name": name, "rotated": True}


@router.delete(
    "/{name}",
    summary="Delete a credential",
    status_code=status.HTTP_200_OK,
)
async def delete_credential(
    name: str,
    vault: Annotated[CredentialManager, Depends(get_credential_manager)],
) -> dict:
    """Delete a credential by name."""
    deleted = vault.delete_credential(name)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Credential '{name}' not found",
        )
    return {"name": name, "deleted": True}


@router.post(
    "/{name}/refresh-inventory",
    response_model=dict,
    summary="Re-trigger inventory capture for a credential",
    status_code=status.HTTP_202_ACCEPTED,
)
async def refresh_inventory(
    name: str,
    tenant_id: Annotated[str, Depends(get_tenant_id)],
    vault: Annotated[CredentialManager, Depends(get_credential_manager)],
    app_settings: Annotated[Settings, Depends(get_settings)],
) -> dict:
    """Re-trigger a background inventory sweep for an existing credential.

    Useful after infrastructure changes or if the initial capture failed.
    Returns immediately; the sweep runs in the background.
    """
    # Retrieve the stored plaintext (Fernet-decrypted)
    plaintext = vault.get_plaintext(name)
    if plaintext is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Credential '{name}' not found or has no encrypted value",
        )

    # Determine provider from stored metadata
    creds = vault.list_credentials()
    cred = next((c for c in creds if c.name == name), None)
    if cred is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Credential '{name}' not found",
        )

    db_path = str(app_settings.tenant_db_path(tenant_id))
    schedule_inventory_capture(
        tenant_id=tenant_id,
        credential_name=name,
        provider=cred.provider,
        credential_value=plaintext,
        db_path=db_path,
    )

    return {
        "name": name,
        "provider": cred.provider,
        "status": "inventory_capture_scheduled",
        "message": "Inventory sweep started in the background.",
    }
