import sqlite3
import uuid
from typing import Annotated, List, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel

from vce_hq.auth import gcp_oauth
from vce_hq.auth.dependencies import get_auth_db, get_current_admin_user, get_current_user, User
from vce_hq.auth.security import create_access_token, get_password_hash, verify_password
from vce_hq.config import settings
from vce_hq.db.connection import create_connection

router = APIRouter(prefix="/auth", tags=["auth"])


UserRole = Literal["admin", "user"]


class Token(BaseModel):
    access_token: str
    token_type: str


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: UserRole = "user"


@router.post("/login", response_model=Token)
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Annotated[sqlite3.Connection, Depends(get_auth_db)]
):
    user_row = db.execute(
        "SELECT id, username, password_hash, role FROM users WHERE username = ?", 
        (form_data.username,)
    ).fetchone()
    
    if not user_row or not verify_password(form_data.password, user_row["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    access_token = create_access_token(data={"sub": user_row["username"], "role": user_row["role"]})
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/change-password")
async def change_password(
    payload: ChangePasswordRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[sqlite3.Connection, Depends(get_auth_db)]
):
    user_row = db.execute(
        "SELECT password_hash FROM users WHERE id = ?", (current_user.id,)
    ).fetchone()
    
    if not verify_password(payload.old_password, user_row["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect old password"
        )
        
    new_hash = get_password_hash(payload.new_password)
    db.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (new_hash, current_user.id)
    )
    db.commit()
    return {"message": "Password updated successfully"}


@router.post("/users", response_model=User)
async def create_user(
    payload: CreateUserRequest,
    current_admin: Annotated[User, Depends(get_current_admin_user)],
    db: Annotated[sqlite3.Connection, Depends(get_auth_db)]
):
    # Check if user already exists
    existing = db.execute(
        "SELECT id FROM users WHERE username = ?", (payload.username,)
    ).fetchone()
    
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
        
    user_id = str(uuid.uuid4())
    hashed_pw = get_password_hash(payload.password)
    
    db.execute(
        "INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)",
        (user_id, payload.username, hashed_pw, payload.role)
    )
    db.commit()
    
    return User(id=user_id, username=payload.username, role=payload.role)


@router.get("/users", response_model=List[User])
async def list_users(
    current_admin: Annotated[User, Depends(get_current_admin_user)],
    db: Annotated[sqlite3.Connection, Depends(get_auth_db)]
):
    rows = db.execute("SELECT id, username, role FROM users ORDER BY created_at DESC").fetchall()
    return [User(id=row["id"], username=row["username"], role=row["role"]) for row in rows]


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: str,
    current_admin: Annotated[User, Depends(get_current_admin_user)],
    db: Annotated[sqlite3.Connection, Depends(get_auth_db)]
):
    if user_id == current_admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own admin account"
        )
        
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    return {"message": "User deleted successfully"}


# ─── GCP OAuth 2.0 / OIDC (PRD §7.2) ──────────────────────────────────

@router.get("/gcp/config")
async def gcp_auth_config():
    """UI polls this to decide whether to render the 'Sign in with Google' button."""
    return {
        "enabled": settings.gcp_auth_enabled,
        "allowed_domains": settings.gcp_allowed_domains_list(),
    }


@router.get("/gcp/login")
async def gcp_login(tenant_id: str):
    if not settings.gcp_auth_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="GCP auth disabled")
    if not settings.gcp_oauth_client_id or not settings.gcp_oauth_client_secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="GCP OAuth is not configured (missing client id/secret).",
        )
    url, _state = gcp_oauth.build_authorize_url(tenant_id=tenant_id)
    return RedirectResponse(url=url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)


@router.get("/gcp/callback")
async def gcp_callback(
    request: Request,
    db: Annotated[sqlite3.Connection, Depends(get_auth_db)],
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
):
    if not settings.gcp_auth_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="GCP auth disabled")
    if error:
        return _oauth_redirect_with_error(f"Google returned error: {error}")
    if not code or not state:
        return _oauth_redirect_with_error("Missing OAuth code or state.")

    try:
        state_payload = gcp_oauth.verify_state(state)
    except ValueError as exc:
        return _oauth_redirect_with_error(str(exc))

    tenant_id = state_payload.get("tid")
    if not tenant_id:
        return _oauth_redirect_with_error("State payload missing tenant id.")

    try:
        identity = await gcp_oauth.exchange_code_and_verify(code)
    except PermissionError as exc:
        return _oauth_redirect_with_error(str(exc))
    except Exception as exc:
        return _oauth_redirect_with_error(f"Token exchange failed: {exc}")

    # IAM role resolution uses the *tenant* DB (where the Vault SA lives).
    tenant_conn = create_connection(settings.tenant_db_path(tenant_id))
    try:
        try:
            vce_role, matched = gcp_oauth.resolve_role_from_iam(
                tenant_conn, tenant_id, identity.email
            )
        except PermissionError as exc:
            return _oauth_redirect_with_error(str(exc))
        except LookupError as exc:
            return _oauth_redirect_with_error(f"IAM lookup failed: {exc}")
    finally:
        tenant_conn.close()

    user = gcp_oauth.upsert_oauth_user(db, identity, vce_role)
    token = create_access_token(data={
        "sub": user["username"],
        "role": user["role"],
        "auth": "gcp",
        "matched_roles": matched,
    })

    # Hand token to the SPA via URL fragment (never hits server logs).
    ui_url = f"/ui/#token={token}&role={user['role']}"
    return RedirectResponse(url=ui_url, status_code=status.HTTP_302_FOUND)


def _oauth_redirect_with_error(msg: str) -> RedirectResponse:
    import urllib.parse
    return RedirectResponse(
        url=f"/ui/#oauth_error={urllib.parse.quote(msg)}",
        status_code=status.HTTP_302_FOUND,
    )
