"""GCP OAuth 2.0 (OIDC) + IAM-derived role resolution (PRD §7.2).

Public entry points:
    * ``build_authorize_url``           — construct the Google consent URL.
    * ``exchange_code_and_verify``      — swap ``code`` for verified identity.
    * ``resolve_role_from_iam``         — call ``projects.getIamPolicy`` and
                                          map GCP roles → VCE role.
    * ``upsert_oauth_user``             — persist / refresh the users row.

The IAM lookup reuses the tenant service account already stored in
The Vault — no additional credential surface is introduced.
"""

from __future__ import annotations

import json
import logging
import secrets
import sqlite3
import time
import urllib.parse
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import httpx
import jwt
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token, service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from vce_hq.config import settings
from vce_hq.vault.manager import CredentialManager

logger = logging.getLogger(__name__)


# ── Data classes ─────────────────────────────────────────────────────────

@dataclass(frozen=True)
class GoogleIdentity:
    email: str
    google_sub: str
    name: str | None
    hosted_domain: str | None


# ── OAuth state (signed with JWT secret, prevents CSRF/replay) ───────────

def _make_state(tenant_id: str, nonce: str) -> str:
    payload = {
        "tid": tenant_id,
        "nonce": nonce,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=10),
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm="HS256")


def verify_state(state: str) -> dict:
    try:
        return jwt.decode(state, settings.jwt_secret_key, algorithms=["HS256"])
    except jwt.PyJWTError as exc:
        raise ValueError(f"Invalid OAuth state: {exc}") from exc


# ── Authorize URL ────────────────────────────────────────────────────────

_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"  # noqa: S105 (public URL)


def build_authorize_url(tenant_id: str) -> tuple[str, str]:
    """Return (url, state). Caller must store `state` briefly if desired."""
    nonce = secrets.token_urlsafe(16)
    state = _make_state(tenant_id, nonce)
    params = {
        "client_id": settings.gcp_oauth_client_id,
        "redirect_uri": settings.gcp_oauth_redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "online",
        "prompt": "select_account",
        "state": state,
    }
    domains = settings.gcp_allowed_domains_list()
    if len(domains) == 1:
        # Optimization: Google narrows the account picker to this domain.
        params["hd"] = domains[0]
    return f"{_AUTH_ENDPOINT}?{urllib.parse.urlencode(params)}", state


# ── Code exchange + ID token verify ──────────────────────────────────────

async def exchange_code_and_verify(code: str) -> GoogleIdentity:
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            _TOKEN_ENDPOINT,
            data={
                "code": code,
                "client_id": settings.gcp_oauth_client_id,
                "client_secret": settings.gcp_oauth_client_secret,
                "redirect_uri": settings.gcp_oauth_redirect_uri,
                "grant_type": "authorization_code",
            },
        )
    if resp.status_code != 200:
        raise PermissionError(f"Google token exchange failed: {resp.text}")
    token_payload = resp.json()
    raw_id_token = token_payload.get("id_token")
    if not raw_id_token:
        raise PermissionError("Google response missing id_token.")

    # Verify signature + audience.
    claims = id_token.verify_oauth2_token(
        raw_id_token,
        google_requests.Request(),
        audience=settings.gcp_oauth_client_id,
    )
    if not claims.get("email_verified", False):
        raise PermissionError("Google account email is not verified.")

    email = claims["email"].lower()
    hosted_domain = claims.get("hd")

    allowed = settings.gcp_allowed_domains_list()
    if allowed and (hosted_domain or "").lower() not in allowed:
        raise PermissionError(
            f"Domain '{hosted_domain}' is not in VCE_GCP_ALLOWED_DOMAINS."
        )

    return GoogleIdentity(
        email=email,
        google_sub=claims["sub"],
        name=claims.get("name"),
        hosted_domain=hosted_domain,
    )


# ── IAM role resolution ──────────────────────────────────────────────────

def _load_sa_credentials(tenant_conn: sqlite3.Connection, tenant_id: str):
    """Pull the tenant SA JSON from The Vault and return google credentials."""
    manager = CredentialManager(tenant_conn, tenant_id)
    plaintext = manager.get_plaintext(settings.gcp_iam_credential_name)
    if not plaintext:
        raise LookupError(
            f"Vault has no credential named '{settings.gcp_iam_credential_name}' "
            f"for tenant '{tenant_id}'. Add a GCP service account with "
            f"resourcemanager.projects.getIamPolicy permission."
        )
    try:
        info = json.loads(plaintext)
    except json.JSONDecodeError as exc:
        raise LookupError("Stored GCP credential is not valid service-account JSON.") from exc
    return service_account.Credentials.from_service_account_info(
        info,
        scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"],
    )


def _principal_matches(email: str, member: str) -> bool:
    """True if a Google IAM member string refers to this user's email."""
    if member.startswith(("user:", "serviceAccount:")):
        return member.split(":", 1)[1].lower() == email
    if member == "allAuthenticatedUsers":
        return True
    return False


def resolve_role_from_iam(
    tenant_conn: sqlite3.Connection,
    tenant_id: str,
    email: str,
) -> tuple[str, list[str]]:
    """Return (vce_role, matched_gcp_roles).

    Raises ``PermissionError`` if the user has no mapped role in the tenant
    project. Raises ``LookupError`` on infrastructure problems (missing SA,
    IAM API failure) so callers can distinguish "not authorized" from
    "cannot check" and surface the right message.
    """
    project_id = settings.gcp_project_id
    if not project_id:
        raise LookupError("VCE_GCP_PROJECT_ID is not set — cannot resolve IAM roles.")

    creds = _load_sa_credentials(tenant_conn, tenant_id)
    # cache_discovery=False avoids the ~500ms discovery-cache warning path.
    service = build("cloudresourcemanager", "v1", credentials=creds, cache_discovery=False)

    try:
        policy = service.projects().getIamPolicy(
            resource=project_id, body={"options": {"requestedPolicyVersion": 3}}
        ).execute()
    except HttpError as exc:
        raise LookupError(f"IAM getIamPolicy failed: {exc}") from exc

    role_map = settings.gcp_role_map()
    matched_gcp_roles: list[str] = []
    for binding in policy.get("bindings", []):
        gcp_role = binding.get("role", "")
        if gcp_role not in role_map:
            continue
        for member in binding.get("members", []):
            if _principal_matches(email, member):
                matched_gcp_roles.append(gcp_role)
                break

    if not matched_gcp_roles:
        raise PermissionError(
            f"User '{email}' has no VCE-mapped IAM role on project '{project_id}'."
        )

    # admin wins over user when both are present.
    if any(role_map[r] == "admin" for r in matched_gcp_roles):
        return "admin", matched_gcp_roles
    return "user", matched_gcp_roles


# ── DB upsert ────────────────────────────────────────────────────────────

def upsert_oauth_user(
    auth_db: sqlite3.Connection,
    identity: GoogleIdentity,
    vce_role: str,
) -> dict:
    """Insert or update the users row for a Google-authenticated user.

    Returns {id, username, role}.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    row = auth_db.execute(
        "SELECT id, username, role FROM users WHERE google_sub = ? OR email = ?",
        (identity.google_sub, identity.email),
    ).fetchone()

    if row is None:
        user_id = str(uuid.uuid4())
        auth_db.execute(
            """
            INSERT INTO users
                (id, username, password_hash, role, auth_method,
                 email, google_sub, last_role_sync_at)
            VALUES (?, ?, ?, ?, 'gcp', ?, ?, ?)
            """,
            (
                user_id,
                identity.email,
                "!oauth-no-password!",
                vce_role,
                identity.email,
                identity.google_sub,
                now,
            ),
        )
        auth_db.commit()
        logger.info("GCP OAuth: provisioned new user %s (role=%s)", identity.email, vce_role)
        return {"id": user_id, "username": identity.email, "role": vce_role}

    auth_db.execute(
        """
        UPDATE users
        SET role = ?, google_sub = ?, email = ?,
            auth_method = 'gcp', last_role_sync_at = ?
        WHERE id = ?
        """,
        (vce_role, identity.google_sub, identity.email, now, row["id"]),
    )
    auth_db.commit()
    logger.info("GCP OAuth: refreshed user %s (role=%s)", identity.email, vce_role)
    return {"id": row["id"], "username": identity.email, "role": vce_role}
