"""Microsoft Entra ID (Azure AD) OIDC + Azure RBAC role resolution (PRD §7.2.2).

Public entry points:
    * ``build_authorize_url``            — construct the Microsoft consent URL.
    * ``exchange_code_and_verify``       — swap ``code`` for verified identity.
    * ``resolve_role_from_azure_rbac``   — call the ARM roleAssignments API and
                                           map Azure role names → VCE role.
    * ``upsert_oauth_user``              — persist / refresh the users row.

The RBAC lookup reuses the tenant service principal already stored in
The Vault under ``VCE_AZURE_IAM_CREDENTIAL_NAME`` (default
``azure-iam-lookup``) — no additional credential surface is introduced.
"""

from __future__ import annotations

import json
import logging
import secrets
import sqlite3
import urllib.parse
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import httpx
import jwt

from vce_hq.config import settings
from vce_hq.vault.manager import CredentialManager

logger = logging.getLogger(__name__)


# ── Data classes ─────────────────────────────────────────────────────────

@dataclass(frozen=True)
class AzureIdentity:
    email: str
    oid: str                # Entra objectId — stable per-tenant subject
    name: str | None
    upn_domain: str | None
    tenant_id_claim: str    # 'tid' from ID token (the user's home tenant)


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

def _authority() -> str:
    tenant = settings.azure_tenant_id or "common"
    return f"https://login.microsoftonline.com/{tenant}"


def build_authorize_url(tenant_id: str) -> tuple[str, str]:
    """Return (url, state)."""
    nonce = secrets.token_urlsafe(16)
    state = _make_state(tenant_id, nonce)
    params = {
        "client_id": settings.azure_oauth_client_id,
        "redirect_uri": settings.azure_oauth_redirect_uri,
        "response_type": "code",
        "response_mode": "query",
        "scope": "openid email profile",
        "prompt": "select_account",
        "state": state,
    }
    return f"{_authority()}/oauth2/v2.0/authorize?{urllib.parse.urlencode(params)}", state


# ── Code exchange + ID token verify ──────────────────────────────────────

def _jwks_url() -> str:
    # Per-tenant JWKS — `common` also works but per-tenant is stricter.
    tenant = settings.azure_tenant_id or "common"
    return f"https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys"


async def exchange_code_and_verify(code: str) -> AzureIdentity:
    token_url = f"{_authority()}/oauth2/v2.0/token"
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            token_url,
            data={
                "code": code,
                "client_id": settings.azure_oauth_client_id,
                "client_secret": settings.azure_oauth_client_secret,
                "redirect_uri": settings.azure_oauth_redirect_uri,
                "grant_type": "authorization_code",
                "scope": "openid email profile",
            },
        )
    if resp.status_code != 200:
        raise PermissionError(f"Microsoft token exchange failed: {resp.text}")
    token_payload = resp.json()
    raw_id_token = token_payload.get("id_token")
    if not raw_id_token:
        raise PermissionError("Microsoft response missing id_token.")

    # Verify signature against Microsoft's per-tenant JWKS and enforce aud/iss.
    jwks_client = jwt.PyJWKClient(_jwks_url())
    try:
        signing_key = jwks_client.get_signing_key_from_jwt(raw_id_token).key
        claims = jwt.decode(
            raw_id_token,
            signing_key,
            algorithms=["RS256"],
            audience=settings.azure_oauth_client_id,
            options={"require": ["exp", "iat", "iss", "aud"]},
        )
    except jwt.PyJWTError as exc:
        raise PermissionError(f"Microsoft ID token verification failed: {exc}") from exc

    # Extra issuer check: must be from the configured tenant.
    expected_iss = f"https://login.microsoftonline.com/{settings.azure_tenant_id}/v2.0"
    if settings.azure_tenant_id and claims.get("iss") != expected_iss:
        raise PermissionError(
            f"ID token issuer '{claims.get('iss')}' does not match configured tenant."
        )

    # Microsoft puts the email in one of these; fall back in order.
    email = (
        claims.get("email")
        or claims.get("preferred_username")
        or claims.get("upn")
        or ""
    ).lower()
    if not email:
        raise PermissionError("Microsoft ID token contained no email/UPN claim.")

    oid = claims.get("oid")
    if not oid:
        raise PermissionError("Microsoft ID token missing 'oid' claim.")

    upn_domain = email.split("@", 1)[1] if "@" in email else None
    allowed = settings.azure_allowed_domains_list()
    if allowed and (upn_domain or "").lower() not in allowed:
        raise PermissionError(
            f"Domain '{upn_domain}' is not in VCE_AZURE_ALLOWED_DOMAINS."
        )

    return AzureIdentity(
        email=email,
        oid=oid,
        name=claims.get("name"),
        upn_domain=upn_domain,
        tenant_id_claim=claims.get("tid", ""),
    )


# ── Azure RBAC role resolution ───────────────────────────────────────────

def _load_sp_credential(tenant_conn: sqlite3.Connection, tenant_id: str) -> dict:
    manager = CredentialManager(tenant_conn, tenant_id)
    plaintext = manager.get_plaintext(settings.azure_iam_credential_name)
    if not plaintext:
        raise LookupError(
            f"Vault has no credential named '{settings.azure_iam_credential_name}' "
            f"for tenant '{tenant_id}'. Add a JSON blob with keys "
            f"tenant_id, client_id, client_secret for a service principal "
            f"with 'Microsoft.Authorization/roleAssignments/read' on the subscription."
        )
    try:
        info = json.loads(plaintext)
    except json.JSONDecodeError as exc:
        raise LookupError("Stored Azure credential is not valid JSON.") from exc
    for key in ("tenant_id", "client_id", "client_secret"):
        if not info.get(key):
            raise LookupError(f"Azure Vault credential is missing '{key}'.")
    return info


async def _sp_access_token(sp: dict) -> str:
    """Client-credentials grant for the Azure Resource Manager audience."""
    token_url = (
        f"https://login.microsoftonline.com/{sp['tenant_id']}/oauth2/v2.0/token"
    )
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": sp["client_id"],
                "client_secret": sp["client_secret"],
                "scope": "https://management.azure.com/.default",
            },
        )
    if resp.status_code != 200:
        raise LookupError(f"Azure SP token acquisition failed: {resp.text}")
    return resp.json()["access_token"]


async def _list_role_assignments(access_token: str, subscription_id: str, oid: str) -> list[dict]:
    url = (
        f"https://management.azure.com/subscriptions/{subscription_id}"
        f"/providers/Microsoft.Authorization/roleAssignments"
    )
    params = {
        "api-version": "2022-04-01",
        # This ARM filter returns assignments for the principal AND groups it belongs to.
        "$filter": f"assignedTo('{oid}')",
    }
    headers = {"Authorization": f"Bearer {access_token}"}
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(url, params=params, headers=headers)
    if resp.status_code != 200:
        raise LookupError(f"roleAssignments query failed ({resp.status_code}): {resp.text}")
    return resp.json().get("value", [])


async def _role_definition_name(access_token: str, role_definition_id: str) -> str:
    """Resolve a full roleDefinitionId path (or bare GUID) to its display name."""
    # roleDefinitionId comes back as a full ARM path — GET it directly.
    url = f"https://management.azure.com{role_definition_id}"
    params = {"api-version": "2022-04-01"}
    headers = {"Authorization": f"Bearer {access_token}"}
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(url, params=params, headers=headers)
    if resp.status_code != 200:
        raise LookupError(
            f"roleDefinitions GET failed ({resp.status_code}) for {role_definition_id}: {resp.text}"
        )
    return resp.json()["properties"]["roleName"]


async def resolve_role_from_azure_rbac(
    tenant_conn: sqlite3.Connection,
    tenant_id: str,
    oid: str,
    email: str,
) -> tuple[str, list[str]]:
    """Return (vce_role, matched_azure_role_names).

    Raises PermissionError if the user has no mapped role. Raises
    LookupError on infrastructure problems (missing SP, ARM API failure).
    """
    subscription_id = settings.azure_subscription_id
    if not subscription_id:
        raise LookupError("VCE_AZURE_SUBSCRIPTION_ID is not set — cannot resolve RBAC.")

    sp = _load_sp_credential(tenant_conn, tenant_id)
    access_token = await _sp_access_token(sp)
    assignments = await _list_role_assignments(access_token, subscription_id, oid)

    role_map = settings.azure_role_map()
    matched_role_names: list[str] = []
    # Cache role-definition lookups within this call.
    seen_defs: dict[str, str] = {}
    for a in assignments:
        props = a.get("properties", {})
        role_def_id = props.get("roleDefinitionId")
        if not role_def_id:
            continue
        if role_def_id not in seen_defs:
            try:
                seen_defs[role_def_id] = await _role_definition_name(access_token, role_def_id)
            except LookupError as exc:
                logger.warning("azure rbac: skipping unresolved role def %s: %s", role_def_id, exc)
                continue
        role_name = seen_defs[role_def_id]
        if role_name in role_map:
            matched_role_names.append(role_name)

    if not matched_role_names:
        raise PermissionError(
            f"User '{email}' has no VCE-mapped Azure role on subscription '{subscription_id}'."
        )

    if any(role_map[r] == "admin" for r in matched_role_names):
        return "admin", matched_role_names
    return "user", matched_role_names


# ── DB upsert ────────────────────────────────────────────────────────────

def upsert_oauth_user(
    auth_db: sqlite3.Connection,
    identity: AzureIdentity,
    vce_role: str,
) -> dict:
    """Insert or update the users row for an Azure-authenticated user.

    Returns {id, username, role}.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    row = auth_db.execute(
        "SELECT id, username, role FROM users WHERE azure_oid = ? OR email = ?",
        (identity.oid, identity.email),
    ).fetchone()

    if row is None:
        user_id = str(uuid.uuid4())
        auth_db.execute(
            """
            INSERT INTO users
                (id, username, password_hash, role, auth_method,
                 email, azure_oid, last_role_sync_at)
            VALUES (?, ?, ?, ?, 'azure', ?, ?, ?)
            """,
            (
                user_id,
                identity.email,
                "!oauth-no-password!",
                vce_role,
                identity.email,
                identity.oid,
                now,
            ),
        )
        auth_db.commit()
        logger.info("Azure OIDC: provisioned new user %s (role=%s)", identity.email, vce_role)
        return {"id": user_id, "username": identity.email, "role": vce_role}

    auth_db.execute(
        """
        UPDATE users
        SET role = ?, azure_oid = ?, email = ?,
            auth_method = 'azure', last_role_sync_at = ?
        WHERE id = ?
        """,
        (vce_role, identity.oid, identity.email, now, row["id"]),
    )
    auth_db.commit()
    logger.info("Azure OIDC: refreshed user %s (role=%s)", identity.email, vce_role)
    return {"id": row["id"], "username": identity.email, "role": vce_role}
