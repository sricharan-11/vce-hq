"""AWS IAM Identity Center OIDC + IAM-policy-derived role resolution (PRD §7.2.3).

Public entry points:
    * ``build_authorize_url``              — construct the IdC consent URL.
    * ``exchange_code_and_verify``         — swap ``code`` for verified identity.
    * ``resolve_role_from_aws_iam``        — find the IAM user matching the OIDC
                                             email and map its policy names to
                                             a VCE role.
    * ``upsert_oauth_user``                — persist / refresh the users row.

The IAM lookup reuses the tenant credentials already stored in The Vault
under ``VCE_AWS_IAM_CREDENTIAL_NAME`` (default ``aws-iam-lookup``) — no
additional credential surface is introduced.

**Convention**: an OIDC email maps to an IAM user whose ``UserName``
equals the email OR whose tag ``Email`` (case-insensitive) equals the email.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
import sqlite3
import urllib.parse
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import lru_cache

import boto3
import httpx
import jwt
from botocore.exceptions import BotoCoreError, ClientError

from vce_hq.config import settings
from vce_hq.vault.manager import CredentialManager

logger = logging.getLogger(__name__)


# ── Data classes ─────────────────────────────────────────────────────────

@dataclass(frozen=True)
class AwsIdentity:
    email: str
    sub: str              # OIDC subject — stable per IdP
    name: str | None


# ── OAuth state ──────────────────────────────────────────────────────────

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


# ── OIDC discovery (issuer → endpoints) ──────────────────────────────────

@lru_cache(maxsize=4)
def _discovery_url() -> str:
    issuer = settings.aws_oidc_issuer.rstrip("/")
    return f"{issuer}/.well-known/openid-configuration"


async def _discover() -> dict:
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(_discovery_url())
    if resp.status_code != 200:
        raise LookupError(
            f"AWS OIDC discovery failed ({resp.status_code}) at {_discovery_url()}: {resp.text}"
        )
    return resp.json()


# ── Authorize URL ────────────────────────────────────────────────────────

async def build_authorize_url(tenant_id: str) -> tuple[str, str]:
    """Return (url, state)."""
    discovery = await _discover()
    nonce = secrets.token_urlsafe(16)
    state = _make_state(tenant_id, nonce)
    params = {
        "client_id": settings.aws_oauth_client_id,
        "redirect_uri": settings.aws_oauth_redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
    }
    return f"{discovery['authorization_endpoint']}?{urllib.parse.urlencode(params)}", state


# ── Code exchange + ID token verify ──────────────────────────────────────

async def exchange_code_and_verify(code: str) -> AwsIdentity:
    discovery = await _discover()
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            discovery["token_endpoint"],
            data={
                "code": code,
                "client_id": settings.aws_oauth_client_id,
                "client_secret": settings.aws_oauth_client_secret,
                "redirect_uri": settings.aws_oauth_redirect_uri,
                "grant_type": "authorization_code",
            },
        )
    if resp.status_code != 200:
        raise PermissionError(f"AWS OIDC token exchange failed: {resp.text}")
    token_payload = resp.json()
    raw_id_token = token_payload.get("id_token")
    if not raw_id_token:
        raise PermissionError("AWS OIDC response missing id_token.")

    jwks_client = jwt.PyJWKClient(discovery["jwks_uri"])
    try:
        signing_key = jwks_client.get_signing_key_from_jwt(raw_id_token).key
        claims = jwt.decode(
            raw_id_token,
            signing_key,
            algorithms=["RS256"],
            audience=settings.aws_oauth_client_id,
            issuer=discovery["issuer"],
            options={"require": ["exp", "iat", "iss", "aud"]},
        )
    except jwt.PyJWTError as exc:
        raise PermissionError(f"AWS OIDC ID token verification failed: {exc}") from exc

    email = (claims.get("email") or "").lower()
    if not email:
        raise PermissionError("AWS OIDC ID token contained no email claim.")

    domain = email.split("@", 1)[1] if "@" in email else ""
    allowed = settings.aws_allowed_domains_list()
    if allowed and domain not in allowed:
        raise PermissionError(
            f"Domain '{domain}' is not in VCE_AWS_ALLOWED_DOMAINS."
        )

    return AwsIdentity(
        email=email,
        sub=claims["sub"],
        name=claims.get("name"),
    )


# ── IAM role resolution ──────────────────────────────────────────────────

def _load_aws_credential(tenant_conn: sqlite3.Connection, tenant_id: str) -> dict:
    manager = CredentialManager(tenant_conn, tenant_id)
    plaintext = manager.get_plaintext(settings.aws_iam_credential_name)
    if not plaintext:
        raise LookupError(
            f"Vault has no credential named '{settings.aws_iam_credential_name}' "
            f"for tenant '{tenant_id}'. Add a JSON blob with keys "
            f"aws_access_key_id, aws_secret_access_key, region for a principal "
            f"with iam:ListUsers, iam:ListAttachedUserPolicies, iam:ListUserPolicies, "
            f"iam:ListGroupsForUser."
        )
    try:
        info = json.loads(plaintext)
    except json.JSONDecodeError as exc:
        raise LookupError("Stored AWS credential is not valid JSON.") from exc
    for key in ("aws_access_key_id", "aws_secret_access_key"):
        if not info.get(key):
            raise LookupError(f"AWS Vault credential is missing '{key}'.")
    return info


def _find_iam_user(iam_client, email: str) -> str | None:
    """Return the IAM UserName that matches this email, or None."""
    email_lc = email.lower()

    # Rule 1: username == email (fast path).
    try:
        iam_client.get_user(UserName=email)
        return email
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            # Anything other than "not found" is an infra problem.
            raise

    # Rule 2: scan users, match by `Email` tag (case-insensitive key + value).
    paginator = iam_client.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page.get("Users", []):
            username = user["UserName"]
            try:
                tags_resp = iam_client.list_user_tags(UserName=username)
            except ClientError:
                continue
            for tag in tags_resp.get("Tags", []):
                if tag["Key"].lower() == "email" and tag["Value"].lower() == email_lc:
                    return username
    return None


def _collect_policy_names(iam_client, username: str) -> list[str]:
    """Union of directly-attached, inline, and group-inherited policy names."""
    names: list[str] = []

    # Directly attached managed policies.
    for page in iam_client.get_paginator("list_attached_user_policies").paginate(UserName=username):
        for p in page.get("AttachedPolicies", []):
            names.append(p["PolicyName"])

    # Inline user policies.
    for page in iam_client.get_paginator("list_user_policies").paginate(UserName=username):
        names.extend(page.get("PolicyNames", []))

    # Group memberships → managed + inline policies of each group.
    for page in iam_client.get_paginator("list_groups_for_user").paginate(UserName=username):
        for g in page.get("Groups", []):
            group_name = g["GroupName"]
            for gp in iam_client.get_paginator("list_attached_group_policies").paginate(
                GroupName=group_name
            ):
                for p in gp.get("AttachedPolicies", []):
                    names.append(p["PolicyName"])
            for gp in iam_client.get_paginator("list_group_policies").paginate(
                GroupName=group_name
            ):
                names.extend(gp.get("PolicyNames", []))

    # De-duplicate while preserving order.
    seen: set[str] = set()
    unique: list[str] = []
    for n in names:
        if n not in seen:
            seen.add(n)
            unique.append(n)
    return unique


def _resolve_role_sync(
    creds: dict,
    email: str,
) -> tuple[str, list[str]]:
    """Blocking IAM lookup — run inside ``asyncio.to_thread``."""
    iam_client = boto3.client(
        "iam",
        aws_access_key_id=creds["aws_access_key_id"],
        aws_secret_access_key=creds["aws_secret_access_key"],
        region_name=creds.get("region") or "us-east-1",
    )

    try:
        username = _find_iam_user(iam_client, email)
    except (ClientError, BotoCoreError) as exc:
        raise LookupError(f"IAM user lookup failed: {exc}") from exc

    if not username:
        raise PermissionError(
            f"No IAM user matches '{email}' (checked UserName and 'Email' tag)."
        )

    try:
        policy_names = _collect_policy_names(iam_client, username)
    except (ClientError, BotoCoreError) as exc:
        raise LookupError(f"IAM policy enumeration failed for '{username}': {exc}") from exc

    role_map = settings.aws_role_map()
    matched = [name for name in policy_names if name in role_map]

    if not matched:
        raise PermissionError(
            f"IAM user '{username}' has no VCE-mapped policy attached."
        )

    if any(role_map[n] == "admin" for n in matched):
        return "admin", matched
    return "user", matched


async def resolve_role_from_aws_iam(
    tenant_conn: sqlite3.Connection,
    tenant_id: str,
    email: str,
) -> tuple[str, list[str]]:
    """Return (vce_role, matched_policy_names).

    Raises PermissionError if the user has no mapped policy. Raises
    LookupError on infrastructure problems (missing credential, IAM
    permission denied, etc).
    """
    creds = _load_aws_credential(tenant_conn, tenant_id)
    return await asyncio.to_thread(_resolve_role_sync, creds, email)


# ── DB upsert ────────────────────────────────────────────────────────────

def upsert_oauth_user(
    auth_db: sqlite3.Connection,
    identity: AwsIdentity,
    vce_role: str,
) -> dict:
    """Insert or update the users row for an AWS-authenticated user.

    Returns {id, username, role}.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    row = auth_db.execute(
        "SELECT id, username, role FROM users WHERE aws_sub = ? OR email = ?",
        (identity.sub, identity.email),
    ).fetchone()

    if row is None:
        user_id = str(uuid.uuid4())
        auth_db.execute(
            """
            INSERT INTO users
                (id, username, password_hash, role, auth_method,
                 email, aws_sub, last_role_sync_at)
            VALUES (?, ?, ?, ?, 'aws', ?, ?, ?)
            """,
            (
                user_id,
                identity.email,
                "!oauth-no-password!",
                vce_role,
                identity.email,
                identity.sub,
                now,
            ),
        )
        auth_db.commit()
        logger.info("AWS OIDC: provisioned new user %s (role=%s)", identity.email, vce_role)
        return {"id": user_id, "username": identity.email, "role": vce_role}

    auth_db.execute(
        """
        UPDATE users
        SET role = ?, aws_sub = ?, email = ?,
            auth_method = 'aws', last_role_sync_at = ?
        WHERE id = ?
        """,
        (vce_role, identity.sub, identity.email, now, row["id"]),
    )
    auth_db.commit()
    logger.info("AWS OIDC: refreshed user %s (role=%s)", identity.email, vce_role)
    return {"id": row["id"], "username": identity.email, "role": vce_role}
