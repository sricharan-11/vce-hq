import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import bcrypt
import jwt

from vce_hq.config import settings


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a hashed one."""
    return bcrypt.checkpw(
        plain_password.encode("utf-8"), 
        hashed_password.encode("utf-8")
    )


def get_password_hash(password: str) -> str:
    """Generate a bcrypt hash for the given password."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a new JWT access token."""
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expiration_minutes)
        
    to_encode.update({"exp": expire, "typ": "session"})
    
    encoded_jwt = jwt.encode(
        to_encode, 
        settings.jwt_secret_key, 
        algorithm="HS256"
    )
    
    return encoded_jwt


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode and verify a JWT access token."""
    try:
        decoded_token = jwt.decode(
            token, 
            settings.jwt_secret_key, 
            algorithms=["HS256"]
        )
        return decoded_token
    except jwt.PyJWTError:
        return None


# ── HttpOnly session cookie ────────────────────────────────────

def set_session_cookie(response, token: str) -> None:
    """Attach the session JWT as an HttpOnly cookie on a FastAPI Response.

    The cookie is Secure/SameSite-configured via settings so local http dev
    still works while production over HTTPS gets full XSS-resistant storage.
    """
    response.set_cookie(
        key=settings.session_cookie_name,
        value=token,
        max_age=settings.jwt_expiration_minutes * 60,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        path="/",
    )


def clear_session_cookie(response) -> None:
    response.delete_cookie(
        key=settings.session_cookie_name,
        path="/",
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
    )


# ── Signed Security-Gate execution ticket ─────────────────────
# Binds a gate approval to (command hash, agent, tenant) with a very short
# TTL so a poisoned/spoofed executor can't reuse tickets for other commands.

import hashlib


def _command_fingerprint(command: str) -> str:
    return hashlib.sha256(command.encode("utf-8")).hexdigest()


def issue_gate_ticket(
    *,
    command: str,
    agent: str,
    tenant_id: str,
    decision: str,
) -> str:
    """Return a short-lived JWT authorising execution of exactly this command."""
    now = datetime.now(timezone.utc)
    payload = {
        "typ": "gate_ticket",
        "cmd_hash": _command_fingerprint(command),
        "agent": agent,
        "tid": tenant_id,
        "decision": decision,
        "iat": now,
        "exp": now + timedelta(seconds=settings.gate_ticket_ttl_seconds),
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm="HS256")


def verify_gate_ticket(
    ticket: str,
    *,
    command: str,
    agent: str,
    tenant_id: str,
) -> Optional[Dict[str, Any]]:
    """Return the ticket claims iff signature, hash, agent, and tenant all match."""
    try:
        claims = jwt.decode(ticket, settings.jwt_secret_key, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    if claims.get("typ") != "gate_ticket":
        return None
    if claims.get("cmd_hash") != _command_fingerprint(command):
        return None
    if claims.get("agent") != agent or claims.get("tid") != tenant_id:
        return None
    return claims
