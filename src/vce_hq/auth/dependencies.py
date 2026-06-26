import sqlite3
from typing import Annotated, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import jwt
from pydantic import BaseModel

from vce_hq.auth.security import decode_access_token
from vce_hq.db.connection import create_connection
from vce_hq.config import settings

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")


class User(BaseModel):
    id: str
    username: str
    role: str


# Assuming a single tenant DB context for now, or you pass tenant_id
# Let's write a generic get_db dependency if it doesn't exist, or just inline it for auth.
# A proper platform would resolve tenant_id from headers/domain, but for this standalone module,
# let's assume we can fetch the user from a predefined DB path (e.g. data/vce_hq.db).

# Actually, the DB path is usually passed or derived from tenant. 
# We will use the VCE_DATA_DIR / 'tenant_db.sqlite' for the single standalone installation.
from pathlib import Path
def get_auth_db() -> sqlite3.Connection:
    """Dependency to get a connection to the auth database."""
    # Using a common tenant or a main db for auth.
    # For a standalone installation as per PRD, there's just one primary db.
    db_path = Path(settings.data_dir) / "vce_hq.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    
    conn = create_connection(db_path)
    try:
        yield conn
    finally:
        conn.close()


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[sqlite3.Connection, Depends(get_auth_db)]
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    payload = decode_access_token(token)
    if payload is None:
        raise credentials_exception
        
    username: str = payload.get("sub")
    if username is None:
        raise credentials_exception
        
    user_row = db.execute(
        "SELECT id, username, role FROM users WHERE username = ?", (username,)
    ).fetchone()
    
    if user_row is None:
        raise credentials_exception
        
    return User(id=user_row["id"], username=user_row["username"], role=user_row["role"])


async def get_current_admin_user(
    current_user: Annotated[User, Depends(get_current_user)]
) -> User:
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The user doesn't have enough privileges"
        )
    return current_user
