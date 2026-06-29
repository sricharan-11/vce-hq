import sqlite3
import uuid
from typing import Annotated, List, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel

from vce_hq.auth.dependencies import get_auth_db, get_current_admin_user, get_current_user, User
from vce_hq.auth.security import create_access_token, get_password_hash, verify_password

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
