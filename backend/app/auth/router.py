from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
import httpx
import uuid

from app.config import get_settings
from app.database.session import get_db
from app.database.models import User
from app.core.security import create_access_token, get_password_hash, verify_password

settings = get_settings()
router = APIRouter()

security = HTTPBearer()


class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class PasswordReset(BaseModel):
    email: EmailStr


class PasswordUpdate(BaseModel):
    token: str
    new_password: str


@router.post("/signup", response_model=Token)
async def signup(user_data: UserCreate, db: Session = Depends(get_db)) -> Any:
    """
    Create new user
    """
    # Check if user with given email exists
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )
    
    # Create supabase user
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{settings.SUPABASE_URL}/auth/v1/admin/users",
                json={
                    "email": user_data.email,
                    "password": user_data.password,
                    "email_confirm": True
                },
                headers={
                    "apikey": settings.SUPABASE_JWT_SECRET,
                    "Authorization": f"Bearer {settings.SUPABASE_JWT_SECRET}"
                }
            )
            response.raise_for_status()
            supabase_user = response.json()
    except httpx.HTTPError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Error creating user in Supabase: {str(e)}",
        )
    
    # Create user in our database
    new_user = User(
        id=uuid.UUID(supabase_user["id"]),
        email=user_data.email,
        full_name=user_data.full_name,
        role="user",
        created_at=datetime.utcnow(),
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Create access token
    access_token = create_access_token(
        subject=new_user.id,
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/login", response_model=Token)
async def login(user_data: UserLogin, db: Session = Depends(get_db)) -> Any:
    """
    Login user
    """
    # Check if user exists in our database
    user = db.query(User).filter(User.email == user_data.email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )
    
    # Login with Supabase
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{settings.SUPABASE_URL}/auth/v1/token",
                json={"email": user_data.email, "password": user_data.password},
                headers={"apikey": settings.SUPABASE_KEY}
            )
            response.raise_for_status()
            supabase_response = response.json()
    except httpx.HTTPError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )
    
    # Update last login timestamp
    user.last_login = datetime.utcnow()
    db.commit()
    
    return {
        "access_token": supabase_response["access_token"],
        "token_type": "bearer"
    }


@router.post("/logout")
async def logout(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Any:
    """
    Logout user
    """
    token = credentials.credentials
    
    # Call Supabase logout
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{settings.SUPABASE_URL}/auth/v1/logout",
                headers={
                    "apikey": settings.SUPABASE_KEY,
                    "Authorization": f"Bearer {token}"
                }
            )
            response.raise_for_status()
    except httpx.HTTPError:
        # Even if there's an error, we'll just return success
        # The frontend should still clear the token
        pass
    
    return {"message": "Successfully logged out"}


@router.post("/reset-password")
async def reset_password(reset_data: PasswordReset) -> Any:
    """
    Send password reset email
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{settings.SUPABASE_URL}/auth/v1/recover",
                json={"email": reset_data.email},
                headers={"apikey": settings.SUPABASE_KEY}
            )
            response.raise_for_status()
    except httpx.HTTPError:
        # We'll still return success even if there's an error or if the email doesn't exist
        # This prevents email enumeration attacks
        pass
    
    return {"message": "Password reset email sent if the account exists"}


@router.post("/update-password")
async def update_password(update_data: PasswordUpdate, db: Session = Depends(get_db)) -> Any:
    """
    Update password using reset token
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{settings.SUPABASE_URL}/auth/v1/recover",
                json={
                    "type": "recovery",
                    "token": update_data.token,
                    "new_password": update_data.new_password
                },
                headers={"apikey": settings.SUPABASE_KEY}
            )
            response.raise_for_status()
    except httpx.HTTPError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired token",
        )
    
    return {"message": "Password updated successfully"}
