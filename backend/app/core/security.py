from datetime import datetime, timedelta
from typing import Any, Optional, Union

import jwt
from passlib.context import CryptContext

from app.config import get_settings

settings = get_settings()

# Password context for hashing and verification
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def create_access_token(subject: Union[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """
    Create JWT access token
    """
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode = {"exp": expire, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, settings.SUPABASE_JWT_SECRET, algorithm=settings.ALGORITHM)
    return encoded_jwt


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify password against hash
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """
    Hash password
    """
    return pwd_context.hash(password)


def verify_token(token: str) -> Optional[str]:
    """
    Verify JWT token and return user id
    """
    try:
        payload = jwt.decode(
            token, settings.SUPABASE_JWT_SECRET, algorithms=[settings.ALGORITHM]
        )
        return payload.get("sub")
    except jwt.PyJWTError:
        return None
