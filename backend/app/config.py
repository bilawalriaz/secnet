import os
from functools import lru_cache
from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    APP_NAME: str = "SecurityScan Pro"
    API_V1_STR: str = "/api/v1"
    
    # Database settings
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@db:5432/securityscan")
    
    # Supabase settings
    SUPABASE_URL: str = os.getenv("SUPABASE_URL", "")
    SUPABASE_KEY: str = os.getenv("SUPABASE_KEY", "")
    SUPABASE_JWT_SECRET: str = os.getenv("SUPABASE_JWT_SECRET", "")
    
    # JWT settings
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days
    
    # CORS settings - hardcoded for development
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost", "http://localhost:8000"]
    
    # Nmap settings
    NMAP_PATH: str = os.getenv("NMAP_PATH", "/usr/bin/nmap")
    
    # Security settings
    ALGORITHM: str = "HS256"


@lru_cache()
def get_settings():
    return Settings()
