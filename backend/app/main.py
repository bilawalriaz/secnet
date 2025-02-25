from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.config import get_settings
from app.database.session import engine
from app.database.models import Base
from app.auth.router import router as auth_router
from app.endpoints.router import router as endpoints_router
from app.groups.router import router as groups_router
from app.scans.router import router as scans_router
from app.reports.router import router as reports_router

import logging

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create tables on startup if they don't exist
    Base.metadata.create_all(bind=engine)
    yield
    # Cleanup resources on shutdown if needed
    pass


app = FastAPI(
    title=settings.APP_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan,
)

# Set up CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth_router, prefix=f"{settings.API_V1_STR}/auth", tags=["authentication"])
app.include_router(endpoints_router, prefix=f"{settings.API_V1_STR}/endpoints", tags=["endpoints"])
app.include_router(groups_router, prefix=f"{settings.API_V1_STR}/endpoint-groups", tags=["endpoint-groups"])
app.include_router(scans_router, prefix=f"{settings.API_V1_STR}/scans", tags=["scans"])
app.include_router(reports_router, prefix=f"{settings.API_V1_STR}/reports", tags=["reports"])


@app.get("/")
async def root():
    return {"message": f"Welcome to {settings.APP_NAME} API"}


@app.get("/health")
async def health_check():
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
