from typing import Optional, List, Dict, Any
from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, Field, validator


class ScanBase(BaseModel):
    name: str
    type: str = Field(description="Type of scan (port-scan, os-detection, vulnerability-scan)")
    parameters: Optional[Dict[str, Any]] = Field(default={})
    
    @validator("type")
    def validate_type(cls, v):
        allowed_types = ["port-scan", "os-detection", "vulnerability-scan"]
        if v not in allowed_types:
            raise ValueError(f"Type must be one of: {', '.join(allowed_types)}")
        return v


class ScanCreate(ScanBase):
    target_endpoints: List[UUID] = Field(..., min_items=1)


class ScanUpdate(BaseModel):
    name: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None


class ScanTarget(BaseModel):
    id: UUID
    scan_id: UUID
    endpoint_id: UUID
    
    class Config:
        orm_mode = True


class ScanResult(BaseModel):
    id: UUID
    scan_id: UUID
    endpoint_id: UUID
    raw_results: Dict[str, Any]
    open_ports: int
    vulnerabilities: int
    os_detection: Optional[str] = None
    created_at: datetime
    
    class Config:
        orm_mode = True


class ScanInDB(ScanBase):
    id: UUID
    user_id: UUID
    scheduled_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    status: str
    
    class Config:
        orm_mode = True


class Scan(ScanBase):
    id: UUID
    user_id: UUID
    status: str = Field(description="Current scan status (pending, running, completed, failed)")
    scheduled_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    targets: List[ScanTarget] = []

    class Config:
        orm_mode = True


class ScanWithResults(Scan):
    results: List[ScanResult] = []

    class Config:
        orm_mode = True


class ScanList(BaseModel):
    items: List[Scan]
    total: int


class ScheduledScanBase(BaseModel):
    name: str
    scan_config: Dict[str, Any]
    schedule_type: str
    cron_expression: Optional[str] = None


class ScheduledScanCreate(ScheduledScanBase):
    pass


class ScheduledScanUpdate(BaseModel):
    name: Optional[str] = None
    scan_config: Optional[Dict[str, Any]] = None
    schedule_type: Optional[str] = None
    cron_expression: Optional[str] = None
    is_active: Optional[bool] = None


class ScheduledScanInDB(ScheduledScanBase):
    id: UUID
    user_id: UUID
    next_run: Optional[datetime] = None
    last_run: Optional[datetime] = None
    is_active: bool
    
    class Config:
        orm_mode = True


class ScheduledScan(ScheduledScanInDB):
    pass


class ScheduledScanList(BaseModel):
    items: List[ScheduledScan]
    total: int
