from typing import Optional, List
from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, Field, validator

from app.core.utils import is_valid_ip, is_valid_hostname


class EndpointBase(BaseModel):
    name: str
    address: str
    type: str = Field(default="ip", description="Type of endpoint (ip, hostname)")
    description: Optional[str] = None
    group_id: Optional[UUID] = None
    
    @validator("type")
    def validate_type(cls, v):
        if v not in ["ip", "hostname", "url"]:
            raise ValueError("Type must be 'ip', 'hostname', or 'url'")
        return v
    
    @validator("address")
    def validate_address(cls, v, values):
        if "type" in values:
            if values["type"] == "ip" and not is_valid_ip(v):
                raise ValueError("Invalid IP address")
            elif values["type"] == "hostname" and not is_valid_hostname(v):
                raise ValueError("Invalid hostname")
        return v


class EndpointCreate(EndpointBase):
    pass


class EndpointUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    group_id: Optional[UUID] = None
    is_active: Optional[bool] = None


class EndpointInDB(EndpointBase):
    id: UUID
    user_id: UUID
    created_at: datetime
    updated_at: datetime
    is_active: bool
    
    class Config:
        orm_mode = True


class Endpoint(EndpointInDB):
    pass


class EndpointList(BaseModel):
    items: List[Endpoint]
    total: int
