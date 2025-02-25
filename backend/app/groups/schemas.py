from typing import Optional, List
from datetime import datetime
from uuid import UUID
from pydantic import BaseModel


class EndpointGroupBase(BaseModel):
    name: str
    description: Optional[str] = None


class EndpointGroupCreate(EndpointGroupBase):
    pass


class EndpointGroupUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None


class EndpointGroupInDB(EndpointGroupBase):
    id: UUID
    user_id: UUID
    created_at: datetime
    updated_at: datetime
    
    class Config:
        orm_mode = True


class EndpointGroup(EndpointGroupInDB):
    pass


class EndpointGroupList(BaseModel):
    items: List[EndpointGroup]
    total: int
