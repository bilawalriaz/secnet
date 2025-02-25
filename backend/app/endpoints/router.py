from typing import Any, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.database.models import Endpoint, EndpointGroup, User
from app.endpoints.schemas import EndpointCreate, EndpointUpdate, Endpoint as EndpointSchema, EndpointList
from app.auth.dependencies import get_current_user

router = APIRouter()


@router.get("/", response_model=EndpointList)
def get_endpoints(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    skip: int = 0,
    limit: int = 100,
    search: Optional[str] = None,
    group_id: Optional[UUID] = None,
    is_active: Optional[bool] = None,
) -> Any:
    """
    Get all endpoints for the current user
    """
    query = db.query(Endpoint).filter(Endpoint.user_id == current_user.id)
    
    # Apply filters
    if search:
        query = query.filter(
            (Endpoint.name.ilike(f"%{search}%")) |
            (Endpoint.address.ilike(f"%{search}%")) |
            (Endpoint.description.ilike(f"%{search}%"))
        )
    
    if group_id:
        query = query.filter(Endpoint.group_id == group_id)
    
    if is_active is not None:
        query = query.filter(Endpoint.is_active == is_active)
    
    # Count total items
    total = query.count()
    
    # Apply pagination
    endpoints = query.offset(skip).limit(limit).all()
    
    return {"items": endpoints, "total": total}


@router.post("/", response_model=EndpointSchema, status_code=status.HTTP_201_CREATED)
def create_endpoint(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    endpoint_in: EndpointCreate,
) -> Any:
    """
    Create new endpoint
    """
    # Validate group_id if provided
    if endpoint_in.group_id:
        group = db.query(EndpointGroup).filter(
            EndpointGroup.id == endpoint_in.group_id,
            EndpointGroup.user_id == current_user.id
        ).first()
        if not group:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Group not found",
            )
    
    # Create endpoint
    endpoint = Endpoint(
        user_id=current_user.id,
        name=endpoint_in.name,
        address=endpoint_in.address,
        type=endpoint_in.type,
        description=endpoint_in.description,
        group_id=endpoint_in.group_id,
    )
    
    db.add(endpoint)
    db.commit()
    db.refresh(endpoint)
    
    return endpoint


@router.get("/{endpoint_id}", response_model=EndpointSchema)
def get_endpoint(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    endpoint_id: UUID,
) -> Any:
    """
    Get endpoint by ID
    """
    endpoint = db.query(Endpoint).filter(
        Endpoint.id == endpoint_id,
        Endpoint.user_id == current_user.id
    ).first()
    
    if not endpoint:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Endpoint not found",
        )
    
    return endpoint


@router.put("/{endpoint_id}", response_model=EndpointSchema)
def update_endpoint(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    endpoint_id: UUID,
    endpoint_in: EndpointUpdate,
) -> Any:
    """
    Update endpoint
    """
    endpoint = db.query(Endpoint).filter(
        Endpoint.id == endpoint_id,
        Endpoint.user_id == current_user.id
    ).first()
    
    if not endpoint:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Endpoint not found",
        )
    
    # Validate group_id if provided
    if endpoint_in.group_id:
        group = db.query(EndpointGroup).filter(
            EndpointGroup.id == endpoint_in.group_id,
            EndpointGroup.user_id == current_user.id
        ).first()
        if not group:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Group not found",
            )
    
    # Update fields
    update_data = endpoint_in.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(endpoint, field, value)
    
    db.add(endpoint)
    db.commit()
    db.refresh(endpoint)
    
    return endpoint


@router.delete("/{endpoint_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_endpoint(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    endpoint_id: UUID,
) -> None:
    """
    Delete endpoint
    """
    endpoint = db.query(Endpoint).filter(
        Endpoint.id == endpoint_id,
        Endpoint.user_id == current_user.id
    ).first()
    
    if not endpoint:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Endpoint not found",
        )
    
    db.delete(endpoint)
    db.commit()
