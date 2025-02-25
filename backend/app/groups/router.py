from typing import Any, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.database.models import EndpointGroup, User
from app.groups.schemas import EndpointGroupCreate, EndpointGroupUpdate, EndpointGroup as EndpointGroupSchema, EndpointGroupList
from app.auth.dependencies import get_current_user

router = APIRouter()


@router.get("/", response_model=EndpointGroupList)
def get_endpoint_groups(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    skip: int = 0,
    limit: int = 100,
    search: Optional[str] = None,
) -> Any:
    """
    Get all endpoint groups for the current user
    """
    query = db.query(EndpointGroup).filter(EndpointGroup.user_id == current_user.id)
    
    # Apply search filter
    if search:
        query = query.filter(
            (EndpointGroup.name.ilike(f"%{search}%")) |
            (EndpointGroup.description.ilike(f"%{search}%"))
        )
    
    # Count total items
    total = query.count()
    
    # Apply pagination
    groups = query.offset(skip).limit(limit).all()
    
    return {"items": groups, "total": total}


@router.post("/", response_model=EndpointGroupSchema, status_code=status.HTTP_201_CREATED)
def create_endpoint_group(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    group_in: EndpointGroupCreate,
) -> Any:
    """
    Create new endpoint group
    """
    # Create group
    group = EndpointGroup(
        user_id=current_user.id,
        name=group_in.name,
        description=group_in.description,
    )
    
    db.add(group)
    db.commit()
    db.refresh(group)
    
    return group


@router.get("/{group_id}", response_model=EndpointGroupSchema)
def get_endpoint_group(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    group_id: UUID,
) -> Any:
    """
    Get endpoint group by ID
    """
    group = db.query(EndpointGroup).filter(
        EndpointGroup.id == group_id,
        EndpointGroup.user_id == current_user.id
    ).first()
    
    if not group:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Endpoint group not found",
        )
    
    return group


@router.put("/{group_id}", response_model=EndpointGroupSchema)
def update_endpoint_group(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    group_id: UUID,
    group_in: EndpointGroupUpdate,
) -> Any:
    """
    Update endpoint group
    """
    group = db.query(EndpointGroup).filter(
        EndpointGroup.id == group_id,
        EndpointGroup.user_id == current_user.id
    ).first()
    
    if not group:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Endpoint group not found",
        )
    
    # Update fields
    update_data = group_in.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(group, field, value)
    
    db.add(group)
    db.commit()
    db.refresh(group)
    
    return group


@router.delete("/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_endpoint_group(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    group_id: UUID,
) -> None:
    """
    Delete endpoint group
    """
    group = db.query(EndpointGroup).filter(
        EndpointGroup.id == group_id,
        EndpointGroup.user_id == current_user.id
    ).first()
    
    if not group:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Endpoint group not found",
        )
    
    db.delete(group)
    db.commit()
