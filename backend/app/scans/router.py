from typing import Any, List, Optional
from uuid import UUID
import asyncio
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

from app.database.session import get_db, SessionLocal
from app.database.models import Scan, ScanTarget, ScanResult, Endpoint, User, ScheduledScan
from app.scans.schemas import (
    ScanCreate, ScanUpdate, Scan as ScanSchema, ScanWithResults,
    ScanList, ScheduledScanCreate, ScheduledScanUpdate, ScheduledScan as ScheduledScanSchema,
    ScheduledScanList
)
from app.auth.dependencies import get_current_user
from app.scans.scanner import scanner

router = APIRouter()


async def run_scan_task(
    scan_id: UUID,
    user_id: UUID,
):
    """
    Background task to run a scan
    """
    # Create a new session for background task
    db = SessionLocal()
    
    try:
        # Get the scan
        scan = db.query(Scan).filter(
            Scan.id == scan_id,
            Scan.user_id == user_id
        ).first()
        
        if not scan:
            db.close()
            return
        
        # Update scan status
        scan.status = "running"
        scan.started_at = datetime.utcnow()
        db.add(scan)
        db.commit()
        
        # Get all targets
        targets = db.query(ScanTarget).filter(ScanTarget.scan_id == scan_id).all()
        if not targets:
            scan.status = "failed"
            scan.completed_at = datetime.utcnow()
            db.add(scan)
            db.commit()
            db.close()
            return
        
        # Get endpoints for targets
        endpoint_ids = [target.endpoint_id for target in targets]
        endpoints = db.query(Endpoint).filter(Endpoint.id.in_(endpoint_ids)).all()
        if not endpoints:
            scan.status = "failed"
            scan.completed_at = datetime.utcnow()
            db.add(scan)
            db.commit()
            db.close()
            return
        
        # Run scan for each endpoint
        for endpoint in endpoints:
            try:
                # Run nmap scan
                formatted_results, open_ports, os_detection = await scanner.run_scan(
                    [endpoint.address],
                    scan.type,
                    scan.parameters or {}
                )
                
                # Create scan result
                scan_result = ScanResult(
                    scan_id=scan_id,
                    endpoint_id=endpoint.id,
                    raw_results=formatted_results,
                    open_ports=open_ports,
                    vulnerabilities=0,  # Set vulnerabilities count if available
                    os_detection=os_detection
                )
                
                db.add(scan_result)
                db.commit()
                
            except Exception as e:
                # Log the error and continue with next endpoint
                print(f"Error scanning endpoint {endpoint.address}: {e}")
        
        # Update scan status
        scan.status = "completed"
        scan.completed_at = datetime.utcnow()
        db.add(scan)
        db.commit()
        
    except Exception as e:
        # Update scan status on error
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = "failed"
                scan.completed_at = datetime.utcnow()
                db.add(scan)
                db.commit()
        except:
            pass
        
        print(f"Error running scan {scan_id}: {e}")
    
    finally:
        db.close()


@router.get("/", response_model=ScanList)
def get_scans(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    skip: int = 0,
    limit: int = 100,
    status: Optional[str] = None,
    type: Optional[str] = None,
) -> Any:
    """
    Get all scans for the current user
    """
    query = db.query(Scan).filter(Scan.user_id == current_user.id)
    
    # Apply filters
    if status:
        query = query.filter(Scan.status == status)
    
    if type:
        query = query.filter(Scan.type == type)
    
    # Count total items
    total = query.count()
    
    # Apply pagination and order by start time descending
    scans = query.order_by(Scan.started_at.desc()).offset(skip).limit(limit).all()
    
    return {"items": scans, "total": total}


@router.post("/", response_model=ScanSchema, status_code=status.HTTP_201_CREATED)
async def create_scan(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    scan_in: ScanCreate,
    background_tasks: BackgroundTasks,
) -> Any:
    """
    Create new scan and start it in background
    """
    # Validate endpoints
    endpoint_ids = scan_in.target_endpoints
    endpoints = db.query(Endpoint).filter(
        Endpoint.id.in_(endpoint_ids),
        Endpoint.user_id == current_user.id
    ).all()
    
    if len(endpoints) != len(endpoint_ids):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="One or more endpoints not found",
        )
    
    # Create scan
    scan = Scan(
        user_id=current_user.id,
        name=scan_in.name,
        type=scan_in.type,
        parameters=scan_in.parameters,
        status="pending",
    )
    
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    # Create scan targets
    for endpoint_id in endpoint_ids:
        scan_target = ScanTarget(
            scan_id=scan.id,
            endpoint_id=endpoint_id,
        )
        db.add(scan_target)
    
    db.commit()
    db.refresh(scan)
    
    # Start scan in background
    background_tasks.add_task(run_scan_task, scan.id, current_user.id)
    
    return scan


@router.get("/{scan_id}", response_model=ScanWithResults)
def get_scan(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    scan_id: UUID,
) -> Any:
    """
    Get scan by ID with results
    """
    # Get scan with results
    scan = db.query(Scan).filter(
        Scan.id == scan_id,
        Scan.user_id == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )
    
    # Explicitly load relationships
    db.refresh(scan)
    
    # Convert to dict for response
    return {
        "id": scan.id,
        "user_id": scan.user_id,
        "name": scan.name,
        "type": scan.type,
        "parameters": scan.parameters,
        "status": scan.status or "pending",  # Ensure status is never null
        "scheduled_at": scan.scheduled_at,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "targets": [
            {
                "id": target.id,
                "scan_id": target.scan_id,
                "endpoint_id": target.endpoint_id
            }
            for target in scan.targets
        ],
        "results": [
            {
                "id": result.id,
                "scan_id": result.scan_id,
                "endpoint_id": result.endpoint_id,
                "raw_results": result.raw_results,
                "open_ports": result.open_ports,
                "vulnerabilities": result.vulnerabilities,
                "os_detection": result.os_detection,
                "created_at": result.created_at
            }
            for result in scan.results
        ]
    }


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    scan_id: UUID,
) -> None:
    """
    Delete scan
    """
    scan = db.query(Scan).filter(
        Scan.id == scan_id,
        Scan.user_id == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )
    
    # Do not allow deleting a running scan
    if scan.status == "running":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete a running scan",
        )
    
    # Delete associated scan results first
    db.query(ScanResult).filter(ScanResult.scan_id == scan_id).delete()
    
    # Delete associated scan targets
    db.query(ScanTarget).filter(ScanTarget.scan_id == scan_id).delete()
    
    # Delete the scan
    db.query(Scan).filter(Scan.id == scan_id).delete()
    
    db.commit()


@router.post("/{scan_id}/stop", response_model=ScanSchema)
def stop_scan(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    scan_id: UUID,
) -> Any:
    """
    Stop a running scan
    """
    scan = db.query(Scan).filter(
        Scan.id == scan_id,
        Scan.user_id == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )
    
    # Only running scans can be stopped
    if scan.status != "running":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot stop a scan with status: {scan.status}",
        )
    
    # Update scan status
    scan.status = "stopped"
    scan.completed_at = datetime.utcnow()
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    return scan


@router.get("/scheduled", response_model=ScheduledScanList)
def get_scheduled_scans(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    skip: int = 0,
    limit: int = 100,
    is_active: Optional[bool] = None,
) -> Any:
    """
    Get all scheduled scans for the current user
    """
    query = db.query(ScheduledScan).filter(ScheduledScan.user_id == current_user.id)
    
    # Apply filters
    if is_active is not None:
        query = query.filter(ScheduledScan.is_active == is_active)
    
    # Count total items
    total = query.count()
    
    # Apply pagination
    scheduled_scans = query.offset(skip).limit(limit).all()
    
    return {"items": scheduled_scans, "total": total}


@router.post("/scheduled", response_model=ScheduledScanSchema, status_code=status.HTTP_201_CREATED)
def create_scheduled_scan(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    scheduled_scan_in: ScheduledScanCreate,
) -> Any:
    """
    Create new scheduled scan
    """
    # Validate scan config
    scan_config = scheduled_scan_in.scan_config
    if not scan_config.get("type") or not scan_config.get("target_endpoints"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid scan configuration, must include type and target_endpoints",
        )
    
    # Validate endpoints
    endpoint_ids = scan_config.get("target_endpoints", [])
    if not endpoint_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No target endpoints specified",
        )
    
    endpoints = db.query(Endpoint).filter(
        Endpoint.id.in_(endpoint_ids),
        Endpoint.user_id == current_user.id
    ).all()
    
    if len(endpoints) != len(endpoint_ids):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="One or more endpoints not found",
        )
    
    # Validate schedule type
    if scheduled_scan_in.schedule_type not in ["daily", "weekly", "monthly", "custom"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid schedule type, must be daily, weekly, monthly, or custom",
        )
    
    # For custom schedules, cron expression is required
    if scheduled_scan_in.schedule_type == "custom" and not scheduled_scan_in.cron_expression:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cron expression is required for custom schedules",
        )
    
    # Create scheduled scan
    scheduled_scan = ScheduledScan(
        user_id=current_user.id,
        name=scheduled_scan_in.name,
        scan_config=scan_config,
        schedule_type=scheduled_scan_in.schedule_type,
        cron_expression=scheduled_scan_in.cron_expression,
        is_active=True,
    )
    
    db.add(scheduled_scan)
    db.commit()
    db.refresh(scheduled_scan)
    
    return scheduled_scan


@router.get("/scheduled/{scheduled_scan_id}", response_model=ScheduledScanSchema)
def get_scheduled_scan(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    scheduled_scan_id: UUID,
) -> Any:
    """
    Get scheduled scan by ID
    """
    scheduled_scan = db.query(ScheduledScan).filter(
        ScheduledScan.id == scheduled_scan_id,
        ScheduledScan.user_id == current_user.id
    ).first()
    
    if not scheduled_scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scheduled scan not found",
        )
    
    return scheduled_scan


@router.put("/scheduled/{scheduled_scan_id}", response_model=ScheduledScanSchema)
def update_scheduled_scan(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    scheduled_scan_id: UUID,
    scheduled_scan_in: ScheduledScanUpdate,
) -> Any:
    """
    Update scheduled scan
    """
    scheduled_scan = db.query(ScheduledScan).filter(
        ScheduledScan.id == scheduled_scan_id,
        ScheduledScan.user_id == current_user.id
    ).first()
    
    if not scheduled_scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scheduled scan not found",
        )
    
    # Update fields
    update_data = scheduled_scan_in.dict(exclude_unset=True)
    
    # Validate scan config if provided
    if "scan_config" in update_data:
        scan_config = update_data["scan_config"]
        if not scan_config.get("type") or not scan_config.get("target_endpoints"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid scan configuration, must include type and target_endpoints",
            )
    
    # Validate schedule type if provided
    if "schedule_type" in update_data:
        if update_data["schedule_type"] not in ["daily", "weekly", "monthly", "custom"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid schedule type, must be daily, weekly, monthly, or custom",
            )
        
        # For custom schedules, cron expression is required
        if update_data["schedule_type"] == "custom" and not (
            "cron_expression" in update_data or scheduled_scan.cron_expression
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cron expression is required for custom schedules",
            )
    
    for field, value in update_data.items():
        setattr(scheduled_scan, field, value)
    
    db.add(scheduled_scan)
    db.commit()
    db.refresh(scheduled_scan)
    
    return scheduled_scan


@router.delete("/scheduled/{scheduled_scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scheduled_scan(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    scheduled_scan_id: UUID,
) -> None:
    """
    Delete scheduled scan
    """
    scheduled_scan = db.query(ScheduledScan).filter(
        ScheduledScan.id == scheduled_scan_id,
        ScheduledScan.user_id == current_user.id
    ).first()
    
    if not scheduled_scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scheduled scan not found",
        )
    
    db.delete(scheduled_scan)
    db.commit()


@router.get("/compare/{scan_id_1}/{scan_id_2}")
def compare_scans(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    scan_id_1: UUID,
    scan_id_2: UUID,
) -> Any:
    """
    Compare two scans and return their differences
    """
    # Get both scans
    scan1 = db.query(Scan).filter(
        Scan.id == scan_id_1,
        Scan.user_id == current_user.id
    ).first()
    
    scan2 = db.query(Scan).filter(
        Scan.id == scan_id_2,
        Scan.user_id == current_user.id
    ).first()
    
    if not scan1 or not scan2:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="One or both scans not found",
        )
    
    # Get scan results
    results1 = db.query(ScanResult).filter(ScanResult.scan_id == scan_id_1).all()
    results2 = db.query(ScanResult).filter(ScanResult.scan_id == scan_id_2).all()
    
    # Compare scan results
    comparison = {
        "scan1": {
            "id": str(scan1.id),
            "name": scan1.name,
            "type": scan1.type,
            "started_at": scan1.started_at,
            "completed_at": scan1.completed_at,
            "results": []
        },
        "scan2": {
            "id": str(scan2.id),
            "name": scan2.name,
            "type": scan2.type,
            "started_at": scan2.started_at,
            "completed_at": scan2.completed_at,
            "results": []
        },
        "differences": {
            "new_ports": [],
            "closed_ports": [],
            "changed_services": [],
            "os_changes": []
        }
    }
    
    # Map results by endpoint for easy comparison
    results1_by_endpoint = {r.endpoint_id: r for r in results1}
    results2_by_endpoint = {r.endpoint_id: r for r in results2}
    
    # Compare results for each endpoint
    all_endpoints = set(results1_by_endpoint.keys()) | set(results2_by_endpoint.keys())
    
    for endpoint_id in all_endpoints:
        result1 = results1_by_endpoint.get(endpoint_id)
        result2 = results2_by_endpoint.get(endpoint_id)
        
        if result1 and result2:
            # Compare open ports
            ports1 = set(result1.raw_results.get("summary", {}).get("open_ports", []))
            ports2 = set(result2.raw_results.get("summary", {}).get("open_ports", []))
            
            comparison["differences"]["new_ports"].extend(list(ports2 - ports1))
            comparison["differences"]["closed_ports"].extend(list(ports1 - ports2))
            
            # Compare OS detection
            os1 = result1.os_detection
            os2 = result2.os_detection
            if os1 != os2:
                comparison["differences"]["os_changes"].append({
                    "endpoint_id": str(endpoint_id),
                    "old": os1,
                    "new": os2
                })
            
            # Compare services
            services1 = set(str(s) for s in result1.raw_results.get("summary", {}).get("services", []))
            services2 = set(str(s) for s in result2.raw_results.get("summary", {}).get("services", []))
            
            changed_services = []
            for service in (services1 | services2):
                if service in services1 and service not in services2:
                    changed_services.append({"service": service, "status": "removed"})
                elif service not in services1 and service in services2:
                    changed_services.append({"service": service, "status": "added"})
            
            if changed_services:
                comparison["differences"]["changed_services"].extend(changed_services)
    
    return comparison
