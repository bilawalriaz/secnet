from typing import Any, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status, Response
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
import io

from app.database.session import get_db
from app.database.models import Scan, ScanResult, User
from app.auth.dependencies import get_current_user
from app.reports.generator import report_generator

router = APIRouter()


@router.get("/{scan_id}")
async def get_report(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    scan_id: UUID,
    format: str = Query("json", description="Report format (json, csv, pdf)"),
) -> Any:
    """
    Generate and return a report for a specific scan
    """
    # Check if scan exists and belongs to the user
    scan = db.query(Scan).filter(
        Scan.id == scan_id,
        Scan.user_id == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )
    
    # Check if scan is completed
    if scan.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot generate report for incomplete scan",
        )
    
    # Generate report based on format
    if format.lower() == "json":
        report = report_generator.generate_json_report(db, scan_id, current_user.id)
        return report
    
    elif format.lower() == "csv":
        csv_data = report_generator.generate_csv_report(db, scan_id, current_user.id)
        return StreamingResponse(
            io.StringIO(csv_data),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=scan_report_{scan_id}.csv"}
        )
    
    elif format.lower() == "pdf":
        pdf_data = report_generator.generate_pdf_report(db, scan_id, current_user.id)
        return Response(
            content=pdf_data,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=scan_report_{scan_id}.pdf"}
        )
    
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported report format",
        )


@router.get("/scan/{scan_id}/summary")
async def get_scan_summary(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    scan_id: UUID,
) -> Any:
    """
    Get a summary of scan results
    """
    # Check if scan exists and belongs to the user
    scan = db.query(Scan).filter(
        Scan.id == scan_id,
        Scan.user_id == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )
    
    # Get scan results
    results = db.query(ScanResult).filter(ScanResult.scan_id == scan_id).all()
    
    # Calculate summary statistics
    total_endpoints = len(results)
    total_open_ports = sum(result.open_ports for result in results)
    total_vulnerabilities = sum(result.vulnerabilities for result in results)
    
    os_detections = {}
    for result in results:
        if result.os_detection:
            os_detections[result.os_detection] = os_detections.get(result.os_detection, 0) + 1
    
    # Prepare summary data
    summary = {
        "scan_info": {
            "id": str(scan.id),
            "name": scan.name,
            "type": scan.type,
            "status": scan.status,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        },
        "summary": {
            "total_endpoints": total_endpoints,
            "total_open_ports": total_open_ports,
            "total_vulnerabilities": total_vulnerabilities,
            "os_distribution": os_detections,
        }
    }
    
    return summary


@router.get("/comparison")
async def compare_scans(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    scan_id_1: UUID,
    scan_id_2: UUID,
) -> Any:
    """
    Compare results of two scans
    """
    # Check if scans exist and belong to the user
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
    
    # Check if scans are completed
    if scan1.status != "completed" or scan2.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot compare incomplete scans",
        )
    
    # Get scan results
    results1 = db.query(ScanResult).filter(ScanResult.scan_id == scan_id_1).all()
    results2 = db.query(ScanResult).filter(ScanResult.scan_id == scan_id_2).all()
    
    # Organize results by endpoint
    endpoints1 = {str(result.endpoint_id): result for result in results1}
    endpoints2 = {str(result.endpoint_id): result for result in results2}
    
    # Find common endpoints
    common_endpoints = set(endpoints1.keys()) & set(endpoints2.keys())
    only_in_scan1 = set(endpoints1.keys()) - set(endpoints2.keys())
    only_in_scan2 = set(endpoints2.keys()) - set(endpoints1.keys())
    
    # Compare results for common endpoints
    comparison = []
    for endpoint_id in common_endpoints:
        result1 = endpoints1[endpoint_id]
        result2 = endpoints2[endpoint_id]
        
        # Compare open ports
        port_diff = result2.open_ports - result1.open_ports
        
        # Compare OS detection
        os_changed = result1.os_detection != result2.os_detection
        
        comparison.append({
            "endpoint_id": endpoint_id,
            "comparison": {
                "open_ports_change": port_diff,
                "os_detection_change": os_changed,
                "before": {
                    "open_ports": result1.open_ports,
                    "os_detection": result1.os_detection,
                },
                "after": {
                    "open_ports": result2.open_ports,
                    "os_detection": result2.os_detection,
                }
            }
        })
    
    # Prepare comparison data
    result = {
        "scan1": {
            "id": str(scan1.id),
            "name": scan1.name,
            "date": scan1.completed_at.isoformat() if scan1.completed_at else None,
        },
        "scan2": {
            "id": str(scan2.id),
            "name": scan2.name,
            "date": scan2.completed_at.isoformat() if scan2.completed_at else None,
        },
        "summary": {
            "common_endpoints": len(common_endpoints),
            "only_in_scan1": len(only_in_scan1),
            "only_in_scan2": len(only_in_scan2),
        },
        "comparison": comparison
    }
    
    return result
