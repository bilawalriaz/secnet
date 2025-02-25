import csv
import io
import json
from typing import Dict, Any, List, Optional
from uuid import UUID
from datetime import datetime
import logging

from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from fpdf import FPDF

from app.database.models import Scan, ScanResult, Endpoint

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generate reports in different formats
    """
    
    @staticmethod
    def generate_csv_report(
        db: Session,
        scan_id: UUID,
        user_id: UUID
    ) -> str:
        """
        Generate CSV report for a scan
        """
        # Get scan data
        scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user_id).first()
        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found",
            )
        
        # Get scan results
        results = db.query(ScanResult).filter(ScanResult.scan_id == scan_id).all()
        if not results:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No scan results found",
            )
        
        # Get endpoints
        endpoint_ids = [result.endpoint_id for result in results]
        endpoints = db.query(Endpoint).filter(Endpoint.id.in_(endpoint_ids)).all()
        endpoints_map = {endpoint.id: endpoint for endpoint in endpoints}
        
        # Create CSV file
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        header = ["Endpoint Name", "Endpoint Address", "Open Ports", "OS Detection", "Timestamp"]
        writer.writerow(header)
        
        # Write data
        for result in results:
            endpoint = endpoints_map.get(result.endpoint_id)
            if endpoint:
                row = [
                    endpoint.name,
                    endpoint.address,
                    result.open_ports,
                    result.os_detection or "Unknown",
                    result.created_at.isoformat(),
                ]
                writer.writerow(row)
        
        return output.getvalue()
    
    @staticmethod
    def generate_pdf_report(
        db: Session,
        scan_id: UUID,
        user_id: UUID
    ) -> bytes:
        """
        Generate PDF report for a scan
        """
        # Get scan data
        scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user_id).first()
        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found",
            )
        
        # Get scan results
        results = db.query(ScanResult).filter(ScanResult.scan_id == scan_id).all()
        if not results:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No scan results found",
            )
        
        # Get endpoints
        endpoint_ids = [result.endpoint_id for result in results]
        endpoints = db.query(Endpoint).filter(Endpoint.id.in_(endpoint_ids)).all()
        endpoints_map = {endpoint.id: endpoint for endpoint in endpoints}
        
        # Create PDF
        pdf = FPDF()
        pdf.add_page()
        
        # Title
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, f"Scan Report: {scan.name}", 0, 1, "C")
        
        # Scan info
        pdf.set_font("Arial", "", 12)
        pdf.cell(0, 10, f"Scan Type: {scan.type}", 0, 1)
        pdf.cell(0, 10, f"Date: {scan.completed_at.strftime('%Y-%m-%d %H:%M:%S')}", 0, 1)
        pdf.cell(0, 10, f"Status: {scan.status}", 0, 1)
        pdf.ln(10)
        
        # Results table
        pdf.set_font("Arial", "B", 12)
        pdf.cell(50, 10, "Endpoint", 1, 0, "C")
        pdf.cell(50, 10, "Address", 1, 0, "C")
        pdf.cell(30, 10, "Open Ports", 1, 0, "C")
        pdf.cell(60, 10, "OS Detection", 1, 1, "C")
        
        # Table data
        pdf.set_font("Arial", "", 10)
        for result in results:
            endpoint = endpoints_map.get(result.endpoint_id)
            if endpoint:
                pdf.cell(50, 10, endpoint.name, 1, 0)
                pdf.cell(50, 10, endpoint.address, 1, 0)
                pdf.cell(30, 10, str(result.open_ports), 1, 0, "C")
                pdf.cell(60, 10, result.os_detection or "Unknown", 1, 1)
        
        # Summary
        pdf.ln(10)
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "Summary", 0, 1)
        pdf.set_font("Arial", "", 12)
        
        # Calculate summary stats
        total_open_ports = sum(result.open_ports for result in results)
        
        pdf.cell(0, 10, f"Total endpoints scanned: {len(endpoints)}", 0, 1)
        pdf.cell(0, 10, f"Total open ports found: {total_open_ports}", 0, 1)
        
        # Add recommendations based on scan type
        pdf.ln(10)
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "Recommendations", 0, 1)
        pdf.set_font("Arial", "", 12)
        
        if scan.type == "port-scan":
            pdf.multi_cell(0, 10, "- Review open ports and close unnecessary ones\n"
                             "- Ensure required ports are properly secured\n"
                             "- Implement firewall rules to restrict access")
        elif scan.type == "os-detection":
            pdf.multi_cell(0, 10, "- Ensure operating systems are up-to-date\n"
                             "- Apply security patches regularly\n"
                             "- Consider masking OS information where possible")
        elif scan.type == "vulnerability-scan":
            pdf.multi_cell(0, 10, "- Address identified vulnerabilities promptly\n"
                             "- Prioritize critical vulnerabilities\n"
                             "- Implement regular vulnerability scanning")
        
        return pdf.output(dest="S").encode("latin1")
    
    @staticmethod
    def generate_json_report(
        db: Session,
        scan_id: UUID,
        user_id: UUID
    ) -> Dict[str, Any]:
        """
        Generate JSON report for a scan
        """
        # Get scan data
        scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user_id).first()
        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found",
            )
        
        # Get scan results
        results = db.query(ScanResult).filter(ScanResult.scan_id == scan_id).all()
        if not results:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No scan results found",
            )
        
        # Get endpoints
        endpoint_ids = [result.endpoint_id for result in results]
        endpoints = db.query(Endpoint).filter(Endpoint.id.in_(endpoint_ids)).all()
        endpoints_map = {endpoint.id: endpoint for endpoint in endpoints}
        
        # Prepare report data
        report = {
            "scan_info": {
                "id": str(scan.id),
                "name": scan.name,
                "type": scan.type,
                "status": scan.status,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            },
            "results": []
        }
        
        # Add results
        for result in results:
            endpoint = endpoints_map.get(result.endpoint_id)
            if endpoint:
                result_data = {
                    "endpoint": {
                        "id": str(endpoint.id),
                        "name": endpoint.name,
                        "address": endpoint.address,
                        "type": endpoint.type,
                    },
                    "scan_result": {
                        "open_ports": result.open_ports,
                        "os_detection": result.os_detection,
                        "created_at": result.created_at.isoformat(),
                    }
                }
                
                # Include summarized results based on scan type
                if scan.type == "port-scan" and "raw_results" in result.raw_results:
                    result_data["scan_result"]["ports"] = result.raw_results.get("summary", {}).get("open_ports", [])
                    result_data["scan_result"]["services"] = result.raw_results.get("details", {}).get("services", {})
                
                elif scan.type == "os-detection" and "raw_results" in result.raw_results:
                    result_data["scan_result"]["os_matches"] = result.raw_results.get("details", {}).get("os_matches", [])
                    result_data["scan_result"]["accuracy"] = result.raw_results.get("summary", {}).get("accuracy", 0)
                
                elif scan.type == "vulnerability-scan" and "raw_results" in result.raw_results:
                    result_data["scan_result"]["vulnerabilities"] = result.raw_results.get("details", {}).get("vulnerabilities", [])
                    result_data["scan_result"]["summary"] = result.raw_results.get("summary", {})
                
                report["results"].append(result_data)
        
        return report


# Create singleton instance
report_generator = ReportGenerator()
