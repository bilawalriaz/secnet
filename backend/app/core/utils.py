import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional

import ipaddress
import re


def is_valid_uuid(val: str) -> bool:
    """
    Check if string is a valid UUID
    """
    try:
        uuid.UUID(str(val))
        return True
    except ValueError:
        return False


def is_valid_ip(address: str) -> bool:
    """
    Check if string is a valid IP address
    """
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def is_valid_hostname(hostname: str) -> bool:
    """
    Check if string is a valid hostname
    """
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


def validate_scan_parameters(scan_type: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate scan parameters based on scan type
    """
    valid_params = {}
    
    if scan_type == "port-scan":
        # Required parameters
        if "ports" in parameters:
            valid_params["ports"] = parameters["ports"]
        else:
            valid_params["ports"] = "1-1000"  # Default port range
        
        # Optional parameters
        if "speed" in parameters and parameters["speed"] in ["slow", "normal", "fast"]:
            valid_params["speed"] = parameters["speed"]
        else:
            valid_params["speed"] = "normal"
            
    elif scan_type == "os-detection":
        # OS detection specific parameters
        valid_params["os_detection"] = True
        
        # Optional parameters
        if "ports" in parameters:
            valid_params["ports"] = parameters["ports"]
        else:
            valid_params["ports"] = "22,80,443"  # Default ports for OS detection
            
    elif scan_type == "vulnerability-scan":
        # Vulnerability scan specific parameters
        valid_params["vuln_scan"] = True
        
        # Optional parameters
        if "intensity" in parameters and parameters["intensity"] in ["light", "medium", "aggressive"]:
            valid_params["intensity"] = parameters["intensity"]
        else:
            valid_params["intensity"] = "medium"
    
    # Common parameters for all scan types
    if "timeout" in parameters and isinstance(parameters["timeout"], int):
        valid_params["timeout"] = min(max(parameters["timeout"], 30), 3600)  # Between 30s and 1h
    else:
        valid_params["timeout"] = 300  # Default timeout: 5 minutes
        
    return valid_params


def format_scan_results(scan_result: dict, scan_type: str) -> dict:
    """
    Format nmap scan results into a standardized format
    """
    formatted_results = {
        "summary": {
            "open_ports": [],
            "detected_os": None,
            "services": [],
            "vulnerabilities": []
        },
        "details": {}
    }

    for host, host_data in scan_result.items():
        formatted_results["details"][host] = host_data
        
        # Extract open ports and services
        if "tcp" in host_data:
            for port, port_data in host_data["tcp"].items():
                if port_data["state"] == "open":
                    formatted_results["summary"]["open_ports"].append(port)
                    if "product" in port_data and "version" in port_data:
                        service = {
                            "port": port,
                            "name": port_data.get("name", "unknown"),
                            "product": port_data.get("product", "unknown"),
                            "version": port_data.get("version", "unknown")
                        }
                        formatted_results["summary"]["services"].append(service)
        
        # Extract OS detection results
        if scan_type == "os-detection" and "osmatch" in host_data:
            os_matches = host_data["osmatch"]
            if os_matches and len(os_matches) > 0:
                best_match = os_matches[0]
                formatted_results["summary"]["detected_os"] = {
                    "name": best_match.get("name", "unknown"),
                    "accuracy": best_match.get("accuracy", 0),
                    "type": best_match.get("osclass", {}).get("type", "unknown")
                }
        
        # Extract vulnerability scan results
        if scan_type == "vulnerability-scan" and "script" in host_data:
            for script_name, output in host_data["script"].items():
                vuln = {
                    "name": script_name,
                    "output": output
                }
                formatted_results["summary"]["vulnerabilities"].append(vuln)
    
    return formatted_results
