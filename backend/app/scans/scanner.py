import asyncio
import json
from typing import List, Dict, Any, Optional, Tuple
import nmap
import logging
from datetime import datetime

from app.config import get_settings
from app.core.utils import format_scan_results, validate_scan_parameters

settings = get_settings()
logger = logging.getLogger(__name__)


class NmapScanner:
    """
    NmapScanner class for handling nmap scans
    """
    
    def __init__(self):
        try:
            self.scanner = nmap.PortScanner(nmap_search_path=[settings.NMAP_PATH])
        except nmap.PortScannerError as e:
            logger.error(f"Failed to initialize nmap: {e}")
            raise RuntimeError(f"Failed to initialize nmap scanner: {e}")
    
    async def run_scan(
        self, 
        targets: List[str], 
        scan_type: str, 
        parameters: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], int, Optional[str]]:
        """
        Run nmap scan asynchronously
        """
        # Validate parameters
        valid_params = validate_scan_parameters(scan_type, parameters)
        
        # Construct nmap arguments
        args = self._build_nmap_args(scan_type, valid_params)
        
        # Run scan asynchronously
        try:
            # Use ProcessPoolExecutor to run nmap scan in a separate process
            loop = asyncio.get_event_loop()
            scan_result = await loop.run_in_executor(
                None, 
                self._execute_scan,
                targets,
                args
            )
            
            # Parse and format results
            formatted_results = format_scan_results(scan_result, scan_type)
            open_ports = len(formatted_results["summary"].get("open_ports", []))
            os_detection = formatted_results["summary"].get("detected_os", None)
            
            return formatted_results, open_ports, os_detection
            
        except Exception as e:
            logger.error(f"Error during scan: {e}")
            raise RuntimeError(f"Scan failed: {e}")
    
    def _execute_scan(self, targets: List[str], args: str) -> Dict[str, Any]:
        """
        Execute nmap scan synchronously
        """
        target_str = " ".join(targets)
        logger.info(f"Starting nmap scan on {target_str} with args: {args}")
        
        try:
            logger.debug(f"Full nmap command: nmap {args} {target_str}")
            start_time = datetime.now()
            logger.debug("About to execute nmap.scan...")
            self.scanner.scan(hosts=target_str, arguments=args)
            end_time = datetime.now()
            
            logger.info(f"Scan completed in {(end_time - start_time).total_seconds()} seconds")
            logger.debug(f"Raw nmap output: {self.scanner.get_nmap_last_output()}")
            
            # Convert nmap results to dict
            scan_results = {}
            for host in self.scanner.all_hosts():
                scan_results[host] = self.scanner[host]
                logger.debug(f"Results for host {host}: {scan_results[host]}")
            
            return scan_results
            
        except nmap.PortScannerError as e:
            logger.error(f"Nmap scan error: {e}")
            logger.error(f"Last nmap output: {self.scanner.get_nmap_last_output()}")
            raise RuntimeError(f"Nmap scan failed: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during scan: {e}")
            logger.error(f"Last nmap output: {self.scanner.get_nmap_last_output()}")
            raise RuntimeError(f"Scan failed with unexpected error: {e}")
    
    def _build_nmap_args(self, scan_type: str, parameters: Dict[str, Any]) -> str:
        """
        Build nmap command line arguments based on scan type and parameters
        """
        args = []
        
        # Common arguments
        args.append("-n")  # No DNS resolution
        args.append("-Pn")  # Treat all hosts as online
        args.append("-sS")  # SYN scan
        
        # Add timeout
        timeout = parameters.get("timeout", 300)
        args.append(f"--max-rtt-timeout {timeout}s")
        
        # Scan type specific arguments
        if scan_type == "port-scan":
            # Port range
            ports = parameters.get("ports", "1-1000")
            args.append(f"-p {ports}")
            
            # Service detection
            args.append("-sV")
            args.append("--version-intensity 5")
            
            # Speed
            speed = parameters.get("speed", "normal")
            if speed == "slow":
                args.append("-T2")
            elif speed == "normal":
                args.append("-T3")
            elif speed == "fast":
                args.append("-T4")
                
        elif scan_type == "os-detection":
            # OS detection requires root privileges
            args.append("-O")
            args.append("--osscan-guess")
            
            # Service detection
            args.append("-sV")
            args.append("--version-intensity 5")
            
            # Specific ports that help with OS detection
            ports = parameters.get("ports", "22,80,443")
            args.append(f"-p {ports}")
            
        elif scan_type == "vulnerability-scan":
            # Vulnerability scanning uses NSE scripts
            args.append("--script=vuln")
            
            # Intensity affects scan depth
            intensity = parameters.get("intensity", "medium")
            if intensity == "light":
                args.append("-T2")
            elif intensity == "medium":
                args.append("-T3")
            elif intensity == "aggressive":
                args.append("-T4")
            
            # Add version detection for better vulnerability assessment
            args.append("-sV")
            args.append("--version-intensity 5")
        
        return " ".join(args)


# Create singleton instance
scanner = NmapScanner()
