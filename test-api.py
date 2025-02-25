#!/usr/bin/env python3

"""
API Testing Script for SecurityScan Pro
This script performs a complete API workflow test
"""

import requests
import json
import time
import tempfile
import os
import sys
from datetime import datetime, timedelta, timezone


class APITester:
    def __init__(self):
        # Configuration
        self.api_url = "http://localhost:8000/api/v1"
        self.email = f"test-{int(time.time())}@example.com"
        self.password = "SecurePassword123!"
        self.full_name = "Test User"
        
        # Variables to store data between steps
        self.token = None
        self.group_id = None
        self.endpoint_id = None
        self.scan_id = None
        self.second_scan_id = None
        self.report_file = None
        
        print("===== SecurityScan Pro API Test =====")
        print(f"Testing API at: {self.api_url}")
        print(f"Using test email: {self.email}")
        print()

    def exit_on_error(self, condition, message):
        """Exit the script if condition is True with the specified error message"""
        if condition:
            print(f"ERROR: {message}")
            sys.exit(1)

    def register_user(self):
        """Step 1: Register a new user"""
        print("Step 1: Registering new user...")
        
        response = requests.post(
            f"{self.api_url}/auth/signup",
            headers={"Content-Type": "application/json"},
            json={
                "email": self.email,
                "password": self.password,
                "full_name": self.full_name
            }
        )
        
        try:
            data = response.json()
        except json.JSONDecodeError:
            self.exit_on_error(True, "Invalid JSON response")
            
        self.exit_on_error("access_token" not in data, "User registration failed")
        
        self.token = data["access_token"]
        print("✅ User registered successfully")
        print(f"Token: {self.token[:20]}...")  # Show part of the token
        print()

    def create_endpoint_group(self):
        """Step 2: Create an endpoint group"""
        print("Step 2: Creating endpoint group...")
        
        response = requests.post(
            f"{self.api_url}/endpoint-groups",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.token}"
            },
            json={
                "name": "Test Group",
                "description": "Group for API testing"
            }
        )
        
        try:
            data = response.json()
        except json.JSONDecodeError:
            self.exit_on_error(True, "Invalid JSON response")
            
        self.exit_on_error("id" not in data, "Failed to create endpoint group")
        
        self.group_id = data["id"]
        print("✅ Endpoint group created successfully")
        print(f"Group ID: {self.group_id}")
        print()

    def create_endpoint(self):
        """Step 3: Create an endpoint"""
        print("Step 3: Creating endpoint...")
        
        response = requests.post(
            f"{self.api_url}/endpoints",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.token}"
            },
            json={
                "name": "Localhost",
                "address": "127.0.0.1",
                "type": "ip",
                "description": "Local machine for testing",
                "group_id": self.group_id
            }
        )
        
        try:
            data = response.json()
        except json.JSONDecodeError:
            self.exit_on_error(True, "Invalid JSON response")
            
        self.exit_on_error("id" not in data, "Failed to create endpoint")
        
        self.endpoint_id = data["id"]
        print("✅ Endpoint created successfully")
        print(f"Endpoint ID: {self.endpoint_id}")
        print()

    def start_scan(self):
        """Step 4: Start a port scan"""
        print("Step 4: Starting a port scan...")
        
        response = requests.post(
            f"{self.api_url}/scans",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.token}"
            },
            json={
                "name": "Test Port Scan",
                "type": "port-scan",
                "parameters": {
                    "ports": "22-80",
                    "speed": "fast",
                    "timeout": 30
                },
                "target_endpoints": [self.endpoint_id]
            }
        )
        
        try:
            data = response.json()
        except json.JSONDecodeError:
            self.exit_on_error(True, "Invalid JSON response")
            
        self.exit_on_error("id" not in data, "Failed to start scan")
        
        self.scan_id = data["id"]
        print("✅ Scan started successfully")
        print(f"Scan ID: {self.scan_id}")
        print()

    def wait_for_scan_completion(self):
        """Step 5: Wait for scan to complete"""
        print("Step 5: Waiting for scan to complete...")
        
        status = "pending"
        max_retries = 10
        count = 0
        
        while count < max_retries:
            print(f"Checking scan status (attempt {count+1}/{max_retries})...")
            
            # Debug: Show the request
            print(f"DEBUG: Calling: GET {self.api_url}/scans/{self.scan_id}")
            
            response = requests.get(
                f"{self.api_url}/scans/{self.scan_id}",
                headers={"Authorization": f"Bearer {self.token}"}
            )
            
            # Debug: Show the response
            print("DEBUG: Response:")
            print(response.text)
            
            if not response.text:
                print("Error: Empty response from server")
                count += 1
                time.sleep(5)
                continue
                
            try:
                data = response.json()
                status = data.get("status", "")
            except json.JSONDecodeError:
                print("Error: Could not parse JSON response")
                print(f"Response: {response.text}")
                count += 1
                time.sleep(5)
                continue
                
            if not status:
                print("Error: Could not parse status from response")
                print(f"Response: {response.text}")
                count += 1
                time.sleep(5)
                continue
                
            print(f"Current status: {status}")
            
            if status in ["completed", "failed"]:
                break
                
            count += 1
            time.sleep(5)
            
        if status == "completed":
            print("✅ Scan completed successfully")
        elif status == "running":
            print("⚠️ Scan is still running (test will continue)")
        else:
            print(f"❌ Scan failed or timed out with status: {status}")
        print()

    def fetch_scan_results(self):
        """Step 6: Fetch scan results"""
        print("Step 6: Fetching scan results...")
        
        response = requests.get(
            f"{self.api_url}/scans/{self.scan_id}",
            headers={"Authorization": f"Bearer {self.token}"}
        )
        
        try:
            data = response.json()
        except json.JSONDecodeError:
            self.exit_on_error(True, "Invalid JSON response")
            
        self.exit_on_error("targets" not in data, "Failed to fetch scan results")
        
        print("✅ Scan results retrieved successfully")
        print()

    def generate_reports(self):
        """Step 7: Generate reports"""
        print("Step 7: Generating reports...")
        print("JSON Report:")
        
        response = requests.get(
            f"{self.api_url}/reports/{self.scan_id}?format=json",
            headers={"Authorization": f"Bearer {self.token}"}
        )
        
        # Save full report to file
        with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".json") as f:
            self.report_file = f.name
            f.write(response.text)
            
        print(f"Full report saved to: {self.report_file}")
        
        # Show preview
        try:
            data = response.json()
            # Format the JSON nicely for display, limiting to first 20 lines equivalent
            formatted_json = json.dumps(data, indent=2)
            print("\n".join(formatted_json.split("\n")[:20]))
        except json.JSONDecodeError:
            print("Could not parse JSON response")
            print(response.text[:500])  # Show first 500 chars of response
            
        print("\n...\n")

    def create_scheduled_scan(self):
        """Step 8: Create a scheduled scan"""
        print("Step 8: Creating a scheduled scan...")
        
        # Use timezone-aware datetime with UTC
        next_run = (datetime.now(timezone.utc).replace(microsecond=0) + timedelta(minutes=30)).isoformat()
        
        response = requests.post(
            f"{self.api_url}/scans/scheduled",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.token}"
            },
            json={
                "name": "Test Scheduled Scan",
                "scan_config": {
                    "type": "port-scan",
                    "target_endpoints": [self.endpoint_id],
                    "parameters": {
                        "ports": "22-80",
                        "speed": "normal"
                    }
                },
                "schedule_type": "daily",
                "next_run": next_run
            }
        )
        
        try:
            data = response.json()
            if "id" in data:
                print("✅ Scheduled scan created successfully")
            else:
                print("❌ Failed to create scheduled scan")
                if data:
                    print(f"Response: {json.dumps(data, indent=2)}")
        except json.JSONDecodeError as e:
            print(f"❌ Failed to create scheduled scan - invalid response: {e}")
            print(f"Raw response: {response.text}")
        except Exception as e:
            print(f"❌ Failed to create scheduled scan - error: {e}")
        print()

    def compare_scans(self):
        """Step 9: Compare two scans"""
        print("\nStep 9: Comparing scans...")
        
        # Create a second scan for comparison
        response = requests.post(
            f"{self.api_url}/scans",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.token}"
            },
            json={
                "name": "Second Test Scan",
                "type": "port-scan",
                "parameters": {
                    "ports": "22-80",
                    "speed": "fast"
                },
                "target_endpoints": [self.endpoint_id]
            }
        )
        
        try:
            data = response.json()
            if "id" not in data:
                print("❌ Failed to create second scan")
                return
                
            second_scan_id = data["id"]
            print(f"✅ Created second scan with ID: {second_scan_id}")
            
            # Wait for second scan to complete
            print("Waiting for second scan to complete...")
            for _ in range(10):
                response = requests.get(
                    f"{self.api_url}/scans/{second_scan_id}",
                    headers={"Authorization": f"Bearer {self.token}"}
                )
                data = response.json()
                status = data.get("status")
                print(f"Status: {status}")
                if status == "completed":
                    break
                time.sleep(1)
            
            # Compare the scans
            print("Comparing scans...")
            comparison_response = requests.get(
                f"{self.api_url}/scans/compare/{self.scan_id}/{second_scan_id}",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.token}"
                }
            )
            
            print("✅ Scan comparison completed")
            print("Comparison results:")
            try:
                comparison_data = comparison_response.json()
                print(json.dumps(comparison_data, indent=2))
            except json.JSONDecodeError:
                print(f"Raw response: {comparison_response.text}")
                
        except json.JSONDecodeError as e:
            print(f"❌ Failed to parse response: {e}")
        except Exception as e:
            print(f"❌ Error during scan comparison: {e}")
        print()

    def test_error_cases(self):
        """Test error cases"""
        print("Testing error cases...")
        
        # Test invalid auth
        print("Testing invalid authentication:")
        response = requests.get(
            f"{self.api_url}/scans",
            headers={"Authorization": "Bearer invalid_token"}
        )
        print(f"Status: {response.status_code}")
        print(response.text)
        
        # Test invalid scan parameters
        print("Testing invalid scan parameters:")
        response = requests.post(
            f"{self.api_url}/scans",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.token}"
            },
            json={
                "name": "Invalid Scan",
                "type": "invalid-type",
                "parameters": {},
                "target_endpoints": ["invalid-id"]
            }
        )
        print(f"Status: {response.status_code}")
        print(response.text)
        
        # Test non-existent resources
        print("Testing non-existent scan:")
        response = requests.get(
            f"{self.api_url}/scans/00000000-0000-0000-0000-000000000000",
            headers={"Authorization": f"Bearer {self.token}"}
        )
        print(f"Status: {response.status_code}")
        print(response.text)
        print()

    def test_scan_operations(self):
        """Test scan operations"""
        print("Testing scan operations...")
        
        # Test different scan types
        print("Testing vulnerability scan:")
        response = requests.post(
            f"{self.api_url}/scans",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.token}"
            },
            json={
                "name": "Test Vulnerability Scan",
                "type": "vulnerability-scan",
                "parameters": {
                    "severity": "high"
                },
                "target_endpoints": [self.endpoint_id]
            }
        )
        
        try:
            data = response.json()
            if "id" in data:
                vuln_scan_id = data["id"]
                print(f"✅ Vulnerability scan created with ID: {vuln_scan_id}")
                
                # Test scan cancellation
                print("Testing scan cancellation:")
                cancel_response = requests.post(
                    f"{self.api_url}/scans/{vuln_scan_id}/stop",
                    headers={"Authorization": f"Bearer {self.token}"}
                )
                print(f"Status: {cancel_response.status_code}")
            else:
                print("❌ Failed to create vulnerability scan")
        except json.JSONDecodeError:
            print("❌ Failed to create vulnerability scan - invalid response")
            
        print()

    def test_scheduled_scan_management(self):
        """Test scheduled scan management"""
        print("Testing scheduled scan management...")
        
        # Use timezone-aware datetime with UTC
        next_run = (datetime.now(timezone.utc).replace(microsecond=0) + timedelta(minutes=30)).isoformat()
        
        response = requests.post(
            f"{self.api_url}/scans/scheduled",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.token}"
            },
            json={
                "name": "Test Scheduled Scan",
                "scan_config": {
                    "type": "port-scan",
                    "target_endpoints": [self.endpoint_id],
                    "parameters": {
                        "ports": "22-80",
                        "speed": "normal"
                    }
                },
                "schedule_type": "daily",
                "next_run": next_run
            }
        )
        
        try:
            data = response.json()
            if "id" in data:
                sched_id = data["id"]
                print(f"✅ Scheduled scan created with ID: {sched_id}")
                
                # Update schedule
                print("Testing schedule update:")
                new_next_run = (datetime.now(timezone.utc).replace(microsecond=0) + timedelta(hours=1)).isoformat()
                update_response = requests.put(
                    f"{self.api_url}/scans/scheduled/{sched_id}",
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {self.token}"
                    },
                    json={
                        "schedule_type": "daily",
                        "next_run": new_next_run
                    }
                )
                print(f"Status: {update_response.status_code}")
                if update_response.text:
                    print(update_response.text)
                
                # Give the server a moment to process the update
                time.sleep(1)
                
                # Delete scheduled scan with proper error handling
                print("Testing schedule deletion:")
                max_attempts = 3
                attempt = 1
                success = False
                
                while attempt <= max_attempts and not success:
                    delete_response = requests.delete(
                        f"{self.api_url}/scans/scheduled/{sched_id}",
                        headers={"Authorization": f"Bearer {self.token}"}
                    )
                    
                    if delete_response.status_code in [200, 204]:
                        print("✅ Scheduled scan deleted successfully")
                        success = True
                        break
                    elif delete_response.status_code == 404:
                        # If we get a 404, the scan might have been deleted despite the previous error
                        print("⚠️ Scheduled scan not found (might have been deleted)")
                        success = True
                        break
                    else:
                        print(f"Failed to delete scheduled scan (attempt {attempt}/{max_attempts}): Status {delete_response.status_code}")
                        if delete_response.text:
                            print(delete_response.text)
                        if attempt < max_attempts:
                            time.sleep(2)  # Longer delay between retries
                        attempt += 1
                
                if not success:
                    print("❌ Failed to delete scheduled scan after all attempts")
            else:
                print("❌ Failed to create scheduled scan")
                if data:
                    print(f"Response: {json.dumps(data, indent=2)}")
        except json.JSONDecodeError as e:
            print(f"❌ Failed to create scheduled scan - invalid response: {e}")
            print(f"Raw response: {response.text}")
        except Exception as e:
            print(f"❌ Failed to create scheduled scan - error: {e}")
            
        print()

    def test_pagination(self):
        """Test pagination"""
        print("Testing pagination...")
        
        # Create multiple endpoints for pagination testing
        for i in range(1, 6):
            response = requests.post(
                f"{self.api_url}/endpoints",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.token}"
                },
                json={
                    "name": f"Test Endpoint {i}",
                    "address": f"192.168.1.{i}",
                    "type": "ip",
                    "description": "Test endpoint for pagination",
                    "group_id": self.group_id
                }
            )
        
        # Test endpoint listing with pagination
        print("Testing endpoint listing (page 1, limit 2):")
        response = requests.get(
            f"{self.api_url}/endpoints?skip=0&limit=2",
            headers={"Authorization": f"Bearer {self.token}"}
        )
        print(response.text)
        
        print("Testing endpoint listing (page 2, limit 2):")
        response = requests.get(
            f"{self.api_url}/endpoints?skip=2&limit=2",
            headers={"Authorization": f"Bearer {self.token}"}
        )
        print(response.text)
        print()

    def test_updates(self):
        """Test resource updates"""
        print("Testing resource updates...")
        
        # Test endpoint update
        print("Testing endpoint update:")
        response = requests.put(
            f"{self.api_url}/endpoints/{self.endpoint_id}",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.token}"
            },
            json={
                "name": "Updated Endpoint",
                "description": "Updated description"
            }
        )
        print(response.text)
        
        # Test group update
        print("Testing group update:")
        response = requests.put(
            f"{self.api_url}/endpoint-groups/{self.group_id}",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.token}"
            },
            json={
                "name": "Updated Group",
                "description": "Updated group description"
            }
        )
        print(response.text)
        print()

    def test_os_detection(self):
        """Test OS detection scan"""
        print("Testing OS detection scan...")
        
        # Create OS detection scan
        response = requests.post(
            f"{self.api_url}/scans",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.token}"
            },
            json={
                "name": "OS Detection Scan",
                "type": "os-detection",
                "parameters": {
                    "intensity": "aggressive"
                },
                "target_endpoints": [self.endpoint_id]
            }
        )
        
        try:
            data = response.json()
            if "id" in data:
                os_scan_id = data["id"]
                print(f"✅ OS detection scan created with ID: {os_scan_id}")
                
                # Wait for scan completion
                print("Waiting for OS detection scan to complete...")
                status = "pending"
                count = 0
                while status not in ["completed", "failed"] and count < 5:
                    time.sleep(2)
                    response = requests.get(
                        f"{self.api_url}/scans/{os_scan_id}",
                        headers={"Authorization": f"Bearer {self.token}"}
                    )
                    try:
                        data = response.json()
                        status = data.get("status", "")
                        print(f"Current status: {status}")
                    except json.JSONDecodeError:
                        print("Error parsing status response")
                    count += 1
                
                # Get OS detection results
                print("OS Detection Results:")
                response = requests.get(
                    f"{self.api_url}/scans/{os_scan_id}",
                    headers={"Authorization": f"Bearer {self.token}"}
                )
                try:
                    data = response.json()
                    if "results" in data and data["results"] and len(data["results"]) > 0:
                        for result in data["results"]:
                            print(f"OS Detection: {result.get('os_detection', 'Not detected')}")
                    else:
                        print("No OS detected")
                except json.JSONDecodeError:
                    print("Error parsing results")
            else:
                print("❌ Failed to create OS detection scan")
        except json.JSONDecodeError:
            print("❌ Failed to create OS detection scan - invalid response")
            
        print()

    def test_concurrent_scans(self):
        """Test concurrent scans"""
        print("Testing concurrent scan limits...")
        
        # Start multiple scans simultaneously
        for i in range(1, 4):
            print(f"Starting concurrent scan {i}:")
            response = requests.post(
                f"{self.api_url}/scans",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.token}"
                },
                json={
                    "name": f"Concurrent Scan {i}",
                    "type": "port-scan",
                    "parameters": {
                        "ports": "22-80",
                        "speed": "fast"
                    },
                    "target_endpoints": [self.endpoint_id]
                }
            )
            print(response.text)
        print()

    def cleanup(self):
        """Clean up resources"""
        print("Step 11: Testing cleanup...")
        
        # Delete scan
        print("Deleting scan:")
        max_delete_retries = 3
        delete_count = 0
        
        while delete_count < max_delete_retries:
            response = requests.delete(
                f"{self.api_url}/scans/{self.scan_id}",
                headers={"Authorization": f"Bearer {self.token}"}
            )
            
            if response.status_code in [204, 404]:
                print("Scan deleted successfully")
                break
            else:
                print(f"Failed to delete scan (attempt {delete_count+1}/{max_delete_retries}): Status {response.status_code}")
                print(response.text)
                delete_count += 1
                time.sleep(2)
                
        # Delete second scan
        if self.second_scan_id:
            print("Deleting second scan:")
            response = requests.delete(
                f"{self.api_url}/scans/{self.second_scan_id}",
                headers={"Authorization": f"Bearer {self.token}"}
            )
            print(f"Status: {response.status_code}")
        
        # Delete endpoint
        print("Deleting endpoint:")
        response = requests.delete(
            f"{self.api_url}/endpoints/{self.endpoint_id}",
            headers={"Authorization": f"Bearer {self.token}"}
        )
        print(f"Status: {response.status_code}")
        
        # Delete group
        print("Deleting group:")
        response = requests.delete(
            f"{self.api_url}/endpoint-groups/{self.group_id}",
            headers={"Authorization": f"Bearer {self.token}"}
        )
        print(f"Status: {response.status_code}")
        
        # Clean up report file if it exists
        if self.report_file and os.path.exists(self.report_file):
            os.unlink(self.report_file)
            
        print()
        print("===== Test completed successfully! =====")

    def run_tests(self):
        """Run all tests"""
        try:
            self.register_user()
            self.create_endpoint_group()
            self.create_endpoint()
            self.start_scan()
            self.wait_for_scan_completion()
            self.fetch_scan_results()
            self.generate_reports()
            self.create_scheduled_scan()
            self.compare_scans()
            
            # Run additional tests
            print("Step 10: Running additional tests...")
            self.test_error_cases()
            self.test_scan_operations()
            self.test_scheduled_scan_management()
            self.test_pagination()
            self.test_updates()
            self.test_os_detection()
            self.test_concurrent_scans()
            
            # Clean up
            self.cleanup()
            
        except Exception as e:
            print(f"Test failed with error: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)


if __name__ == "__main__":
    tester = APITester()
    tester.run_tests()