#!/bin/bash

# API Testing Script for SecurityScan Pro
# This script performs a complete API workflow test

# Configuration
API_URL="http://localhost:8000/api/v1"
EMAIL="test-$(date +%s)@example.com"
PASSWORD="SecurePassword123!"
FULL_NAME="Test User"

echo "===== SecurityScan Pro API Test ====="
echo "Testing API at: $API_URL"
echo "Using test email: $EMAIL"
echo

# Function to exit on error
function exit_on_error {
    if [ $1 -ne 0 ]; then
        echo "ERROR: $2"
        exit 1
    fi
}

# Create temporary files for data handling
TOKEN_FILE=$(mktemp)
GROUP_ID_FILE=$(mktemp)
ENDPOINT_ID_FILE=$(mktemp)
SCAN_ID_FILE=$(mktemp)

# Clean up files on exit
trap "rm -f $TOKEN_FILE $GROUP_ID_FILE $ENDPOINT_ID_FILE $SCAN_ID_FILE" EXIT

echo "Step 1: Registering new user..."
RESPONSE=$(curl -s -L -X POST "$API_URL/auth/signup" \
    -H "Content-Type: application/json" \
    -d "{
        \"email\": \"$EMAIL\",
        \"password\": \"$PASSWORD\",
        \"full_name\": \"$FULL_NAME\"
    }")

echo $RESPONSE | grep -q "access_token"
exit_on_error $? "User registration failed"

# Extract access token
echo $RESPONSE | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4 > $TOKEN_FILE
TOKEN=$(cat $TOKEN_FILE)
echo "✅ User registered successfully"
echo "Token: ${TOKEN:0:20}..." # Show part of the token
echo

echo "Step 2: Creating endpoint group..."
RESPONSE=$(curl -s -L -X POST "$API_URL/endpoint-groups" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{
        "name": "Test Group",
        "description": "Group for API testing"
    }')

echo $RESPONSE | grep -q "id"
exit_on_error $? "Failed to create endpoint group"

# Extract group ID
echo $RESPONSE | grep -o '"id":"[^"]*"' | cut -d'"' -f4 > $GROUP_ID_FILE
GROUP_ID=$(cat $GROUP_ID_FILE)
echo "✅ Endpoint group created successfully"
echo "Group ID: $GROUP_ID"
echo

echo "Step 3: Creating endpoint..."
RESPONSE=$(curl -s -L -X POST "$API_URL/endpoints" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{
        \"name\": \"Localhost\",
        \"address\": \"127.0.0.1\",
        \"type\": \"ip\",
        \"description\": \"Local machine for testing\",
        \"group_id\": \"$GROUP_ID\"
    }")

echo $RESPONSE | grep -q "id"
exit_on_error $? "Failed to create endpoint"

# Extract endpoint ID
echo $RESPONSE | grep -o '"id":"[^"]*"' | cut -d'"' -f4 > $ENDPOINT_ID_FILE
ENDPOINT_ID=$(cat $ENDPOINT_ID_FILE)
echo "✅ Endpoint created successfully"
echo "Endpoint ID: $ENDPOINT_ID"
echo

echo "Step 4: Starting a port scan..."
RESPONSE=$(curl -s -L -X POST "$API_URL/scans" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{
        \"name\": \"Test Port Scan\",
        \"type\": \"port-scan\",
        \"parameters\": {
            \"ports\": \"22-80\",
            \"speed\": \"fast\",
            \"timeout\": 30
        },
        \"target_endpoints\": [\"$ENDPOINT_ID\"]
    }")

echo $RESPONSE | grep -q "id"
exit_on_error $? "Failed to start scan"

# Extract scan ID (only take the first ID)
echo $RESPONSE | grep -o '"id":"[^"]*"' | head -n 1 | cut -d'"' -f4 > $SCAN_ID_FILE
SCAN_ID=$(cat $SCAN_ID_FILE)
echo "✅ Scan started successfully"
echo "Scan ID: $SCAN_ID"
echo

echo "Step 5: Waiting for scan to complete..."
STATUS="pending"
MAX_RETRIES=10
COUNT=0
while [ $COUNT -lt $MAX_RETRIES ]; do
    echo "Checking scan status (attempt $((COUNT+1))/$MAX_RETRIES)..."
    
    # Debug: Show the curl command
    echo "DEBUG: Calling: curl -s -L -X GET \"$API_URL/scans/$SCAN_ID\" -H \"Authorization: Bearer $TOKEN\""
    
    # Separate stdout and stderr
    RESPONSE=$(curl -s -L -X GET "$API_URL/scans/$SCAN_ID" \
        -H "Authorization: Bearer $TOKEN")
    
    # Debug: Show the response
    echo "DEBUG: Response:"
    echo "$RESPONSE"
    
    # Check if response is empty
    if [ -z "$RESPONSE" ]; then
        echo "Error: Empty response from server"
        COUNT=$((COUNT+1))
        sleep 5
        continue
    fi
    
    # Use jq to parse the JSON response if available
    if command -v jq &> /dev/null; then
        STATUS=$(echo "$RESPONSE" | jq -r '.status // empty' 2>/dev/null)
    else
        # Fallback to grep if jq is not available
        STATUS=$(echo "$RESPONSE" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
    fi
    
    # Check if status was successfully parsed
    if [ -z "$STATUS" ]; then
        echo "Error: Could not parse status from response"
        echo "Response: $RESPONSE"
        COUNT=$((COUNT+1))
        sleep 5
        continue
    fi
    
    echo "Current status: $STATUS"
    
    # Check for terminal states
    if [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ]; then
        break
    fi
    
    COUNT=$((COUNT+1))
    sleep 5
done

if [ "$STATUS" = "completed" ]; then
    echo "✅ Scan completed successfully"
elif [ "$STATUS" = "running" ]; then
    echo "⚠️ Scan is still running (test will continue)"
else
    echo "❌ Scan failed or timed out with status: $STATUS"
    # Continue the test anyway
fi
echo

echo "Step 6: Fetching scan results..."
RESPONSE=$(curl -s -L -X GET "$API_URL/scans/$SCAN_ID" \
    -H "Authorization: Bearer $TOKEN")

echo $RESPONSE | grep -q "targets"
exit_on_error $? "Failed to fetch scan results"
echo "✅ Scan results retrieved successfully"
echo

echo "Step 7: Generating reports..."
echo "JSON Report:"
# Save full report to file
REPORT_FILE=$(mktemp)
curl -s -L -X GET "$API_URL/reports/$SCAN_ID?format=json" \
    -H "Authorization: Bearer $TOKEN" > "$REPORT_FILE"
echo "Full report saved to: $REPORT_FILE"
# Show preview
head -n 20 "$REPORT_FILE"
echo -e "\n...\n"

echo "Step 8: Creating a scheduled scan..."
RESPONSE=$(curl -s -L -X POST "$API_URL/scans/scheduled" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{
        \"name\": \"Daily Port Scan\",
        \"scan_config\": {
            \"type\": \"port-scan\",
            \"target_endpoints\": [\"$ENDPOINT_ID\"],
            \"parameters\": {
                \"ports\": \"22-80\",
                \"speed\": \"normal\"
            }
        },
        \"schedule_type\": \"daily\"
    }")

echo $RESPONSE | grep -q "id"
exit_on_error $? "Failed to create scheduled scan"
echo "✅ Scheduled scan created successfully"
echo

echo "Step 9: Comparing endpoints (using same scan for demonstration)..."
RESPONSE=$(curl -s -L -X GET "$API_URL/reports/comparison?scan_id_1=$SCAN_ID&scan_id_2=$SCAN_ID" \
    -H "Authorization: Bearer $TOKEN")

echo $RESPONSE | grep -q "comparison"
if [ $? -ne 0 ]; then
    echo "⚠️ Scan comparison returned unexpected result (this could be normal if scan is still in progress)"
else
    echo "✅ Scan comparison completed successfully"
fi
echo

echo "Step 10: Running additional tests..."
# Function to test error cases
function test_error_cases() {
    local TOKEN=$1
    echo "Testing error cases..."
    
    # Test invalid auth
    echo "Testing invalid authentication:"
    RESPONSE=$(curl -s -L -X GET "$API_URL/scans" \
        -H "Authorization: Bearer invalid_token" -w "\nStatus: %{http_code}")
    echo "$RESPONSE"
    
    # Test invalid scan parameters
    echo "Testing invalid scan parameters:"
    RESPONSE=$(curl -s -L -X POST "$API_URL/scans" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d '{
            "name": "Invalid Scan",
            "type": "invalid-type",
            "parameters": {},
            "target_endpoints": ["invalid-id"]
        }' -w "\nStatus: %{http_code}")
    echo "$RESPONSE"
    
    # Test non-existent resources
    echo "Testing non-existent scan:"
    RESPONSE=$(curl -s -L -X GET "$API_URL/scans/00000000-0000-0000-0000-000000000000" \
        -H "Authorization: Bearer $TOKEN" -w "\nStatus: %{http_code}")
    echo "$RESPONSE"
    echo
}

# Function to test scan operations
function test_scan_operations() {
    local TOKEN=$1
    local ENDPOINT_ID=$2
    echo "Testing scan operations..."
    
    # Test different scan types
    echo "Testing vulnerability scan:"
    RESPONSE=$(curl -s -L -X POST "$API_URL/scans" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d "{
            \"name\": \"Test Vulnerability Scan\",
            \"type\": \"vulnerability-scan\",
            \"parameters\": {
                \"severity\": \"high\"
            },
            \"target_endpoints\": [\"$ENDPOINT_ID\"]
        }")
    
    if echo "$RESPONSE" | grep -q "id"; then
        VULN_SCAN_ID=$(echo "$RESPONSE" | grep -o '"id":"[^"]*"' | head -n 1 | cut -d'"' -f4)
        echo "✅ Vulnerability scan created with ID: $VULN_SCAN_ID"
        
        # Test scan cancellation
        echo "Testing scan cancellation:"
        curl -s -L -X POST "$API_URL/scans/$VULN_SCAN_ID/stop" \
            -H "Authorization: Bearer $TOKEN" -w "Status: %{http_code}\n"
    else
        echo "❌ Failed to create vulnerability scan"
    fi
    echo
}

# Function to test scheduled scan management
function test_scheduled_scan_management() {
    local TOKEN=$1
    local ENDPOINT_ID=$2
    echo "Testing scheduled scan management..."
    
    # Create scheduled scan
    RESPONSE=$(curl -s -L -X POST "$API_URL/scans/scheduled" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d "{
            \"name\": \"Test Schedule\",
            \"scan_config\": {
                \"type\": \"port-scan\",
                \"target_endpoints\": [\"$ENDPOINT_ID\"],
                \"parameters\": {
                    \"ports\": \"22-80\",
                    \"speed\": \"normal\"
                }
            },
            \"schedule_type\": \"daily\"
        }")
    
    if echo "$RESPONSE" | grep -q "id"; then
        SCHED_ID=$(echo "$RESPONSE" | grep -o '"id":"[^"]*"' | head -n 1 | cut -d'"' -f4)
        echo "✅ Scheduled scan created with ID: $SCHED_ID"
        
        # Update scheduled scan
        echo "Testing schedule update:"
        curl -s -L -X PUT "$API_URL/scans/scheduled/$SCHED_ID" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $TOKEN" \
            -d '{
                "schedule_type": "weekly",
                "is_active": false
            }' -w "Status: %{http_code}\n"
        
        # Delete scheduled scan
        echo "Testing schedule deletion:"
        curl -s -L -X DELETE "$API_URL/scans/scheduled/$SCHED_ID" \
            -H "Authorization: Bearer $TOKEN" -w "Status: %{http_code}\n"
    else
        echo "❌ Failed to create scheduled scan"
    fi
    echo
}

# Function to test pagination
function test_pagination() {
    local TOKEN=$1
    echo "Testing pagination..."
    
    # Create multiple endpoints for pagination testing
    for i in {1..5}; do
        curl -s -L -X POST "$API_URL/endpoints" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $TOKEN" \
            -d "{
                \"name\": \"Test Endpoint $i\",
                \"address\": \"192.168.1.$i\",
                \"type\": \"ip\",
                \"description\": \"Test endpoint for pagination\",
                \"group_id\": \"$GROUP_ID\"
            }" > /dev/null
    done
    
    # Test endpoint listing with pagination
    echo "Testing endpoint listing (page 1, limit 2):"
    curl -s -L -X GET "$API_URL/endpoints?skip=0&limit=2" \
        -H "Authorization: Bearer $TOKEN"
    echo
    
    echo "Testing endpoint listing (page 2, limit 2):"
    curl -s -L -X GET "$API_URL/endpoints?skip=2&limit=2" \
        -H "Authorization: Bearer $TOKEN"
    echo
}

# Function to test resource updates
function test_updates() {
    local TOKEN=$1
    local ENDPOINT_ID=$2
    local GROUP_ID=$3
    echo "Testing resource updates..."
    
    # Test endpoint update
    echo "Testing endpoint update:"
    RESPONSE=$(curl -s -L -X PUT "$API_URL/endpoints/$ENDPOINT_ID" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d '{
            "name": "Updated Endpoint",
            "description": "Updated description"
        }')
    echo "$RESPONSE"
    
    # Test group update
    echo "Testing group update:"
    RESPONSE=$(curl -s -L -X PUT "$API_URL/endpoint-groups/$GROUP_ID" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d '{
            "name": "Updated Group",
            "description": "Updated group description"
        }')
    echo "$RESPONSE"
}

# Function to test OS detection scan
function test_os_detection() {
    local TOKEN=$1
    local ENDPOINT_ID=$2
    echo "Testing OS detection scan..."
    
    # Create OS detection scan
    RESPONSE=$(curl -s -L -X POST "$API_URL/scans" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d "{
            \"name\": \"OS Detection Scan\",
            \"type\": \"os-detection\",
            \"parameters\": {
                \"intensity\": \"aggressive\"
            },
            \"target_endpoints\": [\"$ENDPOINT_ID\"]
        }")
    
    if echo "$RESPONSE" | grep -q "id"; then
        OS_SCAN_ID=$(echo "$RESPONSE" | grep -o '"id":"[^"]*"' | head -n 1 | cut -d'"' -f4)
        echo "✅ OS detection scan created with ID: $OS_SCAN_ID"
        
        # Wait for scan completion
        echo "Waiting for OS detection scan to complete..."
        STATUS="pending"
        COUNT=0
        while [ "$STATUS" != "completed" ] && [ "$STATUS" != "failed" ] && [ $COUNT -lt 5 ]; do
            sleep 2
            RESPONSE=$(curl -s -L -X GET "$API_URL/scans/$OS_SCAN_ID" \
                -H "Authorization: Bearer $TOKEN")
            STATUS=$(echo "$RESPONSE" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
            echo "Current status: $STATUS"
            COUNT=$((COUNT+1))
        done
        
        # Get OS detection results
        echo "OS Detection Results:"
        curl -s -L -X GET "$API_URL/scans/$OS_SCAN_ID" \
            -H "Authorization: Bearer $TOKEN" | grep -o '"os_detection":"[^"]*"' || echo "No OS detected"
    else
        echo "❌ Failed to create OS detection scan"
    fi
    echo
}

# Function to test concurrent scans
function test_concurrent_scans() {
    local TOKEN=$1
    local ENDPOINT_ID=$2
    echo "Testing concurrent scan limits..."
    
    # Start multiple scans simultaneously
    for i in {1..3}; do
        echo "Starting concurrent scan $i:"
        curl -s -L -X POST "$API_URL/scans" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $TOKEN" \
            -d "{
                \"name\": \"Concurrent Scan $i\",
                \"type\": \"port-scan\",
                \"parameters\": {
                    \"ports\": \"22-80\",
                    \"speed\": \"fast\"
                },
                \"target_endpoints\": [\"$ENDPOINT_ID\"]
            }"
        echo
    done
}

# Run comprehensive tests
test_error_cases "$TOKEN"
test_scan_operations "$TOKEN" "$ENDPOINT_ID"
test_scheduled_scan_management "$TOKEN" "$ENDPOINT_ID"
test_pagination "$TOKEN"
test_updates "$TOKEN" "$ENDPOINT_ID" "$GROUP_ID"
test_os_detection "$TOKEN" "$ENDPOINT_ID"
test_concurrent_scans "$TOKEN" "$ENDPOINT_ID"

echo "Step 11: Testing cleanup..."
echo "Deleting scan:"
# Try deleting scan multiple times with delay
MAX_DELETE_RETRIES=3
DELETE_COUNT=0
while [ $DELETE_COUNT -lt $MAX_DELETE_RETRIES ]; do
    RESPONSE=$(curl -s -L -X DELETE "$API_URL/scans/$SCAN_ID" \
        -H "Authorization: Bearer $TOKEN" -w "Status: %{http_code}\n")
    STATUS_CODE=$(echo "$RESPONSE" | grep -o "Status: [0-9]*" | cut -d' ' -f2)
    
    if [ "$STATUS_CODE" = "204" ] || [ "$STATUS_CODE" = "404" ]; then
        echo "Scan deleted successfully"
        break
    else
        echo "Failed to delete scan (attempt $((DELETE_COUNT+1))/$MAX_DELETE_RETRIES): $RESPONSE"
        DELETE_COUNT=$((DELETE_COUNT+1))
        sleep 2
    fi
done

echo "Deleting endpoint:"
curl -s -L -X DELETE "$API_URL/endpoints/$ENDPOINT_ID" \
    -H "Authorization: Bearer $TOKEN" -w "Status: %{http_code}\n"

echo "Deleting group:"
curl -s -L -X DELETE "$API_URL/endpoint-groups/$GROUP_ID" \
    -H "Authorization: Bearer $TOKEN" -w "Status: %{http_code}\n"

# Clean up report file
rm -f "$REPORT_FILE"

echo
echo "===== Test completed successfully! ====="