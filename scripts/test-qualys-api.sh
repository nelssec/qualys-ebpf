#!/bin/bash
# Test Qualys API connectivity
# Usage: ./test-qualys-api.sh [platform_url]

set -e

# Default to Canada platform if not specified
PLATFORM_URL="${1:-qualysguard.qg1.apps.qualys.ca}"

echo "=============================================="
echo "Qualys API Connectivity Test"
echo "=============================================="
echo ""
echo "Platform: ${PLATFORM_URL}"
echo ""

# Check for credentials
if [ -z "$QUALYS_USERNAME" ] || [ -z "$QUALYS_PASSWORD" ]; then
    echo "Error: QUALYS_USERNAME and QUALYS_PASSWORD must be set"
    echo ""
    echo "  export QUALYS_USERNAME=your_username"
    echo "  export QUALYS_PASSWORD=your_password"
    echo ""
    exit 1
fi

echo "Testing API endpoints..."
echo ""

# Test 1: Basic connectivity (no auth required for this check)
echo "1. Testing basic HTTPS connectivity..."
if curl -s --connect-timeout 5 "https://${PLATFORM_URL}" > /dev/null 2>&1; then
    echo "   ✓ HTTPS connection successful"
else
    echo "   ✗ Cannot connect to ${PLATFORM_URL}"
    echo "   Check your network/VPN connection"
    exit 1
fi

# Test 2: CDR API endpoint
echo ""
echo "2. Testing CDR API endpoint..."
CDR_URL="https://${PLATFORM_URL}/cloudview/rest/v1/cdr/detections"
echo "   URL: ${CDR_URL}"

CDR_RESPONSE=$(curl -s -w "\n%{http_code}" \
    -u "${QUALYS_USERNAME}:${QUALYS_PASSWORD}" \
    -H "Accept: application/json" \
    -H "X-Requested-With: curl" \
    "${CDR_URL}?pageSize=1" 2>&1)

CDR_HTTP_CODE=$(echo "$CDR_RESPONSE" | tail -n1)
CDR_BODY=$(echo "$CDR_RESPONSE" | sed '$d')

if [ "$CDR_HTTP_CODE" = "200" ]; then
    echo "   ✓ CDR API accessible (HTTP 200)"
    echo "   Response preview: $(echo "$CDR_BODY" | head -c 200)..."
elif [ "$CDR_HTTP_CODE" = "401" ]; then
    echo "   ✗ Authentication failed (HTTP 401)"
    echo "   Check your QUALYS_USERNAME and QUALYS_PASSWORD"
elif [ "$CDR_HTTP_CODE" = "403" ]; then
    echo "   ✗ Access forbidden (HTTP 403)"
    echo "   Your account may not have CDR access enabled"
elif [ "$CDR_HTTP_CODE" = "404" ]; then
    echo "   ✗ Endpoint not found (HTTP 404)"
    echo "   CDR may not be available on this platform"
else
    echo "   ? Unexpected response (HTTP ${CDR_HTTP_CODE})"
    echo "   Response: ${CDR_BODY}"
fi

# Test 3: Container Security API endpoint
echo ""
echo "3. Testing Container Security API endpoint..."
CS_URL="https://${PLATFORM_URL}/csapi/v1.3/containers"
echo "   URL: ${CS_URL}"

CS_RESPONSE=$(curl -s -w "\n%{http_code}" \
    -u "${QUALYS_USERNAME}:${QUALYS_PASSWORD}" \
    -H "Accept: application/json" \
    -H "X-Requested-With: curl" \
    "${CS_URL}?pageSize=1" 2>&1)

CS_HTTP_CODE=$(echo "$CS_RESPONSE" | tail -n1)
CS_BODY=$(echo "$CS_RESPONSE" | sed '$d')

if [ "$CS_HTTP_CODE" = "200" ]; then
    echo "   ✓ Container Security API accessible (HTTP 200)"
    echo "   Response preview: $(echo "$CS_BODY" | head -c 200)..."
elif [ "$CS_HTTP_CODE" = "401" ]; then
    echo "   ✗ Authentication failed (HTTP 401)"
elif [ "$CS_HTTP_CODE" = "403" ]; then
    echo "   ✗ Access forbidden (HTTP 403)"
    echo "   Your account may not have Container Security enabled"
elif [ "$CS_HTTP_CODE" = "404" ]; then
    echo "   ✗ Endpoint not found (HTTP 404)"
else
    echo "   ? Unexpected response (HTTP ${CS_HTTP_CODE})"
    echo "   Response: ${CS_BODY}"
fi

# Test 4: CRS Runtime Events API
echo ""
echo "4. Testing CRS Runtime Events API..."
CRS_URL="https://${PLATFORM_URL}/csapi/v1.3/crs/events"
echo "   URL: ${CRS_URL}"

CRS_RESPONSE=$(curl -s -w "\n%{http_code}" \
    -u "${QUALYS_USERNAME}:${QUALYS_PASSWORD}" \
    -H "Accept: application/json" \
    -H "X-Requested-With: curl" \
    "${CRS_URL}?pageSize=1" 2>&1)

CRS_HTTP_CODE=$(echo "$CRS_RESPONSE" | tail -n1)
CRS_BODY=$(echo "$CRS_RESPONSE" | sed '$d')

if [ "$CRS_HTTP_CODE" = "200" ]; then
    echo "   ✓ CRS Events API accessible (HTTP 200)"
    echo "   Response preview: $(echo "$CRS_BODY" | head -c 200)..."
elif [ "$CRS_HTTP_CODE" = "401" ]; then
    echo "   ✗ Authentication failed (HTTP 401)"
elif [ "$CRS_HTTP_CODE" = "403" ]; then
    echo "   ✗ Access forbidden (HTTP 403)"
elif [ "$CRS_HTTP_CODE" = "404" ]; then
    echo "   ✗ Endpoint not found (HTTP 404)"
else
    echo "   ? Unexpected response (HTTP ${CRS_HTTP_CODE})"
fi

# Test 5: Swagger/API docs
echo ""
echo "5. Testing API documentation endpoint..."
SWAGGER_URL="https://${PLATFORM_URL}/csapi/v1.3/swagger.json"
echo "   URL: ${SWAGGER_URL}"

SWAGGER_RESPONSE=$(curl -s -w "\n%{http_code}" \
    -u "${QUALYS_USERNAME}:${QUALYS_PASSWORD}" \
    "${SWAGGER_URL}" 2>&1)

SWAGGER_HTTP_CODE=$(echo "$SWAGGER_RESPONSE" | tail -n1)

if [ "$SWAGGER_HTTP_CODE" = "200" ]; then
    echo "   ✓ Swagger docs accessible (HTTP 200)"
else
    echo "   - Swagger endpoint returned HTTP ${SWAGGER_HTTP_CODE}"
fi

echo ""
echo "=============================================="
echo "Test Summary"
echo "=============================================="
echo ""
echo "Platform: ${PLATFORM_URL}"
echo ""
echo "API Endpoints tested:"
echo "  CDR:     https://${PLATFORM_URL}/cloudview/rest/v1/cdr/detections"
echo "  CS:      https://${PLATFORM_URL}/csapi/v1.3/containers"
echo "  CRS:     https://${PLATFORM_URL}/csapi/v1.3/crs/events"
echo ""
echo "If you see 401/403 errors, verify:"
echo "  1. Credentials are correct"
echo "  2. Your account has the required modules enabled"
echo "  3. API access is enabled for your user"
echo ""
