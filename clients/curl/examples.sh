#!/bin/bash

# ABAC API - Curl Examples
# This script demonstrates how to authenticate with Keycloak and use the ABAC API

# Configuration
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
REALM="${KEYCLOAK_REALM:-abac-realm}"
API_URL="${API_URL:-http://localhost:3000}"
CLIENT_ID="${CLIENT_ID:-abac-webapp}"
CLIENT_SECRET="${CLIENT_SECRET:-abac-webapp-secret-change-in-production}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== ABAC API Curl Examples ===${NC}\n"

# Function to get access token with password grant
get_token_password() {
    local username=$1
    local password=$2
    
    echo -e "${YELLOW}Getting token for user: $username${NC}"
    
    response=$(curl -s -X POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=password" \
        -d "client_id=${CLIENT_ID}" \
        -d "client_secret=${CLIENT_SECRET}" \
        -d "username=${username}" \
        -d "password=${password}")
    
    ACCESS_TOKEN=$(echo $response | jq -r '.access_token')
    
    if [ "$ACCESS_TOKEN" == "null" ] || [ -z "$ACCESS_TOKEN" ]; then
        echo -e "${RED}Failed to get token:${NC}"
        echo $response | jq .
        return 1
    fi
    
    echo -e "${GREEN}Token obtained successfully${NC}\n"
    export ACCESS_TOKEN
    return 0
}

# Function to get access token with client credentials
get_token_client_credentials() {
    local client_id=$1
    local client_secret=$2
    
    echo -e "${YELLOW}Getting token for service account: $client_id${NC}"
    
    response=$(curl -s -X POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials" \
        -d "client_id=${client_id}" \
        -d "client_secret=${client_secret}")
    
    ACCESS_TOKEN=$(echo $response | jq -r '.access_token')
    
    if [ "$ACCESS_TOKEN" == "null" ] || [ -z "$ACCESS_TOKEN" ]; then
        echo -e "${RED}Failed to get token:${NC}"
        echo $response | jq .
        return 1
    fi
    
    echo -e "${GREEN}Token obtained successfully${NC}\n"
    export ACCESS_TOKEN
    return 0
}

# Function to make authenticated API call
api_call() {
    local method=$1
    local endpoint=$2
    local data=$3
    
    if [ -z "$ACCESS_TOKEN" ]; then
        echo -e "${RED}No access token. Run get_token_password or get_token_client_credentials first.${NC}"
        return 1
    fi
    
    if [ -n "$data" ]; then
        curl -s -X "$method" "${API_URL}${endpoint}" \
            -H "Authorization: Bearer ${ACCESS_TOKEN}" \
            -H "Content-Type: application/json" \
            -d "$data" | jq .
    else
        curl -s -X "$method" "${API_URL}${endpoint}" \
            -H "Authorization: Bearer ${ACCESS_TOKEN}" \
            -H "Content-Type: application/json" | jq .
    fi
}

# Demo function
demo() {
    echo -e "${BLUE}1. Check API health (no auth required)${NC}"
    curl -s "${API_URL}/health" | jq .
    echo ""

    echo -e "${BLUE}2. Get access token as admin${NC}"
    get_token_password "admin" "admin123"
    if [ $? -ne 0 ]; then
        echo -e "${RED}Authentication failed. Make sure Keycloak is running.${NC}"
        return 1
    fi

    echo -e "${BLUE}3. View token info${NC}"
    api_call GET "/api/token-info"
    echo ""

    echo -e "${BLUE}4. List users${NC}"
    api_call GET "/api/users"
    echo ""

    echo -e "${BLUE}5. List resources${NC}"
    api_call GET "/api/resources"
    echo ""

    echo -e "${BLUE}6. List policies${NC}"
    api_call GET "/api/policies"
    echo ""

    echo -e "${BLUE}7. Check access (user alice reading a document)${NC}"
    # First get a user and resource ID
    user_id=$(curl -s "${API_URL}/api/users" -H "Authorization: Bearer ${ACCESS_TOKEN}" | jq -r '.[0].id // empty')
    resource_id=$(curl -s "${API_URL}/api/resources" -H "Authorization: Bearer ${ACCESS_TOKEN}" | jq -r '.[0].id // empty')
    
    if [ -n "$user_id" ] && [ -n "$resource_id" ]; then
        api_call POST "/api/access/check" "{\"user_id\": \"$user_id\", \"resource_id\": \"$resource_id\", \"action\": \"read\"}"
    else
        echo -e "${YELLOW}No users or resources found. Run seed script first.${NC}"
    fi
    echo ""

    echo -e "${GREEN}=== Demo Complete ===${NC}"
}

# Example commands (comment out demo and uncomment these to run individually)

# # Get token as admin
# get_token_password "admin" "admin123"

# # Get token as regular user
# get_token_password "alice" "alice123"

# # Get token for service account
# get_token_client_credentials "abac-service" "abac-service-secret-change-in-production"

# # API calls after authentication
# api_call GET "/api/users"
# api_call GET "/api/resources"
# api_call GET "/api/policies"

# # Create a new user
# api_call POST "/api/users" '{"username": "newuser", "email": "new@example.com", "display_name": "New User"}'

# # Create a new resource
# api_call POST "/api/resources" '{"name": "New Document", "type": "document", "description": "A test document"}'

# # Set user attribute
# api_call PUT "/api/users/USER_ID/attributes/department" '{"value": "Engineering"}'

# # Check access
# api_call POST "/api/access/check" '{"user_id": "USER_ID", "resource_id": "RESOURCE_ID", "action": "read"}'

# # View audit log
# api_call GET "/api/access/audit?limit=10"

# Run demo by default
demo
