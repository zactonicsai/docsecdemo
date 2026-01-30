#!/usr/bin/env python3
"""
ABAC API Client for Python

This sample client demonstrates how to authenticate with Keycloak
and make authenticated requests to the ABAC API.

Requirements:
    pip install requests
"""

import requests
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List


class ABACClient:
    """Client for interacting with the ABAC API"""

    def __init__(
        self,
        api_base_url: str = "http://localhost:3000",
        keycloak_url: str = "http://localhost:8080",
        realm: str = "abac-realm",
        client_id: str = "abac-webapp",
        client_secret: str = "abac-webapp-secret-change-in-production"
    ):
        self.api_base_url = api_base_url.rstrip('/')
        self.keycloak_url = keycloak_url.rstrip('/')
        self.realm = realm
        self.client_id = client_id
        self.client_secret = client_secret
        
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.token_expiry: Optional[datetime] = None
        
        # Session for connection pooling
        self.session = requests.Session()

    @property
    def token_endpoint(self) -> str:
        return f"{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/token"

    def login_with_password(self, username: str, password: str) -> Dict[str, Any]:
        """
        Authenticate with username and password (Resource Owner Password Grant)
        """
        data = {
            "grant_type": "password",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "username": username,
            "password": password
        }

        response = self.session.post(self.token_endpoint, data=data)
        
        if not response.ok:
            error = response.json()
            raise AuthenticationError(
                f"Authentication failed: {error.get('error_description', error.get('error'))}"
            )

        tokens = response.json()
        self._store_tokens(tokens)
        return tokens

    def login_with_client_credentials(self) -> Dict[str, Any]:
        """
        Authenticate with client credentials (for service accounts)
        """
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }

        response = self.session.post(self.token_endpoint, data=data)
        
        if not response.ok:
            error = response.json()
            raise AuthenticationError(
                f"Authentication failed: {error.get('error_description', error.get('error'))}"
            )

        tokens = response.json()
        self._store_tokens(tokens)
        return tokens

    def refresh_access_token(self) -> Dict[str, Any]:
        """
        Refresh the access token using the refresh token
        """
        if not self.refresh_token:
            raise AuthenticationError("No refresh token available")

        data = {
            "grant_type": "refresh_token",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "refresh_token": self.refresh_token
        }

        response = self.session.post(self.token_endpoint, data=data)
        
        if not response.ok:
            error = response.json()
            raise AuthenticationError(
                f"Token refresh failed: {error.get('error_description', error.get('error'))}"
            )

        tokens = response.json()
        self._store_tokens(tokens)
        return tokens

    def _store_tokens(self, tokens: Dict[str, Any]):
        """Store token data from response"""
        self.access_token = tokens.get("access_token")
        self.refresh_token = tokens.get("refresh_token")
        expires_in = tokens.get("expires_in", 300)
        self.token_expiry = datetime.now() + timedelta(seconds=expires_in)

    def _ensure_authenticated(self):
        """Ensure we have a valid access token, refreshing if necessary"""
        if not self.access_token:
            raise AuthenticationError("Not authenticated. Call login_with_password() or login_with_client_credentials() first.")
        
        # Refresh token if it expires within 30 seconds
        if self.token_expiry and datetime.now() >= self.token_expiry - timedelta(seconds=30):
            if self.refresh_token:
                self.refresh_access_token()
            else:
                raise AuthenticationError("Token expired and no refresh token available")

    def _request(self, method: str, path: str, json: Any = None) -> Dict[str, Any]:
        """Make an authenticated API request"""
        self._ensure_authenticated()
        
        url = f"{self.api_base_url}{path}"
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }

        response = self.session.request(method, url, headers=headers, json=json)
        data = response.json()

        if not response.ok:
            raise APIError(
                f"API request failed: {data.get('message', data.get('error'))}",
                status_code=response.status_code,
                response=data
            )

        return data

    # User Management
    def get_users(self) -> List[Dict[str, Any]]:
        """List all users"""
        return self._request("GET", "/api/users")

    def get_user(self, user_id: str) -> Dict[str, Any]:
        """Get a specific user"""
        return self._request("GET", f"/api/users/{user_id}")

    def create_user(self, username: str, email: str, display_name: Optional[str] = None) -> Dict[str, Any]:
        """Create a new user"""
        return self._request("POST", "/api/users", {
            "username": username,
            "email": email,
            "display_name": display_name or username
        })

    def update_user(self, user_id: str, **kwargs) -> Dict[str, Any]:
        """Update a user"""
        return self._request("PUT", f"/api/users/{user_id}", kwargs)

    def delete_user(self, user_id: str) -> Dict[str, Any]:
        """Delete a user"""
        return self._request("DELETE", f"/api/users/{user_id}")

    def set_user_attribute(self, user_id: str, attr_name: str, attr_value: str) -> Dict[str, Any]:
        """Set a user attribute"""
        return self._request("PUT", f"/api/users/{user_id}/attributes/{attr_name}", {
            "value": attr_value
        })

    def delete_user_attribute(self, user_id: str, attr_name: str) -> Dict[str, Any]:
        """Delete a user attribute"""
        return self._request("DELETE", f"/api/users/{user_id}/attributes/{attr_name}")

    # Resource Management
    def get_resources(self) -> List[Dict[str, Any]]:
        """List all resources"""
        return self._request("GET", "/api/resources")

    def get_resource(self, resource_id: str) -> Dict[str, Any]:
        """Get a specific resource"""
        return self._request("GET", f"/api/resources/{resource_id}")

    def create_resource(self, name: str, resource_type: str, description: Optional[str] = None) -> Dict[str, Any]:
        """Create a new resource"""
        return self._request("POST", "/api/resources", {
            "name": name,
            "type": resource_type,
            "description": description
        })

    def delete_resource(self, resource_id: str) -> Dict[str, Any]:
        """Delete a resource"""
        return self._request("DELETE", f"/api/resources/{resource_id}")

    def set_resource_attribute(self, resource_id: str, attr_name: str, attr_value: str) -> Dict[str, Any]:
        """Set a resource attribute"""
        return self._request("PUT", f"/api/resources/{resource_id}/attributes/{attr_name}", {
            "value": attr_value
        })

    # Policy Management
    def get_policies(self) -> List[Dict[str, Any]]:
        """List all policies"""
        return self._request("GET", "/api/policies")

    def get_policy(self, policy_id: str) -> Dict[str, Any]:
        """Get a specific policy"""
        return self._request("GET", f"/api/policies/{policy_id}")

    def create_policy(self, name: str, effect: str, description: Optional[str] = None, priority: int = 0) -> Dict[str, Any]:
        """Create a new policy"""
        return self._request("POST", "/api/policies", {
            "name": name,
            "effect": effect,
            "description": description,
            "priority": priority
        })

    def delete_policy(self, policy_id: str) -> Dict[str, Any]:
        """Delete a policy"""
        return self._request("DELETE", f"/api/policies/{policy_id}")

    def add_policy_condition(self, policy_id: str, subject_type: str, attribute_name: str, 
                            operator: str, value: str) -> Dict[str, Any]:
        """Add a condition to a policy"""
        return self._request("POST", f"/api/policies/{policy_id}/conditions", {
            "subject_type": subject_type,
            "attribute_name": attribute_name,
            "operator": operator,
            "value": value
        })

    def toggle_policy(self, policy_id: str) -> Dict[str, Any]:
        """Toggle policy active status"""
        return self._request("PATCH", f"/api/policies/{policy_id}/toggle")

    # Access Control
    def check_access(self, user_id: str, resource_id: str, action: str, 
                    environment: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Check access without logging"""
        return self._request("POST", "/api/access/check", {
            "user_id": user_id,
            "resource_id": resource_id,
            "action": action,
            "environment": environment or {}
        })

    def evaluate_access(self, user_id: str, resource_id: str, action: str,
                       environment: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Evaluate access with logging"""
        return self._request("POST", "/api/access/evaluate", {
            "user_id": user_id,
            "resource_id": resource_id,
            "action": action,
            "environment": environment or {}
        })

    def batch_check_access(self, requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check access for multiple requests"""
        return self._request("POST", "/api/access/batch-check", {"requests": requests})

    def get_permissions(self, user_id: str, resource_id: str) -> Dict[str, Any]:
        """Get all permissions for a user on a resource"""
        return self._request("GET", f"/api/access/permissions/{user_id}/{resource_id}")

    # Audit
    def get_audit_log(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Get audit log entries"""
        return self._request("GET", f"/api/access/audit?limit={limit}&offset={offset}")

    def get_audit_stats(self) -> Dict[str, Any]:
        """Get audit statistics"""
        return self._request("GET", "/api/access/audit/stats")

    def clear_audit_log(self) -> Dict[str, Any]:
        """Clear audit log"""
        return self._request("DELETE", "/api/access/audit")

    # Token Info
    def get_token_info(self) -> Dict[str, Any]:
        """Get information about the current token"""
        return self._request("GET", "/api/token-info")


class ABACError(Exception):
    """Base exception for ABAC client"""
    pass


class AuthenticationError(ABACError):
    """Authentication related errors"""
    pass


class APIError(ABACError):
    """API request errors"""
    def __init__(self, message: str, status_code: int = None, response: Dict = None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response


def main():
    """Demo script showing client usage"""
    print("=== ABAC API Python Client Demo ===\n")

    client = ABACClient(
        api_base_url="http://localhost:3000",
        keycloak_url="http://localhost:8080",
        realm="abac-realm",
        client_id="abac-webapp",
        client_secret="abac-webapp-secret-change-in-production"
    )

    try:
        # Login as admin
        print("1. Logging in as admin...")
        client.login_with_password("admin", "admin123")
        print("   Login successful!\n")

        # Get token info
        print("2. Getting token info...")
        token_info = client.get_token_info()
        print(f"   User: {token_info['user'].get('preferred_username')}")
        print(f"   Realm roles: {', '.join(token_info['roles']['realm'])}")
        print(f"   Client roles: {', '.join(token_info['roles']['client'])}\n")

        # List users
        print("3. Listing users...")
        users = client.get_users()
        print(f"   Found {len(users)} users:")
        for user in users[:3]:
            print(f"   - {user['username']} ({user.get('email', 'N/A')})")
        if len(users) > 3:
            print(f"   ... and {len(users) - 3} more\n")

        # List resources
        print("4. Listing resources...")
        resources = client.get_resources()
        print(f"   Found {len(resources)} resources:")
        for resource in resources[:3]:
            print(f"   - {resource['name']} ({resource.get('type', 'N/A')})")
        if len(resources) > 3:
            print(f"   ... and {len(resources) - 3} more\n")

        # Check access
        if users and resources:
            print("5. Checking access...")
            result = client.check_access(
                user_id=users[0]['id'],
                resource_id=resources[0]['id'],
                action='read'
            )
            allowed = "CAN" if result['allowed'] else "CANNOT"
            print(f"   User \"{users[0]['username']}\" {allowed} read \"{resources[0]['name']}\"")
            print(f"   Decision: {result['decision']}\n")

        print("=== Demo Complete ===")

    except AuthenticationError as e:
        print(f"Authentication error: {e}")
    except APIError as e:
        print(f"API error ({e.status_code}): {e}")
        if e.response:
            print(f"Response: {e.response}")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
