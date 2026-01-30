# ABAC/CBAC Access Control System

A complete **Attribute-Based Access Control (ABAC)** / **Claims-Based Access Control (CBAC)** system with a RESTful API, built with Node.js, Express, SQLite, and **Keycloak** for authentication.

## 🎯 Overview

This system implements fine-grained access control based on attributes (claims) rather than traditional roles. Access decisions are made by evaluating policies that combine:

- **User Attributes**: Properties of the user (department, role, clearance level, etc.)
- **Resource Attributes**: Properties of the resource (type, classification, owner, etc.)
- **Environment Attributes**: Contextual factors (time, location, system state)
- **Action**: The operation being performed (create, read, update, delete)

### Security Features

- **OAuth2/OpenID Connect** authentication via Keycloak
- **JWT token validation** with automatic key rotation support (JWKS)
- **Role-based API access** control
- **Audit logging** of all access decisions

## 🚀 Quick Start

### Using Docker (Recommended)

```bash
# Start all services (Keycloak, PostgreSQL, ABAC API)
docker-compose up -d

# Wait for Keycloak to be ready (may take 1-2 minutes)
docker-compose logs -f keycloak

# Seed the ABAC database with example data
docker-compose run --rm seed

# View API logs
docker-compose logs -f abac-api
```

**Services will be available at:**
- **ABAC API**: http://localhost:3000
- **Keycloak Admin Console**: http://localhost:8080 (admin/admin)
- **Keycloak Realm**: http://localhost:8080/realms/abac-realm

### Development Mode (Auth Disabled)

```bash
# Run with authentication disabled for development
docker-compose --profile dev up abac-api-dev

# API available at http://localhost:3001 (no auth required)
```

### Local Development (Without Docker)

```bash
# Install dependencies
npm install

# Run with auth disabled
DISABLE_AUTH=true npm start

# In another terminal, seed the database
npm run seed

# Run API tests
npm test
```

## 🔐 Keycloak Authentication

### Pre-configured Realm

The system comes with a pre-configured Keycloak realm (`abac-realm`) that includes:

#### Clients

| Client ID | Type | Use Case |
|-----------|------|----------|
| `abac-api` | Bearer Only | API resource server |
| `abac-webapp` | Confidential | Web applications |
| `abac-service` | Service Account | Service-to-service auth |
| `abac-cli` | Public | CLI tools |

#### Sample Users

| Username | Password | Roles |
|----------|----------|-------|
| `admin` | `admin123` | admin, user |
| `alice` | `alice123` | policy-manager, user |
| `bob` | `bob123` | user-manager, user |
| `charlie` | `charlie123` | auditor, user |
| `viewer` | `viewer123` | user |

#### Roles

- `admin` - Full administrative access
- `policy-manager` - Can manage policies
- `user-manager` - Can manage users
- `resource-manager` - Can manage resources
- `auditor` - Read-only access to audit logs
- `user` - Basic user role

### Getting an Access Token

#### Password Grant (Users)

```bash
curl -X POST "http://localhost:8080/realms/abac-realm/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=abac-webapp" \
  -d "client_secret=abac-webapp-secret-change-in-production" \
  -d "username=admin" \
  -d "password=admin123"
```

#### Client Credentials (Services)

```bash
curl -X POST "http://localhost:8080/realms/abac-realm/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=abac-service" \
  -d "client_secret=abac-service-secret-change-in-production"
```

### Making Authenticated Requests

```bash
# Get token
TOKEN=$(curl -s -X POST "http://localhost:8080/realms/abac-realm/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=abac-webapp&client_secret=abac-webapp-secret-change-in-production&username=admin&password=admin123" \
  | jq -r '.access_token')

# Use token to call API
curl -H "Authorization: Bearer $TOKEN" http://localhost:3000/api/users
```

## 📦 Sample Clients

### Node.js Client

```javascript
const ABACClient = require('./clients/nodejs/client');

const client = new ABACClient({
  apiBaseUrl: 'http://localhost:3000',
  keycloakUrl: 'http://localhost:8080',
  realm: 'abac-realm',
  clientId: 'abac-webapp',
  clientSecret: 'abac-webapp-secret-change-in-production'
});

// Login
await client.loginWithPassword('admin', 'admin123');

// Use API
const users = await client.getUsers();
const access = await client.checkAccess(userId, resourceId, 'read');
```

### Python Client

```python
from clients.python.client import ABACClient

client = ABACClient(
    api_base_url="http://localhost:3000",
    keycloak_url="http://localhost:8080",
    realm="abac-realm",
    client_id="abac-webapp",
    client_secret="abac-webapp-secret-change-in-production"
)

# Login
client.login_with_password("admin", "admin123")

# Use API
users = client.get_users()
access = client.check_access(user_id, resource_id, "read")
```

### Curl Examples

```bash
# Run the example script
chmod +x clients/curl/examples.sh
./clients/curl/examples.sh
```

### Web Client

Open `clients/web/index.html` in a browser for an interactive testing interface.

## 📊 Database Schema

```
┌──────────────────┐     ┌─────────────────────┐
│      users       │     │   user_attributes   │
├──────────────────┤     ├─────────────────────┤
│ id (PK)          │────<│ user_id (FK)        │
│ username         │     │ attribute_name      │
│ email            │     │ attribute_value     │
│ created_at       │     └─────────────────────┘
└──────────────────┘

┌──────────────────┐     ┌─────────────────────┐
│    resources     │     │ resource_attributes │
├──────────────────┤     ├─────────────────────┤
│ id (PK)          │────<│ resource_id (FK)    │
│ name             │     │ attribute_name      │
│ type             │     │ attribute_value     │
│ created_at       │     └─────────────────────┘
└──────────────────┘

┌──────────────────┐     ┌─────────────────────┐
│    policies      │     │  policy_conditions  │
├──────────────────┤     ├─────────────────────┤
│ id (PK)          │────<│ policy_id (FK)      │
│ name             │     │ subject_type        │
│ description      │     │ attribute_name      │
│ effect           │     │ operator            │
│ priority         │     │ attribute_value     │
│ is_active        │     └─────────────────────┘
└──────────────────┘

┌─────────────────────┐
│  access_audit_log   │
├─────────────────────┤
│ user_id             │
│ resource_id         │
│ action              │
│ decision            │
│ policy_id           │
│ reason              │
│ timestamp           │
└─────────────────────┘
```

## 🔧 API Reference

### Users

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/users` | List all users with attributes |
| GET | `/api/users/:id` | Get a specific user |
| POST | `/api/users` | Create a new user |
| PUT | `/api/users/:id` | Update a user |
| DELETE | `/api/users/:id` | Delete a user |
| PUT | `/api/users/:id/attributes/:name` | Set a user attribute |
| DELETE | `/api/users/:id/attributes/:name` | Remove a user attribute |

### Resources

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/resources` | List all resources |
| GET | `/api/resources/:id` | Get a specific resource |
| POST | `/api/resources` | Create a new resource |
| PUT | `/api/resources/:id` | Update a resource |
| DELETE | `/api/resources/:id` | Delete a resource |
| PUT | `/api/resources/:id/attributes/:name` | Set a resource attribute |
| DELETE | `/api/resources/:id/attributes/:name` | Remove a resource attribute |

### Policies

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/policies` | List all policies |
| GET | `/api/policies/:id` | Get a specific policy |
| POST | `/api/policies` | Create a new policy |
| PUT | `/api/policies/:id` | Update a policy |
| DELETE | `/api/policies/:id` | Delete a policy |
| POST | `/api/policies/:id/conditions` | Add a condition |
| DELETE | `/api/policies/:id/conditions/:cid` | Remove a condition |
| PATCH | `/api/policies/:id/toggle` | Toggle active status |

### Access Control

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/access/check` | Check access (no logging) |
| POST | `/api/access/evaluate` | Evaluate and log decision |
| POST | `/api/access/batch-check` | Batch check multiple requests |
| GET | `/api/access/permissions/:uid/:rid` | Get all permissions |
| GET | `/api/access/audit` | View audit log |
| GET | `/api/access/audit/stats` | Get audit statistics |
| DELETE | `/api/access/audit` | Clear audit log |

## 📝 Example Usage

### Create a User with Attributes

```bash
curl -X POST http://localhost:3000/api/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "email": "john@company.com",
    "attributes": {
      "department": "engineering",
      "role": "developer",
      "clearance_level": "2",
      "team": "backend"
    }
  }'
```

### Create a Resource

```bash
curl -X POST http://localhost:3000/api/resources \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Project Specs",
    "type": "document",
    "attributes": {
      "department": "engineering",
      "classification": "internal",
      "sensitivity": "2"
    }
  }'
```

### Create a Policy

```bash
curl -X POST http://localhost:3000/api/policies \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Engineer Read Access",
    "description": "Engineers can read engineering documents",
    "effect": "allow",
    "priority": 10,
    "conditions": [
      {
        "subject_type": "user",
        "attribute_name": "department",
        "operator": "equals",
        "attribute_value": "engineering"
      },
      {
        "subject_type": "resource",
        "attribute_name": "department",
        "operator": "equals",
        "attribute_value": "engineering"
      },
      {
        "subject_type": "action",
        "attribute_name": "action",
        "operator": "equals",
        "attribute_value": "read"
      }
    ]
  }'
```

### Check Access

```bash
curl -X POST http://localhost:3000/api/access/check \
  -H "Content-Type: application/json" \
  -d '{
    "userId": "user-uuid-here",
    "resourceId": "resource-uuid-here",
    "action": "read"
  }'
```

### Get All Permissions

```bash
curl http://localhost:3000/api/access/permissions/{userId}/{resourceId}
```

## 🔐 Policy Evaluation Logic

The policy engine uses a **deny-overrides** algorithm:

1. Policies are evaluated in order of priority (highest first)
2. If any matching policy has `effect: "deny"` → **Access Denied**
3. If at least one policy has `effect: "allow"` and none deny → **Access Allowed**
4. If no policies match → **Default Deny**

### Condition Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `equals` | Exact match (case-insensitive) | `role equals admin` |
| `not_equals` | Not equal to value | `status not_equals inactive` |
| `contains` | String contains | `email contains @company.com` |
| `in` | Value in comma-separated list | `action in read,update` |
| `greater_than` | Numeric greater than | `clearance_level greater_than 3` |
| `less_than` | Numeric less than | `sensitivity less_than 5` |
| `matches` | Regex match | `email matches .*@admin\.com` |

### Subject Types

- `user` - Matches against user attributes
- `resource` - Matches against resource attributes
- `environment` - Matches against environment attributes
- `action` - Matches the action being performed (create/read/update/delete)

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      Client                              │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                   Express API                            │
│  ┌─────────┐ ┌───────────┐ ┌──────────┐ ┌────────────┐  │
│  │ Users   │ │ Resources │ │ Policies │ │  Access    │  │
│  │ Router  │ │  Router   │ │  Router  │ │  Router    │  │
│  └─────────┘ └───────────┘ └──────────┘ └────────────┘  │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                  Policy Engine                           │
│  ┌────────────────────────────────────────────────────┐ │
│  │ 1. Load user attributes                            │ │
│  │ 2. Load resource attributes                        │ │
│  │ 3. Get environment context                         │ │
│  │ 4. Evaluate policies by priority                   │ │
│  │ 5. Return decision with audit logging              │ │
│  └────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                SQLite Database                           │
│  ┌─────────┐ ┌───────────┐ ┌──────────┐ ┌────────────┐  │
│  │ Users   │ │ Resources │ │ Policies │ │   Audit    │  │
│  │+ Attrs  │ │ + Attrs   │ │+ Conds   │ │    Log     │  │
│  └─────────┘ └───────────┘ └──────────┘ └────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## 🐳 Docker Commands

```bash
# Build image
docker build -t abac-system .

# Run container
docker run -d -p 3000:3000 -v abac-data:/app/data abac-system

# Run with docker-compose
docker-compose up -d

# Seed database
docker-compose run --rm seed

# View logs
docker-compose logs -f

# Stop
docker-compose down

# Stop and remove volumes
docker-compose down -v
```

## 📁 Project Structure

```
abac-system/
├── src/
│   ├── index.js          # Main application entry
│   ├── database.js       # Database schema and initialization
│   ├── policy-engine.js  # Policy evaluation engine
│   ├── seed.js          # Database seeding script
│   ├── test-api.js      # API test script
│   └── routes/
│       ├── users.js     # User CRUD routes
│       ├── resources.js # Resource CRUD routes
│       ├── policies.js  # Policy CRUD routes
│       └── access.js    # Access control routes
├── data/                # SQLite database (created at runtime)
├── package.json
├── Dockerfile
├── docker-compose.yml
└── README.md
```

## 🔒 Security Considerations

This is a demonstration system. For production use, consider:

1. **Authentication**: Add JWT or session-based auth
2. **HTTPS**: Use TLS in production
3. **Rate Limiting**: Protect against abuse
4. **Input Validation**: Sanitize all inputs
5. **Audit Log Security**: Protect audit logs from tampering
6. **Database Security**: Use proper credentials and encryption

## 📄 License

MIT License - Feel free to use and modify.
