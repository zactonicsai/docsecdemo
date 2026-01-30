# ABAC/CBAC Access Control System - Complete Tutorial

## Table of Contents

1. [Introduction](#1-introduction)
2. [Key Concepts](#2-key-concepts)
3. [Authentication vs Authorization](#3-authentication-vs-authorization)
4. [How JWT Authentication Works](#4-how-jwt-authentication-works)
5. [How ABAC Authorization Works](#5-how-abac-authorization-works)
6. [The Policy Evaluation Engine](#6-the-policy-evaluation-engine)
7. [Protecting API Endpoints](#7-protecting-api-endpoints)
8. [Resource-Level Access Control](#8-resource-level-access-control)
9. [Cell-Level Access Control](#9-cell-level-access-control)
10. [Data Masking and Redaction](#10-data-masking-and-redaction)
11. [Full-Text Search with OpenSearch](#11-full-text-search-with-opensearch)
12. [Roles and Permissions](#12-roles-and-permissions)
13. [Real-World Examples](#13-real-world-examples)
14. [Architecture Deep Dive](#14-architecture-deep-dive)
15. [Security Best Practices](#15-security-best-practices)
16. [API Reference](#16-api-reference)
17. [Troubleshooting](#17-troubleshooting)

---

## 1. Introduction

### What is ABAC?

**Attribute-Based Access Control (ABAC)** is a security model that makes access decisions based on attributes (characteristics) of:

- **Users** (who is requesting access)
- **Resources** (what they want to access)
- **Actions** (what they want to do)
- **Environment** (contextual conditions)
- **Fields/Cells** (which specific data elements within a resource)

### What is CBAC?

**Claims-Based Access Control (CBAC)** is essentially the same concept, using the term "claims" instead of "attributes." In modern systems like OAuth2/OIDC, user attributes are often called "claims" because they are assertions about the user's identity.

### Why ABAC over RBAC?

Traditional **Role-Based Access Control (RBAC)** assigns permissions to roles:
```
Admin Role → Can do everything
User Role → Can read only
```

ABAC is more flexible and granular:
```
IF user.department = "engineering" 
AND user.clearance_level >= 3 
AND resource.classification <= "confidential"
AND time.hour BETWEEN 9 AND 17
THEN allow access
```

### The Four Levels of Access Control

This system provides **four levels** of access control:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    FOUR LEVELS OF ACCESS CONTROL                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Level 1: API ENDPOINT PROTECTION                                   │
│  ├── "Can this user call this API endpoint?"                        │
│  ├── Based on: JWT token validity + Keycloak roles                  │
│  └── Example: Only 'admin' role can call DELETE /api/users          │
│                                                                     │
│  Level 2: RESOURCE-LEVEL PROTECTION                                 │
│  ├── "Can this user access this specific resource?"                 │
│  ├── Based on: User attributes vs Resource attributes               │
│  └── Example: Engineering users can access engineering documents    │
│                                                                     │
│  Level 3: CELL/FIELD-LEVEL PROTECTION                               │
│  ├── "Which fields within this resource can the user see?"          │
│  ├── Based on: User attributes vs Field attributes                  │
│  ├── Effects: Allow / Deny / Mask / Redact                          │
│  └── Example: Only HR can see SSN; others see ***-**-1234           │
│                                                                     │
│  Level 4: SEARCH RESULT PROTECTION                                  │
│  ├── "Which fields in search results can the user see?"             │
│  ├── Based on: Same cell-level policies applied to search results   │
│  └── Example: Search returns documents but sensitive fields masked  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLIENT REQUEST                          │
│                    (with JWT Bearer Token)                      │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                          KEYCLOAK                               │
│              (Identity Provider / Auth Server)                  │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│   │    Users    │  │   Clients   │  │    Roles    │            │
│   │  Passwords  │  │   Secrets   │  │   Claims    │            │
│   └─────────────┘  └─────────────┘  └─────────────┘            │
└─────────────────────────────────────────────────────────────────┘
                                │
                                │ JWT Token (signed)
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                        ABAC API SERVER                          │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │           Level 1: Authentication Layer                   │  │
│  │            (JWT Validation via JWKS)                      │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              │                                  │
│                              ▼                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │           Level 2: Resource Authorization                 │  │
│  │     (Can this user access this resource at all?)          │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              │                                  │
│                              ▼                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │           Level 3: Cell/Field Authorization               │  │
│  │     (Which fields can the user see? Mask/Redact?)         │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              │                                  │
│              ┌───────────────┴───────────────┐                  │
│              ▼                               ▼                  │
│  ┌─────────────────────┐         ┌─────────────────────┐       │
│  │      Database       │         │     OpenSearch      │       │
│  │  (SQLite/sql.js)    │         │  (Full-text search) │       │
│  │  Users, Resources,  │         │  Documents with     │       │
│  │  Policies, Data     │         │  field protection   │       │
│  └─────────────────────┘         └─────────────────────┘       │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Key Concepts

### 2.1 Core Terminology

| Term | Definition | Example |
|------|------------|---------|
| **Subject** | The entity requesting access (usually a user) | Alice, Service Account |
| **Resource** | The object being accessed | Document, Database, API |
| **Action** | The operation being performed | read, write, delete |
| **Attribute** | A property of a subject, resource, or environment | department=engineering |
| **Claim** | Same as attribute (OAuth2/OIDC terminology) | role=admin |
| **Policy** | A rule that grants or denies access | "Engineers can read engineering docs" |
| **Effect** | The result of a policy | allow, deny, mask, redact |
| **Field** | A column or property within a resource | ssn, salary, email |
| **Cell** | A specific value at the intersection of row and field | John's SSN |

### 2.2 Attributes

Attributes are key-value pairs that describe characteristics:

```javascript
// User Attributes - WHO is requesting access
{
  "department": "engineering",
  "role": "senior_engineer",
  "clearance_level": "3",
  "team": "backend",
  "location": "US",
  "user_type": "internal"       // internal vs external
}

// Resource Attributes - WHAT is being accessed
{
  "type": "document",
  "classification": "confidential",
  "department": "engineering",
  "owner": "alice"
}

// Field Attributes - WHICH data element (for cell-level)
{
  "sensitivity": "high",         // low, medium, high
  "pii": "true",                 // personally identifiable information
  "data_classification": "confidential",
  "field_type": "ssn"            // for auto-masking
}

// Environment Attributes - WHEN/WHERE/HOW
{
  "time": "14:30",
  "ip_address": "192.168.1.100",
  "day_of_week": "monday",
  "is_business_hours": "true"
}
```

### 2.3 Policies

A policy is a rule that defines access:

| Component | Description | Example |
|-----------|-------------|---------|
| **Name** | Descriptive identifier | "Engineering Read Access" |
| **Effect** | What happens when matched | `allow`, `deny`, `mask`, `redact` |
| **Conditions** | Rules that must ALL match | user.department = "engineering" |
| **Priority** | Order of evaluation (higher = first) | `100` |
| **Active** | Is the policy enabled? | `true` |
| **Field Pattern** | (Cell-level) Which fields to match | `ssn`, `salary.*` |

### 2.4 Conditions

Conditions are the building blocks of policies:

```javascript
{
  "subject_type": "user",         // What to check: user, resource, field, environment, action
  "attribute_name": "department", // Which attribute
  "operator": "equals",           // How to compare
  "value": "engineering"          // Expected value
}
```

### 2.5 Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `equals` | Exact match | `department equals "engineering"` |
| `not_equals` | Not equal | `status not_equals "disabled"` |
| `contains` | String contains | `email contains "@company.com"` |
| `in` | Value in comma-separated list | `role in "admin,manager"` |
| `greater_than` | Numeric > | `clearance_level greater_than 2` |
| `less_than` | Numeric < | `classification less_than 3` |
| `matches` | Regex pattern | `email matches ".*@company\\.com"` |

### 2.6 Policy Effects

#### Resource-Level Effects

| Effect | Description |
|--------|-------------|
| `allow` | Grants access to the entire resource |
| `deny` | Blocks access to the entire resource |

#### Cell/Field-Level Effects

| Effect | Description | Example Output |
|--------|-------------|----------------|
| `allow` | Full access to field value | `123-45-6789` |
| `deny` | Field removed from response | *(field not present)* |
| `mask` | Partial data based on field type | `***-**-6789` |
| `redact` | Replace with placeholder | `***CONFIDENTIAL***` |

### 2.7 Subject Types

| Subject Type | What it Checks | Example Use |
|--------------|----------------|-------------|
| `user` | Attributes of the requesting user | `user.department = "hr"` |
| `resource` | Attributes of the target resource | `resource.classification <= 2` |
| `field` | Attributes of a specific field (cell-level) | `field.sensitivity = "high"` |
| `environment` | Contextual/environmental factors | `environment.is_business_hours = true` |
| `action` | The operation being requested | `action IN "read,list"` |

---

## 3. Authentication vs Authorization

### Authentication (AuthN) - "Who are you?"

Handled by **Keycloak**:
- User provides credentials (username/password)
- Keycloak validates and issues JWT token
- Token contains identity and roles

### Authorization (AuthZ) - "What can you do?"

Handled by **ABAC system** at three levels:

```
Level 1 - API Access:
  "Can this user call this API endpoint?"
  → Check JWT validity and roles

Level 2 - Resource Access:
  "Can this user access this specific resource?"
  → Check user attributes vs resource attributes

Level 3 - Cell Access:
  "Which fields can this user see?"
  → Check user attributes vs field attributes
  → Apply masking/redaction as needed
```

---

## 4. How JWT Authentication Works

### 4.1 JWT Structure

```
HEADER.PAYLOAD.SIGNATURE

Header: { "alg": "RS256", "typ": "JWT" }
Payload: { 
  "sub": "user-id",
  "preferred_username": "alice",
  "realm_access": { "roles": ["user"] },
  "department": "engineering",
  "clearance_level": 3,
  "exp": 1704070800
}
Signature: (cryptographic proof)
```

### 4.2 Validation Process

1. Extract token from `Authorization: Bearer <token>` header
2. Fetch Keycloak's public key via JWKS endpoint
3. Verify signature using public key
4. Validate issuer, expiration, and other claims
5. Attach decoded user info to request

---

## 5. How ABAC Authorization Works

### 5.1 Context Building

```javascript
const context = {
  user: { department: "engineering", clearance_level: "3" },
  resource: { department: "engineering", classification: "2" },
  field: { sensitivity: "high", pii: "true" },  // For cell-level
  action: "read",
  environment: { time: "14:30", business_hours: "true" }
};
```

### 5.2 Policy Evaluation

For each policy (sorted by priority):
1. Check if all conditions match the context
2. If matched and effect is `deny` → return DENY immediately
3. If matched and effect is `allow` → mark as allowed, continue checking
4. After all policies: if any allow and no deny → ALLOW

---

## 6. The Policy Evaluation Engine

### 6.1 Deny-Overrides Algorithm

```
┌─────────────────────────────────────────────────────────────┐
│                    POLICY DECISIONS                         │
├──────────────────┬──────────────────┬───────────────────────┤
│  Allow Policies  │  Deny Policies   │  Final Decision       │
├──────────────────┼──────────────────┼───────────────────────┤
│  0 match         │  0 match         │  DENY (default)       │
│  1+ match        │  0 match         │  ALLOW                │
│  0 match         │  1+ match        │  DENY                 │
│  1+ match        │  1+ match        │  DENY (deny wins)     │
└──────────────────┴──────────────────┴───────────────────────┘
```

### 6.2 Policy Priority

Higher priority policies are evaluated first. Use high priority for:
- Emergency lockdowns
- Admin overrides
- Security-critical deny policies

---

## 7. Protecting API Endpoints

### 7.1 Middleware Chain

```javascript
// Authentication (JWT validation)
app.use('/api/*', authenticate);

// Role-based protection
app.use('/api/policies', requireRole(['admin', 'policy-manager']));
app.use('/api/access/audit', requireRole(['admin', 'auditor']));
```

### 7.2 Endpoint Protection Matrix

| Endpoint | Auth | Role Required |
|----------|------|---------------|
| `GET /health` | ❌ | None |
| `GET /api/users` | ✅ | Any authenticated |
| `POST /api/policies` | ✅ | admin, policy-manager |
| `GET /api/cells/*/data` | ✅ | Any (cell filtering applied) |

---

## 8. Resource-Level Access Control

### 8.1 What It Controls

Resource-level protection determines if a user can access an **entire resource** (document, record, file).

### 8.2 Example Policy

```javascript
{
  name: "Engineers access engineering docs",
  effect: "allow",
  conditions: [
    { subject_type: "user", attribute_name: "department", operator: "equals", value: "engineering" },
    { subject_type: "resource", attribute_name: "department", operator: "equals", value: "engineering" }
  ]
}
```

---

## 9. Cell-Level Access Control

### 9.1 What It Controls

Cell-level protection determines **which fields** within a resource a user can see, and **how** they see them (full, masked, or redacted).

### 9.2 Why Cell-Level Control?

Consider an employee database. Different users need different views:

| User | emp_id | name | email | ssn | salary |
|------|--------|------|-------|-----|--------|
| HR Manager | ✓ | ✓ | ✓ | ✓ | ✓ |
| Manager | ✓ | ✓ | ✓ | ***-**-1234 | Range |
| Employee | ✓ | ✓ | masked | hidden | hidden |
| External | ✓ | hidden | hidden | hidden | hidden |

**Without cell-level control**: Create separate tables/views for each access level.
**With cell-level control**: One table, automatic filtering per user.

### 9.3 Data Model

```
┌─────────────────────────────────────────────────────────────────┐
│  RESOURCES           RESOURCE_FIELDS          FIELD_ATTRIBUTES  │
│  ───────────         ───────────────          ────────────────  │
│  id, name, type  →   id, field_name,    →    field_id,          │
│                      field_type               attribute_name,   │
│                                               attribute_value   │
│                                                                 │
│                      Examples:                Examples:         │
│                      - ssn (type: ssn)        - sensitivity:high│
│                      - email (type: email)    - pii: true       │
│                      - salary (type: salary)  - classification: │
│                                                 confidential    │
└─────────────────────────────────────────────────────────────────┘
```

### 9.4 Field Attributes

| Attribute | Values | Purpose |
|-----------|--------|---------|
| `sensitivity` | low, medium, high | Data sensitivity level |
| `pii` | true, false | Personally Identifiable Information flag |
| `data_classification` | public, internal, confidential, restricted | Security classification |
| `field_type` | ssn, email, phone, credit_card, salary | For automatic masking |

### 9.5 Cell-Level Policy Effects

| Effect | What Happens | When to Use |
|--------|--------------|-------------|
| `allow` | Show original value | Non-sensitive fields, authorized users |
| `deny` | Remove field entirely | External users, unauthorized access |
| `mask` | Show partial data | Medium authorization level |
| `redact` | Replace with placeholder | Complete hiding without removal |

### 9.6 Cell-Level Policy Example

```javascript
{
  name: "Mask SSN for non-HR users",
  effect: "mask",
  field_pattern: "ssn",       // Only applies to SSN field
  priority: 25,
  conditions: [
    { subject_type: "user", attribute_name: "department", operator: "not_equals", value: "hr" }
  ]
}
```

### 9.7 Cell-Level Evaluation Flow

```
For each field in the resource:
  1. Load field attributes (sensitivity, pii, etc.)
  2. Build context (user + resource + field + environment + action)
  3. Evaluate field policies (sorted by priority)
  4. Apply first matching effect:
     - DENY → remove field from response
     - REDACT → replace with placeholder
     - MASK → apply type-specific masking
     - ALLOW → include original value
  5. Log access decision
```

### 9.8 API Usage Example

```bash
# Get employee data with cell-level filtering
curl "http://localhost:3000/api/cells/resources/$RESOURCE_ID/data?user_id=$USER_ID" \
  -H "Authorization: Bearer $TOKEN"

# Response for non-HR user:
{
  "rows": [{
    "employee_id": "EMP001",
    "name": "John Smith",
    "email": "****@company.com",      // masked
    "ssn": "***-**-6789",             // masked
    "salary": "***CONFIDENTIAL***",   // redacted
    "_accessControl": {
      "employee_id": "allow",
      "name": "allow",
      "email": "mask",
      "ssn": "mask",
      "salary": "redact"
    }
  }]
}
```

---

## 10. Data Masking and Redaction

### 10.1 Masking vs Redaction

| Technique | Description | Use Case |
|-----------|-------------|----------|
| **Masking** | Partially hide data | User needs to verify/identify |
| **Redaction** | Complete replacement | User shouldn't see any part |

### 10.2 Auto-Masking by Field Type

| Field Type | Original | Masked Output |
|------------|----------|---------------|
| `ssn` | `123-45-6789` | `***-**-6789` |
| `credit_card` | `4111111111111234` | `****-****-****-1234` |
| `phone` | `555-123-4567` | `(***) ***-4567` |
| `email` | `john@company.com` | `****@company.com` |
| `salary` | `85000` | `$***,*** (50k-100k)` |

### 10.3 Custom Masking

```javascript
{
  name: "Custom salary mask",
  effect: "mask",
  mask_value: "Salary hidden - contact HR",  // Custom text
  field_pattern: "salary",
  conditions: [...]
}
```

---

## 11. OpenSearch Integration

### 11.1 Overview

OpenSearch provides full-text search capabilities while respecting cell-level access control. When you search for documents, the results are automatically filtered based on your user attributes - sensitive fields may be masked, redacted, or completely hidden.

```
┌─────────────────────────────────────────────────────────────────┐
│                  SEARCH WITH FIELD PROTECTION                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. User searches: "security architecture"                      │
│                                                                 │
│  2. OpenSearch finds matching documents                         │
│                                                                 │
│  3. For each document, cell-level filtering is applied:         │
│     - title: allow (low sensitivity)                            │
│     - content: allow (low sensitivity)                          │
│     - confidential_notes: mask (high sensitivity, user L3)      │
│     - financial_data: redact (non-finance user)                 │
│     - pii_data: deny (non-HR user)                              │
│                                                                 │
│  4. Filtered results returned to user                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 11.2 Document Structure

Documents in OpenSearch have both public and protected fields:

| Field | Sensitivity | Description |
|-------|-------------|-------------|
| `title` | low | Document title (searchable) |
| `content` | low | Main content (searchable) |
| `summary` | low | Document summary |
| `author` | low | Document author |
| `department` | low | Owning department |
| `classification` | low | public, internal, confidential, restricted |
| `tags` | low | Document tags |
| `confidential_notes` | **high** | Internal confidential notes |
| `internal_comments` | **medium** | Team comments |
| `financial_data` | **high** | Financial information |
| `pii_data` | **high** | Personally identifiable information |

### 11.3 Sample Documents

The system includes 12 sample documents across departments:

| Department | Count | Example Documents |
|------------|-------|-------------------|
| Engineering | 3 | System Architecture, Database Migration Guide, Security Playbook |
| Finance | 2 | Q4 Financial Report, Compensation Guidelines |
| HR | 2 | Employee Handbook, Performance Review Guide |
| Product | 2 | Product Roadmap, Customer Research Report |
| Legal | 2 | Data Processing Agreement, IP Guidelines |
| Sales | 1 | Enterprise Sales Playbook |

### 11.4 Search API

```bash
# Basic search with cell-level filtering
curl -X POST "http://localhost:3000/api/search" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "security architecture",
    "user_id": "USER_UUID"
  }'
```

**Response:**
```json
{
  "query": "security architecture",
  "total": 2,
  "results": [
    {
      "_id": "doc-uuid",
      "_score": 5.234,
      "title": "System Architecture Overview",
      "content": "Our platform is built on...",
      "department": "engineering",
      "confidential_notes": "AWS account ID:... [MASKED - 45 chars hidden]",
      "financial_data": "***FINANCIAL DATA - FINANCE DEPT ONLY***",
      "_accessControl": {
        "title": "allow",
        "content": "allow",
        "confidential_notes": "mask",
        "financial_data": "redact",
        "pii_data": "deny"
      }
    }
  ],
  "filtered_fields": ["confidential_notes:mask", "financial_data:redact"]
}
```

### 11.5 Search with Filters

```bash
curl -X POST "http://localhost:3000/api/search" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "budget",
    "user_id": "USER_UUID",
    "filters": {
      "department": "finance",
      "classification": "confidential"
    },
    "size": 10
  }'
```

### 11.6 Aggregations (Faceted Search)

```bash
curl -X POST "http://localhost:3000/api/search/aggregations" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "policy", "user_id": "USER_UUID"}'
```

**Response:**
```json
{
  "total": 5,
  "aggregations": {
    "by_department": [
      { "key": "engineering", "doc_count": 3 },
      { "key": "hr", "doc_count": 2 }
    ],
    "by_classification": [
      { "key": "internal", "doc_count": 4 },
      { "key": "confidential", "doc_count": 1 }
    ]
  }
}
```

### 11.7 Field Visibility by User Type

| User Type | title | content | confidential_notes | financial_data | pii_data |
|-----------|-------|---------|-------------------|----------------|----------|
| Engineering (L3) | ✓ | ✓ | Masked | Redacted | Hidden |
| Finance (L3) | ✓ | ✓ | Masked | ✓ | Hidden |
| HR (L3) | ✓ | ✓ | Masked | Redacted | ✓ |
| Executive (L4+) | ✓ | ✓ | ✓ | Per dept | Per dept |
| Admin | ✓ | ✓ | ✓ | ✓ | ✓ |

### 11.8 Search Field Policies

```javascript
// Mask confidential notes for non-executives
{
  name: "Mask confidential notes",
  effect: "mask",
  field_pattern: "confidential_notes",
  priority: 40,
  conditions: [
    { subject_type: "user", attribute_name: "clearance_level", operator: "less_than", value: "4" }
  ]
}

// Redact financial data for non-finance
{
  name: "Redact financial data",
  effect: "redact",
  mask_value: "***FINANCIAL DATA - FINANCE DEPT ONLY***",
  field_pattern: "financial_data",
  priority: 50,
  conditions: [
    { subject_type: "user", attribute_name: "department", operator: "not_equals", value: "finance" }
  ]
}

// Deny PII to non-HR
{
  name: "Deny PII data",
  effect: "deny",
  field_pattern: "pii_data",
  priority: 60,
  conditions: [
    { subject_type: "user", attribute_name: "department", operator: "not_equals", value: "hr" }
  ]
}
```

### 11.9 Search Audit Logging

All searches are logged for compliance:

```json
{
  "user_id": "user-uuid",
  "query": "security architecture",
  "results_count": 2,
  "filtered_fields": ["confidential_notes:mask", "financial_data:redact"],
  "timestamp": "2024-01-15T10:30:00Z"
}
```

---

## 12. Roles and Permissions

### 12.1 Keycloak Roles (API Level)

| Role | Access |
|------|--------|
| `admin` | All endpoints |
| `policy-manager` | Policy management |
| `user-manager` | User management |
| `auditor` | Audit log access |
| `user` | Basic read access |

### 12.2 ABAC Attributes (Data Level)

| Attribute | Purpose |
|-----------|---------|
| `department` | Department-based access |
| `clearance_level` | Classification-based access |
| `role` | Job function permissions |
| `user_type` | Internal vs external users |

---

## 13. Real-World Examples

### 13.1 Healthcare (HIPAA)

```javascript
// Nurses see masked diagnosis
{ effect: "mask", field_pattern: "diagnosis",
  conditions: [{ subject_type: "user", attribute_name: "role", operator: "equals", value: "nurse" }] }

// Billing cannot see medical info
{ effect: "deny",
  conditions: [
    { subject_type: "user", attribute_name: "department", operator: "equals", value: "billing" },
    { subject_type: "field", attribute_name: "phi", operator: "equals", value: "true" }
  ] }
```

### 13.2 Financial Services

```javascript
// Traders see only their own trades
{ effect: "allow",
  conditions: [
    { subject_type: "resource", attribute_name: "trader_id", operator: "equals", value: "${user.id}" }
  ] }

// Chinese wall enforcement
{ effect: "deny", priority: 200,
  conditions: [
    { subject_type: "user", attribute_name: "restricted_securities", operator: "contains", value: "${resource.security_id}" }
  ] }
```

### 13.3 Multi-Tenant SaaS

```javascript
// Tenant isolation
{ effect: "deny", priority: 1000,
  conditions: [
    { subject_type: "user", attribute_name: "tenant_id", operator: "not_equals", value: "${resource.tenant_id}" }
  ] }
```

---

## 14. Architecture Deep Dive

### 14.1 Key Database Tables

**Resource-Level:**
- `users`, `user_attributes`
- `resources`, `resource_attributes`
- `policies`, `policy_conditions`

**Cell-Level:**
- `resource_fields` - Column definitions
- `field_attributes` - Security properties per field
- `resource_data` - Actual cell values
- `field_policies`, `field_policy_conditions`

**Audit:**
- `access_audit_log` - All access decisions

---

## 15. Security Best Practices

### 15.1 Policy Design

```javascript
// ✅ Start with default deny
{ name: "Default Deny", effect: "deny", priority: 0, conditions: [] }

// ✅ Use high-priority deny for sensitive fields
{ name: "Block SSN by default", effect: "deny", priority: 100, field_pattern: "ssn" }

// ✅ Specific allow policies with higher priority
{ name: "HR sees SSN", effect: "allow", priority: 110, field_pattern: "ssn",
  conditions: [{ subject_type: "user", attribute_name: "department", operator: "equals", value: "hr" }] }

// ❌ DON'T create overly broad allow policies
{ name: "Allow everything", effect: "allow", conditions: [] }  // DANGEROUS
```

### 15.2 Defense in Depth

```
Layer 1: Network (Firewall)
Layer 2: Transport (HTTPS)
Layer 3: Authentication (JWT)
Layer 4: API Authorization (Roles)
Layer 5: Resource Authorization (ABAC)
Layer 6: Cell Authorization (Field policies)
Layer 7: Search Result Filtering (OpenSearch)
Layer 8: Data Protection (Encryption)
Layer 9: Audit (Logging)
```

---

## 16. API Reference

### Resource-Level
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/access/check` | Check resource access |
| POST | `/api/access/evaluate` | Check and log |
| GET | `/api/access/audit` | View audit log |

### Cell-Level
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/cells/resources/:id/fields` | List fields |
| POST | `/api/cells/resources/:id/fields` | Create field |
| GET | `/api/cells/policies` | List field policies |
| POST | `/api/cells/policies` | Create field policy |
| GET | `/api/cells/resources/:id/data?user_id=X` | Get filtered data |
| POST | `/api/cells/access/check` | Check field access |

### Search (OpenSearch)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/search/health` | Check OpenSearch status |
| POST | `/api/search` | Full-text search with filtering |
| POST | `/api/search/aggregations` | Search with facets |
| GET | `/api/search/documents/:id?user_id=X` | Get document with filtering |
| POST | `/api/search/documents` | Index a document |
| POST | `/api/search/documents/bulk` | Bulk index documents |
| PUT | `/api/search/documents/:id` | Update document |
| DELETE | `/api/search/documents/:id` | Delete document |
| GET | `/api/search/stats` | Index statistics |

---

## 17. Troubleshooting

| Issue | Solution |
|-------|----------|
| 401 Unauthorized | Check JWT token presence and expiration |
| 403 Forbidden on endpoint | Verify user has required role |
| Resource access denied | Check user/resource attributes and policies |
| Field unexpectedly masked | Check field sensitivity and user clearance |
| Cell filtering not working | Ensure fields and field policies are defined |
| OpenSearch not available | Check if container is running: `docker-compose logs opensearch` |
| Search returns no results | Verify documents are indexed: `GET /api/search/stats` |
| Search fields not filtered | Check field policies exist for search document fields |

### Debug Endpoints

```bash
# Check token contents
curl -H "Authorization: Bearer $TOKEN" http://localhost:3000/api/token-info

# Check single field access
curl -X POST http://localhost:3000/api/cells/access/check \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"user_id":"...","resource_id":"...","field_id":"...","action":"read"}'

# View recent audit entries
curl -H "Authorization: Bearer $TOKEN" http://localhost:3000/api/access/audit?limit=10

# Check OpenSearch health
curl -H "Authorization: Bearer $TOKEN" http://localhost:3000/api/search/health

# Test search with filtering
curl -X POST http://localhost:3000/api/search \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "security", "user_id": "USER_UUID"}'
```

---

## Summary

This system provides **four-level access control**:

1. **API Level**: JWT + role-based endpoint protection
2. **Resource Level**: ABAC policies for entire resources
3. **Cell Level**: Field-level policies with masking/redaction
4. **Search Level**: Cell-level filtering on search results

**Key Features:**
- Flexible attribute-based policies
- Automatic data masking by field type
- Full-text search with field protection
- 12 sample documents with sensitive fields
- Complete audit trail
- Defense in depth architecture

**Components:**
- **Keycloak**: Authentication and role management
- **SQLite**: User, resource, policy, and cell data storage
- **OpenSearch**: Full-text search with field-level security
- **Express API**: RESTful endpoints with middleware protection
