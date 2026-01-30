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
11. [Roles and Permissions](#11-roles-and-permissions)
12. [Real-World Examples](#12-real-world-examples)
13. [Architecture Deep Dive](#13-architecture-deep-dive)
14. [Security Best Practices](#14-security-best-practices)
15. [API Reference](#15-api-reference)
16. [Troubleshooting](#16-troubleshooting)

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

### The Three Levels of Access Control

This system provides **three levels** of access control:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    THREE LEVELS OF ACCESS CONTROL                   │
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
│                              ▼                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    Database                               │  │
│  │   Users │ Resources │ Fields │ Policies │ Data │ Audit    │  │
│  └──────────────────────────────────────────────────────────┘  │
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

## 11. Roles and Permissions

### 11.1 Keycloak Roles (API Level)

| Role | Access |
|------|--------|
| `admin` | All endpoints |
| `policy-manager` | Policy management |
| `user-manager` | User management |
| `auditor` | Audit log access |
| `user` | Basic read access |

### 11.2 ABAC Attributes (Data Level)

| Attribute | Purpose |
|-----------|---------|
| `department` | Department-based access |
| `clearance_level` | Classification-based access |
| `role` | Job function permissions |
| `user_type` | Internal vs external users |

---

## 12. Real-World Examples

### 12.1 Healthcare (HIPAA)

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

### 12.2 Financial Services

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

### 12.3 Multi-Tenant SaaS

```javascript
// Tenant isolation
{ effect: "deny", priority: 1000,
  conditions: [
    { subject_type: "user", attribute_name: "tenant_id", operator: "not_equals", value: "${resource.tenant_id}" }
  ] }
```

---

## 13. Architecture Deep Dive

### 13.1 Key Database Tables

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

## 14. Security Best Practices

### 14.1 Policy Design

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

### 14.2 Defense in Depth

```
Layer 1: Network (Firewall)
Layer 2: Transport (HTTPS)
Layer 3: Authentication (JWT)
Layer 4: API Authorization (Roles)
Layer 5: Resource Authorization (ABAC)
Layer 6: Cell Authorization (Field policies)
Layer 7: Data Protection (Encryption)
Layer 8: Audit (Logging)
```

---

## 15. API Reference

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

---

## 16. Troubleshooting

| Issue | Solution |
|-------|----------|
| 401 Unauthorized | Check JWT token presence and expiration |
| 403 Forbidden on endpoint | Verify user has required role |
| Resource access denied | Check user/resource attributes and policies |
| Field unexpectedly masked | Check field sensitivity and user clearance |
| Cell filtering not working | Ensure fields and field policies are defined |

### Debug Endpoints

```bash
# Check token contents
curl -H "Authorization: Bearer $TOKEN" http://localhost:3000/api/token-info

# Check single field access
curl -X POST http://localhost:3000/api/cells/access/check \
  -d '{"user_id":"...","resource_id":"...","field_id":"...","action":"read"}'

# View recent audit entries
curl http://localhost:3000/api/access/audit?limit=10
```

---

## Summary

This system provides **three-level access control**:

1. **API Level**: JWT + role-based endpoint protection
2. **Resource Level**: ABAC policies for entire resources
3. **Cell Level**: Field-level policies with masking/redaction

**Key Features:**
- Flexible attribute-based policies
- Automatic data masking by field type
- Complete audit trail
- Defense in depth architecture


# ABAC System - Key Concepts Reference

A quick reference guide for all key concepts in the ABAC/CBAC access control system.

---

## 1. Access Control Levels

### Level 1: API Endpoint Protection
**Question:** "Can this user call this API endpoint?"

| Component | Purpose |
|-----------|---------|
| JWT Token | Proves user identity |
| Keycloak Roles | Determines endpoint access |
| Middleware | Enforces authentication and role checks |

```
Request → JWT Validation → Role Check → Endpoint Access
```

### Level 2: Resource-Level Protection  
**Question:** "Can this user access this specific resource?"

| Component | Purpose |
|-----------|---------|
| User Attributes | Properties of the requester |
| Resource Attributes | Properties of the target |
| Resource Policies | Rules comparing user vs resource |

```
User Attributes + Resource Attributes → Policy Evaluation → Allow/Deny
```

### Level 3: Cell/Field-Level Protection
**Question:** "Which fields within this resource can the user see, and how?"

| Component | Purpose |
|-----------|---------|
| Field Definitions | Schema of resource columns |
| Field Attributes | Security properties per field |
| Field Policies | Rules for field visibility/masking |

```
User Attributes + Field Attributes → Field Policy Evaluation → Allow/Deny/Mask/Redact
```

---

## 2. Core Entities

### Users
The subjects requesting access.

```javascript
{
  id: "user-uuid",
  username: "alice",
  email: "alice@company.com",
  attributes: {
    department: "engineering",
    clearance_level: "3",
    role: "senior_engineer",
    user_type: "internal"
  }
}
```

### Resources
The objects being accessed.

```javascript
{
  id: "resource-uuid",
  name: "Employee Database",
  type: "database",
  attributes: {
    department: "hr",
    classification: "3",
    owner: "diana"
  }
}
```

### Fields (Cell-Level)
Individual columns within a resource.

```javascript
{
  id: "field-uuid",
  resource_id: "resource-uuid",
  field_name: "ssn",
  field_type: "ssn",        // For auto-masking
  attributes: {
    sensitivity: "high",
    pii: "true",
    data_classification: "confidential"
  }
}
```

### Policies
Rules that determine access.

```javascript
// Resource-level policy
{
  id: "policy-uuid",
  name: "Engineering Document Access",
  effect: "allow",          // allow or deny
  priority: 10,
  is_active: true,
  conditions: [...]
}

// Field-level policy
{
  id: "field-policy-uuid",
  name: "Mask SSN for non-HR",
  effect: "mask",           // allow, deny, mask, redact
  mask_value: null,         // null = auto-mask by type
  field_pattern: "ssn",     // regex to match field names
  resource_type: null,      // optional: limit to resource type
  priority: 25,
  conditions: [...]
}
```

### Conditions
Building blocks of policies.

```javascript
{
  subject_type: "user",       // user, resource, field, environment, action
  attribute_name: "department",
  operator: "equals",         // equals, not_equals, contains, in, greater_than, less_than, matches
  value: "engineering"
}
```

---

## 3. Attributes Reference

### User Attributes

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `department` | string | User's department | "engineering", "hr", "finance" |
| `clearance_level` | number | Security clearance level | 1, 2, 3, 4, 5 |
| `role` | string | Job role | "senior_engineer", "hr_manager" |
| `user_type` | string | Type of user | "internal", "external", "contractor" |
| `team` | string | Team membership | "backend", "frontend" |
| `location` | string | Geographic location | "US", "EU", "APAC" |
| `projects` | list | Project access | "projectA,projectB" |

### Resource Attributes

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `type` | string | Resource type | "document", "database", "api" |
| `department` | string | Owning department | "engineering", "hr" |
| `classification` | number | Security classification | 1 (public) to 5 (top secret) |
| `owner` | string | Resource owner | "alice", "bob" |
| `project` | string | Associated project | "projectA" |

### Field Attributes (Cell-Level)

| Attribute | Values | Description |
|-----------|--------|-------------|
| `sensitivity` | low, medium, high | Data sensitivity level |
| `pii` | true, false | Personally Identifiable Information |
| `phi` | true, false | Protected Health Information (HIPAA) |
| `data_classification` | public, internal, confidential, restricted | Data classification |
| `field_type` | ssn, email, phone, credit_card, salary, date | For automatic masking |

### Environment Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `time` | string | Current time (HH:MM) |
| `day_of_week` | string | Day name |
| `is_business_hours` | boolean | Within business hours |
| `ip_address` | string | Client IP address |
| `maintenance_mode` | boolean | System in maintenance |

---

## 4. Operators Reference

| Operator | Description | Example Condition | Matches |
|----------|-------------|-------------------|---------|
| `equals` | Exact match | `department equals "hr"` | department = "hr" |
| `not_equals` | Not equal | `status not_equals "disabled"` | status ≠ "disabled" |
| `contains` | String contains | `email contains "@company"` | "john@company.com" |
| `in` | Value in list | `role in "admin,manager"` | role = "admin" OR "manager" |
| `greater_than` | Numeric > | `clearance greater_than 2` | clearance > 2 |
| `less_than` | Numeric < | `classification less_than 3` | classification < 3 |
| `matches` | Regex match | `email matches ".*@company\\.com"` | Regex pattern |

---

## 5. Policy Effects Reference

### Resource-Level Effects

| Effect | Description | HTTP Result |
|--------|-------------|-------------|
| `allow` | Grant access | 200 OK with data |
| `deny` | Block access | 403 Forbidden |

### Field-Level Effects

| Effect | Description | Field Result |
|--------|-------------|--------------|
| `allow` | Show full value | `"123-45-6789"` |
| `deny` | Remove from response | *(field absent)* |
| `mask` | Partial visibility | `"***-**-6789"` |
| `redact` | Replace with placeholder | `"***CONFIDENTIAL***"` |

---

## 6. Auto-Masking by Field Type

When `effect: "mask"` is applied, the system auto-masks based on `field_type`:

| Field Type | Original Value | Masked Output | Logic |
|------------|----------------|---------------|-------|
| `ssn` | `123-45-6789` | `***-**-6789` | Show last 4 |
| `credit_card` | `4111111111111234` | `****-****-****-1234` | Show last 4 |
| `phone` | `555-123-4567` | `(***) ***-4567` | Show last 4 |
| `email` | `john.smith@company.com` | `****@company.com` | Show domain |
| `salary` | `85000` | `$***,*** (50k-100k)` | Show range |
| `date` | `1990-05-15` | `****-**-15` | Show day |
| *(default)* | `SecretData123` | `S*****3` | First/last char |

---

## 7. Subject Types Reference

Used in policy conditions to specify what to check:

| Subject Type | Checks Against | Example Attributes |
|--------------|----------------|-------------------|
| `user` | Requesting user's attributes | department, clearance_level, role |
| `resource` | Target resource's attributes | type, classification, owner |
| `field` | Specific field's attributes | sensitivity, pii, field_type |
| `environment` | Environmental context | time, ip_address, business_hours |
| `action` | Requested operation | read, write, delete |

---

## 8. Policy Evaluation Algorithm

### Deny-Overrides (Resource & Field Level)

```
1. Sort policies by priority (highest first)
2. For each policy:
   a. Check if ALL conditions match
   b. If matched:
      - If effect = DENY → Return DENY immediately
      - If effect = REDACT → Return REDACT immediately (field-level)
      - If effect = MASK → Store as result, continue checking (field-level)
      - If effect = ALLOW → Store as result, continue checking
3. After all policies:
   - If any DENY matched → DENY
   - If MASK matched (no deny) → MASK
   - If ALLOW matched (no deny/mask) → ALLOW
   - If nothing matched → DENY (default)
```

### Priority Guidelines

| Priority Range | Use Case |
|----------------|----------|
| 0 | Default deny policy |
| 1-50 | Standard allow policies |
| 51-100 | Restrictive/sensitive data policies |
| 100+ | Emergency/override policies |
| 200+ | Security lockdown policies |

---

## 9. Cell-Level Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     CELL-LEVEL DATA FLOW                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Request: GET /api/cells/resources/{id}/data?user_id={uid}   │
│                                                                 │
│  2. Load user attributes from database                          │
│     { department: "engineering", clearance_level: 3, ... }      │
│                                                                 │
│  3. Load resource and its fields                                │
│     Resource: { type: "database", department: "hr" }            │
│     Fields: [ {name: "ssn", sensitivity: "high"}, ... ]         │
│                                                                 │
│  4. For each field, evaluate field policies:                    │
│     ┌─────────────────────────────────────────────────┐        │
│     │  Field: ssn                                      │        │
│     │  Field attrs: { sensitivity: high, pii: true }   │        │
│     │                                                  │        │
│     │  Policy: "Mask high sensitivity for non-HR"      │        │
│     │  Conditions:                                     │        │
│     │    - field.sensitivity = "high" ✓               │        │
│     │    - user.department != "hr" ✓                  │        │
│     │  Effect: MASK                                    │        │
│     │                                                  │        │
│     │  Result: Apply SSN masking → "***-**-6789"      │        │
│     └─────────────────────────────────────────────────┘        │
│                                                                 │
│  5. Build filtered response:                                    │
│     {                                                           │
│       "rows": [{                                                │
│         "employee_id": "EMP001",        // allowed              │
│         "name": "John Smith",           // allowed              │
│         "ssn": "***-**-6789",           // masked               │
│         "salary": "***CONFIDENTIAL***", // redacted             │
│         "_accessControl": {                                     │
│           "employee_id": "allow",                               │
│           "name": "allow",                                      │
│           "ssn": "mask",                                        │
│           "salary": "redact"                                    │
│         }                                                       │
│       }]                                                        │
│     }                                                           │
│                                                                 │
│  6. Log access decisions to audit table                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 10. Common Policy Patterns

### Pattern 1: Department-Based Isolation
```javascript
// Users can only access resources in their department
{
  name: "Department Isolation",
  effect: "allow",
  conditions: [
    { subject_type: "user", attribute_name: "department", 
      operator: "equals", value: "${resource.department}" }
  ]
}
```

### Pattern 2: Clearance-Based Access
```javascript
// User clearance must meet or exceed resource classification
{
  name: "Clearance Check",
  effect: "deny",
  priority: 100,
  conditions: [
    { subject_type: "user", attribute_name: "clearance_level",
      operator: "less_than", value: "${resource.classification}" }
  ]
}
```

### Pattern 3: PII Protection
```javascript
// External users cannot see PII
{
  name: "Block PII for External",
  effect: "deny",
  priority: 200,
  conditions: [
    { subject_type: "field", attribute_name: "pii", operator: "equals", value: "true" },
    { subject_type: "user", attribute_name: "user_type", operator: "equals", value: "external" }
  ]
}
```

### Pattern 4: Sensitivity-Based Masking
```javascript
// Mask high-sensitivity fields for users with clearance < 4
{
  name: "Mask High Sensitivity",
  effect: "mask",
  priority: 50,
  conditions: [
    { subject_type: "field", attribute_name: "sensitivity", operator: "equals", value: "high" },
    { subject_type: "user", attribute_name: "clearance_level", operator: "less_than", value: "4" }
  ]
}
```

### Pattern 5: Role-Based Full Access
```javascript
// HR managers see everything in HR resources
{
  name: "HR Manager Full Access",
  effect: "allow",
  priority: 100,
  conditions: [
    { subject_type: "user", attribute_name: "role", operator: "equals", value: "hr_manager" },
    { subject_type: "resource", attribute_name: "department", operator: "equals", value: "hr" }
  ]
}
```

### Pattern 6: Time-Based Restrictions
```javascript
// Deny access outside business hours
{
  name: "Business Hours Only",
  effect: "deny",
  priority: 150,
  conditions: [
    { subject_type: "resource", attribute_name: "require_business_hours", operator: "equals", value: "true" },
    { subject_type: "environment", attribute_name: "is_business_hours", operator: "equals", value: "false" }
  ]
}
```

---

## 11. Quick Reference Cards

### JWT Token Structure
```
Header:   { alg: "RS256", typ: "JWT" }
Payload:  { sub, preferred_username, realm_access, exp, iat, iss, ... }
Signature: RSASHA256(header + "." + payload, privateKey)
```

### API Authentication
```bash
# Get token
TOKEN=$(curl -s -X POST "$KEYCLOAK/token" \
  -d "grant_type=password&client_id=...&username=...&password=..." \
  | jq -r '.access_token')

# Use token
curl -H "Authorization: Bearer $TOKEN" $API_URL/...
```

### Cell-Level API Flow
```bash
# 1. Define fields
POST /api/cells/resources/{id}/fields
{ "field_name": "ssn", "field_type": "ssn", "attributes": {"sensitivity": "high"} }

# 2. Create policies
POST /api/cells/policies
{ "name": "Mask SSN", "effect": "mask", "field_pattern": "ssn", "conditions": [...] }

# 3. Insert data
POST /api/cells/resources/{id}/data
{ "rows": [{ "ssn": "123-45-6789", ... }] }

# 4. Retrieve filtered data
GET /api/cells/resources/{id}/data?user_id={uid}
→ Returns data with masking applied based on user's attributes
```

---

## 12. Glossary

| Term | Definition |
|------|------------|
| **ABAC** | Attribute-Based Access Control |
| **CBAC** | Claims-Based Access Control |
| **RBAC** | Role-Based Access Control |
| **JWT** | JSON Web Token |
| **JWKS** | JSON Web Key Set (public keys for JWT verification) |
| **PII** | Personally Identifiable Information |
| **PHI** | Protected Health Information |
| **Cell** | A specific value at the intersection of a row and column |
| **Field** | A column definition in a resource |
| **Masking** | Partially hiding data while preserving some information |
| **Redaction** | Completely replacing data with a placeholder |
| **Subject** | The entity (user/service) requesting access |
| **Resource** | The object being accessed |
| **Policy** | A rule that determines access |
| **Condition** | A single test within a policy |
| **Effect** | The result when a policy matches (allow/deny/mask/redact) |

# Cell-Level Access Control Guide

A comprehensive guide to implementing and using cell-level (field-level) access control in the ABAC system.

---

## Overview

Cell-level access control allows you to protect individual **fields** (columns) within a resource, enabling different users to see different views of the same data.

### What Cell-Level Control Solves

**Without Cell-Level Control:**
```
Problem: Different users need different views of employee data
- HR needs: All fields
- Managers need: Names, emails, performance
- Employees need: Names only
- External auditors need: Anonymized data

Traditional Solution: Create separate tables/views for each access level
- employee_full (HR only)
- employee_manager (managers)
- employee_basic (all employees)
- employee_anonymous (external)

Issues: Data duplication, sync problems, maintenance nightmare
```

**With Cell-Level Control:**
```
Solution: Single data source with automatic per-field filtering

GET /api/cells/resources/employees/data?user_id=hr_manager
→ Returns all fields with full values

GET /api/cells/resources/employees/data?user_id=regular_employee  
→ Returns only allowed fields, sensitive data masked/removed

Benefits: Single source of truth, automatic enforcement, audit trail
```

---

## Data Model

### Schema Diagram

```
┌────────────────────┐         ┌─────────────────────┐
│     RESOURCES      │         │   RESOURCE_FIELDS   │
├────────────────────┤         ├─────────────────────┤
│ id (PK)            │────────<│ id (PK)             │
│ name               │         │ resource_id (FK)    │
│ type               │         │ field_name          │
│ created_at         │         │ field_type          │
└────────────────────┘         │ description         │
                               └──────────┬──────────┘
                                          │
                    ┌─────────────────────┴─────────────────────┐
                    │                                           │
                    ▼                                           ▼
        ┌─────────────────────┐                    ┌─────────────────────┐
        │  FIELD_ATTRIBUTES   │                    │    RESOURCE_DATA    │
        ├─────────────────────┤                    ├─────────────────────┤
        │ id (PK)             │                    │ id (PK)             │
        │ field_id (FK)       │                    │ resource_id (FK)    │
        │ attribute_name      │                    │ field_id (FK)       │
        │ attribute_value     │                    │ row_id              │
        └─────────────────────┘                    │ cell_value          │
                                                   └─────────────────────┘

┌─────────────────────┐         ┌──────────────────────────┐
│   FIELD_POLICIES    │         │ FIELD_POLICY_CONDITIONS  │
├─────────────────────┤         ├──────────────────────────┤
│ id (PK)             │────────<│ id (PK)                  │
│ name                │         │ policy_id (FK)           │
│ description         │         │ subject_type             │
│ effect              │         │ attribute_name           │
│ mask_value          │         │ operator                 │
│ field_pattern       │         │ attribute_value          │
│ resource_type       │         └──────────────────────────┘
│ priority            │
│ is_active           │
└─────────────────────┘
```

### Table Definitions

```sql
-- Fields define the structure (columns) of a resource
CREATE TABLE resource_fields (
    id TEXT PRIMARY KEY,
    resource_id TEXT NOT NULL REFERENCES resources(id),
    field_name TEXT NOT NULL,           -- Column name (e.g., 'ssn')
    field_type TEXT DEFAULT 'string',   -- For auto-masking: ssn, email, phone, etc.
    description TEXT,
    UNIQUE(resource_id, field_name)
);

-- Field attributes define security properties
CREATE TABLE field_attributes (
    id INTEGER PRIMARY KEY,
    field_id TEXT NOT NULL REFERENCES resource_fields(id),
    attribute_name TEXT NOT NULL,       -- 'sensitivity', 'pii', etc.
    attribute_value TEXT NOT NULL,      -- 'high', 'true', etc.
    UNIQUE(field_id, attribute_name)
);

-- Actual data stored in cells
CREATE TABLE resource_data (
    id INTEGER PRIMARY KEY,
    resource_id TEXT NOT NULL REFERENCES resources(id),
    field_id TEXT NOT NULL REFERENCES resource_fields(id),
    row_id TEXT NOT NULL,               -- Groups cells into rows
    cell_value TEXT,
    UNIQUE(resource_id, field_id, row_id)
);

-- Field-level policies
CREATE TABLE field_policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    effect TEXT NOT NULL CHECK(effect IN ('allow', 'deny', 'mask', 'redact')),
    mask_value TEXT,                    -- Custom mask text (null = auto-mask)
    field_pattern TEXT,                 -- Regex to match field names
    resource_type TEXT,                 -- Limit to specific resource types
    priority INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 1
);

-- Conditions for field policies
CREATE TABLE field_policy_conditions (
    id INTEGER PRIMARY KEY,
    policy_id TEXT NOT NULL REFERENCES field_policies(id),
    subject_type TEXT NOT NULL,         -- 'user', 'resource', 'field', 'environment', 'action'
    attribute_name TEXT NOT NULL,
    operator TEXT NOT NULL,
    attribute_value TEXT NOT NULL
);
```

---

## Field Types and Auto-Masking

### Supported Field Types

| Field Type | Description | Auto-Mask Pattern |
|------------|-------------|-------------------|
| `string` | Generic text (default) | `S*****g` (first/last char) |
| `ssn` | Social Security Number | `***-**-6789` |
| `credit_card` | Credit card number | `****-****-****-1234` |
| `phone` | Phone number | `(***) ***-4567` |
| `email` | Email address | `****@domain.com` |
| `salary` | Salary/currency | `$***,*** (range)` |
| `date` | Date | `****-**-15` |
| `number` | Numeric value | `***` |

### Masking Implementation

```javascript
function applyMask(value, fieldType, customMask) {
  // Custom mask takes precedence
  if (customMask) return customMask;
  
  const str = String(value);
  
  switch (fieldType) {
    case 'ssn':
      // Show last 4 digits
      return str.length >= 4 ? `***-**-${str.slice(-4)}` : '***-**-****';
    
    case 'credit_card':
      return str.length >= 4 ? `****-****-****-${str.slice(-4)}` : '****-****-****-****';
    
    case 'phone':
      return str.length >= 4 ? `(***) ***-${str.slice(-4)}` : '(***) ***-****';
    
    case 'email':
      const at = str.indexOf('@');
      return at > 0 ? `****${str.slice(at)}` : '****@****.***';
    
    case 'salary':
      const num = parseFloat(str.replace(/[^0-9.-]/g, ''));
      const range = num < 50000 ? '<50k' : num < 100000 ? '50k-100k' : '>100k';
      return `$***,*** (${range})`;
    
    default:
      // Generic: first and last character
      if (str.length <= 2) return '***';
      return `${str[0]}${'*'.repeat(5)}${str[str.length - 1]}`;
  }
}
```

---

## Field Attributes

### Standard Attributes

| Attribute | Type | Values | Description |
|-----------|------|--------|-------------|
| `sensitivity` | enum | low, medium, high | Data sensitivity level |
| `pii` | boolean | true, false | Personally Identifiable Information |
| `phi` | boolean | true, false | Protected Health Information |
| `pci` | boolean | true, false | Payment Card Industry data |
| `data_classification` | enum | public, internal, confidential, restricted | Classification level |
| `encryption_required` | boolean | true, false | Must be encrypted at rest |
| `audit_access` | boolean | true, false | Log all access |

### Setting Field Attributes

```bash
# Set sensitivity attribute
curl -X PUT "http://localhost:3000/api/cells/fields/$FIELD_ID/attributes/sensitivity" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"value": "high"}'

# Set PII flag
curl -X PUT "http://localhost:3000/api/cells/fields/$FIELD_ID/attributes/pii" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"value": "true"}'
```

---

## Field Policies

### Policy Structure

```javascript
{
  "id": "policy-uuid",
  "name": "Descriptive Name",
  "description": "What this policy does",
  
  // Effect when conditions match
  "effect": "mask",  // allow | deny | mask | redact
  
  // Custom mask text (null = auto-mask by field_type)
  "mask_value": "***HIDDEN***",
  
  // Target fields (regex pattern, null = all fields)
  "field_pattern": "^(ssn|social_security)$",
  
  // Target resource types (null = all types)
  "resource_type": "database",
  
  // Evaluation order (higher = first)
  "priority": 25,
  
  // Enable/disable
  "is_active": true,
  
  // Conditions (all must match)
  "conditions": [
    {
      "subject_type": "field",
      "attribute_name": "sensitivity",
      "operator": "equals",
      "value": "high"
    },
    {
      "subject_type": "user",
      "attribute_name": "department",
      "operator": "not_equals",
      "value": "hr"
    }
  ]
}
```

### Effect Types

| Effect | Behavior | Use Case |
|--------|----------|----------|
| `allow` | Return original value | Authorized users, non-sensitive fields |
| `deny` | Remove field from response | Unauthorized users, blocked content |
| `mask` | Partial data visibility | Verification needs, partial authorization |
| `redact` | Replace with placeholder | Complete hiding with indication |

### Policy Examples

#### 1. Allow Low-Sensitivity Fields to Everyone
```javascript
{
  "name": "Public Fields",
  "effect": "allow",
  "priority": 10,
  "conditions": [
    { "subject_type": "field", "attribute_name": "sensitivity", "operator": "equals", "value": "low" }
  ]
}
```

#### 2. Mask Medium-Sensitivity for Non-Department
```javascript
{
  "name": "Mask Medium Sensitivity",
  "effect": "mask",
  "priority": 20,
  "conditions": [
    { "subject_type": "field", "attribute_name": "sensitivity", "operator": "equals", "value": "medium" },
    { "subject_type": "user", "attribute_name": "department", "operator": "not_equals", "value": "${resource.department}" }
  ]
}
```

#### 3. Redact High-Sensitivity for Low Clearance
```javascript
{
  "name": "Redact High Sensitivity",
  "effect": "redact",
  "mask_value": "***ACCESS DENIED - CLEARANCE REQUIRED***",
  "priority": 30,
  "conditions": [
    { "subject_type": "field", "attribute_name": "sensitivity", "operator": "equals", "value": "high" },
    { "subject_type": "user", "attribute_name": "clearance_level", "operator": "less_than", "value": "3" }
  ]
}
```

#### 4. Deny PII to External Users
```javascript
{
  "name": "Block PII for External",
  "effect": "deny",
  "priority": 200,  // High priority
  "conditions": [
    { "subject_type": "field", "attribute_name": "pii", "operator": "equals", "value": "true" },
    { "subject_type": "user", "attribute_name": "user_type", "operator": "equals", "value": "external" }
  ]
}
```

#### 5. Full Access for Authorized Role
```javascript
{
  "name": "HR Manager Full Access",
  "effect": "allow",
  "priority": 100,
  "conditions": [
    { "subject_type": "user", "attribute_name": "role", "operator": "equals", "value": "hr_manager" },
    { "subject_type": "user", "attribute_name": "clearance_level", "operator": "greater_than", "value": "3" }
  ]
}
```

#### 6. Field Pattern Matching
```javascript
{
  "name": "Mask All Secret Fields",
  "effect": "mask",
  "field_pattern": ".*_(secret|private|confidential)$",  // Regex
  "priority": 50,
  "conditions": [
    { "subject_type": "user", "attribute_name": "role", "operator": "not_equals", "value": "admin" }
  ]
}
```

---

## Policy Evaluation

### Algorithm

```
For each field in the resource:

1. Get field attributes (sensitivity, pii, etc.)

2. Get applicable policies:
   - Active policies only
   - Match resource_type (if specified)
   - Match field_pattern (if specified)
   - Sort by priority DESC

3. Build evaluation context:
   {
     user: { department, clearance, role, ... },
     resource: { type, department, ... },
     field: { name, sensitivity, pii, ... },
     action: "read",
     environment: { time, ip, ... }
   }

4. For each policy (highest priority first):
   a. Check if ALL conditions match
   b. If matched:
      - DENY → return {effect: "deny"} immediately
      - REDACT → return {effect: "redact"} immediately
      - MASK → store result, continue checking for deny
      - ALLOW → store result if no mask yet, continue

5. Return final result:
   - If deny found → deny
   - If redact found → redact
   - If mask found → mask
   - If allow found → allow
   - If nothing → deny (default)
```

### Priority Guidelines

| Priority | Use For |
|----------|---------|
| 0-10 | Default policies |
| 10-30 | Standard access policies |
| 30-50 | Masking policies |
| 50-100 | Restrictive policies |
| 100-150 | Override policies |
| 150-200 | Emergency/lockdown policies |
| 200+ | Security critical (PII blocking) |

---

## API Reference

### Field Management

#### List Fields for Resource
```http
GET /api/cells/resources/{resourceId}/fields
Authorization: Bearer {token}

Response:
[
  {
    "id": "field-uuid",
    "field_name": "ssn",
    "field_type": "ssn",
    "description": "Social Security Number",
    "attributes": {
      "sensitivity": "high",
      "pii": "true"
    }
  }
]
```

#### Create Field
```http
POST /api/cells/resources/{resourceId}/fields
Authorization: Bearer {token}
Content-Type: application/json

{
  "field_name": "ssn",
  "field_type": "ssn",
  "description": "Social Security Number",
  "attributes": {
    "sensitivity": "high",
    "pii": "true",
    "data_classification": "confidential"
  }
}
```

#### Set Field Attribute
```http
PUT /api/cells/fields/{fieldId}/attributes/{attrName}
Authorization: Bearer {token}
Content-Type: application/json

{
  "value": "high"
}
```

#### Delete Field
```http
DELETE /api/cells/fields/{fieldId}
Authorization: Bearer {token}
```

### Policy Management

#### List Field Policies
```http
GET /api/cells/policies?resource_type={type}
Authorization: Bearer {token}
```

#### Create Field Policy
```http
POST /api/cells/policies
Authorization: Bearer {token}
Content-Type: application/json

{
  "name": "Mask SSN for non-HR",
  "description": "Show only last 4 digits of SSN for non-HR users",
  "effect": "mask",
  "field_pattern": "ssn",
  "priority": 25,
  "conditions": [
    {
      "subject_type": "user",
      "attribute_name": "department",
      "operator": "not_equals",
      "value": "hr"
    }
  ]
}
```

#### Delete Field Policy
```http
DELETE /api/cells/policies/{policyId}
Authorization: Bearer {token}
```

#### Toggle Policy Active Status
```http
PATCH /api/cells/policies/{policyId}/toggle
Authorization: Bearer {token}
```

### Data Management

#### Insert Data Rows
```http
POST /api/cells/resources/{resourceId}/data
Authorization: Bearer {token}
Content-Type: application/json

{
  "rows": [
    {
      "employee_id": "EMP001",
      "name": "John Smith",
      "email": "john@company.com",
      "ssn": "123-45-6789",
      "salary": "85000"
    }
  ]
}
```

#### Get Filtered Data
```http
GET /api/cells/resources/{resourceId}/data?user_id={userId}
Authorization: Bearer {token}

Response:
{
  "rows": [
    {
      "employee_id": "EMP001",
      "name": "John Smith",
      "email": "****@company.com",
      "ssn": "***-**-6789",
      "salary": "***CONFIDENTIAL***",
      "_accessControl": {
        "employee_id": "allow",
        "name": "allow",
        "email": "mask",
        "ssn": "mask",
        "salary": "redact"
      }
    }
  ],
  "fields": [
    {"name": "employee_id", "type": "string"},
    {"name": "name", "type": "string"},
    {"name": "email", "type": "email"},
    {"name": "ssn", "type": "ssn"},
    {"name": "salary", "type": "salary"}
  ],
  "totalRows": 1
}
```

#### Update Row
```http
PUT /api/cells/resources/{resourceId}/data/{rowId}
Authorization: Bearer {token}
Content-Type: application/json

{
  "salary": "90000"
}
```

#### Delete Row
```http
DELETE /api/cells/resources/{resourceId}/data/{rowId}
Authorization: Bearer {token}
```

### Access Checking

#### Check Single Field Access
```http
POST /api/cells/access/check
Authorization: Bearer {token}
Content-Type: application/json

{
  "user_id": "user-uuid",
  "resource_id": "resource-uuid",
  "field_id": "field-uuid",
  "action": "read"
}

Response:
{
  "allowed": true,
  "effect": "mask",
  "policy": {
    "id": "policy-uuid",
    "name": "Mask SSN for non-HR"
  },
  "mask_value": null,
  "reason": "Masked by policy: Mask SSN for non-HR"
}
```

#### Check Multiple Fields
```http
POST /api/cells/access/check-batch
Authorization: Bearer {token}
Content-Type: application/json

{
  "user_id": "user-uuid",
  "resource_id": "resource-uuid",
  "field_ids": ["field-1", "field-2", "field-3"],
  "action": "read"
}

Response:
{
  "field-1": { "allowed": true, "effect": "allow", "reason": "..." },
  "field-2": { "allowed": true, "effect": "mask", "reason": "..." },
  "field-3": { "allowed": false, "effect": "deny", "reason": "..." }
}
```

#### Filter Arbitrary Data
```http
POST /api/cells/access/filter
Authorization: Bearer {token}
Content-Type: application/json

{
  "user_id": "user-uuid",
  "resource_id": "resource-uuid",
  "data": {
    "ssn": "123-45-6789",
    "salary": "85000",
    "name": "John"
  },
  "action": "read"
}

Response:
{
  "filtered_data": {
    "ssn": "***-**-6789",
    "salary": "***CONFIDENTIAL***",
    "name": "John",
    "_accessControl": {
      "ssn": "mask",
      "salary": "redact",
      "name": "allow"
    }
  }
}
```

---

## Complete Example

### Scenario: Employee Database

#### 1. Create the Resource
```bash
curl -X POST "http://localhost:3000/api/resources" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Employee Database",
    "type": "database",
    "description": "Company employee records"
  }'
# Returns: { "id": "emp-db-uuid", ... }
```

#### 2. Define Fields
```bash
# Employee ID (public)
curl -X POST "http://localhost:3000/api/cells/resources/emp-db-uuid/fields" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "field_name": "employee_id",
    "field_type": "string",
    "attributes": { "sensitivity": "low", "pii": "false" }
  }'

# SSN (highly sensitive)
curl -X POST "http://localhost:3000/api/cells/resources/emp-db-uuid/fields" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "field_name": "ssn",
    "field_type": "ssn",
    "attributes": { "sensitivity": "high", "pii": "true", "data_classification": "confidential" }
  }'

# Salary (confidential)
curl -X POST "http://localhost:3000/api/cells/resources/emp-db-uuid/fields" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "field_name": "salary",
    "field_type": "salary",
    "attributes": { "sensitivity": "high", "pii": "true" }
  }'

# Email (medium sensitivity)
curl -X POST "http://localhost:3000/api/cells/resources/emp-db-uuid/fields" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "field_name": "email",
    "field_type": "email",
    "attributes": { "sensitivity": "medium", "pii": "true" }
  }'
```

#### 3. Create Field Policies
```bash
# Allow low-sensitivity to everyone
curl -X POST "http://localhost:3000/api/cells/policies" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Allow Public Fields",
    "effect": "allow",
    "priority": 10,
    "conditions": [
      { "subject_type": "field", "attribute_name": "sensitivity", "operator": "equals", "value": "low" }
    ]
  }'

# Mask medium-sensitivity for non-HR
curl -X POST "http://localhost:3000/api/cells/policies" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Mask Medium Sensitivity",
    "effect": "mask",
    "priority": 20,
    "conditions": [
      { "subject_type": "field", "attribute_name": "sensitivity", "operator": "equals", "value": "medium" },
      { "subject_type": "user", "attribute_name": "department", "operator": "not_equals", "value": "hr" }
    ]
  }'

# Mask SSN for clearance level 3
curl -X POST "http://localhost:3000/api/cells/policies" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Mask SSN for Clearance 3",
    "effect": "mask",
    "priority": 25,
    "field_pattern": "ssn",
    "conditions": [
      { "subject_type": "user", "attribute_name": "clearance_level", "operator": "equals", "value": "3" }
    ]
  }'

# Redact high-sensitivity for clearance < 3
curl -X POST "http://localhost:3000/api/cells/policies" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Redact High Sensitivity",
    "effect": "redact",
    "mask_value": "***CONFIDENTIAL***",
    "priority": 30,
    "conditions": [
      { "subject_type": "field", "attribute_name": "sensitivity", "operator": "equals", "value": "high" },
      { "subject_type": "user", "attribute_name": "clearance_level", "operator": "less_than", "value": "3" }
    ]
  }'

# Full access for HR managers
curl -X POST "http://localhost:3000/api/cells/policies" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "HR Manager Full Access",
    "effect": "allow",
    "priority": 100,
    "conditions": [
      { "subject_type": "user", "attribute_name": "role", "operator": "equals", "value": "hr_manager" },
      { "subject_type": "user", "attribute_name": "clearance_level", "operator": "greater_than", "value": "3" }
    ]
  }'
```

#### 4. Insert Data
```bash
curl -X POST "http://localhost:3000/api/cells/resources/emp-db-uuid/data" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "rows": [
      { "employee_id": "EMP001", "ssn": "123-45-6789", "salary": "85000", "email": "john@company.com" },
      { "employee_id": "EMP002", "ssn": "234-56-7890", "salary": "92000", "email": "jane@company.com" }
    ]
  }'
```

#### 5. Query with Different Users

**HR Manager (clearance 4):**
```bash
curl "http://localhost:3000/api/cells/resources/emp-db-uuid/data?user_id=$HR_MANAGER_ID" \
  -H "Authorization: Bearer $TOKEN"

# Response: All fields visible
{
  "rows": [{
    "employee_id": "EMP001",
    "ssn": "123-45-6789",
    "salary": "85000",
    "email": "john@company.com"
  }]
}
```

**Engineer (clearance 3):**
```bash
curl "http://localhost:3000/api/cells/resources/emp-db-uuid/data?user_id=$ENGINEER_ID" \
  -H "Authorization: Bearer $TOKEN"

# Response: SSN masked, salary masked, email masked
{
  "rows": [{
    "employee_id": "EMP001",
    "ssn": "***-**-6789",
    "salary": "$***,*** (50k-100k)",
    "email": "****@company.com",
    "_accessControl": {
      "employee_id": "allow",
      "ssn": "mask",
      "salary": "mask",
      "email": "mask"
    }
  }]
}
```

**Junior Employee (clearance 1):**
```bash
curl "http://localhost:3000/api/cells/resources/emp-db-uuid/data?user_id=$JUNIOR_ID" \
  -H "Authorization: Bearer $TOKEN"

# Response: High sensitivity redacted
{
  "rows": [{
    "employee_id": "EMP001",
    "ssn": "***CONFIDENTIAL***",
    "salary": "***CONFIDENTIAL***",
    "email": "****@company.com",
    "_accessControl": {
      "employee_id": "allow",
      "ssn": "redact",
      "salary": "redact",
      "email": "mask"
    }
  }]
}
```

---

## Troubleshooting

### Issue: All fields showing as denied

**Check:**
1. Fields are defined for the resource
2. Field policies exist and are active
3. At least one ALLOW policy exists
4. No high-priority DENY policy is blocking

### Issue: Fields not being masked

**Check:**
1. Field has correct `field_type` for auto-masking
2. Policy effect is `mask` (not `allow`)
3. Policy priority is correct
4. Conditions are matching

### Issue: Wrong mask applied

**Check:**
1. Verify `field_type` is set correctly
2. Check for custom `mask_value` in policy
3. Ensure policy with correct effect has highest priority

### Debug Commands

```bash
# Check field definition
curl "http://localhost:3000/api/cells/resources/$RID/fields" -H "Authorization: Bearer $TOKEN"

# Check active policies
curl "http://localhost:3000/api/cells/policies" -H "Authorization: Bearer $TOKEN"

# Check single field access
curl -X POST "http://localhost:3000/api/cells/access/check" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"...","resource_id":"...","field_id":"...","action":"read"}'
```

---

## Best Practices

1. **Start with default deny** - Create a low-priority policy that denies all fields
2. **Use sensitivity levels consistently** - Define low/medium/high across all fields
3. **Group by field type** - Use `field_pattern` for similar fields (e.g., `*_ssn`, `*_secret`)
4. **Layer policies** - Use priorities to layer from general to specific
5. **Test with different users** - Verify each user role sees the correct view
6. **Audit regularly** - Review access logs for unusual patterns
7. **Document policies** - Use descriptive names and descriptions


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
