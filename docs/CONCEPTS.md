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
