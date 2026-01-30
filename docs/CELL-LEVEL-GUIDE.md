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
