# OpenSearch Integration Guide

Full-text search with cell-level field protection for the ABAC system.

---

## Overview

This system integrates OpenSearch to provide:
- **Full-text search** across documents
- **Cell-level field protection** on search results
- **Automatic masking/redaction** based on user attributes
- **Search audit logging** for compliance

### How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                    SEARCH WITH FIELD PROTECTION                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. User submits search query                                   │
│     POST /api/search                                            │
│     { "query": "security architecture", "user_id": "alice" }    │
│                                                                 │
│  2. OpenSearch executes full-text search                        │
│     - Searches title, content, summary, etc.                    │
│     - Returns matching documents with scores                    │
│                                                                 │
│  3. For each document, cell-level filtering is applied          │
│     For each field in document:                                 │
│       - Evaluate field policies against user attributes         │
│       - Apply effect: allow / mask / redact / deny              │
│                                                                 │
│  4. Return filtered results                                     │
│     {                                                           │
│       "results": [{                                             │
│         "title": "Security Architecture...",                    │
│         "content": "Full content visible...",                   │
│         "confidential_notes": "***MASKED***",  // masked        │
│         "financial_data": "***REDACTED***",    // redacted      │
│         "_accessControl": {...}                // metadata      │
│       }]                                                        │
│     }                                                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Sample Documents

The system comes with **12 sample documents** across different departments:

### Engineering Documents
| Document | Classification | Sensitive Fields |
|----------|----------------|------------------|
| System Architecture Overview | internal | confidential_notes |
| Database Migration Guide | confidential | confidential_notes, financial_data |
| Security Incident Response Playbook | restricted | confidential_notes, pii_data |

### Finance Documents
| Document | Classification | Sensitive Fields |
|----------|----------------|------------------|
| Q4 2024 Financial Report | confidential | confidential_notes, financial_data |
| Employee Compensation Guidelines | internal | confidential_notes, financial_data, pii_data |

### HR Documents
| Document | Classification | Sensitive Fields |
|----------|----------------|------------------|
| Employee Handbook 2024 | public | internal_comments |
| Performance Review Process Guide | internal | confidential_notes |

### Product Documents
| Document | Classification | Sensitive Fields |
|----------|----------------|------------------|
| Product Roadmap 2024 | confidential | confidential_notes, financial_data |
| Customer Research Report | internal | confidential_notes, pii_data |

### Legal Documents
| Document | Classification | Sensitive Fields |
|----------|----------------|------------------|
| Data Processing Agreement Template | internal | internal_comments |
| Intellectual Property Guidelines | confidential | confidential_notes |

### Sales Documents
| Document | Classification | Sensitive Fields |
|----------|----------------|------------------|
| Enterprise Sales Playbook | internal | confidential_notes, financial_data |

---

## Document Field Structure

Each document has the following fields with associated security levels:

| Field | Type | Sensitivity | Description |
|-------|------|-------------|-------------|
| `title` | text | low | Document title (searchable) |
| `content` | text | low | Main document content (searchable) |
| `summary` | text | low | Document summary (searchable) |
| `author` | text | low | Document author |
| `department` | keyword | low | Owning department |
| `classification` | keyword | low | public, internal, confidential, restricted |
| `tags` | keyword[] | low | Document tags |
| `confidential_notes` | text | **high** | Internal confidential notes |
| `internal_comments` | text | **medium** | Internal team comments |
| `financial_data` | text | **high** | Financial information |
| `pii_data` | text | **high** | Personally identifiable information |

---

## Field Policies

The following policies control access to sensitive document fields:

### Allow Public Fields
```javascript
{
  "name": "Allow public document fields",
  "effect": "allow",
  "priority": 5,
  "conditions": [
    { "subject_type": "field", "attribute_name": "sensitivity", "operator": "equals", "value": "low" }
  ]
}
```

### Mask Confidential Notes
```javascript
{
  "name": "Mask confidential notes for non-executives",
  "effect": "mask",
  "field_pattern": "confidential_notes",
  "priority": 40,
  "conditions": [
    { "subject_type": "user", "attribute_name": "clearance_level", "operator": "less_than", "value": "4" }
  ]
}
```

### Redact Financial Data
```javascript
{
  "name": "Redact financial data for non-finance",
  "effect": "redact",
  "mask_value": "***FINANCIAL DATA - FINANCE DEPT ONLY***",
  "field_pattern": "financial_data",
  "priority": 50,
  "conditions": [
    { "subject_type": "user", "attribute_name": "department", "operator": "not_equals", "value": "finance" }
  ]
}
```

### Deny PII Data
```javascript
{
  "name": "Deny PII data to most users",
  "effect": "deny",
  "field_pattern": "pii_data",
  "priority": 60,
  "conditions": [
    { "subject_type": "user", "attribute_name": "department", "operator": "not_equals", "value": "hr" }
  ]
}
```

---

## API Usage

### Basic Search

```bash
# Search for documents about "security"
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
  "max_score": 5.234,
  "results": [
    {
      "_id": "doc-uuid",
      "_score": 5.234,
      "title": "System Architecture Overview",
      "content": "Our platform is built on...",
      "summary": "High-level overview of our...",
      "department": "engineering",
      "classification": "internal",
      "confidential_notes": "AWS account ID: 123... [MASKED - 45 chars hidden]",
      "internal_comments": "Need to review security... [MASKED - 38 chars hidden]",
      "_accessControl": {
        "title": "allow",
        "content": "allow",
        "confidential_notes": "mask",
        "internal_comments": "mask",
        "financial_data": "deny"
      }
    }
  ],
  "filtered_fields": ["confidential_notes:mask", "internal_comments:mask"],
  "message": "Some fields were filtered based on your access level"
}
```

### Search with Filters

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
    "from": 0,
    "size": 10
  }'
```

### Search with Aggregations

```bash
curl -X POST "http://localhost:3000/api/search/aggregations" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "policy",
    "user_id": "USER_UUID"
  }'
```

**Response includes:**
```json
{
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

### Get Single Document

```bash
curl "http://localhost:3000/api/search/documents/DOC_ID?user_id=USER_UUID" \
  -H "Authorization: Bearer $TOKEN"
```

### Index New Document

```bash
curl -X POST "http://localhost:3000/api/search/documents" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "New Engineering Document",
    "content": "Document content here...",
    "summary": "Brief summary",
    "author": "John Smith",
    "department": "engineering",
    "classification": "internal",
    "sensitivity": "medium",
    "confidential_notes": "Secret internal notes",
    "tags": ["engineering", "documentation"]
  }'
```

### Check Search Health

```bash
curl "http://localhost:3000/api/search/health" \
  -H "Authorization: Bearer $TOKEN"
```

**Response:**
```json
{
  "status": "healthy",
  "opensearch": true,
  "stats": {
    "document_count": 12,
    "index_size": "125.4 KB",
    "index_size_human": "125.4 KB"
  }
}
```

---

## Access Control by User Type

### Engineering User (clearance 3)
- ✅ Can see: title, content, summary, author, tags
- ⚠️ Masked: confidential_notes, internal_comments
- ❌ Redacted: financial_data (not finance dept)
- ❌ Denied: pii_data (not HR)

### Finance User (clearance 3)
- ✅ Can see: title, content, summary, author, tags
- ✅ Can see: financial_data (finance dept)
- ⚠️ Masked: confidential_notes, internal_comments
- ❌ Denied: pii_data (not HR)

### HR User (clearance 3)
- ✅ Can see: title, content, summary, author, tags
- ✅ Can see: pii_data (HR dept)
- ⚠️ Masked: confidential_notes, internal_comments
- ❌ Redacted: financial_data (not finance dept)

### Executive (clearance 4+)
- ✅ Can see: title, content, summary, author, tags
- ✅ Can see: confidential_notes (high clearance)
- ⚠️ May still have restrictions on financial_data, pii_data based on department

### Admin
- ✅ Full access to all fields

---

## Docker Services

The system includes these OpenSearch-related services:

```yaml
# OpenSearch
opensearch:
  image: opensearchproject/opensearch:2.11.1
  ports:
    - "9200:9200"  # REST API
    - "9600:9600"  # Performance analyzer

# OpenSearch Dashboards (optional)
opensearch-dashboards:
  image: opensearchproject/opensearch-dashboards:2.11.1
  ports:
    - "5601:5601"  # Web UI
  profiles:
    - dashboards  # Enable with: --profile dashboards
```

### Start with Dashboards

```bash
docker-compose --profile dashboards up -d
```

Access dashboards at: http://localhost:5601

---

## Search Audit Logging

All searches are logged to the `abac-search-audit` index:

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

## Troubleshooting

### OpenSearch Not Available

```bash
# Check OpenSearch status
curl http://localhost:9200/_cluster/health

# View OpenSearch logs
docker-compose logs opensearch
```

### Documents Not Indexed

```bash
# Re-run seed to index documents
docker-compose run --rm seed

# Or manually index
curl -X POST http://localhost:3000/api/search/documents/bulk \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"documents": [...]}'
```

### Search Returns No Results

1. Check if index exists:
   ```bash
   curl http://localhost:9200/_cat/indices
   ```

2. Check document count:
   ```bash
   curl http://localhost:9200/abac-documents/_count
   ```

3. Verify search is working:
   ```bash
   curl 'http://localhost:9200/abac-documents/_search?q=*'
   ```

### Field Filtering Not Working

1. Verify user has attributes set:
   ```bash
   curl http://localhost:3000/api/users/USER_ID
   ```

2. Check field policies exist:
   ```bash
   curl http://localhost:3000/api/cells/policies
   ```

3. Test field access directly:
   ```bash
   curl -X POST http://localhost:3000/api/cells/access/check \
     -d '{"user_id":"...","resource_id":"...","field_id":"..."}'
   ```

---

## Best Practices

1. **Index Security Metadata**: Include `field_security` in documents for policy evaluation
2. **Use Appropriate Classifications**: Match document classification to sensitivity level
3. **Review Audit Logs**: Regularly review search audit logs for unusual patterns
4. **Test Access Levels**: Verify search results with different user types before production
5. **Keep Policies Updated**: Update field policies when adding new sensitive fields
