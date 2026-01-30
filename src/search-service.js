/**
 * OpenSearch Service with Cell-Level Access Control
 * 
 * This module provides full-text search capabilities while respecting
 * cell/field-level access control policies. Search results are automatically
 * filtered based on user permissions.
 */

const { Client } = require('@opensearch-project/opensearch');
const { getDatabase } = require('./database');
const { 
  evaluateFieldAccess, 
  applyMask, 
  EFFECTS 
} = require('./cell-policy-engine');

// OpenSearch client
let client = null;

// Index names
const INDICES = {
  DOCUMENTS: 'abac-documents',
  AUDIT_SEARCH: 'abac-search-audit'
};

/**
 * Initialize OpenSearch client
 */
function getClient() {
  if (!client) {
    const opensearchUrl = process.env.OPENSEARCH_URL || 'http://localhost:9200';
    client = new Client({
      node: opensearchUrl,
      ssl: {
        rejectUnauthorized: false
      }
    });
  }
  return client;
}

/**
 * Check if OpenSearch is available
 */
async function isAvailable() {
  try {
    const client = getClient();
    const health = await client.cluster.health();
    return health.body.status === 'green' || health.body.status === 'yellow';
  } catch (error) {
    console.error('OpenSearch not available:', error.message);
    return false;
  }
}

/**
 * Initialize indices with mappings
 */
async function initializeIndices() {
  const client = getClient();
  
  // Document index mapping
  const documentMapping = {
    mappings: {
      properties: {
        // Document metadata
        id: { type: 'keyword' },
        resource_id: { type: 'keyword' },
        title: { type: 'text', analyzer: 'standard' },
        type: { type: 'keyword' },
        
        // Searchable content fields
        content: { type: 'text', analyzer: 'standard' },
        summary: { type: 'text', analyzer: 'standard' },
        author: { type: 'text' },
        
        // Sensitive fields (will be masked/redacted based on policy)
        confidential_notes: { type: 'text' },
        internal_comments: { type: 'text' },
        financial_data: { type: 'text' },
        pii_data: { type: 'text' },
        
        // Classification and access control
        department: { type: 'keyword' },
        classification: { type: 'keyword' },
        sensitivity: { type: 'keyword' },
        tags: { type: 'keyword' },
        
        // Timestamps
        created_at: { type: 'date' },
        updated_at: { type: 'date' },
        
        // Field-level metadata for access control
        field_security: {
          type: 'object',
          properties: {
            confidential_notes: { type: 'keyword' },    // sensitivity level
            internal_comments: { type: 'keyword' },
            financial_data: { type: 'keyword' },
            pii_data: { type: 'keyword' }
          }
        }
      }
    },
    settings: {
      number_of_shards: 1,
      number_of_replicas: 0,
      analysis: {
        analyzer: {
          standard: {
            type: 'standard',
            stopwords: '_english_'
          }
        }
      }
    }
  };

  // Create document index
  try {
    const exists = await client.indices.exists({ index: INDICES.DOCUMENTS });
    if (!exists.body) {
      await client.indices.create({
        index: INDICES.DOCUMENTS,
        body: documentMapping
      });
      console.log(`Created index: ${INDICES.DOCUMENTS}`);
    }
  } catch (error) {
    if (error.meta?.body?.error?.type !== 'resource_already_exists_exception') {
      console.error('Error creating document index:', error.message);
    }
  }

  // Create search audit index
  try {
    const exists = await client.indices.exists({ index: INDICES.AUDIT_SEARCH });
    if (!exists.body) {
      await client.indices.create({
        index: INDICES.AUDIT_SEARCH,
        body: {
          mappings: {
            properties: {
              user_id: { type: 'keyword' },
              query: { type: 'text' },
              results_count: { type: 'integer' },
              filtered_fields: { type: 'keyword' },
              timestamp: { type: 'date' }
            }
          }
        }
      });
      console.log(`Created index: ${INDICES.AUDIT_SEARCH}`);
    }
  } catch (error) {
    if (error.meta?.body?.error?.type !== 'resource_already_exists_exception') {
      console.error('Error creating audit index:', error.message);
    }
  }
}

/**
 * Index a document
 */
async function indexDocument(doc) {
  const client = getClient();
  
  const document = {
    id: doc.id,
    resource_id: doc.resource_id,
    title: doc.title,
    type: doc.type || 'document',
    content: doc.content,
    summary: doc.summary,
    author: doc.author,
    confidential_notes: doc.confidential_notes,
    internal_comments: doc.internal_comments,
    financial_data: doc.financial_data,
    pii_data: doc.pii_data,
    department: doc.department,
    classification: doc.classification || 'internal',
    sensitivity: doc.sensitivity || 'medium',
    tags: doc.tags || [],
    created_at: doc.created_at || new Date().toISOString(),
    updated_at: new Date().toISOString(),
    field_security: doc.field_security || {
      confidential_notes: 'high',
      internal_comments: 'medium',
      financial_data: 'high',
      pii_data: 'high'
    }
  };

  await client.index({
    index: INDICES.DOCUMENTS,
    id: doc.id,
    body: document,
    refresh: true
  });

  return document;
}

/**
 * Bulk index documents
 */
async function bulkIndexDocuments(documents) {
  const client = getClient();
  
  const body = documents.flatMap(doc => [
    { index: { _index: INDICES.DOCUMENTS, _id: doc.id } },
    {
      ...doc,
      created_at: doc.created_at || new Date().toISOString(),
      updated_at: new Date().toISOString()
    }
  ]);

  const result = await client.bulk({ body, refresh: true });
  
  return {
    indexed: documents.length,
    errors: result.body.errors,
    items: result.body.items
  };
}

/**
 * Delete a document
 */
async function deleteDocument(docId) {
  const client = getClient();
  
  try {
    await client.delete({
      index: INDICES.DOCUMENTS,
      id: docId,
      refresh: true
    });
    return true;
  } catch (error) {
    if (error.meta?.statusCode === 404) {
      return false;
    }
    throw error;
  }
}

/**
 * Get field sensitivity mapping for a document
 */
function getFieldSensitivity(doc) {
  return {
    title: 'low',
    content: 'low',
    summary: 'low',
    author: 'low',
    department: 'low',
    tags: 'low',
    type: 'low',
    classification: 'low',
    confidential_notes: doc.field_security?.confidential_notes || 'high',
    internal_comments: doc.field_security?.internal_comments || 'medium',
    financial_data: doc.field_security?.financial_data || 'high',
    pii_data: doc.field_security?.pii_data || 'high'
  };
}

/**
 * Apply cell-level filtering to a search result document
 */
async function filterDocumentFields(doc, userId, action = 'read') {
  const db = await getDatabase();
  
  try {
    // Get user attributes
    const userAttrs = {};
    const userAttrRows = db.prepare(`
      SELECT attribute_name, attribute_value FROM user_attributes WHERE user_id = ?
    `).all(userId);
    userAttrRows.forEach(a => { userAttrs[a.attribute_name] = a.attribute_value; });

    // Get field policies
    const fieldPolicies = db.prepare(`
      SELECT fp.*, 
        (SELECT json_group_array(json_object(
          'subject_type', fpc.subject_type,
          'attribute_name', fpc.attribute_name,
          'operator', fpc.operator,
          'value', fpc.attribute_value
        ))
        FROM field_policy_conditions fpc 
        WHERE fpc.policy_id = fp.id) as conditions
      FROM field_policies fp
      WHERE fp.is_active = 1
      ORDER BY fp.priority DESC
    `).all();

    const policies = fieldPolicies.map(p => ({
      ...p,
      conditions: JSON.parse(p.conditions || '[]')
    }));

    const fieldSensitivity = getFieldSensitivity(doc);
    const filtered = {};
    const accessControl = {};

    // Evaluate each field
    for (const [fieldName, value] of Object.entries(doc)) {
      // Skip metadata fields
      if (['_index', '_id', '_score', 'field_security'].includes(fieldName)) {
        continue;
      }

      const sensitivity = fieldSensitivity[fieldName] || 'low';
      
      // Build context for this field
      const context = {
        user: userAttrs,
        resource: {
          type: doc.type || 'document',
          department: doc.department,
          classification: doc.classification
        },
        field: {
          name: fieldName,
          sensitivity: sensitivity,
          pii: ['pii_data'].includes(fieldName) ? 'true' : 'false'
        },
        action: action,
        environment: {}
      };

      // Evaluate policies
      let effect = EFFECTS.DENY;
      let maskValue = null;

      for (const policy of policies) {
        if (evaluatePolicyConditions(policy, context)) {
          if (policy.effect === EFFECTS.DENY) {
            effect = EFFECTS.DENY;
            break;
          }
          if (policy.effect === EFFECTS.REDACT) {
            effect = EFFECTS.REDACT;
            maskValue = policy.mask_value || '***REDACTED***';
            break;
          }
          if (policy.effect === EFFECTS.MASK) {
            effect = EFFECTS.MASK;
            maskValue = policy.mask_value;
          }
          if (policy.effect === EFFECTS.ALLOW && effect !== EFFECTS.MASK) {
            effect = EFFECTS.ALLOW;
          }
        }
      }

      // Apply effect
      switch (effect) {
        case EFFECTS.ALLOW:
          filtered[fieldName] = value;
          accessControl[fieldName] = 'allow';
          break;
        case EFFECTS.MASK:
          filtered[fieldName] = applyMaskToText(value, maskValue);
          accessControl[fieldName] = 'mask';
          break;
        case EFFECTS.REDACT:
          filtered[fieldName] = maskValue || '***REDACTED***';
          accessControl[fieldName] = 'redact';
          break;
        case EFFECTS.DENY:
        default:
          // Don't include field
          accessControl[fieldName] = 'deny';
          break;
      }
    }

    filtered._accessControl = accessControl;
    return filtered;
  } finally {
    db.close();
  }
}

/**
 * Evaluate policy conditions
 */
function evaluatePolicyConditions(policy, context) {
  if (!policy.conditions || policy.conditions.length === 0) {
    return true;
  }

  // Check field pattern if specified
  if (policy.field_pattern) {
    try {
      const regex = new RegExp(policy.field_pattern, 'i');
      if (!regex.test(context.field.name)) {
        return false;
      }
    } catch {
      return false;
    }
  }

  // All conditions must match
  return policy.conditions.every(cond => {
    let actualValue;
    switch (cond.subject_type) {
      case 'user':
        actualValue = context.user[cond.attribute_name];
        break;
      case 'resource':
        actualValue = context.resource[cond.attribute_name];
        break;
      case 'field':
        actualValue = context.field[cond.attribute_name];
        break;
      case 'environment':
        actualValue = context.environment?.[cond.attribute_name];
        break;
      case 'action':
        actualValue = context.action;
        break;
      default:
        return false;
    }

    if (actualValue === undefined || actualValue === null) {
      return false;
    }

    const expectedValue = cond.value;

    switch (cond.operator) {
      case 'equals':
        return String(actualValue).toLowerCase() === String(expectedValue).toLowerCase();
      case 'not_equals':
        return String(actualValue).toLowerCase() !== String(expectedValue).toLowerCase();
      case 'contains':
        return String(actualValue).toLowerCase().includes(String(expectedValue).toLowerCase());
      case 'in':
        const allowedValues = expectedValue.split(',').map(v => v.trim().toLowerCase());
        return allowedValues.includes(String(actualValue).toLowerCase());
      case 'greater_than':
        return Number(actualValue) > Number(expectedValue);
      case 'less_than':
        return Number(actualValue) < Number(expectedValue);
      default:
        return false;
    }
  });
}

/**
 * Apply masking to text content
 */
function applyMaskToText(text, customMask) {
  if (!text) return text;
  if (customMask) return customMask;
  
  // For long text, show first 20 chars and mask the rest
  const str = String(text);
  if (str.length <= 20) {
    return '*'.repeat(str.length);
  }
  return str.substring(0, 20) + '... [MASKED - ' + (str.length - 20) + ' chars hidden]';
}

/**
 * Search documents with cell-level filtering
 */
async function search(query, userId, options = {}) {
  const client = getClient();
  const {
    fields = ['title', 'content', 'summary', 'author', 'tags'],
    filters = {},
    from = 0,
    size = 10,
    highlight = true
  } = options;

  // Build search query
  const searchBody = {
    from,
    size,
    query: {
      bool: {
        must: [
          {
            multi_match: {
              query: query,
              fields: fields,
              type: 'best_fields',
              fuzziness: 'AUTO'
            }
          }
        ],
        filter: []
      }
    }
  };

  // Add filters
  if (filters.department) {
    searchBody.query.bool.filter.push({ term: { department: filters.department } });
  }
  if (filters.classification) {
    searchBody.query.bool.filter.push({ term: { classification: filters.classification } });
  }
  if (filters.type) {
    searchBody.query.bool.filter.push({ term: { type: filters.type } });
  }
  if (filters.tags && filters.tags.length > 0) {
    searchBody.query.bool.filter.push({ terms: { tags: filters.tags } });
  }

  // Add highlighting
  if (highlight) {
    searchBody.highlight = {
      fields: {
        content: { fragment_size: 150, number_of_fragments: 3 },
        title: {},
        summary: { fragment_size: 200, number_of_fragments: 2 }
      },
      pre_tags: ['<mark>'],
      post_tags: ['</mark>']
    };
  }

  // Execute search
  const response = await client.search({
    index: INDICES.DOCUMENTS,
    body: searchBody
  });

  // Apply cell-level filtering to each result
  const filteredResults = [];
  const filteredFieldsSet = new Set();

  for (const hit of response.body.hits.hits) {
    const doc = hit._source;
    const filtered = await filterDocumentFields(doc, userId);
    
    // Track which fields were filtered
    Object.entries(filtered._accessControl || {}).forEach(([field, effect]) => {
      if (effect !== 'allow') {
        filteredFieldsSet.add(`${field}:${effect}`);
      }
    });

    filteredResults.push({
      _id: hit._id,
      _score: hit._score,
      _highlight: hit.highlight,
      ...filtered
    });
  }

  // Log search audit
  await logSearchAudit(userId, query, filteredResults.length, Array.from(filteredFieldsSet));

  return {
    total: response.body.hits.total.value,
    max_score: response.body.hits.max_score,
    results: filteredResults,
    filtered_fields: Array.from(filteredFieldsSet)
  };
}

/**
 * Search with aggregations
 */
async function searchWithAggregations(query, userId, options = {}) {
  const client = getClient();
  
  const searchBody = {
    size: options.size || 10,
    query: query ? {
      multi_match: {
        query: query,
        fields: ['title', 'content', 'summary'],
        fuzziness: 'AUTO'
      }
    } : { match_all: {} },
    aggs: {
      by_department: {
        terms: { field: 'department', size: 10 }
      },
      by_classification: {
        terms: { field: 'classification', size: 10 }
      },
      by_type: {
        terms: { field: 'type', size: 10 }
      },
      by_sensitivity: {
        terms: { field: 'sensitivity', size: 10 }
      }
    }
  };

  const response = await client.search({
    index: INDICES.DOCUMENTS,
    body: searchBody
  });

  // Filter results
  const filteredResults = [];
  for (const hit of response.body.hits.hits) {
    const filtered = await filterDocumentFields(hit._source, userId);
    filteredResults.push({
      _id: hit._id,
      _score: hit._score,
      ...filtered
    });
  }

  return {
    total: response.body.hits.total.value,
    results: filteredResults,
    aggregations: {
      by_department: response.body.aggregations.by_department.buckets,
      by_classification: response.body.aggregations.by_classification.buckets,
      by_type: response.body.aggregations.by_type.buckets,
      by_sensitivity: response.body.aggregations.by_sensitivity.buckets
    }
  };
}

/**
 * Get document by ID with filtering
 */
async function getDocument(docId, userId) {
  const client = getClient();
  
  try {
    const response = await client.get({
      index: INDICES.DOCUMENTS,
      id: docId
    });

    return await filterDocumentFields(response.body._source, userId);
  } catch (error) {
    if (error.meta?.statusCode === 404) {
      return null;
    }
    throw error;
  }
}

/**
 * Log search audit
 */
async function logSearchAudit(userId, query, resultsCount, filteredFields) {
  const client = getClient();
  
  try {
    await client.index({
      index: INDICES.AUDIT_SEARCH,
      body: {
        user_id: userId,
        query: query,
        results_count: resultsCount,
        filtered_fields: filteredFields,
        timestamp: new Date().toISOString()
      }
    });
  } catch (error) {
    console.error('Failed to log search audit:', error.message);
  }
}

/**
 * Get search statistics
 */
async function getSearchStats() {
  const client = getClient();
  
  const [docCount, indexStats] = await Promise.all([
    client.count({ index: INDICES.DOCUMENTS }),
    client.indices.stats({ index: INDICES.DOCUMENTS })
  ]);

  return {
    document_count: docCount.body.count,
    index_size: indexStats.body._all.total.store.size_in_bytes,
    index_size_human: formatBytes(indexStats.body._all.total.store.size_in_bytes)
  };
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

module.exports = {
  getClient,
  isAvailable,
  initializeIndices,
  indexDocument,
  bulkIndexDocuments,
  deleteDocument,
  search,
  searchWithAggregations,
  getDocument,
  getSearchStats,
  INDICES
};
