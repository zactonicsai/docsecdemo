/**
 * Cell/Field Level Policy Engine
 * 
 * This module handles fine-grained access control at the field/cell level.
 * It can:
 * - Allow/Deny access to specific fields
 * - Mask sensitive data (show partial data like "***-**-1234")
 * - Redact fields entirely (replace with placeholder)
 * - Filter data based on user attributes and field sensitivity
 */

const { getDatabase } = require('./database');

/**
 * Field policy effects:
 * - allow: Full access to the field
 * - deny: No access, field is removed from response
 * - mask: Partial masking (e.g., SSN shows last 4 digits)
 * - redact: Replace with redaction placeholder
 */
const EFFECTS = {
  ALLOW: 'allow',
  DENY: 'deny',
  MASK: 'mask',
  REDACT: 'redact'
};

/**
 * Get all attributes for a specific field
 */
async function getFieldAttributes(fieldId) {
  const db = await getDatabase();
  try {
    const attrs = db.prepare(`
      SELECT attribute_name, attribute_value 
      FROM field_attributes 
      WHERE field_id = ?
    `).all(fieldId);
    
    const result = {};
    attrs.forEach(a => {
      result[a.attribute_name] = a.attribute_value;
    });
    return result;
  } finally {
    db.close();
  }
}

/**
 * Get all fields for a resource with their attributes
 */
async function getResourceFields(resourceId) {
  const db = await getDatabase();
  try {
    const fields = db.prepare(`
      SELECT rf.id, rf.field_name, rf.field_type, rf.description
      FROM resource_fields rf
      WHERE rf.resource_id = ?
    `).all(resourceId);
    
    // Get attributes for each field
    for (const field of fields) {
      const attrs = db.prepare(`
        SELECT attribute_name, attribute_value 
        FROM field_attributes 
        WHERE field_id = ?
      `).all(field.id);
      
      field.attributes = {};
      attrs.forEach(a => {
        field.attributes[a.attribute_name] = a.attribute_value;
      });
    }
    
    return fields;
  } finally {
    db.close();
  }
}

/**
 * Get active field-level policies
 */
async function getFieldPolicies(resourceType = null) {
  const db = await getDatabase();
  try {
    let query = `
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
    `;
    
    const params = [];
    if (resourceType) {
      query += ` AND (fp.resource_type IS NULL OR fp.resource_type = ?)`;
      params.push(resourceType);
    }
    
    query += ` ORDER BY fp.priority DESC`;
    
    const policies = db.prepare(query).all(...params);
    
    // Parse conditions JSON
    return policies.map(p => ({
      ...p,
      conditions: JSON.parse(p.conditions || '[]')
    }));
  } finally {
    db.close();
  }
}

/**
 * Evaluate a single condition
 */
function evaluateCondition(condition, context) {
  let actualValue;
  
  switch (condition.subject_type) {
    case 'user':
      actualValue = context.user[condition.attribute_name];
      break;
    case 'resource':
      actualValue = context.resource[condition.attribute_name];
      break;
    case 'field':
      actualValue = context.field[condition.attribute_name];
      break;
    case 'environment':
      actualValue = context.environment?.[condition.attribute_name];
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
  
  const expectedValue = condition.value;
  
  switch (condition.operator) {
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
    case 'matches':
      try {
        const regex = new RegExp(expectedValue, 'i');
        return regex.test(String(actualValue));
      } catch {
        return false;
      }
    default:
      return false;
  }
}

/**
 * Check if all conditions in a policy match
 */
function evaluatePolicyConditions(policy, context) {
  if (!policy.conditions || policy.conditions.length === 0) {
    return true; // No conditions = matches all
  }
  
  // Check if field pattern matches
  if (policy.field_pattern) {
    try {
      const regex = new RegExp(policy.field_pattern, 'i');
      if (!regex.test(context.field.name || context.field.field_name)) {
        return false;
      }
    } catch {
      return false;
    }
  }
  
  // All conditions must match (AND logic)
  return policy.conditions.every(condition => evaluateCondition(condition, context));
}

/**
 * Evaluate field-level access for a single field
 * Returns: { effect: 'allow'|'deny'|'mask'|'redact', policy: {...}, maskValue: '...' }
 */
async function evaluateFieldAccess(userId, resourceId, fieldId, action, environment = {}) {
  const db = await getDatabase();
  
  try {
    // Get user attributes
    const userAttrs = {};
    const userAttrRows = db.prepare(`
      SELECT attribute_name, attribute_value FROM user_attributes WHERE user_id = ?
    `).all(userId);
    userAttrRows.forEach(a => { userAttrs[a.attribute_name] = a.attribute_value; });
    
    // Get resource info and attributes
    const resource = db.prepare(`SELECT * FROM resources WHERE id = ?`).get(resourceId);
    if (!resource) {
      return { effect: EFFECTS.DENY, reason: 'Resource not found' };
    }
    
    const resourceAttrs = { type: resource.type, name: resource.name };
    const resAttrRows = db.prepare(`
      SELECT attribute_name, attribute_value FROM resource_attributes WHERE resource_id = ?
    `).all(resourceId);
    resAttrRows.forEach(a => { resourceAttrs[a.attribute_name] = a.attribute_value; });
    
    // Get field info and attributes
    const field = db.prepare(`SELECT * FROM resource_fields WHERE id = ?`).get(fieldId);
    if (!field) {
      return { effect: EFFECTS.DENY, reason: 'Field not found' };
    }
    
    const fieldAttrs = { name: field.field_name, type: field.field_type };
    const fieldAttrRows = db.prepare(`
      SELECT attribute_name, attribute_value FROM field_attributes WHERE field_id = ?
    `).all(fieldId);
    fieldAttrRows.forEach(a => { fieldAttrs[a.attribute_name] = a.attribute_value; });
    
    // Build context
    const context = {
      user: userAttrs,
      resource: resourceAttrs,
      field: fieldAttrs,
      action: action,
      environment: environment
    };
    
    // Get applicable policies
    const policies = await getFieldPolicies(resource.type);
    
    // Evaluate policies (deny/redact/mask override allow)
    let result = { effect: EFFECTS.DENY, reason: 'No matching allow policy' };
    
    for (const policy of policies) {
      if (evaluatePolicyConditions(policy, context)) {
        if (policy.effect === EFFECTS.DENY) {
          return { 
            effect: EFFECTS.DENY, 
            policy: policy,
            reason: `Denied by policy: ${policy.name}` 
          };
        }
        if (policy.effect === EFFECTS.REDACT) {
          return { 
            effect: EFFECTS.REDACT, 
            policy: policy,
            maskValue: policy.mask_value || '***REDACTED***',
            reason: `Redacted by policy: ${policy.name}` 
          };
        }
        if (policy.effect === EFFECTS.MASK) {
          result = { 
            effect: EFFECTS.MASK, 
            policy: policy,
            maskValue: policy.mask_value,
            reason: `Masked by policy: ${policy.name}` 
          };
          // Continue checking for deny policies
        }
        if (policy.effect === EFFECTS.ALLOW && result.effect !== EFFECTS.MASK) {
          result = { 
            effect: EFFECTS.ALLOW, 
            policy: policy,
            reason: `Allowed by policy: ${policy.name}` 
          };
        }
      }
    }
    
    return result;
  } finally {
    db.close();
  }
}

/**
 * Apply masking to a value based on field type
 */
function applyMask(value, fieldType, maskPattern) {
  if (value === null || value === undefined) return value;
  
  const strValue = String(value);
  
  // Custom mask pattern
  if (maskPattern) {
    return maskPattern;
  }
  
  // Auto-mask based on field type
  switch (fieldType) {
    case 'ssn':
      // Show last 4 digits: ***-**-1234
      return strValue.length >= 4 
        ? `***-**-${strValue.slice(-4)}` 
        : '***-**-****';
    
    case 'credit_card':
      // Show last 4 digits: ****-****-****-1234
      return strValue.length >= 4 
        ? `****-****-****-${strValue.slice(-4)}` 
        : '****-****-****-****';
    
    case 'phone':
      // Show last 4 digits: (***) ***-1234
      return strValue.length >= 4 
        ? `(***) ***-${strValue.slice(-4)}` 
        : '(***) ***-****';
    
    case 'email':
      // Show domain: ****@domain.com
      const atIndex = strValue.indexOf('@');
      return atIndex > 0 
        ? `****${strValue.slice(atIndex)}` 
        : '****@****.***';
    
    case 'salary':
    case 'currency':
      // Show range: $***,*** (50k-100k)
      const num = parseFloat(strValue.replace(/[^0-9.-]/g, ''));
      if (isNaN(num)) return '$***,***';
      const range = num < 50000 ? '<50k' : num < 100000 ? '50k-100k' : '>100k';
      return `$***,*** (${range})`;
    
    default:
      // Generic mask: show first and last character
      if (strValue.length <= 2) return '***';
      return `${strValue[0]}${'*'.repeat(Math.min(strValue.length - 2, 5))}${strValue[strValue.length - 1]}`;
  }
}

/**
 * Filter resource data based on field-level policies
 * Returns data with unauthorized fields removed, masked, or redacted
 */
async function filterResourceData(userId, resourceId, data, action = 'read', environment = {}) {
  const db = await getDatabase();
  
  try {
    // Get all fields for this resource
    const fields = db.prepare(`
      SELECT id, field_name, field_type 
      FROM resource_fields 
      WHERE resource_id = ?
    `).all(resourceId);
    
    // Build field lookup
    const fieldMap = {};
    for (const field of fields) {
      fieldMap[field.field_name] = field;
    }
    
    // If data is an array (multiple rows), filter each row
    if (Array.isArray(data)) {
      const filteredRows = [];
      for (const row of data) {
        const filteredRow = await filterSingleRow(userId, resourceId, row, fieldMap, action, environment);
        filteredRows.push(filteredRow);
      }
      return filteredRows;
    }
    
    // Single object
    return await filterSingleRow(userId, resourceId, data, fieldMap, action, environment);
  } finally {
    db.close();
  }
}

/**
 * Filter a single row of data
 */
async function filterSingleRow(userId, resourceId, row, fieldMap, action, environment) {
  const filtered = {};
  const accessLog = {};
  
  for (const [fieldName, value] of Object.entries(row)) {
    const field = fieldMap[fieldName];
    
    if (!field) {
      // Field not defined in schema, include as-is (or could deny)
      filtered[fieldName] = value;
      continue;
    }
    
    // Evaluate access for this field
    const access = await evaluateFieldAccess(userId, resourceId, field.id, action, environment);
    accessLog[fieldName] = access.effect;
    
    switch (access.effect) {
      case EFFECTS.ALLOW:
        filtered[fieldName] = value;
        break;
      
      case EFFECTS.MASK:
        filtered[fieldName] = applyMask(value, field.field_type, access.maskValue);
        break;
      
      case EFFECTS.REDACT:
        filtered[fieldName] = access.maskValue || '***REDACTED***';
        break;
      
      case EFFECTS.DENY:
        // Field is completely removed from response
        break;
    }
  }
  
  // Optionally add metadata about what was filtered
  filtered._accessControl = accessLog;
  
  return filtered;
}

/**
 * Get all data for a resource with cell-level filtering applied
 */
async function getFilteredResourceData(userId, resourceId, action = 'read', environment = {}) {
  const db = await getDatabase();
  
  try {
    // Get resource fields
    const fields = db.prepare(`
      SELECT id, field_name, field_type 
      FROM resource_fields 
      WHERE resource_id = ?
    `).all(resourceId);
    
    if (fields.length === 0) {
      return { rows: [], fields: [], message: 'No fields defined for this resource' };
    }
    
    // Get all unique row IDs
    const rowIds = db.prepare(`
      SELECT DISTINCT row_id 
      FROM resource_data 
      WHERE resource_id = ?
      ORDER BY row_id
    `).all(resourceId);
    
    // Build data rows
    const rows = [];
    for (const { row_id } of rowIds) {
      const row = { _row_id: row_id };
      
      for (const field of fields) {
        const cell = db.prepare(`
          SELECT cell_value 
          FROM resource_data 
          WHERE resource_id = ? AND field_id = ? AND row_id = ?
        `).get(resourceId, field.id, row_id);
        
        row[field.field_name] = cell ? cell.cell_value : null;
      }
      
      rows.push(row);
    }
    
    // Apply field-level filtering
    const fieldMap = {};
    for (const field of fields) {
      fieldMap[field.field_name] = field;
    }
    
    const filteredRows = [];
    for (const row of rows) {
      const filtered = await filterSingleRow(userId, resourceId, row, fieldMap, action, environment);
      filteredRows.push(filtered);
    }
    
    return {
      rows: filteredRows,
      fields: fields.map(f => ({ name: f.field_name, type: f.field_type })),
      totalRows: rows.length
    };
  } finally {
    db.close();
  }
}

/**
 * Batch evaluate field access for multiple fields
 */
async function evaluateBatchFieldAccess(userId, resourceId, fieldIds, action, environment = {}) {
  const results = {};
  
  for (const fieldId of fieldIds) {
    results[fieldId] = await evaluateFieldAccess(userId, resourceId, fieldId, action, environment);
  }
  
  return results;
}

module.exports = {
  EFFECTS,
  getFieldAttributes,
  getResourceFields,
  getFieldPolicies,
  evaluateFieldAccess,
  evaluateBatchFieldAccess,
  filterResourceData,
  getFilteredResourceData,
  applyMask
};
