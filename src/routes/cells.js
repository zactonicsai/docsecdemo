/**
 * Cell/Field Level Access Control Routes
 * 
 * These routes handle field-level security:
 * - Define fields for resources with security attributes
 * - Create field-level policies
 * - Store and retrieve data with automatic filtering
 * - Evaluate field-level access
 */

const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { getDatabase } = require('../database');
const { 
  evaluateFieldAccess, 
  evaluateBatchFieldAccess,
  getFilteredResourceData,
  filterResourceData,
  getResourceFields,
  getFieldPolicies,
  EFFECTS
} = require('../cell-policy-engine');

// ============================================
// RESOURCE FIELDS (Schema Definition)
// ============================================

/**
 * GET /api/cells/resources/:resourceId/fields
 * Get all fields defined for a resource
 */
router.get('/resources/:resourceId/fields', async (req, res) => {
  try {
    const fields = await getResourceFields(req.params.resourceId);
    res.json(fields);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST /api/cells/resources/:resourceId/fields
 * Define a new field for a resource
 * Body: { field_name, field_type, description, attributes: { sensitivity, pii, classification } }
 */
router.post('/resources/:resourceId/fields', async (req, res) => {
  const db = await getDatabase();
  try {
    const { field_name, field_type, description, attributes } = req.body;
    const fieldId = uuidv4();
    
    // Create field
    db.prepare(`
      INSERT INTO resource_fields (id, resource_id, field_name, field_type, description)
      VALUES (?, ?, ?, ?, ?)
    `).run(fieldId, req.params.resourceId, field_name, field_type || 'string', description);
    
    // Add attributes
    if (attributes) {
      for (const [name, value] of Object.entries(attributes)) {
        db.prepare(`
          INSERT INTO field_attributes (field_id, attribute_name, attribute_value)
          VALUES (?, ?, ?)
        `).run(fieldId, name, String(value));
      }
    }
    
    db.save();
    
    res.status(201).json({
      id: fieldId,
      resource_id: req.params.resourceId,
      field_name,
      field_type: field_type || 'string',
      description,
      attributes: attributes || {}
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  } finally {
    db.close();
  }
});

/**
 * PUT /api/cells/fields/:fieldId/attributes/:attrName
 * Set a field attribute
 */
router.put('/fields/:fieldId/attributes/:attrName', async (req, res) => {
  const db = await getDatabase();
  try {
    const { value } = req.body;
    
    db.prepare(`
      INSERT OR REPLACE INTO field_attributes (field_id, attribute_name, attribute_value)
      VALUES (?, ?, ?)
    `).run(req.params.fieldId, req.params.attrName, String(value));
    
    db.save();
    
    res.json({ 
      field_id: req.params.fieldId,
      attribute_name: req.params.attrName, 
      attribute_value: value 
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  } finally {
    db.close();
  }
});

/**
 * DELETE /api/cells/fields/:fieldId
 * Delete a field definition
 */
router.delete('/fields/:fieldId', async (req, res) => {
  const db = await getDatabase();
  try {
    db.prepare(`DELETE FROM field_attributes WHERE field_id = ?`).run(req.params.fieldId);
    db.prepare(`DELETE FROM resource_data WHERE field_id = ?`).run(req.params.fieldId);
    const result = db.prepare(`DELETE FROM resource_fields WHERE id = ?`).run(req.params.fieldId);
    
    db.save();
    
    if (result.changes === 0) {
      return res.status(404).json({ error: 'Field not found' });
    }
    
    res.json({ deleted: true, field_id: req.params.fieldId });
  } catch (error) {
    res.status(500).json({ error: error.message });
  } finally {
    db.close();
  }
});

// ============================================
// FIELD POLICIES
// ============================================

/**
 * GET /api/cells/policies
 * List all field-level policies
 */
router.get('/policies', async (req, res) => {
  try {
    const policies = await getFieldPolicies(req.query.resource_type);
    res.json(policies);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST /api/cells/policies
 * Create a field-level policy
 * Body: {
 *   name, description, resource_type, field_pattern,
 *   effect: 'allow'|'deny'|'mask'|'redact',
 *   mask_value, priority, conditions: [...]
 * }
 */
router.post('/policies', async (req, res) => {
  const db = await getDatabase();
  try {
    const { 
      name, description, resource_type, field_pattern,
      effect, mask_value, priority, conditions 
    } = req.body;
    
    const policyId = uuidv4();
    
    // Validate effect
    if (!['allow', 'deny', 'mask', 'redact'].includes(effect)) {
      return res.status(400).json({ 
        error: 'Invalid effect. Must be: allow, deny, mask, or redact' 
      });
    }
    
    // Create policy
    db.prepare(`
      INSERT INTO field_policies 
      (id, name, description, resource_type, field_pattern, effect, mask_value, priority)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(policyId, name, description, resource_type, field_pattern, effect, mask_value, priority || 0);
    
    // Add conditions
    if (conditions && conditions.length > 0) {
      for (const cond of conditions) {
        db.prepare(`
          INSERT INTO field_policy_conditions 
          (policy_id, subject_type, attribute_name, operator, attribute_value)
          VALUES (?, ?, ?, ?, ?)
        `).run(policyId, cond.subject_type, cond.attribute_name, cond.operator, cond.value);
      }
    }
    
    db.save();
    
    res.status(201).json({
      id: policyId,
      name,
      description,
      resource_type,
      field_pattern,
      effect,
      mask_value,
      priority: priority || 0,
      conditions: conditions || []
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  } finally {
    db.close();
  }
});

/**
 * DELETE /api/cells/policies/:policyId
 * Delete a field policy
 */
router.delete('/policies/:policyId', async (req, res) => {
  const db = await getDatabase();
  try {
    db.prepare(`DELETE FROM field_policy_conditions WHERE policy_id = ?`).run(req.params.policyId);
    const result = db.prepare(`DELETE FROM field_policies WHERE id = ?`).run(req.params.policyId);
    
    db.save();
    
    if (result.changes === 0) {
      return res.status(404).json({ error: 'Policy not found' });
    }
    
    res.json({ deleted: true, policy_id: req.params.policyId });
  } catch (error) {
    res.status(500).json({ error: error.message });
  } finally {
    db.close();
  }
});

/**
 * PATCH /api/cells/policies/:policyId/toggle
 * Toggle policy active status
 */
router.patch('/policies/:policyId/toggle', async (req, res) => {
  const db = await getDatabase();
  try {
    const policy = db.prepare(`SELECT is_active FROM field_policies WHERE id = ?`).get(req.params.policyId);
    
    if (!policy) {
      return res.status(404).json({ error: 'Policy not found' });
    }
    
    const newStatus = policy.is_active ? 0 : 1;
    db.prepare(`UPDATE field_policies SET is_active = ? WHERE id = ?`).run(newStatus, req.params.policyId);
    
    db.save();
    
    res.json({ policy_id: req.params.policyId, is_active: Boolean(newStatus) });
  } catch (error) {
    res.status(500).json({ error: error.message });
  } finally {
    db.close();
  }
});

// ============================================
// RESOURCE DATA (Cells)
// ============================================

/**
 * POST /api/cells/resources/:resourceId/data
 * Insert data rows into a resource
 * Body: { rows: [{ field1: value1, field2: value2 }, ...] }
 */
router.post('/resources/:resourceId/data', async (req, res) => {
  const db = await getDatabase();
  try {
    const { rows } = req.body;
    const resourceId = req.params.resourceId;
    
    // Get field definitions
    const fields = db.prepare(`
      SELECT id, field_name FROM resource_fields WHERE resource_id = ?
    `).all(resourceId);
    
    const fieldMap = {};
    fields.forEach(f => { fieldMap[f.field_name] = f.id; });
    
    const insertedRows = [];
    
    for (const row of rows) {
      const rowId = uuidv4();
      
      for (const [fieldName, value] of Object.entries(row)) {
        const fieldId = fieldMap[fieldName];
        if (!fieldId) continue; // Skip unknown fields
        
        db.prepare(`
          INSERT INTO resource_data (resource_id, field_id, row_id, cell_value)
          VALUES (?, ?, ?, ?)
        `).run(resourceId, fieldId, rowId, value !== null ? String(value) : null);
      }
      
      insertedRows.push({ row_id: rowId, ...row });
    }
    
    db.save();
    
    res.status(201).json({
      resource_id: resourceId,
      inserted_count: insertedRows.length,
      rows: insertedRows
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  } finally {
    db.close();
  }
});

/**
 * GET /api/cells/resources/:resourceId/data
 * Get resource data with cell-level filtering applied
 * Query: user_id (required for filtering)
 */
router.get('/resources/:resourceId/data', async (req, res) => {
  try {
    const userId = req.query.user_id;
    
    if (!userId) {
      return res.status(400).json({ 
        error: 'user_id query parameter required for cell-level filtering' 
      });
    }
    
    const environment = {
      time: new Date().toISOString(),
      ip: req.ip
    };
    
    const result = await getFilteredResourceData(
      userId, 
      req.params.resourceId, 
      'read',
      environment
    );
    
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * PUT /api/cells/resources/:resourceId/data/:rowId
 * Update a specific row
 */
router.put('/resources/:resourceId/data/:rowId', async (req, res) => {
  const db = await getDatabase();
  try {
    const { resourceId, rowId } = req.params;
    const updates = req.body;
    
    // Get field definitions
    const fields = db.prepare(`
      SELECT id, field_name FROM resource_fields WHERE resource_id = ?
    `).all(resourceId);
    
    const fieldMap = {};
    fields.forEach(f => { fieldMap[f.field_name] = f.id; });
    
    let updatedCount = 0;
    
    for (const [fieldName, value] of Object.entries(updates)) {
      const fieldId = fieldMap[fieldName];
      if (!fieldId) continue;
      
      db.prepare(`
        INSERT OR REPLACE INTO resource_data (resource_id, field_id, row_id, cell_value, updated_at)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
      `).run(resourceId, fieldId, rowId, value !== null ? String(value) : null);
      
      updatedCount++;
    }
    
    db.save();
    
    res.json({ 
      resource_id: resourceId,
      row_id: rowId,
      updated_fields: updatedCount
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  } finally {
    db.close();
  }
});

/**
 * DELETE /api/cells/resources/:resourceId/data/:rowId
 * Delete a specific row
 */
router.delete('/resources/:resourceId/data/:rowId', async (req, res) => {
  const db = await getDatabase();
  try {
    const result = db.prepare(`
      DELETE FROM resource_data 
      WHERE resource_id = ? AND row_id = ?
    `).run(req.params.resourceId, req.params.rowId);
    
    db.save();
    
    res.json({ 
      deleted: result.changes > 0,
      deleted_cells: result.changes 
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  } finally {
    db.close();
  }
});

// ============================================
// ACCESS EVALUATION
// ============================================

/**
 * POST /api/cells/access/check
 * Check access to a specific field
 * Body: { user_id, resource_id, field_id, action }
 */
router.post('/access/check', async (req, res) => {
  try {
    const { user_id, resource_id, field_id, action, environment } = req.body;
    
    const result = await evaluateFieldAccess(
      user_id, 
      resource_id, 
      field_id, 
      action || 'read',
      environment || {}
    );
    
    res.json({
      allowed: result.effect === EFFECTS.ALLOW,
      effect: result.effect,
      policy: result.policy ? { id: result.policy.id, name: result.policy.name } : null,
      mask_value: result.maskValue,
      reason: result.reason
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST /api/cells/access/check-batch
 * Check access to multiple fields at once
 * Body: { user_id, resource_id, field_ids: [...], action }
 */
router.post('/access/check-batch', async (req, res) => {
  try {
    const { user_id, resource_id, field_ids, action, environment } = req.body;
    
    const results = await evaluateBatchFieldAccess(
      user_id,
      resource_id,
      field_ids,
      action || 'read',
      environment || {}
    );
    
    // Transform results
    const transformed = {};
    for (const [fieldId, result] of Object.entries(results)) {
      transformed[fieldId] = {
        allowed: result.effect === EFFECTS.ALLOW,
        effect: result.effect,
        reason: result.reason
      };
    }
    
    res.json(transformed);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST /api/cells/access/filter
 * Filter arbitrary data through cell-level policies
 * Body: { user_id, resource_id, data: {...} or [...], action }
 */
router.post('/access/filter', async (req, res) => {
  try {
    const { user_id, resource_id, data, action, environment } = req.body;
    
    const filtered = await filterResourceData(
      user_id,
      resource_id,
      data,
      action || 'read',
      environment || {}
    );
    
    res.json({ filtered_data: filtered });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
