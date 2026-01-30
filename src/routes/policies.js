/**
 * Policy Routes - CRUD operations for policies and their conditions (Async)
 */

const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { getDatabase } = require('../database');

const router = express.Router();

// List all policies
router.get('/', async (req, res) => {
  const db = await getDatabase();
  try {
    const policies = db.prepare('SELECT * FROM policies ORDER BY priority DESC, created_at DESC').all();
    
    const policiesWithConditions = policies.map(policy => {
      const conditions = db.prepare('SELECT * FROM policy_conditions WHERE policy_id = ?')
        .all(policy.id);
      return {
        ...policy,
        is_active: Boolean(policy.is_active),
        conditions
      };
    });
    
    res.json(policiesWithConditions);
  } finally {
    db.close();
  }
});

// Get single policy
router.get('/:id', async (req, res) => {
  const db = await getDatabase();
  try {
    const policy = db.prepare('SELECT * FROM policies WHERE id = ?').get(req.params.id);
    if (!policy) {
      return res.status(404).json({ error: 'Policy not found' });
    }
    
    const conditions = db.prepare('SELECT * FROM policy_conditions WHERE policy_id = ?')
      .all(policy.id);
    
    res.json({
      ...policy,
      is_active: Boolean(policy.is_active),
      conditions
    });
  } finally {
    db.close();
  }
});

// Create policy
router.post('/', async (req, res) => {
  const { name, description, effect, priority, is_active, conditions } = req.body;
  
  if (!name || !effect) {
    return res.status(400).json({ error: 'Name and effect are required' });
  }
  
  if (!['allow', 'deny'].includes(effect)) {
    return res.status(400).json({ error: 'Effect must be "allow" or "deny"' });
  }

  const db = await getDatabase();
  try {
    const id = uuidv4();
    
    db.prepare(`
      INSERT INTO policies (id, name, description, effect, priority, is_active)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(id, name, description || null, effect, priority || 0, is_active !== false ? 1 : 0);
    
    if (conditions && Array.isArray(conditions)) {
      for (const condition of conditions) {
        if (!condition.subject_type || !condition.attribute_name || !condition.operator || condition.attribute_value === undefined) {
          continue;
        }
        db.prepare(`
          INSERT INTO policy_conditions (policy_id, subject_type, attribute_name, operator, attribute_value)
          VALUES (?, ?, ?, ?, ?)
        `).run(id, condition.subject_type, condition.attribute_name, condition.operator, String(condition.attribute_value));
      }
    }
    
    const savedConditions = db.prepare('SELECT * FROM policy_conditions WHERE policy_id = ?').all(id);
    
    res.status(201).json({
      id,
      name,
      description,
      effect,
      priority: priority || 0,
      is_active: is_active !== false,
      conditions: savedConditions
    });
  } finally {
    db.close();
  }
});

// Update policy
router.put('/:id', async (req, res) => {
  const { name, description, effect, priority, is_active, conditions } = req.body;
  const db = await getDatabase();
  
  try {
    const existing = db.prepare('SELECT * FROM policies WHERE id = ?').get(req.params.id);
    if (!existing) {
      return res.status(404).json({ error: 'Policy not found' });
    }
    
    if (effect && !['allow', 'deny'].includes(effect)) {
      return res.status(400).json({ error: 'Effect must be "allow" or "deny"' });
    }
    
    db.prepare(`
      UPDATE policies 
      SET name = ?, description = ?, effect = ?, priority = ?, is_active = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(
      name || existing.name,
      description !== undefined ? description : existing.description,
      effect || existing.effect,
      priority !== undefined ? priority : existing.priority,
      is_active !== undefined ? (is_active ? 1 : 0) : existing.is_active,
      req.params.id
    );
    
    if (conditions && Array.isArray(conditions)) {
      db.prepare('DELETE FROM policy_conditions WHERE policy_id = ?').run(req.params.id);
      
      for (const condition of conditions) {
        if (!condition.subject_type || !condition.attribute_name || !condition.operator || condition.attribute_value === undefined) {
          continue;
        }
        db.prepare(`
          INSERT INTO policy_conditions (policy_id, subject_type, attribute_name, operator, attribute_value)
          VALUES (?, ?, ?, ?, ?)
        `).run(req.params.id, condition.subject_type, condition.attribute_name, condition.operator, String(condition.attribute_value));
      }
    }
    
    const savedConditions = db.prepare('SELECT * FROM policy_conditions WHERE policy_id = ?').all(req.params.id);
    const updated = db.prepare('SELECT * FROM policies WHERE id = ?').get(req.params.id);
    
    res.json({
      ...updated,
      is_active: Boolean(updated.is_active),
      conditions: savedConditions
    });
  } finally {
    db.close();
  }
});

// Delete policy
router.delete('/:id', async (req, res) => {
  const db = await getDatabase();
  try {
    const existing = db.prepare('SELECT id FROM policies WHERE id = ?').get(req.params.id);
    if (!existing) {
      return res.status(404).json({ error: 'Policy not found' });
    }
    
    db.prepare('DELETE FROM policy_conditions WHERE policy_id = ?').run(req.params.id);
    db.prepare('DELETE FROM policies WHERE id = ?').run(req.params.id);
    
    res.json({ message: 'Policy deleted successfully' });
  } finally {
    db.close();
  }
});

// Add condition to policy
router.post('/:id/conditions', async (req, res) => {
  const { subject_type, attribute_name, operator, attribute_value } = req.body;
  
  if (!subject_type || !attribute_name || !operator || attribute_value === undefined) {
    return res.status(400).json({ error: 'subject_type, attribute_name, operator, and attribute_value are required' });
  }

  const db = await getDatabase();
  try {
    const policy = db.prepare('SELECT * FROM policies WHERE id = ?').get(req.params.id);
    if (!policy) {
      return res.status(404).json({ error: 'Policy not found' });
    }
    
    const result = db.prepare(`
      INSERT INTO policy_conditions (policy_id, subject_type, attribute_name, operator, attribute_value)
      VALUES (?, ?, ?, ?, ?)
    `).run(req.params.id, subject_type, attribute_name, operator, String(attribute_value));
    
    res.status(201).json({
      id: result.lastInsertRowid,
      policy_id: req.params.id,
      subject_type,
      attribute_name,
      operator,
      attribute_value: String(attribute_value)
    });
  } finally {
    db.close();
  }
});

// Delete condition
router.delete('/:id/conditions/:conditionId', async (req, res) => {
  const db = await getDatabase();
  try {
    const existing = db.prepare('SELECT id FROM policy_conditions WHERE id = ? AND policy_id = ?')
      .get(req.params.conditionId, req.params.id);
    
    if (!existing) {
      return res.status(404).json({ error: 'Condition not found' });
    }
    
    db.prepare('DELETE FROM policy_conditions WHERE id = ? AND policy_id = ?')
      .run(req.params.conditionId, req.params.id);
    
    res.json({ message: 'Condition deleted successfully' });
  } finally {
    db.close();
  }
});

// Toggle policy active status
router.patch('/:id/toggle', async (req, res) => {
  const db = await getDatabase();
  try {
    const policy = db.prepare('SELECT * FROM policies WHERE id = ?').get(req.params.id);
    if (!policy) {
      return res.status(404).json({ error: 'Policy not found' });
    }
    
    const newStatus = policy.is_active ? 0 : 1;
    db.prepare('UPDATE policies SET is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
      .run(newStatus, req.params.id);
    
    res.json({ id: req.params.id, is_active: Boolean(newStatus) });
  } finally {
    db.close();
  }
});

module.exports = router;
