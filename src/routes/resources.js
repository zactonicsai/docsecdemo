/**
 * Resource Routes - CRUD operations for resources and their attributes (Async)
 */

const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { getDatabase } = require('../database');

const router = express.Router();

// List all resources
router.get('/', async (req, res) => {
  const db = await getDatabase();
  try {
    const resources = db.prepare('SELECT * FROM resources ORDER BY created_at DESC').all();
    
    const resourcesWithAttrs = resources.map(resource => {
      const attrs = db.prepare('SELECT attribute_name, attribute_value FROM resource_attributes WHERE resource_id = ?')
        .all(resource.id);
      return {
        ...resource,
        attributes: attrs.reduce((acc, attr) => {
          acc[attr.attribute_name] = attr.attribute_value;
          return acc;
        }, {})
      };
    });
    
    res.json(resourcesWithAttrs);
  } finally {
    db.close();
  }
});

// Get single resource
router.get('/:id', async (req, res) => {
  const db = await getDatabase();
  try {
    const resource = db.prepare('SELECT * FROM resources WHERE id = ?').get(req.params.id);
    if (!resource) {
      return res.status(404).json({ error: 'Resource not found' });
    }
    
    const attrs = db.prepare('SELECT attribute_name, attribute_value FROM resource_attributes WHERE resource_id = ?')
      .all(resource.id);
    
    res.json({
      ...resource,
      attributes: attrs.reduce((acc, attr) => {
        acc[attr.attribute_name] = attr.attribute_value;
        return acc;
      }, {})
    });
  } finally {
    db.close();
  }
});

// Create resource
router.post('/', async (req, res) => {
  const { name, type, attributes } = req.body;
  
  if (!name || !type) {
    return res.status(400).json({ error: 'Name and type are required' });
  }

  const db = await getDatabase();
  try {
    const id = uuidv4();
    
    db.prepare('INSERT INTO resources (id, name, type) VALUES (?, ?, ?)')
      .run(id, name, type);
    
    if (attributes && typeof attributes === 'object') {
      for (const [attrName, value] of Object.entries(attributes)) {
        db.prepare('INSERT INTO resource_attributes (resource_id, attribute_name, attribute_value) VALUES (?, ?, ?)')
          .run(id, attrName, String(value));
      }
    }
    
    res.status(201).json({ id, name, type, attributes: attributes || {} });
  } finally {
    db.close();
  }
});

// Update resource
router.put('/:id', async (req, res) => {
  const { name, type, attributes } = req.body;
  const db = await getDatabase();
  
  try {
    const existing = db.prepare('SELECT * FROM resources WHERE id = ?').get(req.params.id);
    if (!existing) {
      return res.status(404).json({ error: 'Resource not found' });
    }
    
    db.prepare('UPDATE resources SET name = ?, type = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
      .run(name || existing.name, type || existing.type, req.params.id);
    
    if (attributes && typeof attributes === 'object') {
      db.prepare('DELETE FROM resource_attributes WHERE resource_id = ?').run(req.params.id);
      
      for (const [attrName, value] of Object.entries(attributes)) {
        db.prepare('INSERT INTO resource_attributes (resource_id, attribute_name, attribute_value) VALUES (?, ?, ?)')
          .run(req.params.id, attrName, String(value));
      }
    }
    
    res.json({ id: req.params.id, name: name || existing.name, type: type || existing.type, attributes });
  } finally {
    db.close();
  }
});

// Delete resource
router.delete('/:id', async (req, res) => {
  const db = await getDatabase();
  try {
    const existing = db.prepare('SELECT id FROM resources WHERE id = ?').get(req.params.id);
    if (!existing) {
      return res.status(404).json({ error: 'Resource not found' });
    }
    
    db.prepare('DELETE FROM resource_attributes WHERE resource_id = ?').run(req.params.id);
    db.prepare('DELETE FROM resources WHERE id = ?').run(req.params.id);
    
    res.json({ message: 'Resource deleted successfully' });
  } finally {
    db.close();
  }
});

// Add/Update single attribute
router.put('/:id/attributes/:attrName', async (req, res) => {
  const { value } = req.body;
  
  if (value === undefined) {
    return res.status(400).json({ error: 'Attribute value is required' });
  }

  const db = await getDatabase();
  try {
    const resource = db.prepare('SELECT * FROM resources WHERE id = ?').get(req.params.id);
    if (!resource) {
      return res.status(404).json({ error: 'Resource not found' });
    }
    
    const existingAttr = db.prepare('SELECT id FROM resource_attributes WHERE resource_id = ? AND attribute_name = ?')
      .get(req.params.id, req.params.attrName);
    
    if (existingAttr) {
      db.prepare('UPDATE resource_attributes SET attribute_value = ? WHERE resource_id = ? AND attribute_name = ?')
        .run(String(value), req.params.id, req.params.attrName);
    } else {
      db.prepare('INSERT INTO resource_attributes (resource_id, attribute_name, attribute_value) VALUES (?, ?, ?)')
        .run(req.params.id, req.params.attrName, String(value));
    }
    
    res.json({ attribute: req.params.attrName, value: String(value) });
  } finally {
    db.close();
  }
});

// Delete single attribute
router.delete('/:id/attributes/:attrName', async (req, res) => {
  const db = await getDatabase();
  try {
    const existing = db.prepare('SELECT id FROM resource_attributes WHERE resource_id = ? AND attribute_name = ?')
      .get(req.params.id, req.params.attrName);
    
    if (!existing) {
      return res.status(404).json({ error: 'Attribute not found' });
    }
    
    db.prepare('DELETE FROM resource_attributes WHERE resource_id = ? AND attribute_name = ?')
      .run(req.params.id, req.params.attrName);
    
    res.json({ message: 'Attribute deleted successfully' });
  } finally {
    db.close();
  }
});

module.exports = router;
