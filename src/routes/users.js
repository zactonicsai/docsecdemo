/**
 * User Routes - CRUD operations for users and their attributes (Async)
 */

const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { getDatabase } = require('../database');

const router = express.Router();

// List all users
router.get('/', async (req, res) => {
  const db = await getDatabase();
  try {
    const users = db.prepare('SELECT * FROM users ORDER BY created_at DESC').all();
    
    const usersWithAttrs = users.map(user => {
      const attrs = db.prepare('SELECT attribute_name, attribute_value FROM user_attributes WHERE user_id = ?')
        .all(user.id);
      return {
        ...user,
        attributes: attrs.reduce((acc, attr) => {
          acc[attr.attribute_name] = attr.attribute_value;
          return acc;
        }, {})
      };
    });
    
    res.json(usersWithAttrs);
  } finally {
    db.close();
  }
});

// Get single user
router.get('/:id', async (req, res) => {
  const db = await getDatabase();
  try {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const attrs = db.prepare('SELECT attribute_name, attribute_value FROM user_attributes WHERE user_id = ?')
      .all(user.id);
    
    res.json({
      ...user,
      attributes: attrs.reduce((acc, attr) => {
        acc[attr.attribute_name] = attr.attribute_value;
        return acc;
      }, {})
    });
  } finally {
    db.close();
  }
});

// Create user
router.post('/', async (req, res) => {
  const { username, email, attributes } = req.body;
  
  if (!username) {
    return res.status(400).json({ error: 'Username is required' });
  }

  const db = await getDatabase();
  try {
    const id = uuidv4();
    
    // Check if username exists
    const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
    if (existing) {
      return res.status(409).json({ error: 'Username already exists' });
    }
    
    db.prepare('INSERT INTO users (id, username, email) VALUES (?, ?, ?)')
      .run(id, username, email || null);
    
    if (attributes && typeof attributes === 'object') {
      for (const [name, value] of Object.entries(attributes)) {
        db.prepare('INSERT INTO user_attributes (user_id, attribute_name, attribute_value) VALUES (?, ?, ?)')
          .run(id, name, String(value));
      }
    }
    
    res.status(201).json({ id, username, email, attributes: attributes || {} });
  } finally {
    db.close();
  }
});

// Update user
router.put('/:id', async (req, res) => {
  const { username, email, attributes } = req.body;
  const db = await getDatabase();
  
  try {
    const existing = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
    if (!existing) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    db.prepare('UPDATE users SET username = ?, email = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
      .run(username || existing.username, email || existing.email, req.params.id);
    
    if (attributes && typeof attributes === 'object') {
      db.prepare('DELETE FROM user_attributes WHERE user_id = ?').run(req.params.id);
      
      for (const [name, value] of Object.entries(attributes)) {
        db.prepare('INSERT INTO user_attributes (user_id, attribute_name, attribute_value) VALUES (?, ?, ?)')
          .run(req.params.id, name, String(value));
      }
    }
    
    res.json({ id: req.params.id, username: username || existing.username, email: email || existing.email, attributes });
  } finally {
    db.close();
  }
});

// Delete user
router.delete('/:id', async (req, res) => {
  const db = await getDatabase();
  try {
    const existing = db.prepare('SELECT id FROM users WHERE id = ?').get(req.params.id);
    if (!existing) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    db.prepare('DELETE FROM user_attributes WHERE user_id = ?').run(req.params.id);
    db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
    
    res.json({ message: 'User deleted successfully' });
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
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Check if attribute exists
    const existingAttr = db.prepare('SELECT id FROM user_attributes WHERE user_id = ? AND attribute_name = ?')
      .get(req.params.id, req.params.attrName);
    
    if (existingAttr) {
      db.prepare('UPDATE user_attributes SET attribute_value = ? WHERE user_id = ? AND attribute_name = ?')
        .run(String(value), req.params.id, req.params.attrName);
    } else {
      db.prepare('INSERT INTO user_attributes (user_id, attribute_name, attribute_value) VALUES (?, ?, ?)')
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
    const existing = db.prepare('SELECT id FROM user_attributes WHERE user_id = ? AND attribute_name = ?')
      .get(req.params.id, req.params.attrName);
    
    if (!existing) {
      return res.status(404).json({ error: 'Attribute not found' });
    }
    
    db.prepare('DELETE FROM user_attributes WHERE user_id = ? AND attribute_name = ?')
      .run(req.params.id, req.params.attrName);
    
    res.json({ message: 'Attribute deleted successfully' });
  } finally {
    db.close();
  }
});

module.exports = router;
