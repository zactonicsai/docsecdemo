/**
 * Access Control Routes - Evaluate access and view audit logs (Async)
 */

const express = require('express');
const { getDatabase } = require('../database');
const policyEngine = require('../policy-engine');

const router = express.Router();

/**
 * Check if a user can perform an action on a resource
 * POST /api/access/check
 * Body: { userId, resourceId, action }
 */
router.post('/check', async (req, res) => {
  const { userId, resourceId, action } = req.body;
  
  if (!userId || !resourceId || !action) {
    return res.status(400).json({ 
      error: 'userId, resourceId, and action are required' 
    });
  }
  
  const validActions = ['create', 'read', 'update', 'delete'];
  if (!validActions.includes(action.toLowerCase())) {
    return res.status(400).json({ 
      error: `Invalid action. Must be one of: ${validActions.join(', ')}` 
    });
  }
  
  const result = await policyEngine.checkAccess(userId, resourceId, action.toLowerCase());
  res.json(result);
});

/**
 * Evaluate and log access decision
 * POST /api/access/evaluate
 * Body: { userId, resourceId, action }
 */
router.post('/evaluate', async (req, res) => {
  const { userId, resourceId, action } = req.body;
  
  if (!userId || !resourceId || !action) {
    return res.status(400).json({ 
      error: 'userId, resourceId, and action are required' 
    });
  }
  
  const validActions = ['create', 'read', 'update', 'delete'];
  if (!validActions.includes(action.toLowerCase())) {
    return res.status(400).json({ 
      error: `Invalid action. Must be one of: ${validActions.join(', ')}` 
    });
  }
  
  const result = await policyEngine.evaluate(userId, resourceId, action.toLowerCase());
  
  if (result.allowed) {
    res.json(result);
  } else {
    res.status(403).json(result);
  }
});

/**
 * Batch check multiple access requests
 * POST /api/access/batch-check
 * Body: { requests: [{ userId, resourceId, action }, ...] }
 */
router.post('/batch-check', async (req, res) => {
  const { requests } = req.body;
  
  if (!Array.isArray(requests)) {
    return res.status(400).json({ error: 'requests must be an array' });
  }
  
  const results = [];
  for (const request of requests) {
    const { userId, resourceId, action } = request;
    if (!userId || !resourceId || !action) {
      results.push({ ...request, error: 'Missing required fields' });
    } else {
      const result = await policyEngine.checkAccess(userId, resourceId, action.toLowerCase());
      results.push({ ...request, ...result });
    }
  }
  
  res.json(results);
});

/**
 * Get what actions a user can perform on a resource
 * GET /api/access/permissions/:userId/:resourceId
 */
router.get('/permissions/:userId/:resourceId', async (req, res) => {
  const { userId, resourceId } = req.params;
  
  const actions = ['create', 'read', 'update', 'delete'];
  const permissions = {};
  const details = [];
  
  for (const action of actions) {
    const result = await policyEngine.checkAccess(userId, resourceId, action);
    permissions[action] = result.allowed;
    details.push({ action, ...result });
  }
  
  res.json({
    userId,
    resourceId,
    permissions,
    details
  });
});

/**
 * Get audit log
 * GET /api/access/audit
 * Query params: userId, resourceId, action, decision, limit, offset
 */
router.get('/audit', async (req, res) => {
  const { userId, resourceId, action, decision, limit = 100, offset = 0 } = req.query;
  
  const db = await getDatabase();
  try {
    let query = 'SELECT * FROM access_audit_log WHERE 1=1';
    const params = [];
    
    if (userId) {
      query += ' AND user_id = ?';
      params.push(userId);
    }
    if (resourceId) {
      query += ' AND resource_id = ?';
      params.push(resourceId);
    }
    if (action) {
      query += ' AND action = ?';
      params.push(action);
    }
    if (decision) {
      query += ' AND decision = ?';
      params.push(decision);
    }
    
    query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?';
    params.push(Number(limit), Number(offset));
    
    const logs = db.prepare(query).all(...params);
    
    // Get total count
    let countQuery = 'SELECT COUNT(*) as total FROM access_audit_log WHERE 1=1';
    const countParams = [];
    if (userId) {
      countQuery += ' AND user_id = ?';
      countParams.push(userId);
    }
    if (resourceId) {
      countQuery += ' AND resource_id = ?';
      countParams.push(resourceId);
    }
    if (action) {
      countQuery += ' AND action = ?';
      countParams.push(action);
    }
    if (decision) {
      countQuery += ' AND decision = ?';
      countParams.push(decision);
    }
    
    const countResult = db.prepare(countQuery).get(...countParams);
    const total = countResult ? countResult.total : 0;
    
    res.json({
      logs,
      pagination: {
        total,
        limit: Number(limit),
        offset: Number(offset),
        hasMore: Number(offset) + logs.length < total
      }
    });
  } finally {
    db.close();
  }
});

/**
 * Get audit statistics
 * GET /api/access/audit/stats
 */
router.get('/audit/stats', async (req, res) => {
  const db = await getDatabase();
  try {
    const totalResult = db.prepare('SELECT COUNT(*) as count FROM access_audit_log').get();
    const allowedResult = db.prepare("SELECT COUNT(*) as count FROM access_audit_log WHERE decision = 'allow'").get();
    const deniedResult = db.prepare("SELECT COUNT(*) as count FROM access_audit_log WHERE decision = 'deny'").get();
    
    const byAction = db.prepare(`
      SELECT action, decision, COUNT(*) as count 
      FROM access_audit_log 
      GROUP BY action, decision
    `).all();
    
    const recentActivity = db.prepare(`
      SELECT DATE(timestamp) as date, COUNT(*) as count 
      FROM access_audit_log 
      GROUP BY DATE(timestamp) 
      ORDER BY date DESC 
      LIMIT 7
    `).all();
    
    res.json({
      totalDecisions: totalResult ? totalResult.count : 0,
      allowedCount: allowedResult ? allowedResult.count : 0,
      deniedCount: deniedResult ? deniedResult.count : 0,
      byAction,
      recentActivity
    });
  } finally {
    db.close();
  }
});

/**
 * Clear audit log (admin operation)
 * DELETE /api/access/audit
 */
router.delete('/audit', async (req, res) => {
  const { before } = req.query;
  
  const db = await getDatabase();
  try {
    let deletedCount = 0;
    
    if (before) {
      const countBefore = db.prepare('SELECT COUNT(*) as count FROM access_audit_log WHERE timestamp < ?').get(before);
      deletedCount = countBefore ? countBefore.count : 0;
      db.prepare('DELETE FROM access_audit_log WHERE timestamp < ?').run(before);
    } else {
      const countAll = db.prepare('SELECT COUNT(*) as count FROM access_audit_log').get();
      deletedCount = countAll ? countAll.count : 0;
      db.prepare('DELETE FROM access_audit_log').run();
    }
    
    res.json({ 
      message: 'Audit log cleared', 
      deletedCount 
    });
  } finally {
    db.close();
  }
});

module.exports = router;
