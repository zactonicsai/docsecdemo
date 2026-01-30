/**
 * ABAC Policy Evaluation Engine (Async version)
 * 
 * This module evaluates access requests against defined policies.
 * It implements a deny-overrides algorithm where:
 * 1. If any applicable policy explicitly denies, access is denied
 * 2. If at least one policy allows and none deny, access is allowed
 * 3. If no policies apply, access is denied by default
 */

const { getDatabase } = require('./database');

class PolicyEngine {
  constructor() {
    this.operators = {
      equals: (a, b) => String(a).toLowerCase() === String(b).toLowerCase(),
      not_equals: (a, b) => String(a).toLowerCase() !== String(b).toLowerCase(),
      contains: (a, b) => String(a).toLowerCase().includes(String(b).toLowerCase()),
      in: (a, b) => {
        const list = b.split(',').map(s => s.trim().toLowerCase());
        return list.includes(String(a).toLowerCase());
      },
      greater_than: (a, b) => Number(a) > Number(b),
      less_than: (a, b) => Number(a) < Number(b),
      matches: (a, b) => new RegExp(b, 'i').test(String(a))
    };
  }

  /**
   * Evaluate if a user can perform an action on a resource
   * @param {string} userId - The user requesting access
   * @param {string} resourceId - The resource being accessed
   * @param {string} action - The action (create, read, update, delete)
   * @returns {object} - { allowed: boolean, reason: string, policyId: string|null }
   */
  async evaluate(userId, resourceId, action) {
    const db = await getDatabase();
    
    try {
      // Get user attributes
      const userAttrs = this.getUserAttributes(db, userId);
      if (!userAttrs) {
        return this.logAndReturn(db, userId, resourceId, action, false, null, 'User not found');
      }

      // Get resource attributes
      const resourceAttrs = this.getResourceAttributes(db, resourceId);
      if (!resourceAttrs) {
        return this.logAndReturn(db, userId, resourceId, action, false, null, 'Resource not found');
      }

      // Get environment attributes
      const envAttrs = this.getEnvironmentAttributes(db);

      // Get all active policies ordered by priority (higher priority first)
      const policies = db.prepare(`
        SELECT * FROM policies 
        WHERE is_active = 1 
        ORDER BY priority DESC, created_at ASC
      `).all();

      let allowingPolicy = null;
      
      for (const policy of policies) {
        const conditions = db.prepare(`
          SELECT * FROM policy_conditions WHERE policy_id = ?
        `).all(policy.id);

        const matches = this.evaluateConditions(conditions, userAttrs, resourceAttrs, envAttrs, action);
        
        if (matches) {
          if (policy.effect === 'deny') {
            // Deny takes precedence
            return this.logAndReturn(db, userId, resourceId, action, false, policy.id, 
              `Denied by policy: ${policy.name}`);
          } else if (!allowingPolicy) {
            allowingPolicy = policy;
          }
        }
      }

      if (allowingPolicy) {
        return this.logAndReturn(db, userId, resourceId, action, true, allowingPolicy.id,
          `Allowed by policy: ${allowingPolicy.name}`);
      }

      // Default deny
      return this.logAndReturn(db, userId, resourceId, action, false, null, 
        'No applicable policy found - default deny');
    } finally {
      db.close();
    }
  }

  /**
   * Evaluate all conditions for a policy
   */
  evaluateConditions(conditions, userAttrs, resourceAttrs, envAttrs, action) {
    if (conditions.length === 0) return false;

    // All conditions must match (AND logic)
    return conditions.every(condition => {
      let actualValue;
      
      switch (condition.subject_type) {
        case 'user':
          actualValue = userAttrs[condition.attribute_name];
          break;
        case 'resource':
          actualValue = resourceAttrs[condition.attribute_name];
          break;
        case 'environment':
          actualValue = envAttrs[condition.attribute_name];
          break;
        case 'action':
          actualValue = action;
          break;
        default:
          return false;
      }

      if (actualValue === undefined || actualValue === null) {
        return false;
      }

      const operator = this.operators[condition.operator];
      if (!operator) return false;

      return operator(actualValue, condition.attribute_value);
    });
  }

  getUserAttributes(db, userId) {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    if (!user) return null;

    const attrs = db.prepare('SELECT attribute_name, attribute_value FROM user_attributes WHERE user_id = ?')
      .all(userId);
    
    const result = { id: user.id, username: user.username, email: user.email };
    attrs.forEach(attr => {
      result[attr.attribute_name] = attr.attribute_value;
    });
    return result;
  }

  getResourceAttributes(db, resourceId) {
    const resource = db.prepare('SELECT * FROM resources WHERE id = ?').get(resourceId);
    if (!resource) return null;

    const attrs = db.prepare('SELECT attribute_name, attribute_value FROM resource_attributes WHERE resource_id = ?')
      .all(resourceId);
    
    const result = { id: resource.id, name: resource.name, type: resource.type };
    attrs.forEach(attr => {
      result[attr.attribute_name] = attr.attribute_value;
    });
    return result;
  }

  getEnvironmentAttributes(db) {
    const attrs = db.prepare('SELECT attribute_name, attribute_value FROM environment_attributes').all();
    const result = {
      current_time: new Date().toISOString(),
      current_hour: new Date().getHours(),
      current_day: new Date().toLocaleDateString('en-US', { weekday: 'long' }).toLowerCase()
    };
    attrs.forEach(attr => {
      result[attr.attribute_name] = attr.attribute_value;
    });
    return result;
  }

  logAndReturn(db, userId, resourceId, action, allowed, policyId, reason) {
    // Log the access decision
    db.prepare(`
      INSERT INTO access_audit_log (user_id, resource_id, action, decision, policy_id, reason)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(userId, resourceId, action, allowed ? 'allow' : 'deny', policyId, reason);

    return { allowed, reason, policyId };
  }

  /**
   * Check access without logging (for UI/preview purposes)
   */
  async checkAccess(userId, resourceId, action) {
    const db = await getDatabase();
    
    try {
      const userAttrs = this.getUserAttributes(db, userId);
      if (!userAttrs) return { allowed: false, reason: 'User not found' };

      const resourceAttrs = this.getResourceAttributes(db, resourceId);
      if (!resourceAttrs) return { allowed: false, reason: 'Resource not found' };

      const envAttrs = this.getEnvironmentAttributes(db);

      const policies = db.prepare(`
        SELECT * FROM policies WHERE is_active = 1 ORDER BY priority DESC
      `).all();

      let allowingPolicy = null;
      
      for (const policy of policies) {
        const conditions = db.prepare(`
          SELECT * FROM policy_conditions WHERE policy_id = ?
        `).all(policy.id);

        if (this.evaluateConditions(conditions, userAttrs, resourceAttrs, envAttrs, action)) {
          if (policy.effect === 'deny') {
            return { allowed: false, reason: `Denied by policy: ${policy.name}`, policy };
          } else if (!allowingPolicy) {
            allowingPolicy = policy;
          }
        }
      }

      if (allowingPolicy) {
        return { allowed: true, reason: `Allowed by policy: ${allowingPolicy.name}`, policy: allowingPolicy };
      }

      return { allowed: false, reason: 'No applicable policy - default deny' };
    } finally {
      db.close();
    }
  }
}

module.exports = new PolicyEngine();
