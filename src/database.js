/**
 * ABAC/CBAC Database Schema using sql.js
 * 
 * This module defines the database schema for Attribute-Based Access Control.
 * Uses sql.js which is a pure JavaScript implementation of SQLite.
 */

const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, '../data/abac.db');

// Ensure data directory exists
const dataDir = path.dirname(DB_PATH);
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

let SQL = null;

async function initSql() {
  if (!SQL) {
    SQL = await initSqlJs();
  }
  return SQL;
}

async function loadDatabase() {
  const SQL = await initSql();
  
  try {
    if (fs.existsSync(DB_PATH)) {
      const buffer = fs.readFileSync(DB_PATH);
      return new SQL.Database(buffer);
    }
  } catch (err) {
    console.error('Error loading database:', err);
  }
  
  return new SQL.Database();
}

function saveDatabase(db) {
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(DB_PATH, buffer);
}

async function initializeDatabase() {
  const db = await loadDatabase();
  
  // Enable foreign keys
  db.run('PRAGMA foreign_keys = ON');
  
  // Create tables
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      email TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS user_attributes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      attribute_name TEXT NOT NULL,
      attribute_value TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      UNIQUE(user_id, attribute_name)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS resources (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS resource_attributes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      resource_id TEXT NOT NULL,
      attribute_name TEXT NOT NULL,
      attribute_value TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (resource_id) REFERENCES resources(id) ON DELETE CASCADE,
      UNIQUE(resource_id, attribute_name)
    )
  `);

  // ============================================
  // CELL/FIELD LEVEL ACCESS CONTROL TABLES
  // ============================================
  
  // Resource fields define the structure (schema) of a resource
  // Each field can have its own security classification
  db.run(`
    CREATE TABLE IF NOT EXISTS resource_fields (
      id TEXT PRIMARY KEY,
      resource_id TEXT NOT NULL,
      field_name TEXT NOT NULL,
      field_type TEXT DEFAULT 'string',
      description TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (resource_id) REFERENCES resources(id) ON DELETE CASCADE,
      UNIQUE(resource_id, field_name)
    )
  `);

  // Field-level attributes (e.g., classification, sensitivity, pii)
  db.run(`
    CREATE TABLE IF NOT EXISTS field_attributes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      field_id TEXT NOT NULL,
      attribute_name TEXT NOT NULL,
      attribute_value TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (field_id) REFERENCES resource_fields(id) ON DELETE CASCADE,
      UNIQUE(field_id, attribute_name)
    )
  `);

  // Actual data stored in resource fields (the cells)
  db.run(`
    CREATE TABLE IF NOT EXISTS resource_data (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      resource_id TEXT NOT NULL,
      field_id TEXT NOT NULL,
      row_id TEXT NOT NULL,
      cell_value TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (resource_id) REFERENCES resources(id) ON DELETE CASCADE,
      FOREIGN KEY (field_id) REFERENCES resource_fields(id) ON DELETE CASCADE,
      UNIQUE(resource_id, field_id, row_id)
    )
  `);

  // Field-level policies (which fields can be accessed)
  db.run(`
    CREATE TABLE IF NOT EXISTS field_policies (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      resource_type TEXT,
      field_pattern TEXT,
      effect TEXT NOT NULL CHECK(effect IN ('allow', 'deny', 'mask', 'redact')),
      mask_value TEXT DEFAULT '***REDACTED***',
      priority INTEGER DEFAULT 0,
      is_active INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Field policy conditions
  db.run(`
    CREATE TABLE IF NOT EXISTS field_policy_conditions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      policy_id TEXT NOT NULL,
      subject_type TEXT NOT NULL CHECK(subject_type IN ('user', 'resource', 'field', 'environment', 'action')),
      attribute_name TEXT NOT NULL,
      operator TEXT NOT NULL CHECK(operator IN ('equals', 'not_equals', 'contains', 'in', 'greater_than', 'less_than', 'matches')),
      attribute_value TEXT NOT NULL,
      FOREIGN KEY (policy_id) REFERENCES field_policies(id) ON DELETE CASCADE
    )
  `);

  // ============================================
  // ORIGINAL TABLES CONTINUED
  // ============================================

  db.run(`
    CREATE TABLE IF NOT EXISTS policies (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      effect TEXT NOT NULL CHECK(effect IN ('allow', 'deny')),
      priority INTEGER DEFAULT 0,
      is_active INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS policy_conditions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      policy_id TEXT NOT NULL,
      subject_type TEXT NOT NULL CHECK(subject_type IN ('user', 'resource', 'environment', 'action')),
      attribute_name TEXT NOT NULL,
      operator TEXT NOT NULL CHECK(operator IN ('equals', 'not_equals', 'contains', 'in', 'greater_than', 'less_than', 'matches')),
      attribute_value TEXT NOT NULL,
      FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE CASCADE
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS access_audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT,
      resource_id TEXT,
      field_id TEXT,
      action TEXT NOT NULL,
      decision TEXT NOT NULL CHECK(decision IN ('allow', 'deny', 'mask', 'redact')),
      policy_id TEXT,
      reason TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS environment_attributes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      attribute_name TEXT UNIQUE NOT NULL,
      attribute_value TEXT NOT NULL,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Create indexes
  db.run('CREATE INDEX IF NOT EXISTS idx_user_attributes_user_id ON user_attributes(user_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_user_attributes_name ON user_attributes(attribute_name)');
  db.run('CREATE INDEX IF NOT EXISTS idx_resource_attributes_resource_id ON resource_attributes(resource_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_policy_conditions_policy_id ON policy_conditions(policy_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON access_audit_log(user_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON access_audit_log(timestamp)');
  
  // Cell-level indexes
  db.run('CREATE INDEX IF NOT EXISTS idx_resource_fields_resource_id ON resource_fields(resource_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_field_attributes_field_id ON field_attributes(field_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_resource_data_resource_id ON resource_data(resource_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_resource_data_field_id ON resource_data(field_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_resource_data_row_id ON resource_data(row_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_field_policy_conditions ON field_policy_conditions(policy_id)');

  saveDatabase(db);
  db.close();
}

// Helper class to wrap sql.js with a more convenient API
class DatabaseWrapper {
  constructor(db) {
    this.db = db;
  }

  prepare(sql) {
    const db = this.db;
    return {
      run: (...params) => {
        db.run(sql, params);
        const changes = db.getRowsModified();
        let lastInsertRowid = null;
        try {
          const result = db.exec("SELECT last_insert_rowid()");
          if (result.length > 0 && result[0].values.length > 0) {
            lastInsertRowid = result[0].values[0][0];
          }
        } catch (e) {
          // Ignore
        }
        return { changes, lastInsertRowid };
      },
      get: (...params) => {
        const stmt = db.prepare(sql);
        stmt.bind(params);
        if (stmt.step()) {
          const row = stmt.getAsObject();
          stmt.free();
          return row;
        }
        stmt.free();
        return undefined;
      },
      all: (...params) => {
        const results = [];
        const stmt = db.prepare(sql);
        stmt.bind(params);
        while (stmt.step()) {
          results.push(stmt.getAsObject());
        }
        stmt.free();
        return results;
      }
    };
  }

  exec(sql) {
    this.db.run(sql);
  }

  save() {
    saveDatabase(this.db);
  }

  close() {
    saveDatabase(this.db);
    this.db.close();
  }
}

async function getDatabaseWrapper() {
  const db = await loadDatabase();
  return new DatabaseWrapper(db);
}

module.exports = { 
  initializeDatabase, 
  getDatabase: getDatabaseWrapper, 
  DB_PATH,
  loadDatabase,
  saveDatabase,
  DatabaseWrapper
};
