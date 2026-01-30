/**
 * Seed Script - Populate database with example data
 * 
 * This creates a realistic ABAC scenario with:
 * - Users in different departments with various clearance levels
 * - Resources (documents) with classifications
 * - Policies that demonstrate ABAC capabilities
 */

const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const { initializeDatabase, getDatabase } = require('./database');

async function seed() {
  // Ensure data directory exists
  const dataDir = path.join(__dirname, '../data');
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }

  // Initialize fresh database
  console.log('Initializing database...');
  await initializeDatabase();

  const db = await getDatabase();

  console.log('Seeding database with example data...\n');

// Create Users
const users = [
  {
    id: uuidv4(),
    username: 'alice',
    email: 'alice@company.com',
    attributes: {
      department: 'engineering',
      role: 'senior_engineer',
      clearance_level: '3',
      team: 'backend'
    }
  },
  {
    id: uuidv4(),
    username: 'bob',
    email: 'bob@company.com',
    attributes: {
      department: 'engineering',
      role: 'junior_engineer',
      clearance_level: '1',
      team: 'frontend'
    }
  },
  {
    id: uuidv4(),
    username: 'charlie',
    email: 'charlie@company.com',
    attributes: {
      department: 'hr',
      role: 'hr_manager',
      clearance_level: '2',
      team: 'recruitment'
    }
  },
  {
    id: uuidv4(),
    username: 'diana',
    email: 'diana@company.com',
    attributes: {
      department: 'finance',
      role: 'accountant',
      clearance_level: '2',
      team: 'accounting'
    }
  },
  {
    id: uuidv4(),
    username: 'eve',
    email: 'eve@company.com',
    attributes: {
      department: 'engineering',
      role: 'admin',
      clearance_level: '5',
      team: 'platform'
    }
  }
];

console.log('Creating users...');
const insertUser = db.prepare('INSERT INTO users (id, username, email) VALUES (?, ?, ?)');
const insertUserAttr = db.prepare('INSERT INTO user_attributes (user_id, attribute_name, attribute_value) VALUES (?, ?, ?)');

for (const user of users) {
  insertUser.run(user.id, user.username, user.email);
  for (const [name, value] of Object.entries(user.attributes)) {
    insertUserAttr.run(user.id, name, value);
  }
  console.log(`  Created user: ${user.username} (${user.attributes.role})`);
}

// Create Resources
const resources = [
  {
    id: uuidv4(),
    name: 'Engineering Docs',
    type: 'document',
    attributes: {
      department: 'engineering',
      classification: 'internal',
      sensitivity: '2'
    }
  },
  {
    id: uuidv4(),
    name: 'HR Policies',
    type: 'document',
    attributes: {
      department: 'hr',
      classification: 'confidential',
      sensitivity: '3'
    }
  },
  {
    id: uuidv4(),
    name: 'Financial Reports',
    type: 'document',
    attributes: {
      department: 'finance',
      classification: 'confidential',
      sensitivity: '4'
    }
  },
  {
    id: uuidv4(),
    name: 'Public Announcements',
    type: 'document',
    attributes: {
      department: 'all',
      classification: 'public',
      sensitivity: '1'
    }
  },
  {
    id: uuidv4(),
    name: 'System Architecture',
    type: 'document',
    attributes: {
      department: 'engineering',
      classification: 'restricted',
      sensitivity: '5'
    }
  }
];

console.log('\nCreating resources...');
const insertResource = db.prepare('INSERT INTO resources (id, name, type) VALUES (?, ?, ?)');
const insertResourceAttr = db.prepare('INSERT INTO resource_attributes (resource_id, attribute_name, attribute_value) VALUES (?, ?, ?)');

for (const resource of resources) {
  insertResource.run(resource.id, resource.name, resource.type);
  for (const [name, value] of Object.entries(resource.attributes)) {
    insertResourceAttr.run(resource.id, name, value);
  }
  console.log(`  Created resource: ${resource.name} (${resource.attributes.classification})`);
}

// Create Policies
const policies = [
  {
    id: uuidv4(),
    name: 'Public Access',
    description: 'Anyone can read public documents',
    effect: 'allow',
    priority: 1,
    conditions: [
      { subject_type: 'resource', attribute_name: 'classification', operator: 'equals', attribute_value: 'public' },
      { subject_type: 'action', attribute_name: 'action', operator: 'equals', attribute_value: 'read' }
    ]
  },
  {
    id: uuidv4(),
    name: 'Department Read Access',
    description: 'Users can read documents from their own department',
    effect: 'allow',
    priority: 10,
    conditions: [
      { subject_type: 'user', attribute_name: 'department', operator: 'equals', attribute_value: '${resource.department}' },
      { subject_type: 'action', attribute_name: 'action', operator: 'equals', attribute_value: 'read' }
    ]
  },
  {
    id: uuidv4(),
    name: 'Engineering Department Access',
    description: 'Engineering department members can read engineering docs',
    effect: 'allow',
    priority: 20,
    conditions: [
      { subject_type: 'user', attribute_name: 'department', operator: 'equals', attribute_value: 'engineering' },
      { subject_type: 'resource', attribute_name: 'department', operator: 'equals', attribute_value: 'engineering' },
      { subject_type: 'action', attribute_name: 'action', operator: 'in', attribute_value: 'read,update' }
    ]
  },
  {
    id: uuidv4(),
    name: 'High Clearance Full Access',
    description: 'Users with clearance level 5+ have full access to everything',
    effect: 'allow',
    priority: 100,
    conditions: [
      { subject_type: 'user', attribute_name: 'clearance_level', operator: 'greater_than', attribute_value: '4' }
    ]
  },
  {
    id: uuidv4(),
    name: 'Restricted Document Protection',
    description: 'Deny access to restricted documents for users with clearance below 4',
    effect: 'deny',
    priority: 50,
    conditions: [
      { subject_type: 'resource', attribute_name: 'classification', operator: 'equals', attribute_value: 'restricted' },
      { subject_type: 'user', attribute_name: 'clearance_level', operator: 'less_than', attribute_value: '4' }
    ]
  },
  {
    id: uuidv4(),
    name: 'Admin Full CRUD',
    description: 'Admins can perform all actions on any resource',
    effect: 'allow',
    priority: 90,
    conditions: [
      { subject_type: 'user', attribute_name: 'role', operator: 'equals', attribute_value: 'admin' }
    ]
  },
  {
    id: uuidv4(),
    name: 'Senior Engineer Create/Update',
    description: 'Senior engineers can create and update engineering documents',
    effect: 'allow',
    priority: 30,
    conditions: [
      { subject_type: 'user', attribute_name: 'role', operator: 'equals', attribute_value: 'senior_engineer' },
      { subject_type: 'resource', attribute_name: 'department', operator: 'equals', attribute_value: 'engineering' },
      { subject_type: 'action', attribute_name: 'action', operator: 'in', attribute_value: 'create,update' }
    ]
  },
  {
    id: uuidv4(),
    name: 'HR Confidential Access',
    description: 'HR managers can access confidential HR documents',
    effect: 'allow',
    priority: 25,
    conditions: [
      { subject_type: 'user', attribute_name: 'role', operator: 'equals', attribute_value: 'hr_manager' },
      { subject_type: 'resource', attribute_name: 'department', operator: 'equals', attribute_value: 'hr' }
    ]
  }
];

console.log('\nCreating policies...');
const insertPolicy = db.prepare('INSERT INTO policies (id, name, description, effect, priority) VALUES (?, ?, ?, ?, ?)');
const insertCondition = db.prepare('INSERT INTO policy_conditions (policy_id, subject_type, attribute_name, operator, attribute_value) VALUES (?, ?, ?, ?, ?)');

for (const policy of policies) {
  insertPolicy.run(policy.id, policy.name, policy.description, policy.effect, policy.priority);
  for (const condition of policy.conditions) {
    insertCondition.run(policy.id, condition.subject_type, condition.attribute_name, condition.operator, condition.attribute_value);
  }
  console.log(`  Created policy: ${policy.name} (${policy.effect}, priority: ${policy.priority})`);
}

// Set some environment attributes
console.log('\nSetting environment attributes...');
const insertEnv = db.prepare('INSERT OR REPLACE INTO environment_attributes (attribute_name, attribute_value) VALUES (?, ?)');
insertEnv.run('business_hours', 'true');
insertEnv.run('maintenance_mode', 'false');
console.log('  Set business_hours = true');
console.log('  Set maintenance_mode = false');

// ============================================
// CELL-LEVEL ACCESS CONTROL SEED DATA
// ============================================

console.log('\n--- Cell-Level Access Control Data ---');

// Create an "Employee Database" resource for demonstrating cell-level security
const employeeDbId = uuidv4();
db.prepare(`
  INSERT INTO resources (id, name, type, description) 
  VALUES (?, ?, ?, ?)
`).run(employeeDbId, 'Employee Database', 'database', 'Employee records with sensitive PII fields');

db.prepare(`
  INSERT INTO resource_attributes (resource_id, attribute_name, attribute_value) 
  VALUES (?, ?, ?)
`).run(employeeDbId, 'department', 'hr');

db.prepare(`
  INSERT INTO resource_attributes (resource_id, attribute_name, attribute_value) 
  VALUES (?, ?, ?)
`).run(employeeDbId, 'classification', '3');

console.log('\nCreated Employee Database resource');

// Define fields with different sensitivity levels
const fields = [
  { id: uuidv4(), name: 'employee_id', type: 'string', attrs: { sensitivity: 'low', pii: 'false' } },
  { id: uuidv4(), name: 'first_name', type: 'string', attrs: { sensitivity: 'low', pii: 'true' } },
  { id: uuidv4(), name: 'last_name', type: 'string', attrs: { sensitivity: 'low', pii: 'true' } },
  { id: uuidv4(), name: 'email', type: 'email', attrs: { sensitivity: 'medium', pii: 'true' } },
  { id: uuidv4(), name: 'phone', type: 'phone', attrs: { sensitivity: 'medium', pii: 'true' } },
  { id: uuidv4(), name: 'ssn', type: 'ssn', attrs: { sensitivity: 'high', pii: 'true', data_classification: 'confidential' } },
  { id: uuidv4(), name: 'salary', type: 'salary', attrs: { sensitivity: 'high', pii: 'true', data_classification: 'confidential' } },
  { id: uuidv4(), name: 'department', type: 'string', attrs: { sensitivity: 'low', pii: 'false' } },
  { id: uuidv4(), name: 'hire_date', type: 'date', attrs: { sensitivity: 'low', pii: 'false' } },
  { id: uuidv4(), name: 'performance_rating', type: 'number', attrs: { sensitivity: 'high', pii: 'false', data_classification: 'internal' } }
];

console.log('\nCreating fields for Employee Database...');
const insertField = db.prepare('INSERT INTO resource_fields (id, resource_id, field_name, field_type) VALUES (?, ?, ?, ?)');
const insertFieldAttr = db.prepare('INSERT INTO field_attributes (field_id, attribute_name, attribute_value) VALUES (?, ?, ?)');

for (const field of fields) {
  insertField.run(field.id, employeeDbId, field.name, field.type);
  for (const [attrName, attrValue] of Object.entries(field.attrs)) {
    insertFieldAttr.run(field.id, attrName, attrValue);
  }
  console.log(`  Created field: ${field.name} (${field.type}, sensitivity: ${field.attrs.sensitivity})`);
}

// Insert sample employee data
console.log('\nInserting sample employee data...');
const sampleEmployees = [
  { employee_id: 'EMP001', first_name: 'John', last_name: 'Smith', email: 'john.smith@company.com', phone: '555-123-4567', ssn: '123-45-6789', salary: '85000', department: 'Engineering', hire_date: '2020-03-15', performance_rating: '4' },
  { employee_id: 'EMP002', first_name: 'Jane', last_name: 'Doe', email: 'jane.doe@company.com', phone: '555-234-5678', ssn: '234-56-7890', salary: '92000', department: 'Engineering', hire_date: '2019-07-22', performance_rating: '5' },
  { employee_id: 'EMP003', first_name: 'Bob', last_name: 'Johnson', email: 'bob.j@company.com', phone: '555-345-6789', ssn: '345-67-8901', salary: '78000', department: 'Finance', hire_date: '2021-01-10', performance_rating: '3' }
];

const fieldMap = {};
fields.forEach(f => { fieldMap[f.name] = f.id; });

const insertData = db.prepare('INSERT INTO resource_data (resource_id, field_id, row_id, cell_value) VALUES (?, ?, ?, ?)');

for (const emp of sampleEmployees) {
  const rowId = uuidv4();
  for (const [fieldName, value] of Object.entries(emp)) {
    if (fieldMap[fieldName]) {
      insertData.run(employeeDbId, fieldMap[fieldName], rowId, value);
    }
  }
  console.log(`  Inserted employee: ${emp.first_name} ${emp.last_name}`);
}

// Create field-level policies
console.log('\nCreating field-level policies...');

const fieldPolicies = [
  {
    id: uuidv4(),
    name: 'Allow public fields to everyone',
    description: 'Non-sensitive fields are accessible to all authenticated users',
    effect: 'allow',
    priority: 10,
    conditions: [
      { subject_type: 'field', attribute_name: 'sensitivity', operator: 'equals', value: 'low' }
    ]
  },
  {
    id: uuidv4(),
    name: 'Mask medium sensitivity fields for non-HR',
    description: 'Email and phone are masked for users outside HR',
    effect: 'mask',
    priority: 20,
    conditions: [
      { subject_type: 'field', attribute_name: 'sensitivity', operator: 'equals', value: 'medium' },
      { subject_type: 'user', attribute_name: 'department', operator: 'not_equals', value: 'hr' }
    ]
  },
  {
    id: uuidv4(),
    name: 'Redact high sensitivity fields for low clearance',
    description: 'SSN and salary completely hidden for clearance < 3',
    effect: 'redact',
    mask_value: '***CONFIDENTIAL***',
    priority: 30,
    conditions: [
      { subject_type: 'field', attribute_name: 'sensitivity', operator: 'equals', value: 'high' },
      { subject_type: 'user', attribute_name: 'clearance_level', operator: 'less_than', value: '3' }
    ]
  },
  {
    id: uuidv4(),
    name: 'Mask SSN for medium clearance',
    description: 'Show last 4 digits of SSN for clearance level 3',
    effect: 'mask',
    priority: 25,
    field_pattern: 'ssn',
    conditions: [
      { subject_type: 'user', attribute_name: 'clearance_level', operator: 'equals', value: '3' }
    ]
  },
  {
    id: uuidv4(),
    name: 'Full access to HR managers',
    description: 'HR managers with high clearance see everything',
    effect: 'allow',
    priority: 100,
    conditions: [
      { subject_type: 'user', attribute_name: 'role', operator: 'equals', value: 'hr_manager' },
      { subject_type: 'user', attribute_name: 'clearance_level', operator: 'greater_than', value: '3' }
    ]
  },
  {
    id: uuidv4(),
    name: 'Deny PII to external users',
    description: 'External users cannot see any PII fields',
    effect: 'deny',
    priority: 200,
    conditions: [
      { subject_type: 'field', attribute_name: 'pii', operator: 'equals', value: 'true' },
      { subject_type: 'user', attribute_name: 'user_type', operator: 'equals', value: 'external' }
    ]
  }
];

const insertFieldPolicy = db.prepare('INSERT INTO field_policies (id, name, description, effect, mask_value, priority, field_pattern) VALUES (?, ?, ?, ?, ?, ?, ?)');
const insertFieldPolicyCondition = db.prepare('INSERT INTO field_policy_conditions (policy_id, subject_type, attribute_name, operator, attribute_value) VALUES (?, ?, ?, ?, ?)');

for (const policy of fieldPolicies) {
  insertFieldPolicy.run(policy.id, policy.name, policy.description, policy.effect, policy.mask_value || null, policy.priority, policy.field_pattern || null);
  for (const cond of policy.conditions) {
    insertFieldPolicyCondition.run(policy.id, cond.subject_type, cond.attribute_name, cond.operator, cond.value);
  }
  console.log(`  Created field policy: ${policy.name} (${policy.effect})`);
}

// Save database
db.save();

console.log('\n========================================');
console.log('Database seeded successfully!');
console.log('========================================\n');

console.log('Example Users:');
users.forEach(u => {
  console.log(`  - ${u.username} (${u.id})`);
});

console.log('\nExample Resources:');
resources.forEach(r => {
  console.log(`  - ${r.name} (${r.id})`);
});
console.log(`  - Employee Database (${employeeDbId}) [Cell-level demo]`);

console.log('\nTry these example API calls:');
console.log('\n# Check if alice can read Engineering Docs');
console.log(`curl -X POST http://localhost:3000/api/access/check \\
  -H "Content-Type: application/json" \\
  -d '{"user_id": "${users[0].id}", "resource_id": "${resources[0].id}", "action": "read"}'`);

console.log('\n# Get Employee Database with cell-level filtering for alice');
console.log(`curl "http://localhost:3000/api/cells/resources/${employeeDbId}/data?user_id=${users[0].id}"`);

console.log('\n# Get Employee Database with cell-level filtering for eve (HR)');
console.log(`curl "http://localhost:3000/api/cells/resources/${employeeDbId}/data?user_id=${users[4].id}"`);

  // Close database
  db.close();
}

// Run the seed function
seed().catch(err => {
  console.error('Seed failed:', err);
  process.exit(1);
});
