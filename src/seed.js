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

db.close();

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

console.log('\nTry these example API calls:');
console.log('\n# Check if alice can read Engineering Docs');
console.log(`curl -X POST http://localhost:3000/api/access/check \\
  -H "Content-Type: application/json" \\
  -d '{"userId": "${users[0].id}", "resourceId": "${resources[0].id}", "action": "read"}'`);

console.log('\n# Check if bob can read Financial Reports');
console.log(`curl -X POST http://localhost:3000/api/access/check \\
  -H "Content-Type: application/json" \\
  -d '{"userId": "${users[1].id}", "resourceId": "${resources[2].id}", "action": "read"}'`);

console.log('\n# Get all permissions for eve on System Architecture');
console.log(`curl http://localhost:3000/api/access/permissions/${users[4].id}/${resources[4].id}`);

  // Save and close database
  db.close();
}

// Run the seed function
seed().catch(err => {
  console.error('Seed failed:', err);
  process.exit(1);
});
