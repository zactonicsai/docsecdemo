/**
 * API Test Script
 * 
 * Run with: node src/test-api.js
 * Make sure the server is running first!
 */

const BASE_URL = process.env.API_URL || 'http://localhost:3000';

async function request(method, path, body = null) {
  const options = {
    method,
    headers: { 'Content-Type': 'application/json' }
  };
  if (body) {
    options.body = JSON.stringify(body);
  }
  
  const response = await fetch(`${BASE_URL}${path}`, options);
  const data = await response.json();
  return { status: response.status, data };
}

async function runTests() {
  console.log('='.repeat(60));
  console.log('ABAC/CBAC API Test Suite');
  console.log('='.repeat(60));
  console.log(`Testing against: ${BASE_URL}\n`);

  let userId, resourceId, policyId;

  // Test 1: Create User
  console.log('TEST 1: Create User');
  console.log('-'.repeat(40));
  const createUserResult = await request('POST', '/api/users', {
    username: 'testuser',
    email: 'test@example.com',
    attributes: {
      department: 'engineering',
      role: 'developer',
      clearance_level: '2'
    }
  });
  console.log('Status:', createUserResult.status);
  console.log('Response:', JSON.stringify(createUserResult.data, null, 2));
  userId = createUserResult.data.id;
  console.log();

  // Test 2: Get User
  console.log('TEST 2: Get User');
  console.log('-'.repeat(40));
  const getUserResult = await request('GET', `/api/users/${userId}`);
  console.log('Status:', getUserResult.status);
  console.log('Response:', JSON.stringify(getUserResult.data, null, 2));
  console.log();

  // Test 3: Update User Attribute
  console.log('TEST 3: Update User Attribute');
  console.log('-'.repeat(40));
  const updateAttrResult = await request('PUT', `/api/users/${userId}/attributes/clearance_level`, {
    value: '3'
  });
  console.log('Status:', updateAttrResult.status);
  console.log('Response:', JSON.stringify(updateAttrResult.data, null, 2));
  console.log();

  // Test 4: Create Resource
  console.log('TEST 4: Create Resource');
  console.log('-'.repeat(40));
  const createResourceResult = await request('POST', '/api/resources', {
    name: 'Test Document',
    type: 'document',
    attributes: {
      department: 'engineering',
      classification: 'internal',
      sensitivity: '2'
    }
  });
  console.log('Status:', createResourceResult.status);
  console.log('Response:', JSON.stringify(createResourceResult.data, null, 2));
  resourceId = createResourceResult.data.id;
  console.log();

  // Test 5: Create Policy
  console.log('TEST 5: Create Policy');
  console.log('-'.repeat(40));
  const createPolicyResult = await request('POST', '/api/policies', {
    name: 'Test Policy - Engineer Read',
    description: 'Allow engineers to read internal engineering docs',
    effect: 'allow',
    priority: 15,
    conditions: [
      { subject_type: 'user', attribute_name: 'department', operator: 'equals', attribute_value: 'engineering' },
      { subject_type: 'resource', attribute_name: 'department', operator: 'equals', attribute_value: 'engineering' },
      { subject_type: 'resource', attribute_name: 'classification', operator: 'equals', attribute_value: 'internal' },
      { subject_type: 'action', attribute_name: 'action', operator: 'equals', attribute_value: 'read' }
    ]
  });
  console.log('Status:', createPolicyResult.status);
  console.log('Response:', JSON.stringify(createPolicyResult.data, null, 2));
  policyId = createPolicyResult.data.id;
  console.log();

  // Test 6: Check Access (should be allowed)
  console.log('TEST 6: Check Access (should be ALLOWED)');
  console.log('-'.repeat(40));
  const checkAllowedResult = await request('POST', '/api/access/check', {
    userId,
    resourceId,
    action: 'read'
  });
  console.log('Status:', checkAllowedResult.status);
  console.log('Response:', JSON.stringify(checkAllowedResult.data, null, 2));
  console.log('Result:', checkAllowedResult.data.allowed ? '✅ ALLOWED' : '❌ DENIED');
  console.log();

  // Test 7: Check Access (should be denied - wrong action)
  console.log('TEST 7: Check Access (should be DENIED - wrong action)');
  console.log('-'.repeat(40));
  const checkDeniedResult = await request('POST', '/api/access/check', {
    userId,
    resourceId,
    action: 'delete'
  });
  console.log('Status:', checkDeniedResult.status);
  console.log('Response:', JSON.stringify(checkDeniedResult.data, null, 2));
  console.log('Result:', checkDeniedResult.data.allowed ? '✅ ALLOWED' : '❌ DENIED');
  console.log();

  // Test 8: Get All Permissions
  console.log('TEST 8: Get All Permissions for User on Resource');
  console.log('-'.repeat(40));
  const permissionsResult = await request('GET', `/api/access/permissions/${userId}/${resourceId}`);
  console.log('Status:', permissionsResult.status);
  console.log('Permissions:', JSON.stringify(permissionsResult.data.permissions, null, 2));
  console.log();

  // Test 9: Batch Check
  console.log('TEST 9: Batch Check Access');
  console.log('-'.repeat(40));
  const batchResult = await request('POST', '/api/access/batch-check', {
    requests: [
      { userId, resourceId, action: 'create' },
      { userId, resourceId, action: 'read' },
      { userId, resourceId, action: 'update' },
      { userId, resourceId, action: 'delete' }
    ]
  });
  console.log('Status:', batchResult.status);
  batchResult.data.forEach(r => {
    console.log(`  ${r.action}: ${r.allowed ? '✅ ALLOWED' : '❌ DENIED'}`);
  });
  console.log();

  // Test 10: Evaluate with Audit Logging
  console.log('TEST 10: Evaluate Access (with audit logging)');
  console.log('-'.repeat(40));
  const evaluateResult = await request('POST', '/api/access/evaluate', {
    userId,
    resourceId,
    action: 'read'
  });
  console.log('Status:', evaluateResult.status);
  console.log('Response:', JSON.stringify(evaluateResult.data, null, 2));
  console.log();

  // Test 11: View Audit Log
  console.log('TEST 11: View Audit Log');
  console.log('-'.repeat(40));
  const auditResult = await request('GET', '/api/access/audit?limit=5');
  console.log('Status:', auditResult.status);
  console.log('Recent Audit Entries:', auditResult.data.logs.length);
  if (auditResult.data.logs.length > 0) {
    console.log('Latest Entry:', JSON.stringify(auditResult.data.logs[0], null, 2));
  }
  console.log();

  // Test 12: List All Policies
  console.log('TEST 12: List All Policies');
  console.log('-'.repeat(40));
  const policiesResult = await request('GET', '/api/policies');
  console.log('Status:', policiesResult.status);
  console.log('Total Policies:', policiesResult.data.length);
  policiesResult.data.forEach(p => {
    console.log(`  - ${p.name} (${p.effect}, priority: ${p.priority})`);
  });
  console.log();

  // Cleanup
  console.log('CLEANUP: Deleting test data...');
  console.log('-'.repeat(40));
  await request('DELETE', `/api/policies/${policyId}`);
  console.log('  Deleted test policy');
  await request('DELETE', `/api/resources/${resourceId}`);
  console.log('  Deleted test resource');
  await request('DELETE', `/api/users/${userId}`);
  console.log('  Deleted test user');

  console.log('\n' + '='.repeat(60));
  console.log('All tests completed!');
  console.log('='.repeat(60));
}

runTests().catch(console.error);
