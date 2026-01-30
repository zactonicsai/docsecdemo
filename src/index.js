/**
 * ABAC/CBAC System - Main Application Entry Point
 * 
 * This is an Attribute-Based Access Control system that provides:
 * - User management with dynamic attributes (claims)
 * - Resource management with attributes
 * - Policy definition and management
 * - Access control evaluation
 * - Audit logging
 * - Keycloak integration for authentication
 */

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { initializeDatabase } = require('./database');
const { authenticate, requireRole, optionalAuth } = require('./middleware/auth');

// Import routes
const usersRouter = require('./routes/users');
const resourcesRouter = require('./routes/resources');
const policiesRouter = require('./routes/policies');
const accessRouter = require('./routes/access');
const cellsRouter = require('./routes/cells');
const searchRouter = require('./routes/search');

const app = express();
const PORT = process.env.PORT || 3000;

// CORS configuration
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// Middleware
app.use(express.json());

// Request logging with user info
app.use((req, res, next) => {
  const user = req.user ? req.user.preferred_username || req.user.sub : 'anonymous';
  console.log(`${new Date().toISOString()} ${req.method} ${req.path} [${user}]`);
  next();
});

// Public routes (no authentication required)
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    auth_enabled: process.env.DISABLE_AUTH !== 'true',
    keycloak_url: process.env.KEYCLOAK_URL || 'http://localhost:8080',
    keycloak_realm: process.env.KEYCLOAK_REALM || 'abac-realm'
  });
});

// Token info endpoint (for debugging)
app.get('/api/token-info', authenticate, (req, res) => {
  res.json({
    user: req.user,
    roles: {
      realm: req.user.realm_access?.roles || [],
      client: req.user.resource_access?.['abac-api']?.roles || []
    }
  });
});

// Protected API Routes (require authentication)
app.use('/api/users', authenticate, usersRouter);
app.use('/api/resources', authenticate, resourcesRouter);
app.use('/api/policies', authenticate, requireRole(['admin', 'policy-manager']), policiesRouter);
app.use('/api/access', authenticate, accessRouter);
app.use('/api/cells', authenticate, cellsRouter);  // Cell-level access control
app.use('/api/search', authenticate, searchRouter);  // Full-text search with cell-level filtering

// API documentation
app.get('/', (req, res) => {
  res.json({
    name: 'ABAC/CBAC Access Control System',
    version: '1.0.0',
    description: 'Attribute-Based Access Control API with Keycloak Security',
    authentication: {
      type: 'OAuth2/OpenID Connect',
      provider: 'Keycloak',
      keycloak_url: process.env.KEYCLOAK_URL || 'http://localhost:8080',
      realm: process.env.KEYCLOAK_REALM || 'abac-realm',
      token_endpoint: `${process.env.KEYCLOAK_URL || 'http://localhost:8080'}/realms/${process.env.KEYCLOAK_REALM || 'abac-realm'}/protocol/openid-connect/token`,
      clients: {
        'abac-webapp': 'For web applications (confidential client)',
        'abac-cli': 'For CLI tools (public client)',
        'abac-service': 'For service-to-service auth (client credentials)'
      },
      sample_users: {
        admin: { password: 'admin123', roles: ['admin'] },
        alice: { password: 'alice123', roles: ['policy-manager'] },
        bob: { password: 'bob123', roles: ['user-manager'] },
        charlie: { password: 'charlie123', roles: ['auditor'] },
        viewer: { password: 'viewer123', roles: ['user'] }
      }
    },
    endpoints: {
      public: {
        'GET /health': 'Health check (no auth required)',
        'GET /': 'This documentation (no auth required)'
      },
      authenticated: {
        'GET /api/token-info': 'View your token info'
      },
      users: {
        'GET /api/users': 'List all users with their attributes',
        'GET /api/users/:id': 'Get a specific user',
        'POST /api/users': 'Create a new user',
        'PUT /api/users/:id': 'Update a user',
        'DELETE /api/users/:id': 'Delete a user',
        'PUT /api/users/:id/attributes/:name': 'Set a user attribute',
        'DELETE /api/users/:id/attributes/:name': 'Remove a user attribute'
      },
      resources: {
        'GET /api/resources': 'List all resources',
        'GET /api/resources/:id': 'Get a specific resource',
        'POST /api/resources': 'Create a new resource',
        'PUT /api/resources/:id': 'Update a resource',
        'DELETE /api/resources/:id': 'Delete a resource',
        'PUT /api/resources/:id/attributes/:name': 'Set a resource attribute',
        'DELETE /api/resources/:id/attributes/:name': 'Remove a resource attribute'
      },
      policies: {
        note: 'Requires admin or policy-manager role',
        'GET /api/policies': 'List all policies',
        'GET /api/policies/:id': 'Get a specific policy',
        'POST /api/policies': 'Create a new policy',
        'PUT /api/policies/:id': 'Update a policy',
        'DELETE /api/policies/:id': 'Delete a policy',
        'POST /api/policies/:id/conditions': 'Add a condition to a policy',
        'DELETE /api/policies/:id/conditions/:conditionId': 'Remove a condition',
        'PATCH /api/policies/:id/toggle': 'Toggle policy active status'
      },
      access: {
        'POST /api/access/check': 'Check access (no logging)',
        'POST /api/access/evaluate': 'Evaluate and log access decision',
        'POST /api/access/batch-check': 'Batch check multiple requests',
        'GET /api/access/permissions/:userId/:resourceId': 'Get all permissions for user on resource',
        'GET /api/access/audit': 'View audit log',
        'GET /api/access/audit/stats': 'Get audit statistics',
        'DELETE /api/access/audit': 'Clear audit log'
      },
      cells: {
        note: 'Cell/Field-level access control',
        fields: {
          'GET /api/cells/resources/:resourceId/fields': 'Get all fields for a resource',
          'POST /api/cells/resources/:resourceId/fields': 'Define a new field with attributes',
          'PUT /api/cells/fields/:fieldId/attributes/:attrName': 'Set field attribute (e.g., sensitivity, pii)',
          'DELETE /api/cells/fields/:fieldId': 'Delete a field definition'
        },
        field_policies: {
          'GET /api/cells/policies': 'List all field-level policies',
          'POST /api/cells/policies': 'Create a field-level policy (allow/deny/mask/redact)',
          'DELETE /api/cells/policies/:policyId': 'Delete a field policy',
          'PATCH /api/cells/policies/:policyId/toggle': 'Toggle policy active status'
        },
        data: {
          'POST /api/cells/resources/:resourceId/data': 'Insert data rows',
          'GET /api/cells/resources/:resourceId/data?user_id=X': 'Get data with cell-level filtering',
          'PUT /api/cells/resources/:resourceId/data/:rowId': 'Update a row',
          'DELETE /api/cells/resources/:resourceId/data/:rowId': 'Delete a row'
        },
        access_check: {
          'POST /api/cells/access/check': 'Check access to a specific field',
          'POST /api/cells/access/check-batch': 'Check access to multiple fields',
          'POST /api/cells/access/filter': 'Filter arbitrary data through policies'
        }
      },
      search: {
        note: 'Full-text search with cell-level field protection (OpenSearch)',
        info: 'Search results are automatically filtered based on user permissions',
        'GET /api/search/health': 'Check OpenSearch availability and stats',
        'POST /api/search': 'Full-text search with cell-level filtering (query, user_id, filters)',
        'POST /api/search/aggregations': 'Search with faceted aggregations',
        'GET /api/search/documents/:id?user_id=X': 'Get single document with filtering',
        'POST /api/search/documents': 'Index a new document',
        'POST /api/search/documents/bulk': 'Bulk index documents',
        'PUT /api/search/documents/:id': 'Update/reindex a document',
        'DELETE /api/search/documents/:id': 'Delete a document',
        'GET /api/search/stats': 'Get search index statistics',
        field_protection: {
          description: 'Sensitive fields in search results are protected',
          protected_fields: ['confidential_notes', 'internal_comments', 'financial_data', 'pii_data'],
          effects: 'Fields may be allowed, masked, redacted, or denied based on user attributes'
        }
      }
    },
    concepts: {
      attributes: 'Key-value pairs attached to users and resources (e.g., department=engineering, clearance_level=3)',
      policies: 'Rules that combine conditions on user attributes, resource attributes, environment, and actions',
      conditions: {
        subject_types: ['user', 'resource', 'field', 'environment', 'action'],
        operators: ['equals', 'not_equals', 'contains', 'in', 'greater_than', 'less_than', 'matches']
      },
      actions: ['create', 'read', 'update', 'delete'],
      effects: ['allow', 'deny'],
      cell_level: {
        description: 'Field/cell-level access control with masking and redaction',
        field_attributes: ['sensitivity', 'pii', 'classification', 'data_type'],
        field_effects: ['allow', 'deny', 'mask', 'redact'],
        masking: 'Partial data hiding (e.g., SSN: ***-**-1234)',
        redaction: 'Complete replacement with placeholder'
      },
      opensearch: {
        description: 'Full-text search with automatic cell-level filtering',
        features: ['Full-text search', 'Aggregations/facets', 'Field-level security', 'Search audit logging'],
        sample_documents: '12 sample documents across engineering, finance, HR, product, legal, and sales departments'
      }
    }
  });
});

// Error handling
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error', message: err.message });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Async startup function
async function startServer() {
  try {
    // Ensure data directory exists
    const dataDir = path.join(__dirname, '../data');
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }

    // Initialize database
    console.log('Initializing database...');
    await initializeDatabase();
    console.log('Database initialized successfully');

    // Start server
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`ABAC/CBAC System running on http://0.0.0.0:${PORT}`);
      console.log('API documentation available at /');
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

startServer();

module.exports = app;
