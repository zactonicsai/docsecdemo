const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

// Keycloak configuration
const KEYCLOAK_URL = process.env.KEYCLOAK_URL || 'http://keycloak:8080';
const KEYCLOAK_REALM = process.env.KEYCLOAK_REALM || 'abac-realm';
const KEYCLOAK_ISSUER = `${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}`;

// JWKS client for fetching public keys from Keycloak
const client = jwksClient({
  jwksUri: `${KEYCLOAK_ISSUER}/protocol/openid-connect/certs`,
  cache: true,
  cacheMaxAge: 86400000, // 24 hours
  rateLimit: true,
  jwksRequestsPerMinute: 10
});

// Function to get signing key
function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) {
      callback(err);
      return;
    }
    const signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
}

// Verify JWT token
function verifyToken(token) {
  return new Promise((resolve, reject) => {
    jwt.verify(token, getKey, {
      algorithms: ['RS256'],
      issuer: KEYCLOAK_ISSUER
    }, (err, decoded) => {
      if (err) {
        reject(err);
      } else {
        resolve(decoded);
      }
    });
  });
}

// Authentication middleware
async function authenticate(req, res, next) {
  // Skip auth if disabled (for development)
  if (process.env.DISABLE_AUTH === 'true') {
    req.user = {
      sub: 'dev-user',
      preferred_username: 'developer',
      realm_access: { roles: ['admin'] },
      resource_access: { 'abac-api': { roles: ['admin'] } }
    };
    return next();
  }

  const authHeader = req.headers.authorization;
  
  if (!authHeader) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'No authorization header provided'
    });
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Invalid authorization header format. Use: Bearer <token>'
    });
  }

  const token = parts[1];

  try {
    const decoded = await verifyToken(token);
    req.user = decoded;
    req.token = token;
    next();
  } catch (err) {
    console.error('Token verification failed:', err.message);
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Invalid or expired token'
    });
  }
}

// Role-based authorization middleware
function requireRole(roles) {
  if (typeof roles === 'string') {
    roles = [roles];
  }
  
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required'
      });
    }

    // Check realm roles
    const realmRoles = req.user.realm_access?.roles || [];
    
    // Check client roles for 'abac-api' client
    const clientRoles = req.user.resource_access?.['abac-api']?.roles || [];
    
    const userRoles = [...new Set([...realmRoles, ...clientRoles])];
    
    const hasRole = roles.some(role => userRoles.includes(role));
    
    if (!hasRole) {
      return res.status(403).json({
        error: 'Forbidden',
        message: `Required roles: ${roles.join(' or ')}`
      });
    }
    
    next();
  };
}

// Scope-based authorization middleware
function requireScope(scopes) {
  if (typeof scopes === 'string') {
    scopes = [scopes];
  }
  
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required'
      });
    }

    const tokenScopes = req.user.scope?.split(' ') || [];
    const hasScope = scopes.some(scope => tokenScopes.includes(scope));
    
    if (!hasScope) {
      return res.status(403).json({
        error: 'Forbidden',
        message: `Required scopes: ${scopes.join(' or ')}`
      });
    }
    
    next();
  };
}

// Optional authentication - doesn't fail if no token, but validates if present
async function optionalAuth(req, res, next) {
  if (process.env.DISABLE_AUTH === 'true') {
    req.user = {
      sub: 'dev-user',
      preferred_username: 'developer',
      realm_access: { roles: ['admin'] }
    };
    return next();
  }

  const authHeader = req.headers.authorization;
  
  if (!authHeader) {
    return next();
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return next();
  }

  const token = parts[1];

  try {
    const decoded = await verifyToken(token);
    req.user = decoded;
    req.token = token;
  } catch (err) {
    // Log but don't fail
    console.warn('Optional auth token invalid:', err.message);
  }
  
  next();
}

module.exports = {
  authenticate,
  requireRole,
  requireScope,
  optionalAuth,
  verifyToken
};
