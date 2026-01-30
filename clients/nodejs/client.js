/**
 * ABAC API Client for Node.js
 * 
 * This sample client demonstrates how to authenticate with Keycloak
 * and make authenticated requests to the ABAC API.
 */

const https = require('https');
const http = require('http');

class ABACClient {
  constructor(options = {}) {
    this.apiBaseUrl = options.apiBaseUrl || 'http://localhost:3000';
    this.keycloakUrl = options.keycloakUrl || 'http://localhost:8080';
    this.realm = options.realm || 'abac-realm';
    this.clientId = options.clientId || 'abac-webapp';
    this.clientSecret = options.clientSecret || 'abac-webapp-secret-change-in-production';
    this.accessToken = null;
    this.refreshToken = null;
    this.tokenExpiry = null;
  }

  /**
   * Get a new access token using password grant (for users)
   */
  async loginWithPassword(username, password) {
    const tokenUrl = `${this.keycloakUrl}/realms/${this.realm}/protocol/openid-connect/token`;
    
    const params = new URLSearchParams({
      grant_type: 'password',
      client_id: this.clientId,
      client_secret: this.clientSecret,
      username: username,
      password: password
    });

    const response = await this._fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: params.toString()
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Authentication failed: ${error.error_description || error.error}`);
    }

    const tokens = await response.json();
    this.accessToken = tokens.access_token;
    this.refreshToken = tokens.refresh_token;
    this.tokenExpiry = Date.now() + (tokens.expires_in * 1000);

    return tokens;
  }

  /**
   * Get a new access token using client credentials grant (for services)
   */
  async loginWithClientCredentials() {
    const tokenUrl = `${this.keycloakUrl}/realms/${this.realm}/protocol/openid-connect/token`;
    
    const params = new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: this.clientId,
      client_secret: this.clientSecret
    });

    const response = await this._fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: params.toString()
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Authentication failed: ${error.error_description || error.error}`);
    }

    const tokens = await response.json();
    this.accessToken = tokens.access_token;
    this.tokenExpiry = Date.now() + (tokens.expires_in * 1000);

    return tokens;
  }

  /**
   * Refresh the access token
   */
  async refreshAccessToken() {
    if (!this.refreshToken) {
      throw new Error('No refresh token available');
    }

    const tokenUrl = `${this.keycloakUrl}/realms/${this.realm}/protocol/openid-connect/token`;
    
    const params = new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: this.clientId,
      client_secret: this.clientSecret,
      refresh_token: this.refreshToken
    });

    const response = await this._fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: params.toString()
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Token refresh failed: ${error.error_description || error.error}`);
    }

    const tokens = await response.json();
    this.accessToken = tokens.access_token;
    this.refreshToken = tokens.refresh_token;
    this.tokenExpiry = Date.now() + (tokens.expires_in * 1000);

    return tokens;
  }

  /**
   * Make an authenticated API request
   */
  async apiRequest(method, path, body = null) {
    // Auto-refresh token if expired
    if (this.tokenExpiry && Date.now() >= this.tokenExpiry - 30000) {
      if (this.refreshToken) {
        await this.refreshAccessToken();
      } else {
        throw new Error('Token expired and no refresh token available');
      }
    }

    if (!this.accessToken) {
      throw new Error('Not authenticated. Call loginWithPassword() or loginWithClientCredentials() first.');
    }

    const url = `${this.apiBaseUrl}${path}`;
    const options = {
      method: method,
      headers: {
        'Authorization': `Bearer ${this.accessToken}`,
        'Content-Type': 'application/json'
      }
    };

    if (body) {
      options.body = JSON.stringify(body);
    }

    const response = await this._fetch(url, options);
    const data = await response.json();

    if (!response.ok) {
      const error = new Error(data.message || data.error || 'API request failed');
      error.status = response.status;
      error.response = data;
      throw error;
    }

    return data;
  }

  // Convenience methods
  async getUsers() {
    return this.apiRequest('GET', '/api/users');
  }

  async getUser(id) {
    return this.apiRequest('GET', `/api/users/${id}`);
  }

  async createUser(userData) {
    return this.apiRequest('POST', '/api/users', userData);
  }

  async getResources() {
    return this.apiRequest('GET', '/api/resources');
  }

  async getResource(id) {
    return this.apiRequest('GET', `/api/resources/${id}`);
  }

  async createResource(resourceData) {
    return this.apiRequest('POST', '/api/resources', resourceData);
  }

  async getPolicies() {
    return this.apiRequest('GET', '/api/policies');
  }

  async getPolicy(id) {
    return this.apiRequest('GET', `/api/policies/${id}`);
  }

  async createPolicy(policyData) {
    return this.apiRequest('POST', '/api/policies', policyData);
  }

  async checkAccess(userId, resourceId, action, environment = {}) {
    return this.apiRequest('POST', '/api/access/check', {
      user_id: userId,
      resource_id: resourceId,
      action: action,
      environment: environment
    });
  }

  async evaluateAccess(userId, resourceId, action, environment = {}) {
    return this.apiRequest('POST', '/api/access/evaluate', {
      user_id: userId,
      resource_id: resourceId,
      action: action,
      environment: environment
    });
  }

  async getAuditLog(limit = 100, offset = 0) {
    return this.apiRequest('GET', `/api/access/audit?limit=${limit}&offset=${offset}`);
  }

  async getTokenInfo() {
    return this.apiRequest('GET', '/api/token-info');
  }

  // Helper fetch wrapper that works with both http and https
  _fetch(url, options) {
    return new Promise((resolve, reject) => {
      const lib = url.startsWith('https') ? https : http;
      const urlObj = new URL(url);
      
      const reqOptions = {
        hostname: urlObj.hostname,
        port: urlObj.port || (url.startsWith('https') ? 443 : 80),
        path: urlObj.pathname + urlObj.search,
        method: options.method || 'GET',
        headers: options.headers || {}
      };

      const req = lib.request(reqOptions, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          resolve({
            ok: res.statusCode >= 200 && res.statusCode < 300,
            status: res.statusCode,
            json: () => Promise.resolve(JSON.parse(data))
          });
        });
      });

      req.on('error', reject);

      if (options.body) {
        req.write(options.body);
      }

      req.end();
    });
  }
}

// Example usage
async function main() {
  const client = new ABACClient({
    apiBaseUrl: 'http://localhost:3000',
    keycloakUrl: 'http://localhost:8080',
    realm: 'abac-realm',
    clientId: 'abac-webapp',
    clientSecret: 'abac-webapp-secret-change-in-production'
  });

  try {
    console.log('=== ABAC API Client Demo ===\n');

    // Login as admin
    console.log('1. Logging in as admin...');
    await client.loginWithPassword('admin', 'admin123');
    console.log('   Login successful!\n');

    // Get token info
    console.log('2. Getting token info...');
    const tokenInfo = await client.getTokenInfo();
    console.log('   User:', tokenInfo.user.preferred_username);
    console.log('   Realm roles:', tokenInfo.roles.realm.join(', '));
    console.log('   Client roles:', tokenInfo.roles.client.join(', '), '\n');

    // List users
    console.log('3. Listing users...');
    const users = await client.getUsers();
    console.log(`   Found ${users.length} users:`);
    users.slice(0, 3).forEach(u => console.log(`   - ${u.username} (${u.email})`));
    if (users.length > 3) console.log(`   ... and ${users.length - 3} more\n`);

    // List resources
    console.log('4. Listing resources...');
    const resources = await client.getResources();
    console.log(`   Found ${resources.length} resources:`);
    resources.slice(0, 3).forEach(r => console.log(`   - ${r.name} (${r.type})`));
    if (resources.length > 3) console.log(`   ... and ${resources.length - 3} more\n`);

    // Check access
    if (users.length > 0 && resources.length > 0) {
      console.log('5. Checking access...');
      const accessResult = await client.checkAccess(
        users[0].id,
        resources[0].id,
        'read'
      );
      console.log(`   User "${users[0].username}" ${accessResult.allowed ? 'CAN' : 'CANNOT'} read "${resources[0].name}"`);
      console.log(`   Decision: ${accessResult.decision}\n`);
    }

    console.log('=== Demo Complete ===');

  } catch (error) {
    console.error('Error:', error.message);
    if (error.response) {
      console.error('Response:', error.response);
    }
  }
}

// Export for use as module
module.exports = ABACClient;

// Run demo if executed directly
if (require.main === module) {
  main();
}
