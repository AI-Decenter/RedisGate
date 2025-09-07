# Issue #19: API Documentation and Developer Experience

**Priority**: Medium  
**Labels**: documentation, api, developer-experience  
**Milestone**: Phase 6 - Testing & Quality  
**Estimated Effort**: 3-4 days

## Summary
Create comprehensive API documentation, developer guides, and tools to provide an excellent developer experience for users of the Redis HTTP Gateway.

## Motivation
Good documentation and developer experience are crucial for adoption. Developers need clear, comprehensive documentation, interactive examples, SDKs, and tools to effectively use the Redis HTTP Gateway.

## Detailed Description

### Technical Requirements
- OpenAPI/Swagger specification for REST API
- Interactive API documentation with examples
- SDK generation for popular programming languages
- Developer onboarding guides and tutorials
- Code examples and sample applications
- CLI tools for gateway management

### Acceptance Criteria
- [ ] Complete OpenAPI 3.0 specification for all endpoints
- [ ] Interactive API documentation (Swagger UI/Redoc)
- [ ] SDKs generated for JavaScript, Python, Go, and Java
- [ ] Comprehensive developer guides with tutorials
- [ ] Working code examples and sample applications
- [ ] CLI tool for gateway and instance management
- [ ] API versioning strategy and compatibility guide
- [ ] Migration guides for different versions

### Implementation Details

#### OpenAPI Specification
```yaml
# docs/api/openapi.yaml
openapi: 3.0.3
info:
  title: Redis HTTP Gateway API
  description: |
    A cloud-native solution for providing Redis-as-a-Service on Kubernetes, 
    accessible via a secure, high-performance RESTful API.
    
    ## Authentication
    All API requests require authentication using either:
    - Bearer token (JWT) for management operations
    - API key for Redis operations
    
    ## Rate Limiting
    API requests are rate limited per API key. Default limits:
    - 1000 requests per minute
    - 10000 requests per hour
    
  version: 1.0.0
  contact:
    name: Redis Gateway Support
    url: https://github.com/AI-Decenter/Redis-over-HTTP-Cloud
    email: support@company.com
  license:
    name: MIT
    url: https://opensource.org/licenses/MIT

servers:
  - url: https://api.redis-gateway.company.com/v1
    description: Production server
  - url: https://staging-api.redis-gateway.company.com/v1
    description: Staging server
  - url: http://localhost:8080
    description: Local development server

paths:
  # Authentication endpoints
  /auth/login:
    post:
      tags: [Authentication]
      summary: Authenticate user and get JWT token
      description: |
        Authenticate a user with username and password to receive a JWT token
        for management operations.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [username, password]
              properties:
                username:
                  type: string
                  example: "john.doe"
                password:
                  type: string
                  format: password
                  example: "secure_password"
      responses:
        '200':
          description: Authentication successful
          content:
            application/json:
              schema:
                type: object
                properties:
                  token:
                    type: string
                    description: JWT token for authenticated requests
                    example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                  expires_at:
                    type: string
                    format: date-time
                    example: "2024-01-15T10:30:00Z"
                  user_id:
                    type: string
                    example: "user_123"
        '401':
          $ref: '#/components/responses/Unauthorized'
        '429':
          $ref: '#/components/responses/RateLimitExceeded'

  /auth/api-keys:
    post:
      tags: [Authentication]
      summary: Create API key
      description: Create a new API key for Redis operations
      security:
        - BearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [name, permissions]
              properties:
                name:
                  type: string
                  description: Human-readable name for the API key
                  example: "Production API Key"
                permissions:
                  type: array
                  items:
                    type: string
                    enum: [read, write, admin]
                  example: ["read", "write"]
                instance_access:
                  type: array
                  items:
                    type: string
                  description: List of instance names this key can access (* for all)
                  example: ["user-session-cache", "product-catalog"]
                expires_in_days:
                  type: integer
                  minimum: 1
                  maximum: 365
                  description: Number of days until the key expires
                  example: 90
      responses:
        '201':
          description: API key created successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  api_key:
                    type: string
                    description: The generated API key
                    example: "rgk_1234567890abcdef"
                  key_id:
                    type: string
                    example: "key_abc123"
                  created_at:
                    type: string
                    format: date-time
                  expires_at:
                    type: string
                    format: date-time

  # Redis operation endpoints
  /instances/{instance_name}/keys/{key}:
    get:
      tags: [Redis Operations]
      summary: Get key value
      description: |
        Retrieve the value of a Redis key.
        
        ### Method Override
        This endpoint supports method override via query parameters for browser testing:
        - `?method=POST&value=newvalue` - Set key value
        - `?method=DELETE` - Delete key
      parameters:
        - name: instance_name
          in: path
          required: true
          schema:
            type: string
            pattern: '^[a-z0-9-]+$'
          example: "user-session-cache"
          description: Name of the Redis instance
        - name: key
          in: path
          required: true
          schema:
            type: string
            maxLength: 512
          example: "user:123"
          description: Redis key name
        - name: method
          in: query
          schema:
            type: string
            enum: [POST, DELETE]
          description: Method override for browser compatibility
        - name: value
          in: query
          schema:
            type: string
          description: Value to set (when method=POST)
        - name: ttl_seconds
          in: query
          schema:
            type: integer
            minimum: 1
          description: TTL in seconds (when method=POST)
      security:
        - ApiKeyAuth: []
      responses:
        '200':
          description: Key value retrieved successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  key:
                    type: string
                    example: "user:123"
                  value:
                    type: string
                    example: "john_doe"
        '404':
          description: Key not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        '401':
          $ref: '#/components/responses/Unauthorized'
        '429':
          $ref: '#/components/responses/RateLimitExceeded'

    post:
      tags: [Redis Operations]
      summary: Set key value
      description: Set a Redis key with optional TTL
      parameters:
        - name: instance_name
          in: path
          required: true
          schema:
            type: string
          example: "user-session-cache"
        - name: key
          in: path
          required: true
          schema:
            type: string
          example: "user:123"
      security:
        - ApiKeyAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [value]
              properties:
                value:
                  type: string
                  maxLength: 536870912  # 512MB
                  example: "john_doe"
                ttl_seconds:
                  type: integer
                  minimum: 1
                  example: 3600
                  description: TTL in seconds (optional)
      responses:
        '200':
          description: Key set successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  status:
                    type: string
                    example: "OK"

components:
  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
      description: JWT token for authenticated users
    ApiKeyAuth:
      type: http
      scheme: bearer
      description: API key for Redis operations (format: rgk_*)

  schemas:
    Error:
      type: object
      properties:
        error:
          type: string
          description: Error message
        status:
          type: integer
          description: HTTP status code
        timestamp:
          type: string
          format: date-time
      required: [error, status]

  responses:
    Unauthorized:
      description: Authentication required or invalid credentials
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'
            
    RateLimitExceeded:
      description: Rate limit exceeded
      headers:
        X-RateLimit-Limit:
          schema:
            type: integer
          description: Request limit per time window
        X-RateLimit-Remaining:
          schema:
            type: integer
          description: Remaining requests in time window
        X-RateLimit-Reset:
          schema:
            type: integer
          description: Time when rate limit resets (Unix timestamp)
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'

tags:
  - name: Authentication
    description: User authentication and API key management
  - name: Redis Operations
    description: Redis data operations via HTTP
  - name: Instance Management
    description: Redis instance lifecycle management
  - name: Monitoring
    description: Health checks and metrics
```

#### SDK Generation
```typescript
// sdk/typescript/src/client.ts
/**
 * Redis HTTP Gateway TypeScript SDK
 * Generated from OpenAPI specification
 */

export interface RedisGatewayConfig {
  baseUrl: string;
  apiKey?: string;
  timeout?: number;
  retries?: number;
}

export interface SetKeyRequest {
  value: string;
  ttl_seconds?: number;
}

export interface GetKeyResponse {
  key: string;
  value: string;
}

export interface DeleteKeyResponse {
  deleted: number;
}

export class RedisGatewayClient {
  private config: RedisGatewayConfig;
  private httpClient: AxiosInstance;

  constructor(config: RedisGatewayConfig) {
    this.config = config;
    this.httpClient = axios.create({
      baseURL: config.baseUrl,
      timeout: config.timeout || 30000,
      headers: config.apiKey ? {
        'Authorization': `Bearer ${config.apiKey}`
      } : {}
    });

    // Add retry interceptor
    if (config.retries && config.retries > 0) {
      this.setupRetryInterceptor(config.retries);
    }
  }

  /**
   * Get the value of a Redis key
   */
  async getKey(instanceName: string, key: string): Promise<GetKeyResponse> {
    const response = await this.httpClient.get(
      `/instances/${encodeURIComponent(instanceName)}/keys/${encodeURIComponent(key)}`
    );
    return response.data;
  }

  /**
   * Set a Redis key with optional TTL
   */
  async setKey(instanceName: string, key: string, request: SetKeyRequest): Promise<{status: string}> {
    const response = await this.httpClient.post(
      `/instances/${encodeURIComponent(instanceName)}/keys/${encodeURIComponent(key)}`,
      request
    );
    return response.data;
  }

  /**
   * Delete a Redis key
   */
  async deleteKey(instanceName: string, key: string): Promise<DeleteKeyResponse> {
    const response = await this.httpClient.delete(
      `/instances/${encodeURIComponent(instanceName)}/keys/${encodeURIComponent(key)}`
    );
    return response.data;
  }

  /**
   * Set a hash field
   */
  async hset(instanceName: string, hash: string, field: string, value: string): Promise<{status: string}> {
    const response = await this.httpClient.post(
      `/instances/${encodeURIComponent(instanceName)}/hashes/${encodeURIComponent(hash)}`,
      { field, value }
    );
    return response.data;
  }

  /**
   * Get a hash field value
   */
  async hget(instanceName: string, hash: string, field: string): Promise<{hash: string, field: string, value: string}> {
    const response = await this.httpClient.get(
      `/instances/${encodeURIComponent(instanceName)}/hashes/${encodeURIComponent(hash)}/${encodeURIComponent(field)}`
    );
    return response.data;
  }

  /**
   * Execute raw Redis command
   */
  async rawCommand(instanceName: string, command: string, args: string[]): Promise<{result: any}> {
    const response = await this.httpClient.post(
      `/instances/${encodeURIComponent(instanceName)}/raw-command`,
      { command, args }
    );
    return response.data;
  }

  private setupRetryInterceptor(retries: number) {
    this.httpClient.interceptors.response.use(
      (response) => response,
      async (error) => {
        const config = error.config;
        
        if (!config || config.retryCount >= retries) {
          return Promise.reject(error);
        }
        
        config.retryCount = config.retryCount || 0;
        
        // Retry on 5xx errors and network errors
        if (error.response?.status >= 500 || !error.response) {
          config.retryCount += 1;
          const delay = Math.pow(2, config.retryCount) * 1000; // Exponential backoff
          await new Promise(resolve => setTimeout(resolve, delay));
          return this.httpClient(config);
        }
        
        return Promise.reject(error);
      }
    );
  }
}

// Factory function for easy instantiation
export function createClient(config: RedisGatewayConfig): RedisGatewayClient {
  return new RedisGatewayClient(config);
}

// Example usage
export const example = {
  async basicUsage() {
    const client = createClient({
      baseUrl: 'https://api.redis-gateway.company.com',
      apiKey: 'rgk_your-api-key-here'
    });

    // Set a key
    await client.setKey('user-sessions', 'user:123', {
      value: 'john_doe',
      ttl_seconds: 3600
    });

    // Get the key
    const result = await client.getKey('user-sessions', 'user:123');
    console.log(result.value); // 'john_doe'

    // Delete the key
    await client.deleteKey('user-sessions', 'user:123');
  }
};
```

#### Python SDK
```python
# sdk/python/redis_gateway/client.py
"""
Redis HTTP Gateway Python SDK
"""

import requests
from typing import Optional, Dict, Any, List
from urllib.parse import quote
import time
import logging

logger = logging.getLogger(__name__)

class RedisGatewayError(Exception):
    """Base exception for Redis Gateway errors"""
    pass

class AuthenticationError(RedisGatewayError):
    """Authentication related errors"""
    pass

class RateLimitError(RedisGatewayError):
    """Rate limit exceeded"""
    pass

class RedisGatewayClient:
    """
    Redis HTTP Gateway Python Client
    
    Example:
        client = RedisGatewayClient(
            base_url="https://api.redis-gateway.company.com",
            api_key="rgk_your-api-key-here"
        )
        
        # Set a key
        client.set_key("user-sessions", "user:123", "john_doe", ttl_seconds=3600)
        
        # Get the key
        value = client.get_key("user-sessions", "user:123")
        print(value)  # john_doe
        
        # Delete the key
        client.delete_key("user-sessions", "user:123")
    """
    
    def __init__(
        self, 
        base_url: str, 
        api_key: Optional[str] = None,
        timeout: int = 30,
        retries: int = 3,
        backoff_factor: float = 0.3
    ):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.timeout = timeout
        self.retries = retries
        self.backoff_factor = backoff_factor
        
        self.session = requests.Session()
        if api_key:
            self.session.headers['Authorization'] = f'Bearer {api_key}'
        
        # Setup retry strategy
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        retry_strategy = Retry(
            total=retries,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE"],
            backoff_factor=backoff_factor
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def get_key(self, instance_name: str, key: str) -> str:
        """
        Get the value of a Redis key
        
        Args:
            instance_name: Name of the Redis instance
            key: Redis key name
            
        Returns:
            The value of the key
            
        Raises:
            RedisGatewayError: If the key is not found or other errors occur
        """
        url = f"{self.base_url}/instances/{quote(instance_name)}/keys/{quote(key)}"
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            self._handle_response(response)
            return response.json()['value']
        except requests.RequestException as e:
            raise RedisGatewayError(f"Failed to get key: {e}")

    def set_key(
        self, 
        instance_name: str, 
        key: str, 
        value: str, 
        ttl_seconds: Optional[int] = None
    ) -> bool:
        """
        Set a Redis key with optional TTL
        
        Args:
            instance_name: Name of the Redis instance
            key: Redis key name
            value: Value to set
            ttl_seconds: Optional TTL in seconds
            
        Returns:
            True if successful
            
        Raises:
            RedisGatewayError: If the operation fails
        """
        url = f"{self.base_url}/instances/{quote(instance_name)}/keys/{quote(key)}"
        data = {'value': value}
        
        if ttl_seconds is not None:
            data['ttl_seconds'] = ttl_seconds
        
        try:
            response = self.session.post(url, json=data, timeout=self.timeout)
            self._handle_response(response)
            return response.json()['status'] == 'OK'
        except requests.RequestException as e:
            raise RedisGatewayError(f"Failed to set key: {e}")

    def delete_key(self, instance_name: str, key: str) -> int:
        """
        Delete a Redis key
        
        Args:
            instance_name: Name of the Redis instance
            key: Redis key name
            
        Returns:
            Number of keys deleted (0 or 1)
            
        Raises:
            RedisGatewayError: If the operation fails
        """
        url = f"{self.base_url}/instances/{quote(instance_name)}/keys/{quote(key)}"
        
        try:
            response = self.session.delete(url, timeout=self.timeout)
            self._handle_response(response)
            return response.json()['deleted']
        except requests.RequestException as e:
            raise RedisGatewayError(f"Failed to delete key: {e}")

    def hset(self, instance_name: str, hash_key: str, field: str, value: str) -> bool:
        """Set a hash field"""
        url = f"{self.base_url}/instances/{quote(instance_name)}/hashes/{quote(hash_key)}"
        data = {'field': field, 'value': value}
        
        try:
            response = self.session.post(url, json=data, timeout=self.timeout)
            self._handle_response(response)
            return response.json()['status'] == 'OK'
        except requests.RequestException as e:
            raise RedisGatewayError(f"Failed to set hash field: {e}")

    def hget(self, instance_name: str, hash_key: str, field: str) -> str:
        """Get a hash field value"""
        url = f"{self.base_url}/instances/{quote(instance_name)}/hashes/{quote(hash_key)}/{quote(field)}"
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            self._handle_response(response)
            return response.json()['value']
        except requests.RequestException as e:
            raise RedisGatewayError(f"Failed to get hash field: {e}")

    def raw_command(self, instance_name: str, command: str, args: List[str]) -> Any:
        """Execute a raw Redis command"""
        url = f"{self.base_url}/instances/{quote(instance_name)}/raw-command"
        data = {'command': command, 'args': args}
        
        try:
            response = self.session.post(url, json=data, timeout=self.timeout)
            self._handle_response(response)
            return response.json()['result']
        except requests.RequestException as e:
            raise RedisGatewayError(f"Failed to execute raw command: {e}")

    def _handle_response(self, response: requests.Response):
        """Handle HTTP response and raise appropriate errors"""
        if response.status_code == 401:
            raise AuthenticationError("Authentication failed")
        elif response.status_code == 429:
            raise RateLimitError("Rate limit exceeded")
        elif response.status_code >= 400:
            try:
                error_data = response.json()
                raise RedisGatewayError(error_data.get('error', f'HTTP {response.status_code}'))
            except ValueError:
                raise RedisGatewayError(f'HTTP {response.status_code}: {response.text}')
```

#### CLI Tool
```rust
// cli/src/main.rs
use clap::{App, Arg, SubCommand};
use serde_json::{json, Value};
use reqwest::Client;
use std::collections::HashMap;
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = App::new("Redis Gateway CLI")
        .version("1.0.0")
        .author("Redis Gateway Team")
        .about("Command line interface for Redis HTTP Gateway")
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help("Configuration file path")
                .default_value("~/.redis-gateway/config.yaml")
        )
        .arg(
            Arg::with_name("api-key")
                .long("api-key")
                .value_name("KEY")
                .help("API key for authentication")
                .env("REDIS_GATEWAY_API_KEY")
        )
        .arg(
            Arg::with_name("base-url")
                .long("base-url")
                .value_name("URL")
                .help("Base URL of the Redis Gateway")
                .default_value("http://localhost:8080")
                .env("REDIS_GATEWAY_URL")
        )
        .subcommand(
            SubCommand::with_name("get")
                .about("Get a Redis key")
                .arg(Arg::with_name("instance").required(true))
                .arg(Arg::with_name("key").required(true))
        )
        .subcommand(
            SubCommand::with_name("set")
                .about("Set a Redis key")
                .arg(Arg::with_name("instance").required(true))
                .arg(Arg::with_name("key").required(true))
                .arg(Arg::with_name("value").required(true))
                .arg(Arg::with_name("ttl").long("ttl").help("TTL in seconds"))
        )
        .subcommand(
            SubCommand::with_name("del")
                .about("Delete a Redis key")
                .arg(Arg::with_name("instance").required(true))
                .arg(Arg::with_name("key").required(true))
        )
        .subcommand(
            SubCommand::with_name("instances")
                .about("List Redis instances")
        )
        .subcommand(
            SubCommand::with_name("health")
                .about("Check gateway health")
        )
        .get_matches();

    let base_url = matches.value_of("base-url").unwrap();
    let api_key = matches.value_of("api-key");

    let client = create_http_client(api_key)?;

    match matches.subcommand() {
        ("get", Some(sub_m)) => {
            let instance = sub_m.value_of("instance").unwrap();
            let key = sub_m.value_of("key").unwrap();
            get_key(&client, base_url, instance, key).await?;
        }
        ("set", Some(sub_m)) => {
            let instance = sub_m.value_of("instance").unwrap();
            let key = sub_m.value_of("key").unwrap();
            let value = sub_m.value_of("value").unwrap();
            let ttl = sub_m.value_of("ttl").map(|s| s.parse::<u64>().unwrap());
            set_key(&client, base_url, instance, key, value, ttl).await?;
        }
        ("del", Some(sub_m)) => {
            let instance = sub_m.value_of("instance").unwrap();
            let key = sub_m.value_of("key").unwrap();
            delete_key(&client, base_url, instance, key).await?;
        }
        ("health", _) => {
            check_health(&client, base_url).await?;
        }
        _ => {
            println!("{}", matches.usage());
        }
    }

    Ok(())
}

fn create_http_client(api_key: Option<&str>) -> Result<Client, reqwest::Error> {
    let mut builder = Client::builder();
    
    if let Some(key) = api_key {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", key).parse().unwrap(),
        );
        builder = builder.default_headers(headers);
    }
    
    builder.build()
}

async fn get_key(
    client: &Client,
    base_url: &str,
    instance: &str,
    key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("{}/instances/{}/keys/{}", base_url, instance, key);
    let response = client.get(&url).send().await?;
    
    if response.status().is_success() {
        let json: Value = response.json().await?;
        println!("Key: {}", json["key"]);
        println!("Value: {}", json["value"]);
    } else {
        let error: Value = response.json().await?;
        eprintln!("Error: {}", error["error"]);
    }
    
    Ok(())
}

async fn set_key(
    client: &Client,
    base_url: &str,
    instance: &str,
    key: &str,
    value: &str,
    ttl: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("{}/instances/{}/keys/{}", base_url, instance, key);
    let mut body = json!({ "value": value });
    
    if let Some(ttl_seconds) = ttl {
        body["ttl_seconds"] = json!(ttl_seconds);
    }
    
    let response = client.post(&url).json(&body).send().await?;
    
    if response.status().is_success() {
        println!("Key set successfully");
    } else {
        let error: Value = response.json().await?;
        eprintln!("Error: {}", error["error"]);
    }
    
    Ok(())
}

async fn check_health(
    client: &Client,
    base_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("{}/healthz", base_url);
    let response = client.get(&url).send().await?;
    
    let json: Value = response.json().await?;
    println!("Status: {}", json["status"]);
    println!("Version: {}", json["version"]);
    
    if let Some(checks) = json["checks"].as_object() {
        println!("\nHealth Checks:");
        for (name, check) in checks {
            println!("  {}: {}", name, check["status"]);
        }
    }
    
    Ok(())
}
```

#### Documentation Site
```markdown
# Getting Started with Redis HTTP Gateway

## Overview

Redis HTTP Gateway provides a RESTful API for Redis operations, making it easy to use Redis from serverless environments, edge functions, and applications that can't establish direct TCP connections.

## Quick Start

### 1. Authentication

First, obtain an API key:

```bash
curl -X POST https://api.redis-gateway.company.com/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "your-username", "password": "your-password"}'
```

Then create an API key:

```bash
curl -X POST https://api.redis-gateway.company.com/auth/api-keys \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My API Key",
    "permissions": ["read", "write"],
    "instance_access": ["*"]
  }'
```

### 2. Basic Operations

#### Set a key
```bash
curl -X POST https://api.redis-gateway.company.com/instances/my-instance/keys/user:123 \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"value": "john_doe", "ttl_seconds": 3600}'
```

#### Get a key
```bash
curl https://api.redis-gateway.company.com/instances/my-instance/keys/user:123 \
  -H "Authorization: Bearer YOUR_API_KEY"
```

#### Delete a key
```bash
curl -X DELETE https://api.redis-gateway.company.com/instances/my-instance/keys/user:123 \
  -H "Authorization: Bearer YOUR_API_KEY"
```

## SDKs

### JavaScript/TypeScript
```bash
npm install @redis-gateway/client
```

```javascript
import { createClient } from '@redis-gateway/client';

const client = createClient({
  baseUrl: 'https://api.redis-gateway.company.com',
  apiKey: 'your-api-key'
});

await client.setKey('my-instance', 'user:123', {
  value: 'john_doe',
  ttl_seconds: 3600
});

const result = await client.getKey('my-instance', 'user:123');
console.log(result.value); // 'john_doe'
```

### Python
```bash
pip install redis-gateway-client
```

```python
from redis_gateway import RedisGatewayClient

client = RedisGatewayClient(
    base_url='https://api.redis-gateway.company.com',
    api_key='your-api-key'
)

client.set_key('my-instance', 'user:123', 'john_doe', ttl_seconds=3600)
value = client.get_key('my-instance', 'user:123')
print(value)  # john_doe
```

## Method Override for Browser Testing

For easy browser testing, you can use GET requests with method override:

```bash
# Set a key using GET with method override
curl "https://api.redis-gateway.company.com/instances/my-instance/keys/test?method=POST&value=hello&ttl_seconds=3600" \
  -H "Authorization: Bearer YOUR_API_KEY"

# Delete a key using GET with method override  
curl "https://api.redis-gateway.company.com/instances/my-instance/keys/test?method=DELETE" \
  -H "Authorization: Bearer YOUR_API_KEY"
```

## Error Handling

The API returns standard HTTP status codes and JSON error responses:

```json
{
  "error": "Key 'nonexistent' not found",
  "status": 404,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

Common status codes:
- `200` - Success
- `400` - Bad Request (invalid input)
- `401` - Unauthorized (invalid API key)
- `404` - Not Found (key doesn't exist)
- `429` - Rate Limit Exceeded
- `500` - Internal Server Error

## Rate Limiting

API requests are rate limited per API key:
- 1000 requests per minute
- 10000 requests per hour

Rate limit headers are included in responses:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1642248600
```

## Next Steps

- [Instance Management Guide](./instance-management.md)
- [Advanced Operations](./advanced-operations.md)
- [Security Best Practices](./security.md)
- [API Reference](./api-reference.md)
```

### Definition of Done
- Complete OpenAPI specification covers all endpoints
- Interactive API documentation is deployed and accessible
- SDKs are generated and published for major languages
- Comprehensive developer guides and tutorials are available
- CLI tool is functional and well-documented
- Code examples and sample applications work correctly
- API versioning strategy is documented
- Migration guides are available for version updates

### Dependencies
- Issue #8 (HTTP Gateway Core)
- Issue #13 (JWT Authentication)

### Additional Context
- Consider implementing GraphQL endpoint for advanced querying
- Plan for webhook support for real-time notifications
- Implement API playground for interactive testing
- Consider adding Postman collections for easy testing
- Plan for API analytics and usage tracking