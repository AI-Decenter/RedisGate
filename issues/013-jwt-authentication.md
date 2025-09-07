# Issue #13: JWT Authentication and API Key Management

**Priority**: High  
**Labels**: security, authentication, jwt  
**Milestone**: Phase 4 - Security & Authentication  
**Estimated Effort**: 3-4 days

## Summary
Implement comprehensive authentication system using JWT tokens for user management and API keys for Redis instance access, with integration to Kubernetes RBAC.

## Motivation
Security is critical for a multi-tenant system. Users need secure authentication to manage their Redis instances, and API keys provide secure access for client applications while maintaining proper isolation between tenants.

## Detailed Description

### Technical Requirements
- JWT-based user authentication for management operations
- API key generation and management per user/instance
- Integration with Kubernetes RBAC for authorization
- Token refresh and expiration handling
- Secure key storage and rotation
- Rate limiting per API key

### Acceptance Criteria
- [ ] JWT token generation and validation
- [ ] API key generation with configurable permissions
- [ ] User registration and authentication endpoints
- [ ] API key CRUD operations via authenticated endpoints
- [ ] Integration with Kubernetes ServiceAccount/RBAC
- [ ] Token refresh mechanism
- [ ] API key rate limiting and quotas
- [ ] Secure storage of keys and secrets

### Implementation Details

#### Authentication Middleware
```rust
// src/middleware/auth.rs
use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use uuid::Uuid;

use crate::{
    error::{GatewayError, Result},
    server::AppState,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String, // User ID
    pub username: String,
    pub exp: usize, // Expiration time
    pub iat: usize, // Issued at
    pub permissions: Vec<String>,
    pub namespaces: Vec<String>, // Kubernetes namespaces user can access
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApiKey {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub permissions: Vec<Permission>,
    pub instance_access: Vec<String>, // Instance names this key can access
    pub rate_limit: RateLimit,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_used: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Permission {
    Read,
    Write,
    Admin,
    InstanceCreate,
    InstanceDelete,
    KeyManage,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RateLimit {
    pub requests_per_minute: u32,
    pub requests_per_hour: u32,
    pub burst_size: u32,
}

pub struct AuthLayer {
    jwt_secret: String,
    api_keys: Arc<RwLock<HashMap<String, ApiKey>>>,
    rate_limiter: Arc<RateLimiter>,
}

impl AuthLayer {
    pub fn new(jwt_secret: String) -> Self {
        Self {
            jwt_secret,
            api_keys: Arc::new(RwLock::new(HashMap::new())),
            rate_limiter: Arc::new(RateLimiter::new()),
        }
    }

    pub async fn authenticate_request(
        &self,
        headers: &HeaderMap,
    ) -> Result<AuthenticationResult> {
        // Extract Authorization header
        let auth_header = headers
            .get("Authorization")
            .ok_or(GatewayError::Unauthorized)?
            .to_str()
            .map_err(|_| GatewayError::Unauthorized)?;

        if auth_header.starts_with("Bearer ") {
            let token = &auth_header[7..];
            
            // Try JWT first
            if let Ok(claims) = self.validate_jwt(token) {
                return Ok(AuthenticationResult::Jwt(claims));
            }
            
            // Try API key
            if let Ok(api_key) = self.validate_api_key(token).await {
                return Ok(AuthenticationResult::ApiKey(api_key));
            }
        }

        Err(GatewayError::Unauthorized)
    }

    fn validate_jwt(&self, token: &str) -> Result<Claims> {
        let decoding_key = DecodingKey::from_secret(self.jwt_secret.as_bytes());
        let validation = Validation::new(Algorithm::HS256);
        
        let token_data = decode::<Claims>(token, &decoding_key, &validation)
            .map_err(|_| GatewayError::Unauthorized)?;
            
        // Check expiration
        let now = chrono::Utc::now().timestamp() as usize;
        if token_data.claims.exp < now {
            return Err(GatewayError::Unauthorized);
        }
        
        Ok(token_data.claims)
    }

    async fn validate_api_key(&self, key: &str) -> Result<ApiKey> {
        let api_keys = self.api_keys.read().await;
        let api_key = api_keys
            .get(key)
            .ok_or(GatewayError::Unauthorized)?
            .clone();
        
        // Check expiration
        if let Some(expires_at) = api_key.expires_at {
            if expires_at < chrono::Utc::now() {
                return Err(GatewayError::Unauthorized);
            }
        }
        
        // Check rate limits
        if !self.rate_limiter.check_limit(&api_key.id, &api_key.rate_limit).await {
            return Err(GatewayError::RateLimitExceeded);
        }
        
        Ok(api_key)
    }

    pub fn generate_jwt(&self, user_id: &str, username: &str, permissions: Vec<String>) -> Result<String> {
        let now = chrono::Utc::now();
        let expiration = now + chrono::Duration::hours(24);
        
        let claims = Claims {
            sub: user_id.to_string(),
            username: username.to_string(),
            exp: expiration.timestamp() as usize,
            iat: now.timestamp() as usize,
            permissions,
            namespaces: vec![], // Will be populated based on user's K8s permissions
        };
        
        let encoding_key = EncodingKey::from_secret(self.jwt_secret.as_bytes());
        let header = Header::new(Algorithm::HS256);
        
        encode(&header, &claims, &encoding_key)
            .map_err(|e| GatewayError::Internal(format!("JWT generation failed: {}", e)))
    }

    pub async fn create_api_key(&self, user_id: &str, name: &str, permissions: Vec<Permission>) -> Result<(String, ApiKey)> {
        let key_id = Uuid::new_v4().to_string();
        let api_key_value = format!("rgk_{}", Uuid::new_v4().simple());
        
        let api_key = ApiKey {
            id: key_id.clone(),
            user_id: user_id.to_string(),
            name: name.to_string(),
            permissions,
            instance_access: vec![],
            rate_limit: RateLimit {
                requests_per_minute: 1000,
                requests_per_hour: 10000,
                burst_size: 100,
            },
            created_at: chrono::Utc::now(),
            expires_at: None,
            last_used: None,
        };
        
        // Store API key (in production, this would be in a database)
        let mut api_keys = self.api_keys.write().await;
        api_keys.insert(api_key_value.clone(), api_key.clone());
        
        Ok((api_key_value, api_key))
    }
}

#[derive(Debug)]
pub enum AuthenticationResult {
    Jwt(Claims),
    ApiKey(ApiKey),
}

// Middleware function
pub async fn auth_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    match state.auth_layer.authenticate_request(&headers).await {
        Ok(auth_result) => {
            // Add authentication info to request extensions
            request.extensions_mut().insert(auth_result);
            Ok(next.run(request).await)
        }
        Err(_) => Err(StatusCode::UNAUTHORIZED),
    }
}
```

#### Authentication Handlers
```rust
// src/handlers/auth.rs
use axum::{
    extract::{Json, State},
    response::Json as ResponseJson,
};
use serde::{Deserialize, Serialize};

use crate::{
    error::Result,
    middleware::auth::{Permission, AuthLayer},
    server::AppState,
};

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub expires_at: String,
    pub user_id: String,
}

#[derive(Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub permissions: Vec<Permission>,
    pub instance_access: Vec<String>,
    pub expires_in_days: Option<u32>,
}

#[derive(Serialize)]
pub struct CreateApiKeyResponse {
    pub api_key: String,
    pub key_id: String,
    pub created_at: String,
    pub expires_at: Option<String>,
}

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<ResponseJson<LoginResponse>> {
    // In production, verify credentials against database/LDAP/etc
    let user_id = authenticate_user(&payload.username, &payload.password).await?;
    
    // Generate JWT token
    let permissions = get_user_permissions(&user_id).await?;
    let token = state.auth_layer.generate_jwt(&user_id, &payload.username, permissions)?;
    
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(24);
    
    Ok(ResponseJson(LoginResponse {
        token,
        expires_at: expires_at.to_rfc3339(),
        user_id,
    }))
}

pub async fn create_api_key(
    State(state): State<AppState>,
    Json(payload): Json<CreateApiKeyRequest>,
) -> Result<ResponseJson<CreateApiKeyResponse>> {
    // Extract user ID from JWT (would be in request extensions)
    let user_id = "user123"; // This would come from the authenticated JWT
    
    let (api_key_value, api_key) = state
        .auth_layer
        .create_api_key(user_id, &payload.name, payload.permissions)
        .await?;
    
    Ok(ResponseJson(CreateApiKeyResponse {
        api_key: api_key_value,
        key_id: api_key.id,
        created_at: api_key.created_at.to_rfc3339(),
        expires_at: api_key.expires_at.map(|dt| dt.to_rfc3339()),
    }))
}

async fn authenticate_user(username: &str, password: &str) -> Result<String> {
    // This would integrate with your authentication system
    // For now, just a simple check
    if username == "admin" && password == "secret" {
        Ok("user_admin".to_string())
    } else {
        Err(crate::error::GatewayError::Unauthorized)
    }
}

async fn get_user_permissions(user_id: &str) -> Result<Vec<String>> {
    // This would query your authorization system
    Ok(vec![
        "instance:create".to_string(),
        "instance:read".to_string(),
        "key:manage".to_string(),
    ])
}
```

#### Rate Limiter
```rust
// src/middleware/rate_limiter.rs
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

use crate::middleware::auth::RateLimit;

pub struct RateLimiter {
    buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,
}

struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    capacity: f64,
    refill_rate: f64, // tokens per second
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            buckets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn check_limit(&self, key_id: &str, rate_limit: &RateLimit) -> bool {
        let mut buckets = self.buckets.write().await;
        let bucket = buckets
            .entry(key_id.to_string())
            .or_insert_with(|| TokenBucket {
                tokens: rate_limit.requests_per_minute as f64,
                last_refill: Instant::now(),
                capacity: rate_limit.requests_per_minute as f64,
                refill_rate: rate_limit.requests_per_minute as f64 / 60.0, // per second
            });

        let now = Instant::now();
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        
        // Refill tokens
        bucket.tokens = (bucket.tokens + elapsed * bucket.refill_rate).min(bucket.capacity);
        bucket.last_refill = now;
        
        // Check if we can consume a token
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}
```

### Definition of Done
- JWT authentication works for management endpoints
- API keys can be created and managed via authenticated endpoints
- Rate limiting works per API key
- Authentication integrates with request routing
- Secure key storage and rotation mechanisms are in place
- Integration with Kubernetes RBAC for namespace access

### Dependencies
- Issue #8 (HTTP Gateway Core)
- Issue #11 (Gateway Configuration)

### Additional Context
- Consider integrating with external identity providers (OIDC, SAML)
- Implement API key rotation and versioning
- Add audit logging for authentication events
- Plan for integration with Kubernetes admission controllers