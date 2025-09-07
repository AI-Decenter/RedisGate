# Issue #9: Redis Command Translation and Execution

**Priority**: Critical  
**Labels**: gateway, redis, commands  
**Milestone**: Phase 3 - HTTP Gateway  
**Estimated Effort**: 3-4 days

## Summary
Implement HTTP-to-Redis command translation for all supported Redis operations (GET, SET, DEL, HGET, HSET, raw commands) with proper error handling and response formatting.

## Motivation
The gateway needs to translate HTTP requests into Redis commands while maintaining data type integrity, handling Redis-specific errors, and providing consistent HTTP responses.

## Detailed Description

### Technical Requirements
- HTTP endpoint handlers for Redis commands
- Request parameter validation and sanitization
- Redis command execution with connection pooling
- Response formatting and error translation
- Support for method override via query parameters
- TTL handling for key expiration

### Acceptance Criteria
- [ ] GET /keys/{key} - retrieve key values
- [ ] POST /keys/{key} - set key values with optional TTL
- [ ] DELETE /keys/{key} - delete keys
- [ ] GET /hashes/{hash}/{field} - get hash field values
- [ ] POST /hashes/{hash} - set hash field values
- [ ] POST /raw-command - execute arbitrary Redis commands
- [ ] Method override support (?method=POST)
- [ ] Proper HTTP status codes for different Redis responses
- [ ] Input validation and sanitization

### Implementation Details

#### Key Operations Handler
```rust
// src/handlers/keys.rs
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{
    error::{GatewayError, Result},
    server::AppState,
};

#[derive(Deserialize)]
pub struct SetKeyRequest {
    value: String,
    ttl_seconds: Option<u64>,
}

#[derive(Deserialize)]
pub struct MethodOverride {
    method: Option<String>,
    value: Option<String>,
    ttl_seconds: Option<u64>,
}

#[derive(Serialize)]
pub struct SetKeyResponse {
    status: String,
}

#[derive(Serialize)]
pub struct GetKeyResponse {
    key: String,
    value: String,
}

#[derive(Serialize)]
pub struct DeleteKeyResponse {
    deleted: u32,
}

pub async fn get_key(
    Path((instance_name, key)): Path<(String, String)>,
    Query(params): Query<MethodOverride>,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>> {
    // Handle method override
    if let Some(method) = params.method {
        match method.to_uppercase().as_str() {
            "POST" => return set_key_override(instance_name, key, params, state).await,
            "DELETE" => return delete_key_method(instance_name, key, state).await,
            _ => {}
        }
    }

    // Get Redis client for instance
    let mut client = state
        .redis_pool
        .get_client(&instance_name)
        .await
        .ok_or_else(|| GatewayError::InstanceNotFound(instance_name.clone()))?;

    // Execute Redis GET command
    let value: Option<String> = redis::cmd("GET")
        .arg(&key)
        .query_async(&mut client)
        .await
        .map_err(GatewayError::Redis)?;

    match value {
        Some(v) => Ok(Json(serde_json::json!({
            "key": key,
            "value": v
        }))),
        None => Err(GatewayError::BadRequest(format!("Key '{}' not found", key))),
    }
}

pub async fn set_key(
    Path((instance_name, key)): Path<(String, String)>,
    State(state): State<AppState>,
    Json(payload): Json<SetKeyRequest>,
) -> Result<Json<SetKeyResponse>> {
    // Get Redis client for instance
    let mut client = state
        .redis_pool
        .get_client(&instance_name)
        .await
        .ok_or_else(|| GatewayError::InstanceNotFound(instance_name))?;

    // Execute Redis SET command with optional TTL
    if let Some(ttl) = payload.ttl_seconds {
        redis::cmd("SETEX")
            .arg(&key)
            .arg(ttl)
            .arg(&payload.value)
            .query_async(&mut client)
            .await
            .map_err(GatewayError::Redis)?;
    } else {
        redis::cmd("SET")
            .arg(&key)
            .arg(&payload.value)
            .query_async(&mut client)
            .await
            .map_err(GatewayError::Redis)?;
    }

    Ok(Json(SetKeyResponse {
        status: "OK".to_string(),
    }))
}

async fn set_key_override(
    instance_name: String,
    key: String,
    params: MethodOverride,
    state: AppState,
) -> Result<Json<serde_json::Value>> {
    let value = params.value.ok_or_else(|| {
        GatewayError::BadRequest("Missing 'value' parameter for SET operation".to_string())
    })?;

    let request = SetKeyRequest {
        value,
        ttl_seconds: params.ttl_seconds,
    };

    let response = set_key(
        Path((instance_name, key)),
        State(state),
        Json(request),
    ).await?;

    Ok(Json(serde_json::to_value(response.0)?))
}

pub async fn delete_key(
    Path((instance_name, key)): Path<(String, String)>,
    State(state): State<AppState>,
) -> Result<Json<DeleteKeyResponse>> {
    delete_key_method(instance_name, key, state).await
}

async fn delete_key_method(
    instance_name: String,
    key: String,
    state: AppState,
) -> Result<Json<serde_json::Value>> {
    // Get Redis client for instance
    let mut client = state
        .redis_pool
        .get_client(&instance_name)
        .await
        .ok_or_else(|| GatewayError::InstanceNotFound(instance_name))?;

    // Execute Redis DEL command
    let deleted: u32 = redis::cmd("DEL")
        .arg(&key)
        .query_async(&mut client)
        .await
        .map_err(GatewayError::Redis)?;

    Ok(Json(serde_json::json!({
        "deleted": deleted
    })))
}
```

#### Hash Operations Handler
```rust
// src/handlers/hashes.rs
use axum::{
    extract::{Path, State},
    response::Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    error::{GatewayError, Result},
    server::AppState,
};

#[derive(Deserialize)]
pub struct HSetRequest {
    field: String,
    value: String,
}

#[derive(Serialize)]
pub struct HSetResponse {
    status: String,
}

#[derive(Serialize)]
pub struct HGetResponse {
    hash: String,
    field: String,
    value: String,
}

pub async fn hset(
    Path((instance_name, hash)): Path<(String, String)>,
    State(state): State<AppState>,
    Json(payload): Json<HSetRequest>,
) -> Result<Json<HSetResponse>> {
    // Get Redis client for instance
    let mut client = state
        .redis_pool
        .get_client(&instance_name)
        .await
        .ok_or_else(|| GatewayError::InstanceNotFound(instance_name))?;

    // Execute Redis HSET command
    let _: u32 = redis::cmd("HSET")
        .arg(&hash)
        .arg(&payload.field)
        .arg(&payload.value)
        .query_async(&mut client)
        .await
        .map_err(GatewayError::Redis)?;

    Ok(Json(HSetResponse {
        status: "OK".to_string(),
    }))
}

pub async fn hget(
    Path((instance_name, hash, field)): Path<(String, String, String)>,
    State(state): State<AppState>,
) -> Result<Json<HGetResponse>> {
    // Get Redis client for instance
    let mut client = state
        .redis_pool
        .get_client(&instance_name)
        .await
        .ok_or_else(|| GatewayError::InstanceNotFound(instance_name.clone()))?;

    // Execute Redis HGET command
    let value: Option<String> = redis::cmd("HGET")
        .arg(&hash)
        .arg(&field)
        .query_async(&mut client)
        .await
        .map_err(GatewayError::Redis)?;

    match value {
        Some(v) => Ok(Json(HGetResponse {
            hash,
            field,
            value: v,
        })),
        None => Err(GatewayError::BadRequest(format!(
            "Field '{}' not found in hash '{}'",
            field, hash
        ))),
    }
}
```

#### Raw Command Handler
```rust
// src/handlers/raw.rs
use axum::{extract::State, response::Json};
use serde::{Deserialize, Serialize};

use crate::{
    error::{GatewayError, Result},
    server::AppState,
};

#[derive(Deserialize)]
pub struct RawCommandRequest {
    command: String,
    args: Vec<String>,
}

#[derive(Serialize)]
pub struct RawCommandResponse {
    result: serde_json::Value,
}

pub async fn execute_command(
    Path(instance_name): Path<String>,
    State(state): State<AppState>,
    Json(payload): Json<RawCommandRequest>,
) -> Result<Json<RawCommandResponse>> {
    // Validate command (security check)
    validate_command(&payload.command)?;

    // Get Redis client for instance
    let mut client = state
        .redis_pool
        .get_client(&instance_name)
        .await
        .ok_or_else(|| GatewayError::InstanceNotFound(instance_name))?;

    // Build and execute Redis command
    let mut cmd = redis::cmd(&payload.command);
    for arg in payload.args {
        cmd.arg(arg);
    }

    // Execute command and handle different response types
    let result: redis::Value = cmd
        .query_async(&mut client)
        .await
        .map_err(GatewayError::Redis)?;

    let json_result = redis_value_to_json(result);

    Ok(Json(RawCommandResponse {
        result: json_result,
    }))
}

fn validate_command(command: &str) -> Result<()> {
    // Allowlist of safe commands
    const ALLOWED_COMMANDS: &[&str] = &[
        "GET", "SET", "DEL", "HGET", "HSET", "HDEL",
        "LPUSH", "RPUSH", "LPOP", "RPOP", "LLEN",
        "SADD", "SREM", "SMEMBERS", "SCARD",
        "ZADD", "ZREM", "ZRANGE", "ZCARD",
        "EXISTS", "TTL", "EXPIRE", "PERSIST",
        "XADD", "XREAD", "XRANGE"
    ];

    if !ALLOWED_COMMANDS.contains(&command.to_uppercase().as_str()) {
        return Err(GatewayError::BadRequest(format!(
            "Command '{}' is not allowed",
            command
        )));
    }

    Ok(())
}

fn redis_value_to_json(value: redis::Value) -> serde_json::Value {
    match value {
        redis::Value::Nil => serde_json::Value::Null,
        redis::Value::Int(i) => serde_json::json!(i),
        redis::Value::Data(bytes) => {
            if let Ok(s) = String::from_utf8(bytes) {
                serde_json::json!(s)
            } else {
                serde_json::Value::Null
            }
        }
        redis::Value::Bulk(values) => {
            let json_values: Vec<serde_json::Value> = values
                .into_iter()
                .map(redis_value_to_json)
                .collect();
            serde_json::json!(json_values)
        }
        redis::Value::Status(s) => serde_json::json!(s),
        redis::Value::Okay => serde_json::json!("OK"),
    }
}
```

### Definition of Done
- All Redis command endpoints work correctly
- Method override functionality works via query parameters
- Proper error handling for invalid Redis operations
- Response formats match API specification
- Input validation prevents malicious commands
- TTL functionality works for key operations

### Dependencies
- Issue #8 (HTTP Gateway Core)

### Additional Context
- Implement command allowlisting for security
- Consider adding bulk operations support
- Add comprehensive input validation
- Plan for Redis Cluster support in future