use axum::{
    extract::{Path, State, Query},
    response::IntoResponse,
    Json, body::Bytes,
    http::{HeaderMap, StatusCode},
};
use axum::debug_handler;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::{
    error::{GatewayError, Result},
    server::AppState,
};

#[derive(Deserialize)]
pub struct TokenQuery {
    _token: Option<String>,
}

#[derive(Serialize)]
pub struct RedisResponse {
    result: Value,
}

#[derive(Debug, serde::Deserialize)]
pub struct RedisCommandParams {
    pub instance_name: String,
    pub command_parts: String,
}
#[derive(Serialize)]
pub struct RedisError {
    error: String,
}

// Generic Redis command handler - handles path-based commands
#[axum::debug_handler]
pub async fn redis_command(
    Path(params): Path<RedisCommandParams>,
    Query(token_query): Query<TokenQuery>,
    headers: HeaderMap,
    State(state): State<AppState>,
    body: Bytes,
) -> Result<impl IntoResponse> {
    // Extract token from header or query p+aram
    let _token = extract_token(&headers, &token_query)?;
    let instance_name = &params.instance_name;
    let command_parts = &params.command_parts;

    // Parse command from path
    let parts: Vec<&str> = command_parts.split('/').collect();

    // log the command parts for debugging
    println!("Command parts: {:?}", parts);
    if parts.is_empty() {
        return Err(GatewayError::BadRequest("Empty command".to_string()));
    }


    let mut client = state
        .redis_pool
        .get_client(instance_name)
        .await
        .ok_or_else(|| GatewayError::InstanceNotFound(instance_name.to_string()))?;

    // Build Redis command
    let mut cmd = redis::cmd(parts[0].to_uppercase().as_str());

    // Add path arguments
    for &arg in &parts[1..] {
        cmd.arg(arg);
    }

    // Add body as last argument if present (for POST requests)
    if !body.is_empty() {
        let body_str = String::from_utf8_lossy(&body);
        cmd.arg(body_str.as_ref());
    }

    // Execute command
    let result: redis::Value = cmd
        .query_async(&mut client)
        .await
        .map_err(|e| GatewayError::BadRequest(format!("Redis error: {}", e)))?;

    // Convert Redis value to JSON
    let json_result = redis_value_to_json(result);

    Ok(Json(RedisResponse { result: json_result }))
}


// Handle POST requests with JSON array commands
pub async fn redis_command_json(
    Query(token_query): Query<TokenQuery>,
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(command_array): Json<Vec<Value>>,
) -> Result<impl IntoResponse> {
    // Extract token
    let _token = extract_token(&headers, &token_query)?;

    if command_array.is_empty() {
        return Err(GatewayError::BadRequest("Empty command array".to_string()));
    }

    // For now, hardcode instance name
    let instance_name = "my-redis-replicas";

    let mut client = state
        .redis_pool
        .get_client(instance_name)
        .await
        .ok_or_else(|| GatewayError::InstanceNotFound(instance_name.to_string()))?;

    // Build Redis command from JSON array
    let command_name = command_array[0]
        .as_str()
        .ok_or_else(|| GatewayError::BadRequest("First element must be command name".to_string()))?;

    let mut cmd = redis::cmd(command_name);

    // Add arguments
    for arg in &command_array[1..] {
        // Trong redis_command_json và redis_pipeline
        match arg {
            Value::String(s) => { cmd.arg(s); },
            Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    cmd.arg(i);
                } else if let Some(f) = n.as_f64() {
                    cmd.arg(f);
                } else {
                    cmd.arg(n.to_string());
                }
            },
            Value::Bool(b) => { cmd.arg(if *b { "1" } else { "0" }); },
            _ => { cmd.arg(arg.to_string()); },
        };
    }

    // Execute command
    let result: redis::Value = cmd
        .query_async(&mut client)
        .await
        .map_err(|e| GatewayError::BadRequest(format!("Redis error: {}", e)))?;

    // Convert Redis value to JSON
    let json_result = redis_value_to_json(result);

    Ok(Json(RedisResponse { result: json_result }))
}

// Pipeline endpoint
pub async fn redis_pipeline(
    Query(token_query): Query<TokenQuery>,
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(commands): Json<Vec<Vec<Value>>>,
) -> Result<impl IntoResponse> {
    // Extract token
    let _token = extract_token(&headers, &token_query)?;

    if commands.is_empty() {
        return Err(GatewayError::BadRequest("Empty pipeline".to_string()));
    }

    let instance_name = "my-redis-replicas";

    let mut client = state
        .redis_pool
        .get_client(instance_name)
        .await
        .ok_or_else(|| GatewayError::InstanceNotFound(instance_name.to_string()))?;

    let mut results = Vec::new();

    // Execute each command
    for command_array in commands {
        if command_array.is_empty() {
            results.push(json!({"error": "Empty command in pipeline"}));
            continue;
        }

        let command_name = match command_array[0].as_str() {
            Some(name) => name,
            None => {
                results.push(json!({"error": "Invalid command name"}));
                continue;
            }
        };

        let mut cmd = redis::cmd(command_name);

        // Add arguments
        for arg in &command_array[1..] {
            // Trong redis_command_json và redis_pipeline
            match arg {
                Value::String(s) => { cmd.arg(s); },
                Value::Number(n) => {
                    if let Some(i) = n.as_i64() {
                        cmd.arg(i);
                    } else if let Some(f) = n.as_f64() {
                        cmd.arg(f);
                    } else {
                        cmd.arg(n.to_string());
                    }
                },
                Value::Bool(b) => { cmd.arg(if *b { "1" } else { "0" }); },
                _ => { cmd.arg(arg.to_string()); },
            };
        }

        // Execute command
        match cmd.query_async::<_, redis::Value>(&mut client).await {
            Ok(result) => {
                let json_result = redis_value_to_json(result);
                results.push(json!({"result": json_result}));
            },
            Err(e) => {
                results.push(json!({"error": format!("Redis error: {}", e)}));
            }
        }
    }

    Ok(Json(results))
}

// Transaction endpoint (multi-exec)
pub async fn redis_transaction(
    Query(token_query): Query<TokenQuery>,
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(commands): Json<Vec<Vec<Value>>>,
) -> Result<impl IntoResponse> {
    // Extract token
    let _token = extract_token(&headers, &token_query)?;

    if commands.is_empty() {
        return Err(GatewayError::BadRequest("Empty transaction".to_string()));
    }

    let instance_name = "my-redis-replicas";

    let mut client = state
        .redis_pool
        .get_client(instance_name)
        .await
        .ok_or_else(|| GatewayError::InstanceNotFound(instance_name.to_string()))?;

    // Start transaction
    redis::cmd("MULTI")
        .query_async::<_, ()>(&mut client)
        .await
        .map_err(|e| GatewayError::BadRequest(format!("Failed to start transaction: {}", e)))?;

    // Queue commands
    for command_array in &commands {
        if command_array.is_empty() {
            // Discard transaction on error
            let _ = redis::cmd("DISCARD").query_async::<_, ()>(&mut client).await;
            return Err(GatewayError::BadRequest("Empty command in transaction".to_string()));
        }

        let Some(command_name) = command_array[0].as_str() else {
            // Discard transaction on error
            let _ = redis::cmd("DISCARD").query_async::<_, ()>(&mut client).await;
            return Err(GatewayError::BadRequest("Invalid command name".to_string()));
        };


        let mut cmd = redis::cmd(command_name);

        // Add arguments
        for arg in &command_array[1..] {
            match arg {
                Value::String(s) => { cmd.arg(s); },
                Value::Number(n) => {
                    if let Some(i) = n.as_i64() {
                        cmd.arg(i);
                    } else if let Some(f) = n.as_f64() {
                        cmd.arg(f);
                    } else {
                        cmd.arg(n.to_string());
                    }
                },
                Value::Bool(b) => { cmd.arg(if *b { "1" } else { "0" }); },
                _ => { cmd.arg(arg.to_string()); },
            };
        }

        // Queue command
        cmd.query_async::<_, ()>(&mut client)
            .await
            .map_err(|e| {
                // Discard transaction on error
                let _ = redis::cmd("DISCARD").query_async::<_, ()>(&mut client);
                GatewayError::BadRequest(format!("Failed to queue command: {}", e))
            })?;
    }

    // Execute transaction
    let results: Vec<redis::Value> = redis::cmd("EXEC")
        .query_async(&mut client)
        .await
        .map_err(|e| GatewayError::BadRequest(format!("Failed to execute transaction: {}", e)))?;

    // Convert results to JSON
    let json_results: Vec<Value> = results
        .into_iter()
        .map(|result| json!({"result": redis_value_to_json(result)}))
        .collect();

    Ok(Json(json_results))
}

// Helper function to extract token from header or query
fn extract_token(headers: &HeaderMap, query: &TokenQuery) -> Result<String> {
    // Try Authorization header first
    if let Some(auth_header) = headers.get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Bearer ") {
                return Ok(auth_str[7..].to_string());
            }
        }
    }

    // Try query parameter
    if let Some(token) = &query._token {
        return Ok(token.clone());
    }

    Err(GatewayError::BadRequest("Missing authentication token".to_string()))
}

// Helper function to convert Redis value to JSON
fn redis_value_to_json(value: redis::Value) -> Value {
    match value {
        redis::Value::Nil => Value::Null,
        redis::Value::Int(i) => json!(i),
        redis::Value::Data(bytes) => {
            // Try to convert to string, fallback to base64 if invalid UTF-8
            match String::from_utf8(bytes.clone()) {
                Ok(s) => json!(s),
                Err(_) => json!(base64::encode(bytes)),
            }
        },
        redis::Value::Bulk(values) => {
            let json_values: Vec<Value> = values
                .into_iter()
                .map(redis_value_to_json)
                .collect();
            json!(json_values)
        },
        redis::Value::Status(s) => json!(s),
        redis::Value::Okay => json!("OK"),
    }
}

// Legacy handlers for backward compatibility (optional)
pub async fn get_key_legacy(
    Path((instance_name, key)): Path<(String, String)>,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>> {
    let mut client = state
        .redis_pool
        .get_client(&instance_name)
        .await
        .ok_or_else(|| GatewayError::InstanceNotFound(instance_name.clone()))?;

    let value: Option<String> = redis::cmd("GET")
        .arg(&key)
        .query_async(&mut client)
        .await
        .map_err(GatewayError::Redis)?;

    match value {
        Some(v) => Ok(Json(json!({"result": v}))),
        None => Ok(Json(json!({"result": null}))),
    }
}

pub async fn set_key_legacy(
    Path((instance_name, key)): Path<(String, String)>,
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Json<serde_json::Value>> {
    let value = String::from_utf8_lossy(&body);

    let mut client = state
        .redis_pool
        .get_client(&instance_name)
        .await
        .ok_or_else(|| GatewayError::InstanceNotFound(instance_name))?;

    redis::cmd("SET")
        .arg(&key)
        .arg(value.as_ref())
        .query_async::<_, ()>(&mut client)
        .await
        .map_err(GatewayError::Redis)?;

    Ok(Json(json!({"result": "OK"})))
}

// Thêm handler mới này vào file của bạn

pub async fn delete_keys_legacy(
    Path((instance_name, keys)): Path<(String, String)>,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>> {
    // Tách chuỗi keys thành một vector các string
    // Ví dụ: "key1,key2,key3" sẽ được tách thành ["key1", "key2", "key3"]
    let key_parts: Vec<&str> = keys.split(',').collect();

    if key_parts.is_empty() {
        return Err(GatewayError::BadRequest("No keys provided".to_string()));
    }

    let mut client = state
        .redis_pool
        .get_client(&instance_name)
        .await
        .ok_or_else(|| GatewayError::InstanceNotFound(instance_name.clone()))?;

    // Sử dụng lệnh DEL của Redis để xóa các khóa
    let mut cmd = redis::cmd("DEL");
    for &key in &key_parts {
        cmd.arg(key);
    }

    // Thực thi lệnh và nhận số lượng khóa đã bị xóa
    let deleted_count: i64 = cmd
        .query_async(&mut client)
        .await
        .map_err(GatewayError::Redis)?;

    Ok(Json(json!({"result": deleted_count})))
}