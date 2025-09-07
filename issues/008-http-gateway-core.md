# Issue #8: HTTP Gateway Core Server Implementation

**Priority**: Critical  
**Labels**: gateway, rust, http, core  
**Milestone**: Phase 3 - HTTP Gateway  
**Estimated Effort**: 4-5 days

## Summary
Implement the core HTTP server for the Redis gateway using Rust with high-performance async I/O, request routing, and connection pooling.

## Motivation
The HTTP gateway is the core component that handles all client requests and translates them to Redis commands. It needs to be high-performance, reliable, and scalable to handle thousands of concurrent connections.

## Detailed Description

### Technical Requirements
- High-performance async HTTP server using Tokio
- Connection pooling to Redis instances
- Request routing and middleware architecture
- Error handling and response formatting
- Health checks and metrics endpoints
- Graceful shutdown handling

### Acceptance Criteria
- [ ] HTTP server starts and accepts connections on configured port
- [ ] Request routing system with middleware support
- [ ] Redis connection pool management
- [ ] Structured error handling with proper HTTP status codes
- [ ] Health check endpoint (`/healthz`)
- [ ] Metrics endpoint (`/metrics`) for Prometheus
- [ ] Graceful shutdown with connection draining
- [ ] Comprehensive logging with correlation IDs

### Implementation Details

#### Project Structure
```
gateway/
├── src/
│   ├── main.rs
│   ├── config.rs
│   ├── server.rs
│   ├── router.rs
│   ├── middleware/
│   │   ├── mod.rs
│   │   ├── auth.rs
│   │   ├── logging.rs
│   │   └── metrics.rs
│   ├── handlers/
│   │   ├── mod.rs
│   │   ├── health.rs
│   │   ├── keys.rs
│   │   ├── hashes.rs
│   │   └── raw.rs
│   ├── redis/
│   │   ├── mod.rs
│   │   ├── pool.rs
│   │   └── client.rs
│   ├── error.rs
│   └── lib.rs
├── tests/
├── benches/
└── Cargo.toml
```

#### Core Dependencies (Cargo.toml)
```toml
[package]
name = "redis-http-gateway"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio = { version = "1.0", features = ["full"] }
axum = "0.7"
tower = "0.4"
tower-http = { version = "0.5", features = ["cors", "trace"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
redis = { version = "0.24", features = ["aio", "tokio-comp"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
uuid = { version = "1.0", features = ["v4"] }
anyhow = "1.0"
thiserror = "1.0"
config = "0.14"
metrics = "0.22"
metrics-exporter-prometheus = "0.13"

[dev-dependencies]
testcontainers = "0.15"
tokio-test = "0.4"
```

#### Main Server Implementation
```rust
// src/main.rs
use axum::{
    routing::{get, post, delete},
    Router,
};
use std::net::SocketAddr;
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod error;
mod handlers;
mod middleware;
mod redis;
mod router;
mod server;

use crate::{
    config::Config,
    middleware::{auth::AuthLayer, logging::RequestIdLayer, metrics::MetricsLayer},
    redis::pool::RedisPoolManager,
    server::AppState,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "redis_http_gateway=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = Config::from_env()?;
    
    // Initialize Redis pool manager
    let redis_pool = RedisPoolManager::new(&config.redis).await?;
    
    // Create application state
    let state = AppState {
        redis_pool,
        config: config.clone(),
    };

    // Build router with middleware
    let app = create_router(state)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CorsLayer::permissive())
                .layer(RequestIdLayer::new())
                .layer(MetricsLayer::new())
                .layer(AuthLayer::new()),
        );

    // Start metrics server
    let metrics_handle = tokio::spawn(async move {
        metrics_exporter_prometheus::PrometheusBuilder::new()
            .install()
            .expect("failed to install Prometheus recorder");
    });

    // Start HTTP server
    let addr = SocketAddr::from(([0, 0, 0, 0], config.server.port));
    tracing::info!("Starting server on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    metrics_handle.abort();
    Ok(())
}

fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(handlers::health::health_check))
        .route("/readyz", get(handlers::health::readiness_check))
        .route("/metrics", get(handlers::health::metrics))
        .nest("/instances/:instance_name", instance_routes())
        .with_state(state)
}

fn instance_routes() -> Router<AppState> {
    Router::new()
        .route("/keys/:key", get(handlers::keys::get_key))
        .route("/keys/:key", post(handlers::keys::set_key))
        .route("/keys/:key", delete(handlers::keys::delete_key))
        .route("/hashes/:hash", post(handlers::hashes::hset))
        .route("/hashes/:hash/:field", get(handlers::hashes::hget))
        .route("/raw-command", post(handlers::raw::execute_command))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("Shutdown signal received");
}
```

#### Application State
```rust
// src/server.rs
use crate::{config::Config, redis::pool::RedisPoolManager};

#[derive(Clone)]
pub struct AppState {
    pub redis_pool: RedisPoolManager,
    pub config: Config,
}
```

#### Error Handling
```rust
// src/error.rs
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GatewayError {
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),
    
    #[error("Authentication failed")]
    Unauthorized,
    
    #[error("Instance not found: {0}")]
    InstanceNotFound(String),
    
    #[error("Invalid request: {0}")]
    BadRequest(String),
    
    #[error("Internal server error")]
    Internal,
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            GatewayError::Redis(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            GatewayError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()),
            GatewayError::InstanceNotFound(name) => (StatusCode::NOT_FOUND, format!("Instance '{}' not found", name)),
            GatewayError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            GatewayError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()),
        };

        let body = Json(json!({
            "error": error_message,
            "status": status.as_u16()
        }));

        (status, body).into_response()
    }
}

pub type Result<T> = std::result::Result<T, GatewayError>;
```

### Definition of Done
- HTTP server starts successfully and accepts connections
- Basic routing works for all planned endpoints
- Redis connection pooling is implemented
- Error handling returns proper HTTP status codes
- Health checks respond correctly
- Server shuts down gracefully
- Unit tests cover core functionality

### Dependencies
- Issue #1 (Project Setup)
- Issue #2 (Container Images)

### Additional Context
- Use `axum` for HTTP framework (modern, performant)
- Implement connection pooling with `deadpool-redis`
- Use structured logging with correlation IDs
- Consider implementing request/response compression
- Plan for horizontal scaling and load balancing