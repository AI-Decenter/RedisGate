// src/main.rs
use axum::{
    routing::{any, get, post},
    Router,
};
use deadpool_redis::{Pool, Runtime};
use metrics_exporter_prometheus::PrometheusBuilder;
use std::net::SocketAddr;
use axum::routing::delete;
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;
use tracing_subscriber::{fmt, prelude::*};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tracing_subscriber::{filter::EnvFilter};

mod config;
mod handlers;
mod error;
mod redis;
mod server;

use crate::config::{Config, RedisConfig};
use crate::redis::pool::RedisPoolManager;
use crate::server::AppState;

use handlers::health::*;
use handlers::keys::*;

mod middleware;
use middleware::{logging::request_logger, metrics::metrics_middleware};


/// Main entry point
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load configuration
    let cfg = Config::from_env()?;
    tracing::info!(?cfg, "⚙️ Loaded configuration");

    let log_level = cfg.logging.level.clone();
    let server_port = cfg.server.port;
    let redis_cfg = cfg.redis.clone();

    // Initialize tracing subscriber with env filter
    tracing_subscriber::registry()
        .with(
            EnvFilter::new(log_level),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("🚀 Server starting...");

    tracing::info!(?cfg, "⚙️ Loaded configuration");

    // Initialize Redis connection pool
    let redis_pool_manager = RedisPoolManager::new(&redis_cfg).await?;
    tracing::info!("✅ RedisPoolManager initialized");

    // Initialize Prometheus metrics recorder
    let metrics_handle = PrometheusBuilder::new()
        .install_recorder()
        .expect("Failed to install Prometheus recorder");

    let app_state = AppState {
        redis_pool: redis_pool_manager.clone(),
        config: cfg.clone(),
    };

    // Build application router
    // Build application router
    let app = Router::new()
        // New REST API routes
        .route("/{instance_name}/pipeline", post(redis_pipeline))
        .route("/{instance_name}/multi-exec", post(redis_transaction))
        .route("/{instance_name}", post(redis_command_json))
        .route("/{instance_name}/command/{*command_parts}", any(redis_command))

        .route("/legacy/{instance_name}/{key}", get(get_key_legacy))
        .route("/legacy/{instance_name}/{key}", post(set_key_legacy))
        .route("/legacy/{instance_name}/del/{keys}", delete(delete_keys_legacy)) // Thêm route này

        // Health and metrics endpoints
        .route("/healthz", get(health_check))
        .route("/metrics", get({
            let handle = metrics_handle.clone();
            move || async move { metrics_endpoint(handle.clone()).await }
        }),
        )
        .with_state(app_state)
        .layer(
            ServiceBuilder::new()
                .layer(CorsLayer::permissive())
                .layer(axum::middleware::from_fn(request_logger))
                .layer(axum::middleware::from_fn(metrics_middleware)),
        );

    // Server address
    let addr = SocketAddr::from(([0, 0, 0, 0], server_port));
    tracing::info!(%addr, "🌐 Server running");
    println!("🌐 Server running at http://{}", addr);

    // Start server with graceful shutdown
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            tracing::info!("⚡ Shutdown signal received, cleaning up...");
        })
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install terminate signal handler")
            .recv()
            .await;
    };

    #[cfg(unix)]
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    #[cfg(not(unix))]
    ctrl_c.await;

    tracing::info!("⚡ Shutdown signal received");
}
