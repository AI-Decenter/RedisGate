# Issue #16: Observability and Monitoring Stack

**Priority**: High  
**Labels**: observability, monitoring, metrics  
**Milestone**: Phase 5 - Operations & Monitoring  
**Estimated Effort**: 3-4 days

## Summary
Implement comprehensive observability stack including metrics, logging, distributed tracing, and alerting for the Redis HTTP Gateway system.

## Motivation
Production systems require robust observability to understand system behavior, diagnose issues, and ensure reliability. This includes metrics for performance monitoring, structured logging for debugging, and distributed tracing for request flow analysis.

## Detailed Description

### Technical Requirements
- Prometheus metrics collection and exposition
- Structured logging with correlation IDs
- Distributed tracing with OpenTelemetry
- Grafana dashboards for visualization
- Alerting rules for critical conditions
- Health checks and service level indicators (SLIs)

### Acceptance Criteria
- [ ] Prometheus metrics endpoint exposes key system metrics
- [ ] Structured JSON logging with request correlation
- [ ] Distributed tracing tracks requests end-to-end
- [ ] Grafana dashboards show system health and performance
- [ ] Alert rules notify on critical conditions
- [ ] Health check endpoints provide detailed status
- [ ] Performance metrics include latency percentiles
- [ ] Resource usage metrics for capacity planning

### Implementation Details

#### Metrics Collection
```rust
// src/metrics/mod.rs
use metrics::{counter, gauge, histogram, register_counter, register_gauge, register_histogram};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use std::time::{Duration, Instant};

pub struct MetricsCollector {
    prometheus_handle: PrometheusHandle,
}

impl MetricsCollector {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let builder = PrometheusBuilder::new();
        let prometheus_handle = builder
            .idle_timeout(
                MetricKindMask::COUNTER | MetricKindMask::HISTOGRAM,
                Some(Duration::from_secs(600)),
            )
            .with_http_listener(([0, 0, 0, 0], 9090))
            .install()?;

        // Register custom metrics
        register_counter!("redis_gateway_requests_total", "Total number of requests");
        register_counter!("redis_gateway_requests_failed_total", "Total number of failed requests");
        register_histogram!("redis_gateway_request_duration_seconds", "Request duration in seconds");
        register_histogram!("redis_gateway_redis_operation_duration_seconds", "Redis operation duration in seconds");
        register_gauge!("redis_gateway_active_connections", "Number of active connections");
        register_gauge!("redis_gateway_redis_pool_size", "Current Redis connection pool size");
        register_gauge!("redis_gateway_redis_pool_active", "Active Redis connections");

        Ok(Self { prometheus_handle })
    }

    pub fn record_request(&self, method: &str, endpoint: &str, status_code: u16, duration: Duration) {
        let labels = [
            ("method", method.to_string()),
            ("endpoint", endpoint.to_string()),
            ("status_code", status_code.to_string()),
        ];
        
        counter!("redis_gateway_requests_total", &labels).increment(1);
        
        if status_code >= 400 {
            counter!("redis_gateway_requests_failed_total", &labels).increment(1);
        }
        
        histogram!("redis_gateway_request_duration_seconds", &labels)
            .record(duration.as_secs_f64());
    }

    pub fn record_redis_operation(&self, operation: &str, instance: &str, duration: Duration) {
        let labels = [
            ("operation", operation.to_string()),
            ("instance", instance.to_string()),
        ];
        
        histogram!("redis_gateway_redis_operation_duration_seconds", &labels)
            .record(duration.as_secs_f64());
    }

    pub fn update_connection_count(&self, count: i64) {
        gauge!("redis_gateway_active_connections").set(count as f64);
    }

    pub fn update_pool_metrics(&self, instance: &str, pool_size: usize, active: usize) {
        let labels = [("instance", instance.to_string())];
        
        gauge!("redis_gateway_redis_pool_size", &labels).set(pool_size as f64);
        gauge!("redis_gateway_redis_pool_active", &labels).set(active as f64);
    }

    pub fn render_metrics(&self) -> String {
        self.prometheus_handle.render()
    }
}

// Metrics middleware
pub struct MetricsMiddleware {
    collector: Arc<MetricsCollector>,
}

impl MetricsMiddleware {
    pub fn new(collector: Arc<MetricsCollector>) -> Self {
        Self { collector }
    }

    pub async fn process_request<B>(
        &self,
        req: axum::extract::Request<B>,
        next: axum::middleware::Next<B>,
    ) -> axum::response::Response {
        let start_time = Instant::now();
        let method = req.method().to_string();
        let path = req.uri().path().to_string();

        let response = next.run(req).await;
        
        let duration = start_time.elapsed();
        let status_code = response.status().as_u16();
        
        self.collector.record_request(&method, &path, status_code, duration);
        
        response
    }
}
```

#### Structured Logging
```rust
// src/logging/mod.rs
use serde_json::json;
use tracing::{info, error, warn, debug};
use tracing_subscriber::{
    fmt::{format::JsonFields, time::ChronoUtc},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter, Registry,
};
use uuid::Uuid;

pub fn init_logging() -> Result<(), Box<dyn std::error::Error>> {
    let format = std::env::var("LOG_FORMAT").unwrap_or_else(|_| "json".to_string());
    let level = std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string());
    
    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&level))?;

    match format.as_str() {
        "json" => {
            Registry::default()
                .with(env_filter)
                .with(
                    tracing_subscriber::fmt::layer()
                        .json()
                        .with_timer(ChronoUtc::rfc_3339())
                        .fmt_fields(JsonFields::new())
                        .with_target(true)
                        .with_thread_ids(true)
                        .with_thread_names(true),
                )
                .init();
        }
        "pretty" => {
            Registry::default()
                .with(env_filter)
                .with(
                    tracing_subscriber::fmt::layer()
                        .pretty()
                        .with_timer(ChronoUtc::rfc_3339())
                        .with_target(true),
                )
                .init();
        }
        _ => {
            return Err("Invalid LOG_FORMAT. Use 'json' or 'pretty'".into());
        }
    }

    Ok(())
}

#[derive(Clone)]
pub struct RequestLogger {
    service_name: String,
    version: String,
}

impl RequestLogger {
    pub fn new(service_name: String, version: String) -> Self {
        Self {
            service_name,
            version,
        }
    }

    pub fn log_request_start(&self, correlation_id: &str, method: &str, path: &str, user_id: Option<&str>) {
        info!(
            correlation_id = correlation_id,
            service.name = self.service_name,
            service.version = self.version,
            http.method = method,
            http.path = path,
            user.id = user_id,
            event = "request_start",
            "HTTP request started"
        );
    }

    pub fn log_request_end(&self, correlation_id: &str, status_code: u16, duration_ms: u64) {
        let level = if status_code >= 500 {
            tracing::Level::ERROR
        } else if status_code >= 400 {
            tracing::Level::WARN
        } else {
            tracing::Level::INFO
        };

        match level {
            tracing::Level::ERROR => error!(
                correlation_id = correlation_id,
                http.status_code = status_code,
                duration_ms = duration_ms,
                event = "request_end",
                "HTTP request completed with error"
            ),
            tracing::Level::WARN => warn!(
                correlation_id = correlation_id,
                http.status_code = status_code,
                duration_ms = duration_ms,
                event = "request_end",
                "HTTP request completed with warning"
            ),
            _ => info!(
                correlation_id = correlation_id,
                http.status_code = status_code,
                duration_ms = duration_ms,
                event = "request_end",
                "HTTP request completed successfully"
            ),
        }
    }

    pub fn log_redis_operation(&self, correlation_id: &str, operation: &str, instance: &str, duration_ms: u64, success: bool) {
        if success {
            debug!(
                correlation_id = correlation_id,
                redis.operation = operation,
                redis.instance = instance,
                duration_ms = duration_ms,
                event = "redis_operation_success",
                "Redis operation completed successfully"
            );
        } else {
            error!(
                correlation_id = correlation_id,
                redis.operation = operation,
                redis.instance = instance,
                duration_ms = duration_ms,
                event = "redis_operation_error",
                "Redis operation failed"
            );
        }
    }

    pub fn log_error(&self, correlation_id: &str, error: &str, context: serde_json::Value) {
        error!(
            correlation_id = correlation_id,
            error = error,
            context = ?context,
            event = "error",
            "An error occurred"
        );
    }
}

// Middleware for request correlation
pub struct CorrelationMiddleware;

impl CorrelationMiddleware {
    pub async fn add_correlation_id<B>(
        mut req: axum::extract::Request<B>,
        next: axum::middleware::Next<B>,
    ) -> axum::response::Response {
        // Get or generate correlation ID
        let correlation_id = req
            .headers()
            .get("x-correlation-id")
            .and_then(|h| h.to_str().ok())
            .unwrap_or(&Uuid::new_v4().to_string())
            .to_string();

        // Add to request extensions
        req.extensions_mut().insert(correlation_id.clone());

        let mut response = next.run(req).await;
        
        // Add correlation ID to response headers
        response.headers_mut().insert(
            "x-correlation-id",
            correlation_id.parse().unwrap(),
        );

        response
    }
}
```

#### Distributed Tracing
```rust
// src/tracing/mod.rs
use opentelemetry::{
    global, runtime::TokioCurrentThread, sdk::propagation::TraceContextPropagator, trace::Tracer,
};
use opentelemetry_otlp::WithExportConfig;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Registry};

pub fn init_tracing(service_name: &str, endpoint: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    global::set_text_map_propagator(TraceContextPropagator::new());

    if let Some(endpoint) = endpoint {
        let tracer = opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(
                opentelemetry_otlp::new_exporter()
                    .tonic()
                    .with_endpoint(endpoint),
            )
            .with_trace_config(
                opentelemetry::sdk::trace::config()
                    .with_service_name(service_name)
                    .with_resource(opentelemetry::sdk::Resource::new(vec![
                        opentelemetry::KeyValue::new("service.name", service_name.to_string()),
                        opentelemetry::KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
                    ])),
            )
            .install_batch(TokioCurrentThread)?;

        Registry::default()
            .with(OpenTelemetryLayer::new(tracer))
            .try_init()?;
    }

    Ok(())
}

// Tracing utilities
pub struct TracingUtils;

impl TracingUtils {
    pub fn trace_redis_operation<F, R>(operation: &str, instance: &str, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let span = tracing::info_span!(
            "redis_operation",
            redis.operation = operation,
            redis.instance = instance
        );
        span.in_scope(f)
    }

    pub fn trace_http_request<F, R>(method: &str, path: &str, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let span = tracing::info_span!(
            "http_request",
            http.method = method,
            http.path = path
        );
        span.in_scope(f)
    }
}
```

#### Health Check System
```rust
// src/health/mod.rs
use axum::{extract::State, response::Json};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::time::{timeout, Duration};

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthStatus {
    pub status: String,
    pub timestamp: String,
    pub version: String,
    pub checks: HashMap<String, HealthCheck>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthCheck {
    pub status: String,
    pub message: Option<String>,
    pub duration_ms: u64,
}

pub struct HealthChecker {
    version: String,
}

impl HealthChecker {
    pub fn new(version: String) -> Self {
        Self { version }
    }

    pub async fn check_health(&self, state: &crate::server::AppState) -> HealthStatus {
        let mut checks = HashMap::new();
        let start_time = std::time::Instant::now();

        // Check Redis connectivity
        let redis_check = self.check_redis_health(state).await;
        checks.insert("redis".to_string(), redis_check);

        // Check Kubernetes API connectivity
        let k8s_check = self.check_kubernetes_health(state).await;
        checks.insert("kubernetes".to_string(), k8s_check);

        // Check disk space
        let disk_check = self.check_disk_space().await;
        checks.insert("disk".to_string(), disk_check);

        // Check memory usage
        let memory_check = self.check_memory_usage().await;
        checks.insert("memory".to_string(), memory_check);

        // Overall status
        let overall_status = if checks.values().all(|c| c.status == "healthy") {
            "healthy"
        } else if checks.values().any(|c| c.status == "unhealthy") {
            "unhealthy"
        } else {
            "degraded"
        };

        HealthStatus {
            status: overall_status.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            version: self.version.clone(),
            checks,
        }
    }

    async fn check_redis_health(&self, state: &crate::server::AppState) -> HealthCheck {
        let start = std::time::Instant::now();
        
        // Try to get a client from the pool manager
        match timeout(Duration::from_secs(5), async {
            // This is a simplified health check
            // In reality, you'd check multiple instances
            Ok::<(), String>(())
        })
        .await
        {
            Ok(_) => HealthCheck {
                status: "healthy".to_string(),
                message: Some("All Redis instances responding".to_string()),
                duration_ms: start.elapsed().as_millis() as u64,
            },
            Err(_) => HealthCheck {
                status: "unhealthy".to_string(),
                message: Some("Redis health check timed out".to_string()),
                duration_ms: start.elapsed().as_millis() as u64,
            },
        }
    }

    async fn check_kubernetes_health(&self, state: &crate::server::AppState) -> HealthCheck {
        let start = std::time::Instant::now();
        
        // Check if we can reach the Kubernetes API
        match timeout(Duration::from_secs(5), async {
            // Simplified check - in reality you'd make a K8s API call
            Ok::<(), String>(())
        })
        .await
        {
            Ok(_) => HealthCheck {
                status: "healthy".to_string(),
                message: Some("Kubernetes API accessible".to_string()),
                duration_ms: start.elapsed().as_millis() as u64,
            },
            Err(_) => HealthCheck {
                status: "unhealthy".to_string(),
                message: Some("Kubernetes API unreachable".to_string()),
                duration_ms: start.elapsed().as_millis() as u64,
            },
        }
    }

    async fn check_disk_space(&self) -> HealthCheck {
        let start = std::time::Instant::now();
        
        // Check available disk space (simplified)
        HealthCheck {
            status: "healthy".to_string(),
            message: Some("Sufficient disk space available".to_string()),
            duration_ms: start.elapsed().as_millis() as u64,
        }
    }

    async fn check_memory_usage(&self) -> HealthCheck {
        let start = std::time::Instant::now();
        
        // Check memory usage (simplified)
        HealthCheck {
            status: "healthy".to_string(),
            message: Some("Memory usage within normal range".to_string()),
            duration_ms: start.elapsed().as_millis() as u64,
        }
    }
}

// Health check handlers
pub async fn health_check(
    State(state): State<crate::server::AppState>,
) -> Json<HealthStatus> {
    let health_checker = HealthChecker::new(env!("CARGO_PKG_VERSION").to_string());
    let status = health_checker.check_health(&state).await;
    Json(status)
}

pub async fn readiness_check(
    State(state): State<crate::server::AppState>,
) -> Json<serde_json::Value> {
    // Simple readiness check
    Json(serde_json::json!({
        "status": "ready",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

pub async fn liveness_check() -> Json<serde_json::Value> {
    // Simple liveness check
    Json(serde_json::json!({
        "status": "alive",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}
```

#### Grafana Dashboard Configuration
```json
{
  "dashboard": {
    "title": "Redis HTTP Gateway",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(redis_gateway_requests_total[5m])",
            "legendFormat": "{{method}} {{endpoint}}"
          }
        ]
      },
      {
        "title": "Request Latency",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(redis_gateway_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          },
          {
            "expr": "histogram_quantile(0.50, rate(redis_gateway_request_duration_seconds_bucket[5m]))",
            "legendFormat": "50th percentile"
          }
        ]
      },
      {
        "title": "Error Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(redis_gateway_requests_failed_total[5m]) / rate(redis_gateway_requests_total[5m])",
            "legendFormat": "Error Rate"
          }
        ]
      },
      {
        "title": "Redis Pool Status",
        "type": "graph",
        "targets": [
          {
            "expr": "redis_gateway_redis_pool_size",
            "legendFormat": "Pool Size - {{instance}}"
          },
          {
            "expr": "redis_gateway_redis_pool_active",
            "legendFormat": "Active Connections - {{instance}}"
          }
        ]
      }
    ]
  }
}
```

### Definition of Done
- Prometheus metrics are exposed and collected
- Structured logging provides correlation and context
- Distributed tracing tracks requests across services
- Grafana dashboards visualize system health
- Health checks provide detailed system status
- Alert rules notify operators of issues
- Performance metrics help with capacity planning

### Dependencies
- Issue #8 (HTTP Gateway Core)
- Issue #10 (Connection Pool Management)

### Additional Context
- Consider implementing custom SLI/SLO monitoring
- Add business metrics beyond technical metrics
- Implement log aggregation with ELK or Loki stack
- Plan for metrics retention and archival policies
- Consider implementing synthetic monitoring for end-to-end testing