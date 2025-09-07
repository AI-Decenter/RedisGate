# Issue #11: Gateway Configuration Management and Hot Reload

**Priority**: Medium  
**Labels**: gateway, configuration, kubernetes  
**Milestone**: Phase 3 - HTTP Gateway  
**Estimated Effort**: 2-3 days

## Summary
Implement dynamic configuration management for the HTTP gateway with support for Kubernetes ConfigMaps/Secrets and hot reloading without service disruption.

## Motivation
The gateway needs flexible configuration management that allows operators to adjust settings like timeouts, pool sizes, and routing rules without restarting the service. This is critical for production operations.

## Detailed Description

### Technical Requirements
- Configuration from multiple sources (env vars, files, ConfigMaps)
- Hot reload capability without dropping connections
- Configuration validation and rollback on errors
- Support for environment-specific overrides
- Secure handling of sensitive configuration

### Acceptance Criteria
- [ ] Configuration loading from environment variables and files
- [ ] Kubernetes ConfigMap and Secret integration
- [ ] Configuration validation on load
- [ ] Hot reload capability with graceful fallback
- [ ] Configuration schema documentation
- [ ] CLI tool for configuration validation
- [ ] Metrics for configuration reload success/failure
- [ ] Support for configuration profiles (dev/staging/prod)

### Implementation Details

#### Configuration Structure
```rust
// src/config.rs
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub redis: RedisConfig,
    pub auth: AuthConfig,
    pub observability: ObservabilityConfig,
    pub features: FeatureFlags,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: Option<usize>,
    pub max_connections: usize,
    pub request_timeout_seconds: u64,
    pub graceful_shutdown_timeout_seconds: u64,
    pub cors: CorsConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CorsConfig {
    pub enabled: bool,
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub max_age_seconds: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RedisConfig {
    pub pool_max_size: usize,
    pub pool_timeout_seconds: u64,
    pub connection_timeout_seconds: u64,
    pub command_timeout_seconds: u64,
    pub default_password: Option<String>,
    pub refresh_interval_seconds: u64,
    pub health_check_interval_seconds: u64,
    pub max_retries: u32,
    pub retry_delay_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthConfig {
    pub enabled: bool,
    pub jwt_secret: String,
    pub jwt_expiry_hours: u64,
    pub api_key_header: String,
    pub rate_limiting: RateLimitConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub requests_per_minute: u32,
    pub burst_size: u32,
    pub window_size_seconds: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ObservabilityConfig {
    pub logging: LoggingConfig,
    pub metrics: MetricsConfig,
    pub tracing: TracingConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String, // "json" or "pretty"
    pub output: String, // "stdout" or file path
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub port: u16,
    pub path: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TracingConfig {
    pub enabled: bool,
    pub endpoint: Option<String>,
    pub service_name: String,
    pub sample_rate: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FeatureFlags {
    pub method_override: bool,
    pub raw_commands: bool,
    pub admin_endpoints: bool,
    pub debug_mode: bool,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let mut config = config::Config::builder()
            // Start with default values
            .add_source(config::File::from_str(DEFAULT_CONFIG, config::FileFormat::Toml))
            // Add environment variables (with prefix REDIS_GATEWAY_)
            .add_source(config::Environment::with_prefix("REDIS_GATEWAY").separator("_"))
            // Add config file if specified
            .add_source(config::File::with_name("gateway.toml").required(false))
            // Add Kubernetes config if running in cluster
            .add_source(KubernetesConfigSource::new()?)
            .build()?;

        let config: Config = config.try_deserialize()?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate configuration values
        if self.server.port == 0 {
            return Err(ConfigError::InvalidValue("server.port must be > 0".to_string()));
        }
        
        if self.redis.pool_max_size == 0 {
            return Err(ConfigError::InvalidValue("redis.pool_max_size must be > 0".to_string()));
        }
        
        if self.auth.enabled && self.auth.jwt_secret.is_empty() {
            return Err(ConfigError::InvalidValue("auth.jwt_secret is required when auth is enabled".to_string()));
        }
        
        Ok(())
    }
}

const DEFAULT_CONFIG: &str = r#"
[server]
host = "0.0.0.0"
port = 8080
max_connections = 10000
request_timeout_seconds = 30
graceful_shutdown_timeout_seconds = 30

[server.cors]
enabled = true
allowed_origins = ["*"]
allowed_methods = ["GET", "POST", "DELETE", "OPTIONS"]
allowed_headers = ["Content-Type", "Authorization"]
max_age_seconds = 3600

[redis]
pool_max_size = 10
pool_timeout_seconds = 5
connection_timeout_seconds = 5
command_timeout_seconds = 5
refresh_interval_seconds = 30
health_check_interval_seconds = 60
max_retries = 3
retry_delay_ms = 100

[auth]
enabled = true
jwt_expiry_hours = 24
api_key_header = "Authorization"

[auth.rate_limiting]
enabled = true
requests_per_minute = 1000
burst_size = 100
window_size_seconds = 60

[observability.logging]
level = "info"
format = "json"
output = "stdout"

[observability.metrics]
enabled = true
port = 9090
path = "/metrics"

[observability.tracing]
enabled = false
service_name = "redis-http-gateway"
sample_rate = 0.1

[features]
method_override = true
raw_commands = true
admin_endpoints = false
debug_mode = false
"#;
```

#### Kubernetes Configuration Source
```rust
// src/config/kubernetes.rs
use kube::{Client, Api};
use k8s_openapi::api::core::v1::{ConfigMap, Secret};
use serde_json::Value;
use std::collections::HashMap;

pub struct KubernetesConfigSource {
    client: Client,
    namespace: String,
}

impl KubernetesConfigSource {
    pub fn new() -> Result<Self, kube::Error> {
        let client = Client::try_default()?;
        let namespace = std::env::var("KUBERNETES_NAMESPACE")
            .unwrap_or_else(|_| "default".to_string());
            
        Ok(Self { client, namespace })
    }

    pub async fn load_config(&self) -> Result<HashMap<String, Value>, kube::Error> {
        let mut config = HashMap::new();
        
        // Load from ConfigMap
        if let Ok(configmap) = self.load_configmap("redis-gateway-config").await {
            for (key, value) in configmap {
                config.insert(key, Value::String(value));
            }
        }
        
        // Load secrets (for sensitive config)
        if let Ok(secrets) = self.load_secret("redis-gateway-secrets").await {
            for (key, value) in secrets {
                config.insert(key, Value::String(value));
            }
        }
        
        Ok(config)
    }

    async fn load_configmap(&self, name: &str) -> Result<HashMap<String, String>, kube::Error> {
        let configmaps: Api<ConfigMap> = Api::namespaced(self.client.clone(), &self.namespace);
        let configmap = configmaps.get(name).await?;
        
        Ok(configmap.data.unwrap_or_default())
    }

    async fn load_secret(&self, name: &str) -> Result<HashMap<String, String>, kube::Error> {
        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), &self.namespace);
        let secret = secrets.get(name).await?;
        
        let mut result = HashMap::new();
        if let Some(data) = secret.data {
            for (key, value) in data {
                if let Ok(decoded) = std::str::from_utf8(&value.0) {
                    result.insert(key, decoded.to_string());
                }
            }
        }
        
        Ok(result)
    }
}
```

#### Hot Reload Implementation
```rust
// src/config/reload.rs
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};

pub struct ConfigManager {
    current_config: Arc<RwLock<Config>>,
    config_version: Arc<RwLock<u64>>,
}

impl ConfigManager {
    pub fn new(initial_config: Config) -> Self {
        Self {
            current_config: Arc::new(RwLock::new(initial_config)),
            config_version: Arc::new(RwLock::new(1)),
        }
    }

    pub async fn get_config(&self) -> Config {
        self.current_config.read().await.clone()
    }

    pub async fn get_version(&self) -> u64 {
        *self.config_version.read().await
    }

    pub async fn reload_config(&self) -> Result<bool, ConfigError> {
        tracing::info!("Attempting to reload configuration");
        
        match Config::from_env() {
            Ok(new_config) => {
                // Validate new configuration
                new_config.validate()?;
                
                let old_config = self.current_config.read().await.clone();
                
                // Check if configuration actually changed
                if !self.config_changed(&old_config, &new_config) {
                    tracing::debug!("Configuration unchanged, skipping reload");
                    return Ok(false);
                }
                
                // Update configuration
                {
                    let mut config = self.current_config.write().await;
                    *config = new_config.clone();
                }
                
                {
                    let mut version = self.config_version.write().await;
                    *version += 1;
                }
                
                tracing::info!("Configuration reloaded successfully, version: {}", self.get_version().await);
                Ok(true)
            }
            Err(e) => {
                tracing::error!("Failed to reload configuration: {}", e);
                Err(e)
            }
        }
    }

    pub fn start_auto_reload(&self, interval_seconds: u64) {
        let config_manager = ConfigManager {
            current_config: Arc::clone(&self.current_config),
            config_version: Arc::clone(&self.config_version),
        };

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(interval_seconds));
            
            loop {
                interval.tick().await;
                
                if let Err(e) = config_manager.reload_config().await {
                    tracing::error!("Auto-reload failed: {}", e);
                }
            }
        });
    }

    fn config_changed(&self, old: &Config, new: &Config) -> bool {
        // Compare configurations (you might want to implement PartialEq for Config)
        serde_json::to_string(old).unwrap() != serde_json::to_string(new).unwrap()
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
    #[error("Configuration parse error: {0}")]
    ParseError(String),
    
    #[error("Invalid configuration value: {0}")]
    InvalidValue(String),
    
    #[error("Kubernetes API error: {0}")]
    KubernetesError(#[from] kube::Error),
    
    #[error("Config library error: {0}")]
    ConfigError(#[from] config::ConfigError),
}
```

### Definition of Done
- Configuration loads from multiple sources in priority order
- Hot reload works without dropping active connections
- Invalid configurations are rejected with clear error messages
- Configuration schema is documented with examples
- Kubernetes ConfigMap/Secret integration works
- Configuration changes are logged and monitored

### Dependencies
- Issue #8 (HTTP Gateway Core)

### Additional Context
- Consider using a configuration management library like `figment`
- Implement configuration drift detection
- Add configuration backup and restore functionality
- Document best practices for production configuration