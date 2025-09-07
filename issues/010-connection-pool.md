# Issue #10: Connection Pool Management and Redis Discovery

**Priority**: High  
**Labels**: gateway, redis, performance  
**Milestone**: Phase 3 - HTTP Gateway  
**Estimated Effort**: 2-3 days

## Summary
Implement efficient Redis connection pooling with automatic service discovery for Redis instances created by the Kubernetes operator.

## Motivation
The gateway needs to efficiently manage connections to multiple Redis instances while automatically discovering new instances and handling instance lifecycle changes. Connection pooling is critical for performance and resource management.

## Detailed Description

### Technical Requirements
- Redis connection pool management with per-instance pools
- Kubernetes service discovery for Redis instances
- Connection health monitoring and recovery
- Dynamic pool configuration based on load
- Graceful handling of instance lifecycle events

### Acceptance Criteria
- [ ] Connection pool per Redis instance with configurable size
- [ ] Automatic discovery of Redis instances via Kubernetes API
- [ ] Connection health checks and automatic reconnection
- [ ] Pool metrics for monitoring and alerting
- [ ] Graceful pool shutdown and cleanup
- [ ] Configuration via environment variables and config files
- [ ] Support for Redis authentication (password)
- [ ] Circuit breaker pattern for failing instances

### Implementation Details

#### Redis Pool Manager
```rust
// src/redis/pool.rs
use std::{
    collections::HashMap,
    sync::Arc,
    time::Duration,
};
use tokio::sync::RwLock;
use redis::{Client, Connection};
use deadpool_redis::{Config as PoolConfig, Pool, Runtime};

use crate::{config::RedisConfig, error::Result};

pub struct RedisPoolManager {
    pools: Arc<RwLock<HashMap<String, Pool>>>,
    config: RedisConfig,
    k8s_client: kube::Client,
}

impl RedisPoolManager {
    pub async fn new(config: &RedisConfig) -> Result<Self> {
        let k8s_client = kube::Client::try_default().await?;
        
        Ok(Self {
            pools: Arc::new(RwLock::new(HashMap::new())),
            config: config.clone(),
            k8s_client,
        })
    }

    pub async fn get_client(&self, instance_name: &str) -> Option<deadpool_redis::Connection> {
        // Try to get existing pool
        if let Some(pool) = self.get_pool(instance_name).await {
            match pool.get().await {
                Ok(conn) => return Some(conn),
                Err(e) => {
                    tracing::warn!("Failed to get connection from pool for {}: {}", instance_name, e);
                    // Pool might be stale, remove it and try to recreate
                    self.remove_pool(instance_name).await;
                }
            }
        }

        // Try to create new pool for this instance
        if let Ok(pool) = self.create_pool_for_instance(instance_name).await {
            self.add_pool(instance_name.to_string(), pool.clone()).await;
            pool.get().await.ok()
        } else {
            None
        }
    }

    async fn get_pool(&self, instance_name: &str) -> Option<Pool> {
        let pools = self.pools.read().await;
        pools.get(instance_name).cloned()
    }

    async fn add_pool(&self, instance_name: String, pool: Pool) {
        let mut pools = self.pools.write().await;
        pools.insert(instance_name, pool);
    }

    async fn remove_pool(&self, instance_name: &str) {
        let mut pools = self.pools.write().await;
        pools.remove(instance_name);
    }

    async fn create_pool_for_instance(&self, instance_name: &str) -> Result<Pool> {
        // Discover Redis service in Kubernetes
        let redis_url = self.discover_redis_service(instance_name).await?;
        
        tracing::info!("Creating Redis pool for instance {} at {}", instance_name, redis_url);

        // Configure connection pool
        let mut pool_config = PoolConfig::from_url(&redis_url);
        pool_config.max_size = self.config.pool_max_size;
        pool_config.timeouts.wait = Some(Duration::from_secs(self.config.pool_timeout_seconds));
        
        let pool = pool_config.create_pool(Some(Runtime::Tokio1))?;
        
        // Test the connection
        let mut conn = pool.get().await?;
        redis::cmd("PING").query_async::<_, String>(&mut conn).await?;
        
        Ok(pool)
    }

    async fn discover_redis_service(&self, instance_name: &str) -> Result<String> {
        use kube::{Api, api::ListParams};
        use k8s_openapi::api::core::v1::Service;

        let services: Api<Service> = Api::default_namespaced(self.k8s_client.clone());
        let lp = ListParams::default().labels(&format!("instance={}", instance_name));
        
        let service_list = services.list(&lp).await?;
        
        if let Some(service) = service_list.items.first() {
            if let (Some(name), Some(namespace)) = (&service.metadata.name, &service.metadata.namespace) {
                // Construct internal Kubernetes DNS name
                let host = format!("{}.{}.svc.cluster.local", name, namespace);
                let port = service.spec
                    .as_ref()
                    .and_then(|spec| spec.ports.as_ref())
                    .and_then(|ports| ports.first())
                    .map(|port| port.port)
                    .unwrap_or(6379);
                
                let mut url = format!("redis://{}:{}", host, port);
                
                // Add authentication if configured
                if let Some(password) = &self.config.default_password {
                    url = format!("redis://:{}@{}:{}", password, host, port);
                }
                
                return Ok(url);
            }
        }
        
        Err(crate::error::GatewayError::InstanceNotFound(instance_name.to_string()))
    }

    pub async fn refresh_pools(&self) -> Result<()> {
        // Discover all Redis instances
        let instances = self.discover_all_instances().await?;
        
        // Get current pools
        let current_pools: Vec<String> = {
            let pools = self.pools.read().await;
            pools.keys().cloned().collect()
        };
        
        // Remove pools for instances that no longer exist
        for pool_name in &current_pools {
            if !instances.contains(pool_name) {
                tracing::info!("Removing pool for deleted instance: {}", pool_name);
                self.remove_pool(pool_name).await;
            }
        }
        
        // Create pools for new instances
        for instance in &instances {
            if !current_pools.contains(instance) {
                tracing::info!("Creating pool for new instance: {}", instance);
                if let Ok(pool) = self.create_pool_for_instance(instance).await {
                    self.add_pool(instance.clone(), pool).await;
                }
            }
        }
        
        Ok(())
    }

    async fn discover_all_instances(&self) -> Result<Vec<String>> {
        use kube::{Api, api::ListParams};
        use k8s_openapi::api::core::v1::Service;

        let services: Api<Service> = Api::default_namespaced(self.k8s_client.clone());
        let lp = ListParams::default().labels("app=redis");
        
        let service_list = services.list(&lp).await?;
        
        let instances: Vec<String> = service_list
            .items
            .iter()
            .filter_map(|service| {
                service.metadata.labels.as_ref()
                    .and_then(|labels| labels.get("instance"))
                    .cloned()
            })
            .collect();
        
        Ok(instances)
    }

    pub async fn health_check(&self) -> HashMap<String, bool> {
        let pools = self.pools.read().await;
        let mut results = HashMap::new();
        
        for (instance_name, pool) in pools.iter() {
            match pool.get().await {
                Ok(mut conn) => {
                    match redis::cmd("PING").query_async::<_, String>(&mut conn).await {
                        Ok(_) => results.insert(instance_name.clone(), true),
                        Err(_) => results.insert(instance_name.clone(), false),
                    };
                }
                Err(_) => {
                    results.insert(instance_name.clone(), false);
                }
            }
        }
        
        results
    }
}

impl Clone for RedisPoolManager {
    fn clone(&self) -> Self {
        Self {
            pools: Arc::clone(&self.pools),
            config: self.config.clone(),
            k8s_client: self.k8s_client.clone(),
        }
    }
}
```

#### Configuration
```rust
// src/config.rs
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RedisConfig {
    pub pool_max_size: usize,
    pub pool_timeout_seconds: u64,
    pub default_password: Option<String>,
    pub refresh_interval_seconds: u64,
    pub health_check_interval_seconds: u64,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            pool_max_size: 10,
            pool_timeout_seconds: 5,
            default_password: None,
            refresh_interval_seconds: 30,
            health_check_interval_seconds: 60,
        }
    }
}
```

#### Background Services
```rust
// src/redis/manager.rs
use std::time::Duration;
use tokio::time::interval;

pub struct RedisManager {
    pool_manager: RedisPoolManager,
}

impl RedisManager {
    pub fn new(pool_manager: RedisPoolManager) -> Self {
        Self { pool_manager }
    }

    pub async fn start_background_tasks(&self) {
        let pool_manager = self.pool_manager.clone();
        
        // Pool refresh task
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(
                pool_manager.config.refresh_interval_seconds
            ));
            
            loop {
                interval.tick().await;
                if let Err(e) = pool_manager.refresh_pools().await {
                    tracing::error!("Failed to refresh Redis pools: {}", e);
                }
            }
        });

        // Health check task
        let pool_manager = self.pool_manager.clone();
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(
                pool_manager.config.health_check_interval_seconds
            ));
            
            loop {
                interval.tick().await;
                let health_status = pool_manager.health_check().await;
                
                for (instance, healthy) in health_status {
                    if !healthy {
                        tracing::warn!("Redis instance {} is unhealthy", instance);
                        // Could implement alerting here
                    }
                }
            }
        });
    }
}
```

### Definition of Done
- Connection pooling works efficiently for multiple Redis instances
- Automatic service discovery finds new Redis instances
- Connection health monitoring detects and handles failures
- Pool metrics are available for monitoring
- Background tasks manage pool lifecycle automatically
- Configuration is flexible and environment-aware

### Dependencies
- Issue #8 (HTTP Gateway Core)
- Issue #6 (Redis Instance Provisioning)

### Additional Context
- Consider implementing circuit breaker pattern
- Add connection pool metrics for observability
- Plan for Redis Cluster and Sentinel support
- Implement connection warming strategies