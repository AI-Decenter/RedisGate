# Issue #12: Request Routing and Load Balancing

**Priority**: Medium  
**Labels**: gateway, routing, performance  
**Milestone**: Phase 3 - HTTP Gateway  
**Estimated Effort**: 2 days

## Summary
Implement intelligent request routing and load balancing across Redis instances, including support for read replicas and instance-specific routing rules.

## Motivation
As the system scales, efficient request routing becomes critical for performance and reliability. The gateway should intelligently route requests based on instance health, load, and configuration.

## Detailed Description

### Technical Requirements
- Instance routing based on URL path parameters
- Health-aware load balancing
- Circuit breaker pattern for failing instances
- Request sticky sessions support
- Routing metrics and observability
- Support for read/write operation splitting

### Acceptance Criteria
- [ ] Route requests to correct Redis instance based on URL
- [ ] Health-based routing that avoids unhealthy instances
- [ ] Circuit breaker implementation for resilience
- [ ] Configurable routing strategies (round-robin, least-connections)
- [ ] Request tracing through routing pipeline
- [ ] Routing metrics for monitoring
- [ ] Support for maintenance mode (drain traffic)
- [ ] Graceful handling of instance unavailability

### Implementation Details

#### Router Implementation
```rust
// src/router/mod.rs
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

pub mod balancer;
pub mod circuit_breaker;
pub mod health;

use crate::error::{GatewayError, Result};

#[derive(Debug, Clone)]
pub struct RoutingDecision {
    pub instance_name: String,
    pub backend_url: String,
    pub connection_pool_key: String,
}

#[derive(Debug, Clone)]
pub struct RouteRequest {
    pub instance_name: String,
    pub operation_type: OperationType,
    pub client_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OperationType {
    Read,
    Write,
    Admin,
}

pub struct Router {
    balancer: Arc<dyn LoadBalancer + Send + Sync>,
    circuit_breakers: Arc<RwLock<HashMap<String, CircuitBreaker>>>,
    health_checker: Arc<HealthChecker>,
    config: RouterConfig,
}

#[derive(Debug, Clone)]
pub struct RouterConfig {
    pub strategy: LoadBalancingStrategy,
    pub circuit_breaker: CircuitBreakerConfig,
    pub health_check_interval: Duration,
    pub sticky_sessions: bool,
}

#[derive(Debug, Clone)]
pub enum LoadBalancingStrategy {
    RoundRobin,
    LeastConnections,
    Random,
    Weighted(HashMap<String, u32>),
}

impl Router {
    pub fn new(config: RouterConfig) -> Self {
        let balancer: Arc<dyn LoadBalancer + Send + Sync> = match config.strategy {
            LoadBalancingStrategy::RoundRobin => Arc::new(RoundRobinBalancer::new()),
            LoadBalancingStrategy::LeastConnections => Arc::new(LeastConnectionsBalancer::new()),
            LoadBalancingStrategy::Random => Arc::new(RandomBalancer::new()),
            LoadBalancingStrategy::Weighted(ref weights) => Arc::new(WeightedBalancer::new(weights.clone())),
        };

        Self {
            balancer,
            circuit_breakers: Arc::new(RwLock::new(HashMap::new())),
            health_checker: Arc::new(HealthChecker::new()),
            config,
        }
    }

    pub async fn route(&self, request: RouteRequest) -> Result<RoutingDecision> {
        // Check if circuit breaker allows the request
        if !self.check_circuit_breaker(&request.instance_name).await {
            return Err(GatewayError::ServiceUnavailable(
                format!("Circuit breaker open for instance: {}", request.instance_name)
            ));
        }

        // Check instance health
        if !self.health_checker.is_healthy(&request.instance_name).await {
            return Err(GatewayError::InstanceNotFound(request.instance_name));
        }

        // For specific instance requests, route directly
        if !request.instance_name.is_empty() {
            return self.route_to_instance(&request).await;
        }

        // For load balanced requests, use balancer
        let available_instances = self.get_available_instances(&request.operation_type).await;
        if available_instances.is_empty() {
            return Err(GatewayError::ServiceUnavailable(
                "No healthy instances available".to_string()
            ));
        }

        let selected_instance = self.balancer.select(&available_instances, &request).await?;
        self.route_to_instance(&RouteRequest {
            instance_name: selected_instance,
            operation_type: request.operation_type,
            client_id: request.client_id,
        }).await
    }

    async fn route_to_instance(&self, request: &RouteRequest) -> Result<RoutingDecision> {
        // Construct backend URL (could be service discovery or direct connection)
        let backend_url = format!("redis://redis-{}.redis-system.svc.cluster.local:6379", 
                                 request.instance_name);

        Ok(RoutingDecision {
            instance_name: request.instance_name.clone(),
            backend_url,
            connection_pool_key: request.instance_name.clone(),
        })
    }

    async fn get_available_instances(&self, operation_type: &OperationType) -> Vec<String> {
        self.health_checker
            .get_healthy_instances()
            .await
            .into_iter()
            .filter(|instance| self.supports_operation(instance, operation_type))
            .collect()
    }

    fn supports_operation(&self, _instance: &str, _operation_type: &OperationType) -> bool {
        // For now, all instances support all operations
        // In the future, this could check for read replicas, etc.
        true
    }

    async fn check_circuit_breaker(&self, instance_name: &str) -> bool {
        let breakers = self.circuit_breakers.read().await;
        if let Some(breaker) = breakers.get(instance_name) {
            breaker.can_execute()
        } else {
            true // No circuit breaker means it's allowed
        }
    }

    pub async fn record_success(&self, instance_name: &str) {
        if let Some(breaker) = self.circuit_breakers.write().await.get_mut(instance_name) {
            breaker.record_success();
        }
    }

    pub async fn record_failure(&self, instance_name: &str) {
        let mut breakers = self.circuit_breakers.write().await;
        let breaker = breakers
            .entry(instance_name.to_string())
            .or_insert_with(|| CircuitBreaker::new(self.config.circuit_breaker.clone()));
        breaker.record_failure();
    }
}
```

#### Load Balancer Implementations
```rust
// src/router/balancer.rs
use async_trait::async_trait;
use rand::Rng;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use super::{RouteRequest, Result};
use crate::error::GatewayError;

#[async_trait]
pub trait LoadBalancer {
    async fn select(&self, instances: &[String], request: &RouteRequest) -> Result<String>;
}

pub struct RoundRobinBalancer {
    counter: AtomicUsize,
}

impl RoundRobinBalancer {
    pub fn new() -> Self {
        Self {
            counter: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl LoadBalancer for RoundRobinBalancer {
    async fn select(&self, instances: &[String], _request: &RouteRequest) -> Result<String> {
        if instances.is_empty() {
            return Err(GatewayError::ServiceUnavailable("No instances available".to_string()));
        }

        let index = self.counter.fetch_add(1, Ordering::Relaxed) % instances.len();
        Ok(instances[index].clone())
    }
}

pub struct RandomBalancer;

impl RandomBalancer {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl LoadBalancer for RandomBalancer {
    async fn select(&self, instances: &[String], _request: &RouteRequest) -> Result<String> {
        if instances.is_empty() {
            return Err(GatewayError::ServiceUnavailable("No instances available".to_string()));
        }

        let mut rng = rand::thread_rng();
        let index = rng.gen_range(0..instances.len());
        Ok(instances[index].clone())
    }
}

pub struct WeightedBalancer {
    weights: HashMap<String, u32>,
}

impl WeightedBalancer {
    pub fn new(weights: HashMap<String, u32>) -> Self {
        Self { weights }
    }
}

#[async_trait]
impl LoadBalancer for WeightedBalancer {
    async fn select(&self, instances: &[String], _request: &RouteRequest) -> Result<String> {
        if instances.is_empty() {
            return Err(GatewayError::ServiceUnavailable("No instances available".to_string()));
        }

        // Build weighted list
        let mut weighted_instances = Vec::new();
        for instance in instances {
            let weight = self.weights.get(instance).unwrap_or(&1);
            for _ in 0..*weight {
                weighted_instances.push(instance.clone());
            }
        }

        if weighted_instances.is_empty() {
            return Ok(instances[0].clone());
        }

        let mut rng = rand::thread_rng();
        let index = rng.gen_range(0..weighted_instances.len());
        Ok(weighted_instances[index].clone())
    }
}

pub struct LeastConnectionsBalancer {
    connections: Arc<RwLock<HashMap<String, AtomicUsize>>>,
}

impl LeastConnectionsBalancer {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn increment_connections(&self, instance: &str) {
        let connections = self.connections.read().await;
        if let Some(counter) = connections.get(instance) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub async fn decrement_connections(&self, instance: &str) {
        let connections = self.connections.read().await;
        if let Some(counter) = connections.get(instance) {
            counter.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

#[async_trait]
impl LoadBalancer for LeastConnectionsBalancer {
    async fn select(&self, instances: &[String], _request: &RouteRequest) -> Result<String> {
        if instances.is_empty() {
            return Err(GatewayError::ServiceUnavailable("No instances available".to_string()));
        }

        let connections = self.connections.read().await;
        let mut min_connections = usize::MAX;
        let mut selected_instance = instances[0].clone();

        for instance in instances {
            let count = connections
                .get(instance)
                .map(|c| c.load(Ordering::Relaxed))
                .unwrap_or(0);

            if count < min_connections {
                min_connections = count;
                selected_instance = instance.clone();
            }
        }

        Ok(selected_instance)
    }
}
```

#### Circuit Breaker Implementation
```rust
// src/router/circuit_breaker.rs
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    pub failure_threshold: u32,
    pub timeout: Duration,
    pub reset_timeout: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            timeout: Duration::from_secs(60),
            reset_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum CircuitBreakerState {
    Closed,
    Open,
    HalfOpen,
}

pub struct CircuitBreaker {
    state: CircuitBreakerState,
    failure_count: u32,
    last_failure_time: Option<Instant>,
    config: CircuitBreakerConfig,
}

impl CircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            state: CircuitBreakerState::Closed,
            failure_count: 0,
            last_failure_time: None,
            config,
        }
    }

    pub fn can_execute(&mut self) -> bool {
        match self.state {
            CircuitBreakerState::Closed => true,
            CircuitBreakerState::Open => {
                if let Some(last_failure) = self.last_failure_time {
                    if last_failure.elapsed() > self.config.reset_timeout {
                        self.state = CircuitBreakerState::HalfOpen;
                        return true;
                    }
                }
                false
            }
            CircuitBreakerState::HalfOpen => true,
        }
    }

    pub fn record_success(&mut self) {
        self.failure_count = 0;
        self.state = CircuitBreakerState::Closed;
        self.last_failure_time = None;
    }

    pub fn record_failure(&mut self) {
        self.failure_count += 1;
        self.last_failure_time = Some(Instant::now());

        if self.failure_count >= self.config.failure_threshold {
            self.state = CircuitBreakerState::Open;
        }
    }

    pub fn get_state(&self) -> CircuitBreakerState {
        self.state.clone()
    }
}
```

### Definition of Done
- Request routing works correctly based on instance names
- Load balancing distributes requests across healthy instances
- Circuit breakers prevent cascade failures
- Routing decisions are logged and can be monitored
- Different routing strategies can be configured
- System gracefully handles instance failures and recoveries

### Dependencies
- Issue #8 (HTTP Gateway Core)
- Issue #10 (Connection Pool Management)

### Additional Context
- Consider implementing sticky sessions for stateful operations
- Plan for geographic routing in multi-region deployments
- Implement request hedging for improved latency
- Add support for canary deployments and traffic splitting