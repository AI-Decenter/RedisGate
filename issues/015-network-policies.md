# Issue #15: Network Policies and Multi-tenancy

**Priority**: Medium  
**Labels**: security, networking, kubernetes  
**Milestone**: Phase 4 - Security & Authentication  
**Estimated Effort**: 2-3 days

## Summary
Implement Kubernetes network policies and multi-tenancy features to provide secure isolation between different users and Redis instances.

## Motivation
In a multi-tenant environment, proper network isolation is critical to prevent unauthorized access between tenants. Network policies and namespace isolation ensure that users can only access their own Redis instances.

## Detailed Description

### Technical Requirements
- Kubernetes Network Policies for traffic isolation
- Namespace-based multi-tenancy
- Service account and RBAC integration
- DNS-based service discovery within tenant boundaries
- Resource quotas and limits per tenant
- Tenant-scoped monitoring and logging

### Acceptance Criteria
- [ ] Network policies restrict inter-tenant communication
- [ ] Each tenant operates within isolated namespaces
- [ ] RBAC ensures users can only access their resources
- [ ] Resource quotas prevent resource exhaustion
- [ ] Service discovery works within tenant boundaries
- [ ] Monitoring and logging are tenant-aware
- [ ] Multi-tenant configuration management
- [ ] Tenant onboarding and cleanup procedures

### Implementation Details

#### Network Policy Templates
```yaml
# k8s/network-policies/tenant-isolation.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: tenant-isolation
  namespace: "{{ .TenantNamespace }}"
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  # Allow traffic from gateway pods
  - from:
    - namespaceSelector:
        matchLabels:
          name: redis-system
      podSelector:
        matchLabels:
          app: redis-gateway
  # Allow traffic within the same tenant namespace
  - from:
    - namespaceSelector:
        matchLabels:
          tenant: "{{ .TenantId }}"
  # Allow traffic from system namespaces (DNS, etc.)
  - from:
    - namespaceSelector:
        matchLabels:
          name: kube-system
  egress:
  # Allow DNS resolution
  - to: []
    ports:
    - protocol: UDP
      port: 53
  # Allow traffic within tenant namespace
  - to:
    - namespaceSelector:
        matchLabels:
          tenant: "{{ .TenantId }}"
  # Allow outbound traffic for Redis replication (if needed)
  - to:
    - namespaceSelector:
        matchLabels:
          tenant: "{{ .TenantId }}"
    ports:
    - protocol: TCP
      port: 6379

---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: gateway-access
  namespace: redis-system
spec:
  podSelector:
    matchLabels:
      app: redis-gateway
  policyTypes:
  - Egress
  egress:
  # Allow access to all tenant namespaces for Redis connections
  - to:
    - namespaceSelector:
        matchExpressions:
        - key: tenant
          operator: Exists
    ports:
    - protocol: TCP
      port: 6379
  # Allow DNS and other system traffic
  - to: []
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 443
    - protocol: TCP
      port: 80
```

#### Tenant Management System
```rust
// src/tenant/mod.rs
use k8s_openapi::api::core::v1::{Namespace, ResourceQuota, LimitRange};
use k8s_openapi::api::rbac::v1::{Role, RoleBinding, ServiceAccount};
use kube::{Api, Client};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    pub id: String,
    pub name: String,
    pub namespace: String,
    pub resource_quota: TenantResourceQuota,
    pub network_policies: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub status: TenantStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantResourceQuota {
    pub redis_instances: u32,
    pub memory_limit: String,
    pub cpu_limit: String,
    pub storage_limit: String,
    pub api_requests_per_minute: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TenantStatus {
    Pending,
    Active,
    Suspended,
    Terminating,
}

pub struct TenantManager {
    k8s_client: Client,
}

impl TenantManager {
    pub fn new(k8s_client: Client) -> Self {
        Self { k8s_client }
    }

    pub async fn create_tenant(&self, tenant: &Tenant) -> Result<(), TenantError> {
        tracing::info!("Creating tenant: {}", tenant.id);

        // Create namespace
        self.create_tenant_namespace(tenant).await?;
        
        // Create service account
        self.create_tenant_service_account(tenant).await?;
        
        // Create RBAC
        self.create_tenant_rbac(tenant).await?;
        
        // Apply resource quotas
        self.create_resource_quota(tenant).await?;
        
        // Create network policies
        self.create_network_policies(tenant).await?;
        
        tracing::info!("Tenant created successfully: {}", tenant.id);
        Ok(())
    }

    async fn create_tenant_namespace(&self, tenant: &Tenant) -> Result<(), TenantError> {
        let namespaces: Api<Namespace> = Api::all(self.k8s_client.clone());
        
        let namespace = Namespace {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some(tenant.namespace.clone()),
                labels: Some({
                    let mut labels = std::collections::BTreeMap::new();
                    labels.insert("tenant".to_string(), tenant.id.clone());
                    labels.insert("managed-by".to_string(), "redis-operator".to_string());
                    labels
                }),
                annotations: Some({
                    let mut annotations = std::collections::BTreeMap::new();
                    annotations.insert("tenant.redis.kubegateway.io/name".to_string(), tenant.name.clone());
                    annotations.insert("tenant.redis.kubegateway.io/created-at".to_string(), tenant.created_at.to_rfc3339());
                    annotations
                }),
                ..Default::default()
            },
            ..Default::default()
        };

        namespaces.create(&Default::default(), &namespace).await?;
        Ok(())
    }

    async fn create_tenant_service_account(&self, tenant: &Tenant) -> Result<(), TenantError> {
        let service_accounts: Api<ServiceAccount> = Api::namespaced(self.k8s_client.clone(), &tenant.namespace);
        
        let sa = ServiceAccount {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some(format!("tenant-{}", tenant.id)),
                namespace: Some(tenant.namespace.clone()),
                labels: Some({
                    let mut labels = std::collections::BTreeMap::new();
                    labels.insert("tenant".to_string(), tenant.id.clone());
                    labels
                }),
                ..Default::default()
            },
            ..Default::default()
        };

        service_accounts.create(&Default::default(), &sa).await?;
        Ok(())
    }

    async fn create_tenant_rbac(&self, tenant: &Tenant) -> Result<(), TenantError> {
        // Create Role
        let roles: Api<Role> = Api::namespaced(self.k8s_client.clone(), &tenant.namespace);
        
        let role = Role {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some(format!("tenant-{}-role", tenant.id)),
                namespace: Some(tenant.namespace.clone()),
                ..Default::default()
            },
            rules: Some(vec![
                k8s_openapi::api::rbac::v1::PolicyRule {
                    api_groups: Some(vec!["".to_string()]),
                    resources: Some(vec!["configmaps".to_string(), "secrets".to_string(), "services".to_string()]),
                    verbs: vec!["get".to_string(), "list".to_string(), "watch".to_string()],
                    ..Default::default()
                },
                k8s_openapi::api::rbac::v1::PolicyRule {
                    api_groups: Some(vec!["redis.kubegateway.io".to_string()]),
                    resources: Some(vec!["redishttpinstances".to_string()]),
                    verbs: vec!["get".to_string(), "list".to_string(), "watch".to_string(), "create".to_string(), "update".to_string(), "patch".to_string(), "delete".to_string()],
                    ..Default::default()
                },
            ]),
        };

        roles.create(&Default::default(), &role).await?;

        // Create RoleBinding
        let role_bindings: Api<RoleBinding> = Api::namespaced(self.k8s_client.clone(), &tenant.namespace);
        
        let role_binding = RoleBinding {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some(format!("tenant-{}-binding", tenant.id)),
                namespace: Some(tenant.namespace.clone()),
                ..Default::default()
            },
            role_ref: k8s_openapi::api::rbac::v1::RoleRef {
                api_group: "rbac.authorization.k8s.io".to_string(),
                kind: "Role".to_string(),
                name: format!("tenant-{}-role", tenant.id),
            },
            subjects: Some(vec![
                k8s_openapi::api::rbac::v1::Subject {
                    kind: "ServiceAccount".to_string(),
                    name: format!("tenant-{}", tenant.id),
                    namespace: Some(tenant.namespace.clone()),
                    ..Default::default()
                }
            ]),
        };

        role_bindings.create(&Default::default(), &role_binding).await?;
        Ok(())
    }

    async fn create_resource_quota(&self, tenant: &Tenant) -> Result<(), TenantError> {
        let quotas: Api<ResourceQuota> = Api::namespaced(self.k8s_client.clone(), &tenant.namespace);
        
        let quota = ResourceQuota {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some(format!("tenant-{}-quota", tenant.id)),
                namespace: Some(tenant.namespace.clone()),
                ..Default::default()
            },
            spec: Some(k8s_openapi::api::core::v1::ResourceQuotaSpec {
                hard: Some({
                    let mut hard = std::collections::BTreeMap::new();
                    hard.insert("requests.memory".to_string(), k8s_openapi::apimachinery::pkg::api::resource::Quantity(tenant.resource_quota.memory_limit.clone()));
                    hard.insert("requests.cpu".to_string(), k8s_openapi::apimachinery::pkg::api::resource::Quantity(tenant.resource_quota.cpu_limit.clone()));
                    hard.insert("persistentvolumeclaims".to_string(), k8s_openapi::apimachinery::pkg::api::resource::Quantity("10".to_string()));
                    hard.insert("pods".to_string(), k8s_openapi::apimachinery::pkg::api::resource::Quantity("50".to_string()));
                    hard.insert("services".to_string(), k8s_openapi::apimachinery::pkg::api::resource::Quantity("20".to_string()));
                    hard
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        quotas.create(&Default::default(), &quota).await?;
        Ok(())
    }

    async fn create_network_policies(&self, tenant: &Tenant) -> Result<(), TenantError> {
        use k8s_openapi::api::networking::v1::NetworkPolicy;
        
        let network_policies: Api<NetworkPolicy> = Api::namespaced(self.k8s_client.clone(), &tenant.namespace);
        
        // Load and apply network policy template
        let policy_yaml = self.render_network_policy_template(tenant)?;
        let policy: NetworkPolicy = serde_yaml::from_str(&policy_yaml)?;
        
        network_policies.create(&Default::default(), &policy).await?;
        Ok(())
    }

    fn render_network_policy_template(&self, tenant: &Tenant) -> Result<String, TenantError> {
        // This would use a templating engine like Tera or handlebars
        // For now, simple string replacement
        let template = include_str!("../../k8s/network-policies/tenant-isolation.yaml");
        let rendered = template
            .replace("{{ .TenantNamespace }}", &tenant.namespace)
            .replace("{{ .TenantId }}", &tenant.id);
        Ok(rendered)
    }

    pub async fn delete_tenant(&self, tenant_id: &str) -> Result<(), TenantError> {
        tracing::info!("Deleting tenant: {}", tenant_id);
        
        let namespace_name = format!("tenant-{}", tenant_id);
        let namespaces: Api<Namespace> = Api::all(self.k8s_client.clone());
        
        // Delete namespace (this will cascade delete all resources)
        namespaces.delete(&namespace_name, &Default::default()).await?;
        
        tracing::info!("Tenant deleted successfully: {}", tenant_id);
        Ok(())
    }

    pub async fn list_tenant_resources(&self, tenant_id: &str) -> Result<TenantResourceSummary, TenantError> {
        let namespace_name = format!("tenant-{}", tenant_id);
        
        // Get Redis instances
        let redis_instances = self.list_redis_instances(&namespace_name).await?;
        
        // Get resource usage
        let resource_usage = self.get_resource_usage(&namespace_name).await?;
        
        Ok(TenantResourceSummary {
            tenant_id: tenant_id.to_string(),
            namespace: namespace_name,
            redis_instances,
            resource_usage,
        })
    }

    async fn list_redis_instances(&self, namespace: &str) -> Result<Vec<String>, TenantError> {
        // This would query RedisHttpInstance CRDs
        // Simplified implementation
        Ok(vec![])
    }

    async fn get_resource_usage(&self, _namespace: &str) -> Result<ResourceUsage, TenantError> {
        // This would query metrics server
        // Simplified implementation
        Ok(ResourceUsage {
            cpu_usage: "0m".to_string(),
            memory_usage: "0Mi".to_string(),
            storage_usage: "0Gi".to_string(),
        })
    }
}

#[derive(Debug, Serialize)]
pub struct TenantResourceSummary {
    pub tenant_id: String,
    pub namespace: String,
    pub redis_instances: Vec<String>,
    pub resource_usage: ResourceUsage,
}

#[derive(Debug, Serialize)]
pub struct ResourceUsage {
    pub cpu_usage: String,
    pub memory_usage: String,
    pub storage_usage: String,
}

#[derive(thiserror::Error, Debug)]
pub enum TenantError {
    #[error("Kubernetes API error: {0}")]
    KubernetesError(#[from] kube::Error),
    
    #[error("YAML parsing error: {0}")]
    YamlError(#[from] serde_yaml::Error),
    
    #[error("Tenant already exists: {0}")]
    TenantExists(String),
    
    #[error("Tenant not found: {0}")]
    TenantNotFound(String),
    
    #[error("Resource quota exceeded: {0}")]
    ResourceQuotaExceeded(String),
}
```

#### Tenant-aware Gateway Routing
```rust
// src/handlers/tenant.rs
use axum::{
    extract::{Path, State},
    response::Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    error::Result,
    middleware::auth::AuthenticationResult,
    server::AppState,
    tenant::{Tenant, TenantManager, TenantResourceQuota},
};

#[derive(Deserialize)]
pub struct CreateTenantRequest {
    pub name: String,
    pub resource_quota: TenantResourceQuota,
}

#[derive(Serialize)]
pub struct CreateTenantResponse {
    pub tenant_id: String,
    pub namespace: String,
    pub status: String,
}

pub async fn create_tenant(
    State(state): State<AppState>,
    Json(payload): Json<CreateTenantRequest>,
    auth: AuthenticationResult,
) -> Result<Json<CreateTenantResponse>> {
    // Verify user has admin permissions
    match auth {
        AuthenticationResult::Jwt(claims) => {
            if !claims.permissions.contains(&"tenant:create".to_string()) {
                return Err(crate::error::GatewayError::Forbidden);
            }
        }
        _ => return Err(crate::error::GatewayError::Forbidden),
    }

    let tenant_id = uuid::Uuid::new_v4().to_string();
    let namespace = format!("tenant-{}", tenant_id);
    
    let tenant = Tenant {
        id: tenant_id.clone(),
        name: payload.name,
        namespace: namespace.clone(),
        resource_quota: payload.resource_quota,
        network_policies: vec!["tenant-isolation".to_string()],
        created_at: chrono::Utc::now(),
        status: crate::tenant::TenantStatus::Pending,
    };

    state.tenant_manager.create_tenant(&tenant).await?;

    Ok(Json(CreateTenantResponse {
        tenant_id,
        namespace,
        status: "pending".to_string(),
    }))
}

pub async fn get_tenant_resources(
    Path(tenant_id): Path<String>,
    State(state): State<AppState>,
    auth: AuthenticationResult,
) -> Result<Json<crate::tenant::TenantResourceSummary>> {
    // Verify user has access to this tenant
    // Implementation would check user permissions
    
    let summary = state.tenant_manager.list_tenant_resources(&tenant_id).await?;
    Ok(Json(summary))
}
```

### Definition of Done
- Network policies successfully isolate tenant traffic
- Namespaces provide proper resource isolation
- RBAC prevents cross-tenant access
- Resource quotas enforce tenant limits
- Tenant onboarding process works end-to-end
- Multi-tenant monitoring and logging are functional

### Dependencies
- Issue #5 (Kubernetes Operator)
- Issue #13 (JWT Authentication)

### Additional Context
- Consider implementing tenant resource monitoring and alerting
- Plan for tenant backup and disaster recovery
- Implement tenant billing and usage tracking
- Consider multi-cluster tenant distribution for large scale