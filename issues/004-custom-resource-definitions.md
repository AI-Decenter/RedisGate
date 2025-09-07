# Issue #4: Custom Resource Definitions (CRDs)

**Priority**: High  
**Labels**: kubernetes, operator, crd  
**Milestone**: Phase 2 - Kubernetes Integration  
**Estimated Effort**: 2-3 days

## Summary
Define and implement Custom Resource Definitions (CRDs) for declaring Redis instances and API key management in Kubernetes.

## Motivation
CRDs provide a declarative way to manage Redis instances and their configuration. This enables GitOps workflows and integrates naturally with Kubernetes RBAC and resource management.

## Detailed Description

### Technical Requirements
- RedisHttpInstance CRD for declaring Redis instances
- ApiKey CRD for authentication management
- Comprehensive validation and OpenAPI schemas
- Status subresources for operator feedback
- RBAC configuration for CRD access

### Acceptance Criteria
- [ ] `RedisHttpInstance` CRD with complete specification
- [ ] `ApiKey` CRD with security considerations
- [ ] OpenAPI v3 schema validation for all fields
- [ ] Status subresources with condition types
- [ ] RBAC manifests for different user roles
- [ ] CRD installation manifests
- [ ] Comprehensive validation rules
- [ ] Example YAML files for testing

### Implementation Details

#### RedisHttpInstance CRD Structure
```yaml
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: redishttpinstances.redis.kubegateway.io
spec:
  group: redis.kubegateway.io
  versions:
  - name: v1alpha1
    served: true
    storage: true
    schema:
      openAPIV3Schema:
        type: object
        properties:
          spec:
            type: object
            properties:
              instanceName:
                type: string
                pattern: '^[a-z0-9-]+$'
                maxLength: 63
              redisConfig:
                type: object
                properties:
                  memory:
                    type: string
                    pattern: '^[0-9]+(Mi|Gi)$'
                  persistence:
                    type: boolean
                  appendOnly:
                    type: boolean
              networking:
                type: object
                properties:
                  subdomain:
                    type: string
                    pattern: '^[a-z0-9-]+$'
          status:
            type: object
            properties:
              phase:
                type: string
                enum: ["Pending", "Running", "Failed", "Terminating"]
              conditions:
                type: array
                items:
                  type: object
                  properties:
                    type:
                      type: string
                    status:
                      type: string
                    lastTransitionTime:
                      type: string
```

#### ApiKey CRD Structure
```yaml
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: apikeys.redis.kubegateway.io
spec:
  group: redis.kubegateway.io
  versions:
  - name: v1alpha1
    served: true
    storage: true
    schema:
      openAPIV3Schema:
        type: object
        properties:
          spec:
            type: object
            properties:
              userId:
                type: string
              permissions:
                type: array
                items:
                  type: string
                  enum: ["read", "write", "admin"]
              instanceAccess:
                type: array
                items:
                  type: string
              expiresAt:
                type: string
                format: date-time
          status:
            type: object
            properties:
              keyHash:
                type: string
              createdAt:
                type: string
              lastUsed:
                type: string
```

#### RBAC Configuration
- Cluster roles for different user types
- Role bindings for namespace-scoped access
- Service account configurations
- Security policies

### Definition of Done
- CRDs install successfully in Kubernetes cluster
- Validation rules prevent invalid configurations
- Status fields properly reflect resource state
- RBAC restricts access according to security model
- Example resources can be created and managed

### Dependencies
- Issue #1 (Project Setup)

### Additional Context
- Follow Kubernetes API conventions
- Implement admission webhooks for advanced validation
- Consider implementing conversion webhooks for API versioning
- Document upgrade and migration procedures