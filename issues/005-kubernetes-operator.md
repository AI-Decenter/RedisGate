# Issue #5: Kubernetes Operator Core Framework

**Priority**: High  
**Labels**: kubernetes, operator, controller  
**Milestone**: Phase 2 - Kubernetes Integration  
**Estimated Effort**: 3-4 days

## Summary
Implement the core Kubernetes operator framework using controller-runtime to manage RedisHttpInstance and ApiKey custom resources.

## Motivation
The operator provides automated lifecycle management for Redis instances and API keys. It watches for changes to custom resources and reconciles the desired state with the actual cluster state.

## Detailed Description

### Technical Requirements
- Controller-runtime based operator implementation
- Reconciliation loops for custom resources
- Event handling and status updates
- Error handling and retry logic
- Graceful shutdown and leader election

### Acceptance Criteria
- [ ] Operator binary that can be deployed in Kubernetes
- [ ] RedisHttpInstance controller with full reconciliation
- [ ] ApiKey controller with secure key generation
- [ ] Proper event recording for debugging
- [ ] Status updates with conditions and phases
- [ ] Leader election for high availability
- [ ] Metrics endpoint for monitoring
- [ ] Graceful shutdown handling

### Implementation Details

#### Project Structure (Go)
```
operator/
├── cmd/
│   └── main.go
├── pkg/
│   ├── controllers/
│   │   ├── redishttpinstance_controller.go
│   │   └── apikey_controller.go
│   ├── apis/
│   │   └── redis/
│   │       └── v1alpha1/
│   └── util/
├── config/
│   ├── crd/
│   ├── rbac/
│   └── manager/
└── Dockerfile
```

#### RedisHttpInstance Controller
```go
func (r *RedisHttpInstanceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
    log := r.Log.WithValues("redishttpinstance", req.NamespacedName)

    // Fetch the RedisHttpInstance
    instance := &redisv1alpha1.RedisHttpInstance{}
    err := r.Get(ctx, req.NamespacedName, instance)
    if err != nil {
        return ctrl.Result{}, client.IgnoreNotFound(err)
    }

    // Reconciliation logic
    return r.reconcileRedisInstance(ctx, instance)
}

func (r *RedisHttpInstanceReconciler) reconcileRedisInstance(ctx context.Context, instance *redisv1alpha1.RedisHttpInstance) (ctrl.Result, error) {
    // 1. Create Redis deployment
    // 2. Create service for Redis
    // 3. Update gateway configuration
    // 4. Update instance status
}
```

#### Controller Features
- **Finalizers**: Proper cleanup when resources are deleted
- **Owner References**: Automatic garbage collection
- **Status Management**: Phase transitions and conditions
- **Event Recording**: Detailed events for user feedback
- **Error Handling**: Exponential backoff and retry logic

#### Deployment Configuration
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis-operator
spec:
  replicas: 1
  selector:
    matchLabels:
      app: redis-operator
  template:
    metadata:
      labels:
        app: redis-operator
    spec:
      serviceAccountName: redis-operator
      containers:
      - name: manager
        image: ghcr.io/ai-decenter/redis-operator:latest
        ports:
        - containerPort: 9443
          name: webhook-server
        - containerPort: 8080
          name: metrics
```

### Definition of Done
- Operator deploys successfully in Kubernetes
- Creates and manages Redis instances based on CRD specs
- Handles resource updates and deletions properly
- Reports status and events accurately
- Passes integration tests with actual Kubernetes cluster

### Dependencies
- Issue #4 (Custom Resource Definitions)
- Issue #1 (Project Setup)

### Additional Context
- Use Kubebuilder or Operator SDK for scaffolding
- Implement comprehensive logging with structured fields
- Consider using admission webhooks for validation
- Document operator architecture and reconciliation logic