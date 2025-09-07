# Issue #7: Operator Installation and Deployment Manifests

**Priority**: High  
**Labels**: kubernetes, deployment, manifests  
**Milestone**: Phase 2 - Kubernetes Integration  
**Estimated Effort**: 1-2 days

## Summary
Create comprehensive Kubernetes deployment manifests and installation procedures for the Redis HTTP Gateway operator.

## Motivation
The operator needs production-ready deployment manifests with proper RBAC, security configurations, and installation procedures for different environments (development, staging, production).

## Detailed Description

### Technical Requirements
- Complete RBAC configuration for operator permissions
- Deployment manifests with security best practices
- Helm chart for flexible installation
- Namespace isolation and resource quotas
- Installation and upgrade procedures

### Acceptance Criteria
- [ ] Complete RBAC manifests (ClusterRole, ClusterRoleBinding, ServiceAccount)
- [ ] Operator Deployment manifest with security context
- [ ] Helm chart with configurable values
- [ ] Installation script for quick setup
- [ ] Upgrade and uninstallation procedures
- [ ] Multi-environment configuration (dev/staging/prod)
- [ ] Network policies for security isolation
- [ ] Resource quotas and limits

### Implementation Details

#### RBAC Configuration
```yaml
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: redis-operator
  namespace: redis-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: redis-operator
rules:
- apiGroups: [""]
  resources: ["configmaps", "services", "events"]
  verbs: ["create", "get", "list", "watch", "update", "patch", "delete"]
- apiGroups: ["apps"]
  resources: ["statefulsets", "deployments"]
  verbs: ["create", "get", "list", "watch", "update", "patch", "delete"]
- apiGroups: ["redis.kubegateway.io"]
  resources: ["redishttpinstances", "apikeys"]
  verbs: ["create", "get", "list", "watch", "update", "patch", "delete"]
- apiGroups: ["redis.kubegateway.io"]
  resources: ["redishttpinstances/status", "apikeys/status"]
  verbs: ["get", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: redis-operator
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: redis-operator
subjects:
- kind: ServiceAccount
  name: redis-operator
  namespace: redis-system
```

#### Operator Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis-operator
  namespace: redis-system
  labels:
    app: redis-operator
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
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: manager
        image: ghcr.io/ai-decenter/redis-operator:latest
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL
          readOnlyRootFilesystem: true
        ports:
        - containerPort: 8080
          name: metrics
          protocol: TCP
        - containerPort: 9443
          name: webhook
          protocol: TCP
        env:
        - name: WATCH_NAMESPACE
          value: ""
        - name: POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: OPERATOR_NAME
          value: "redis-operator"
        resources:
          limits:
            cpu: 500m
            memory: 512Mi
          requests:
            cpu: 100m
            memory: 128Mi
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8081
          initialDelaySeconds: 15
          periodSeconds: 20
        readinessProbe:
          httpGet:
            path: /readyz
            port: 8081
          initialDelaySeconds: 5
          periodSeconds: 10
```

#### Helm Chart Structure
```
helm/
├── Chart.yaml
├── values.yaml
├── templates/
│   ├── namespace.yaml
│   ├── serviceaccount.yaml
│   ├── rbac.yaml
│   ├── deployment.yaml
│   ├── service.yaml
│   ├── configmap.yaml
│   └── _helpers.tpl
└── crds/
    ├── redishttpinstance-crd.yaml
    └── apikey-crd.yaml
```

#### Helm Values Configuration
```yaml
# values.yaml
operator:
  image:
    repository: ghcr.io/ai-decenter/redis-operator
    tag: latest
    pullPolicy: IfNotPresent
  
  replicas: 1
  
  resources:
    limits:
      cpu: 500m
      memory: 512Mi
    requests:
      cpu: 100m
      memory: 128Mi

  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000

gateway:
  image:
    repository: ghcr.io/ai-decenter/redis-gateway
    tag: latest
  
  replicas: 3
  
  resources:
    limits:
      cpu: 1
      memory: 1Gi
    requests:
      cpu: 250m
      memory: 256Mi

namespace:
  create: true
  name: redis-system

rbac:
  create: true

monitoring:
  enabled: true
  serviceMonitor:
    enabled: false

networkPolicies:
  enabled: false
```

#### Installation Scripts
```bash
#!/bin/bash
# scripts/install.sh

set -e

NAMESPACE=${NAMESPACE:-redis-system}
HELM_RELEASE=${HELM_RELEASE:-redis-operator}

echo "Installing Redis HTTP Gateway Operator..."

# Create namespace if it doesn't exist
kubectl create namespace $NAMESPACE --dry-run=client -o yaml | kubectl apply -f -

# Install CRDs first
kubectl apply -f k8s/crds/

# Install operator via Helm
helm upgrade --install $HELM_RELEASE ./helm/ \
  --namespace $NAMESPACE \
  --create-namespace \
  --wait

echo "Installation completed successfully!"
echo "Verify installation: kubectl get pods -n $NAMESPACE"
```

### Definition of Done
- All Kubernetes manifests deploy successfully
- RBAC permissions are minimal and secure
- Helm chart installs and upgrades work correctly
- Installation script completes without errors
- Operator has proper health checks and monitoring endpoints

### Dependencies
- Issue #5 (Kubernetes Operator Core)
- Issue #4 (Custom Resource Definitions)
- Issue #2 (Container Images)

### Additional Context
- Follow Kubernetes security best practices
- Implement proper resource limits and quotas
- Consider using Kustomize for environment-specific configs
- Document troubleshooting procedures