# Issue #3: Local Development Environment with Kind/Minikube

**Priority**: High  
**Labels**: development, kubernetes, tooling  
**Milestone**: Phase 1 - Foundation  
**Estimated Effort**: 2 days

## Summary
Create a complete local development environment using Kind (Kubernetes in Docker) or Minikube that allows developers to test the entire system locally.

## Motivation
Developers need a way to test Kubernetes operators and HTTP gateways locally without requiring access to cloud Kubernetes clusters. This accelerates development and reduces iteration cycles.

## Detailed Description

### Technical Requirements
- Kind/Minikube cluster configuration
- Local container registry setup
- Development scripts for cluster management
- Port forwarding and ingress configuration
- Redis deployment scripts for testing

### Acceptance Criteria
- [ ] Kind cluster configuration with appropriate node settings
- [ ] Local container registry for development images
- [ ] Script to create/destroy development cluster (`make cluster-up`/`make cluster-down`)
- [ ] Automated deployment of development resources
- [ ] Port forwarding setup for gateway access
- [ ] Local Redis instances for testing
- [ ] Development documentation with troubleshooting guide

### Implementation Details

#### Kind Cluster Configuration
```yaml
# kind-config.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: InitConfiguration
    nodeRegistration:
      kubeletExtraArgs:
        node-labels: "ingress-ready=true"
  extraPortMappings:
  - containerPort: 80
    hostPort: 8080
    protocol: TCP
  - containerPort: 443
    hostPort: 8443
    protocol: TCP
```

#### Development Scripts
- `scripts/dev-cluster-create.sh` - Creates Kind cluster with registry
- `scripts/dev-cluster-load.sh` - Loads images into cluster
- `scripts/dev-redis-deploy.sh` - Deploys test Redis instances
- `scripts/dev-gateway-deploy.sh` - Deploys gateway with config

#### Local Testing Setup
- Ingress controller (nginx or traefik)
- Redis instances with different configurations
- Test data seeding scripts
- Log aggregation setup

### Definition of Done
- Developer can run single command to start development cluster
- All components deploy successfully in local cluster
- HTTP requests can be made to gateway via localhost
- Changes to code can be quickly deployed and tested
- Documentation includes common troubleshooting scenarios

### Dependencies
- Issue #1 (Project Setup)
- Issue #2 (Container Images)

### Additional Context
- Consider using Tilt for automatic rebuilds and deployments
- Include performance testing setup with k6 or similar
- Document resource requirements and limitations
- Provide scripts for different operating systems (Linux, macOS, Windows)