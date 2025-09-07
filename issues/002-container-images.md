# Issue #2: Container Images and Registry Setup

**Priority**: High  
**Labels**: infrastructure, docker, deployment  
**Milestone**: Phase 1 - Foundation  
**Estimated Effort**: 1 day

## Summary
Create optimized container images for the HTTP Gateway and establish container registry workflow for automated image building and publishing.

## Motivation
Container images are essential for Kubernetes deployment. We need optimized, secure images with proper tagging and automated publishing workflows.

## Detailed Description

### Technical Requirements
- Multi-stage Dockerfiles for minimal production images
- Security scanning integration
- Automated image building on CI
- Container registry publishing workflow
- Image tagging strategy

### Acceptance Criteria
- [ ] Multi-stage Dockerfile for HTTP Gateway (Rust)
- [ ] Multi-stage Dockerfile for Kubernetes Operator
- [ ] Images are built on distroless or Alpine base for security
- [ ] Image size is optimized (< 50MB for gateway)
- [ ] Automated security scanning with Trivy or similar
- [ ] GitHub Container Registry (ghcr.io) publishing workflow
- [ ] Semantic versioning for image tags
- [ ] Health check endpoints included in images

### Implementation Details

#### Gateway Dockerfile Structure
```dockerfile
# Build stage
FROM rust:1.75-slim as builder
WORKDIR /app
COPY . .
RUN cargo build --release --bin gateway

# Runtime stage  
FROM gcr.io/distroless/cc-debian12
COPY --from=builder /app/target/release/gateway /gateway
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/gateway", "healthcheck"]
ENTRYPOINT ["/gateway"]
```

#### CI/CD Integration
- Build images on every commit to main
- Tag with commit SHA and semantic version
- Publish to GitHub Container Registry
- Security scanning as part of CI pipeline

### Definition of Done
- Images build successfully in CI
- Images are published to container registry
- Security scans pass with no critical vulnerabilities
- Images can be pulled and run in Kubernetes

### Dependencies
- Issue #1 (Project Setup)

### Additional Context
- Consider using `cargo-chef` for Docker layer caching
- Implement image signing with cosign
- Use SBOM (Software Bill of Materials) generation
- Document image usage and security considerations