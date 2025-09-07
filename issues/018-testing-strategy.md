# Issue #18: Comprehensive Testing Strategy

**Priority**: High  
**Labels**: testing, quality-assurance, ci/cd  
**Milestone**: Phase 6 - Testing & Quality  
**Estimated Effort**: 4-5 days

## Summary
Implement a comprehensive testing strategy including unit tests, integration tests, end-to-end tests, performance tests, and security tests to ensure system reliability and quality.

## Motivation
A robust testing strategy is essential for maintaining code quality, preventing regressions, and ensuring the system works correctly under various conditions. This includes testing individual components, system integration, and real-world scenarios.

## Detailed Description

### Technical Requirements
- Unit tests for core business logic
- Integration tests for database and external services
- End-to-end tests for complete user workflows
- Performance tests for load and stress scenarios
- Security tests for authentication and authorization
- Chaos engineering tests for resilience validation

### Acceptance Criteria
- [ ] Unit test coverage above 80% for critical components
- [ ] Integration tests validate Redis operations and Kubernetes interactions
- [ ] End-to-end tests cover complete user workflows
- [ ] Performance tests establish baseline metrics
- [ ] Security tests validate authentication and authorization
- [ ] Chaos engineering tests validate system resilience
- [ ] Tests run automatically in CI/CD pipeline
- [ ] Test results are reported and tracked over time

### Implementation Details

#### Unit Testing Framework
```rust
// gateway/tests/unit/mod.rs
#[cfg(test)]
mod tests {
    use super::*;
    use tokio_test;
    use mockall::predicate::*;

    mod handlers;
    mod middleware;
    mod redis;
    mod routing;
}

// gateway/tests/unit/handlers/keys_test.rs
use crate::handlers::keys::{get_key, set_key, delete_key};
use crate::error::GatewayError;
use axum::{
    body::Body,
    extract::{Path, State},
    http::{Request, StatusCode},
    response::Response,
    Json,
};
use serde_json::json;
use tokio_test;

#[tokio::test]
async fn test_set_key_success() {
    // Mock dependencies
    let mock_pool = create_mock_redis_pool();
    let state = create_test_app_state(mock_pool);

    let request = Json(crate::handlers::keys::SetKeyRequest {
        value: "test_value".to_string(),
        ttl_seconds: Some(3600),
    });

    let result = set_key(
        Path(("test_instance".to_string(), "test_key".to_string())),
        State(state),
        request,
    ).await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.0.status, "OK");
}

#[tokio::test]
async fn test_get_key_not_found() {
    let mock_pool = create_mock_redis_pool_with_error();
    let state = create_test_app_state(mock_pool);

    let result = get_key(
        Path(("test_instance".to_string(), "nonexistent_key".to_string())),
        axum::extract::Query(Default::default()),
        State(state),
    ).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        GatewayError::BadRequest(msg) => assert!(msg.contains("not found")),
        _ => panic!("Expected BadRequest error"),
    }
}

#[tokio::test]
async fn test_key_validation() {
    use crate::validation::InputValidator;
    
    let validator = InputValidator::new();
    
    // Valid key
    assert!(validator.validate_redis_key("valid:key:123").is_ok());
    
    // Invalid keys
    assert!(validator.validate_redis_key("").is_err());
    assert!(validator.validate_redis_key("key\0with\0nulls").is_err());
    assert!(validator.validate_redis_key(&"x".repeat(1000)).is_err());
}

#[tokio::test]
async fn test_connection_pool_management() {
    use crate::redis::pool::RedisPoolManager;
    
    let config = create_test_redis_config();
    let pool_manager = RedisPoolManager::new(&config).await.unwrap();
    
    // Test pool creation
    assert!(pool_manager.get_client("test_instance").await.is_none());
    
    // Test health check
    let health_status = pool_manager.health_check().await;
    assert!(health_status.is_empty()); // No instances yet
}

fn create_mock_redis_pool() -> MockRedisPool {
    let mut mock = MockRedisPool::new();
    mock.expect_get_client()
        .with(eq("test_instance"))
        .returning(|_| Some(MockRedisConnection::new()));
    mock
}

fn create_test_app_state(redis_pool: MockRedisPool) -> crate::server::AppState {
    crate::server::AppState {
        redis_pool,
        config: create_test_config(),
    }
}
```

#### Integration Testing
```rust
// gateway/tests/integration/mod.rs
use testcontainers::{clients::Cli, images::redis::Redis, Container};
use tokio::time::{sleep, Duration};
use reqwest::Client;

mod redis_integration;
mod kubernetes_integration;
mod authentication_integration;

#[tokio::test]
async fn test_redis_integration() {
    let docker = Cli::default();
    let redis_container = docker.run(Redis::default());
    let redis_port = redis_container.get_host_port_ipv4(6379);
    
    // Configure gateway to use test Redis instance
    let config = create_integration_test_config(redis_port);
    let gateway = start_test_gateway(config).await;
    
    let client = Client::new();
    
    // Test SET operation
    let set_response = client
        .post(&format!("http://localhost:{}/instances/test/keys/mykey", gateway.port()))
        .header("Authorization", "Bearer test-api-key")
        .json(&json!({
            "value": "myvalue",
            "ttl_seconds": 3600
        }))
        .send()
        .await
        .unwrap();
    
    assert_eq!(set_response.status(), 200);
    
    // Test GET operation
    let get_response = client
        .get(&format!("http://localhost:{}/instances/test/keys/mykey", gateway.port()))
        .header("Authorization", "Bearer test-api-key")
        .send()
        .await
        .unwrap();
    
    assert_eq!(get_response.status(), 200);
    
    let response_json: serde_json::Value = get_response.json().await.unwrap();
    assert_eq!(response_json["value"], "myvalue");
    
    // Test DELETE operation
    let delete_response = client
        .delete(&format!("http://localhost:{}/instances/test/keys/mykey", gateway.port()))
        .header("Authorization", "Bearer test-api-key")
        .send()
        .await
        .unwrap();
    
    assert_eq!(delete_response.status(), 200);
}

#[tokio::test]
async fn test_kubernetes_operator_integration() {
    // This test requires a Kubernetes cluster (kind/minikube)
    if !is_kubernetes_available().await {
        eprintln!("Skipping Kubernetes integration test - cluster not available");
        return;
    }
    
    let k8s_client = kube::Client::try_default().await.unwrap();
    let operator = start_test_operator(k8s_client.clone()).await;
    
    // Create a test RedisHttpInstance
    let redis_instance = create_test_redis_instance();
    create_redis_instance(&k8s_client, &redis_instance).await.unwrap();
    
    // Wait for operator to process
    sleep(Duration::from_secs(10)).await;
    
    // Verify Redis pod was created
    let pods = list_redis_pods(&k8s_client, &redis_instance.namespace).await.unwrap();
    assert!(!pods.is_empty());
    
    // Cleanup
    delete_redis_instance(&k8s_client, &redis_instance).await.unwrap();
}

async fn is_kubernetes_available() -> bool {
    kube::Client::try_default().await.is_ok()
}
```

#### End-to-End Testing
```typescript
// e2e/tests/user-workflow.test.ts
import { describe, test, expect, beforeAll, afterAll } from '@jest/globals';
import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';

describe('End-to-End User Workflow', () => {
  let baseUrl: string;
  let authToken: string;
  let apiKey: string;
  let tenantId: string;
  let instanceName: string;

  beforeAll(async () => {
    baseUrl = process.env.GATEWAY_URL || 'http://localhost:8080';
    
    // Authenticate user and get JWT token
    const authResponse = await axios.post(`${baseUrl}/auth/login`, {
      username: 'testuser',
      password: 'testpass'
    });
    
    authToken = authResponse.data.token;
    
    // Create tenant
    const tenantResponse = await axios.post(`${baseUrl}/admin/tenants`, {
      name: `test-tenant-${uuidv4()}`,
      resource_quota: {
        redis_instances: 10,
        memory_limit: '1Gi',
        cpu_limit: '1000m',
        storage_limit: '10Gi',
        api_requests_per_minute: 1000
      }
    }, {
      headers: { Authorization: `Bearer ${authToken}` }
    });
    
    tenantId = tenantResponse.data.tenant_id;
  });

  afterAll(async () => {
    // Cleanup tenant
    if (tenantId) {
      await axios.delete(`${baseUrl}/admin/tenants/${tenantId}`, {
        headers: { Authorization: `Bearer ${authToken}` }
      });
    }
  });

  test('Complete user workflow: create API key, instance, and use Redis operations', async () => {
    // Step 1: Create API key
    const apiKeyResponse = await axios.post(`${baseUrl}/auth/api-keys`, {
      name: `test-key-${uuidv4()}`,
      permissions: ['read', 'write'],
      instance_access: ['*']
    }, {
      headers: { Authorization: `Bearer ${authToken}` }
    });
    
    apiKey = apiKeyResponse.data.api_key;
    expect(apiKey).toMatch(/^rgk_/);

    // Step 2: Create Redis instance
    instanceName = `test-instance-${uuidv4()}`;
    const instanceResponse = await axios.post(`${baseUrl}/instances`, {
      instanceName,
      redisConfig: {
        memory: '256Mi',
        persistence: true,
        appendOnly: false
      },
      networking: {
        subdomain: instanceName
      }
    }, {
      headers: { Authorization: `Bearer ${apiKey}` }
    });
    
    expect(instanceResponse.status).toBe(201);
    
    // Wait for instance to be ready
    await waitForInstanceReady(instanceName);

    // Step 3: Test Redis operations
    const testKey = `test:key:${uuidv4()}`;
    const testValue = `test-value-${Date.now()}`;

    // SET operation
    const setResponse = await axios.post(`${baseUrl}/instances/${instanceName}/keys/${testKey}`, {
      value: testValue,
      ttl_seconds: 3600
    }, {
      headers: { Authorization: `Bearer ${apiKey}` }
    });
    
    expect(setResponse.status).toBe(200);
    expect(setResponse.data.status).toBe('OK');

    // GET operation
    const getResponse = await axios.get(`${baseUrl}/instances/${instanceName}/keys/${testKey}`, {
      headers: { Authorization: `Bearer ${apiKey}` }
    });
    
    expect(getResponse.status).toBe(200);
    expect(getResponse.data.value).toBe(testValue);

    // Hash operations
    const hashKey = `test:hash:${uuidv4()}`;
    
    // HSET operation
    const hsetResponse = await axios.post(`${baseUrl}/instances/${instanceName}/hashes/${hashKey}`, {
      field: 'field1',
      value: 'value1'
    }, {
      headers: { Authorization: `Bearer ${apiKey}` }
    });
    
    expect(hsetResponse.status).toBe(200);

    // HGET operation
    const hgetResponse = await axios.get(`${baseUrl}/instances/${instanceName}/hashes/${hashKey}/field1`, {
      headers: { Authorization: `Bearer ${apiKey}` }
    });
    
    expect(hgetResponse.status).toBe(200);
    expect(hgetResponse.data.value).toBe('value1');

    // DELETE operation
    const deleteResponse = await axios.delete(`${baseUrl}/instances/${instanceName}/keys/${testKey}`, {
      headers: { Authorization: `Bearer ${apiKey}` }
    });
    
    expect(deleteResponse.status).toBe(200);
    expect(deleteResponse.data.deleted).toBe(1);

    // Step 4: Test method override functionality
    const methodOverrideResponse = await axios.get(`${baseUrl}/instances/${instanceName}/keys/override-test?method=POST&value=override-value`, {
      headers: { Authorization: `Bearer ${apiKey}` }
    });
    
    expect(methodOverrideResponse.status).toBe(200);
  });

  test('Authentication and authorization', async () => {
    // Test without API key
    const unauthorizedResponse = await axios.get(`${baseUrl}/instances/${instanceName}/keys/test`, {
      validateStatus: () => true
    });
    
    expect(unauthorizedResponse.status).toBe(401);

    // Test with invalid API key
    const invalidKeyResponse = await axios.get(`${baseUrl}/instances/${instanceName}/keys/test`, {
      headers: { Authorization: 'Bearer invalid-key' },
      validateStatus: () => true
    });
    
    expect(invalidKeyResponse.status).toBe(401);
  });

  test('Rate limiting', async () => {
    // This test would send many requests rapidly to test rate limiting
    // Implementation depends on rate limit configuration
    const promises = [];
    
    for (let i = 0; i < 100; i++) {
      promises.push(
        axios.get(`${baseUrl}/instances/${instanceName}/keys/rate-test-${i}`, {
          headers: { Authorization: `Bearer ${apiKey}` },
          validateStatus: () => true
        })
      );
    }
    
    const responses = await Promise.all(promises);
    const rateLimitedResponses = responses.filter(r => r.status === 429);
    
    // Expect some requests to be rate limited
    expect(rateLimitedResponses.length).toBeGreaterThan(0);
  });

  async function waitForInstanceReady(instanceName: string) {
    const maxRetries = 30;
    const retryDelay = 2000;
    
    for (let i = 0; i < maxRetries; i++) {
      try {
        const healthResponse = await axios.get(`${baseUrl}/instances/${instanceName}/health`, {
          headers: { Authorization: `Bearer ${apiKey}` }
        });
        
        if (healthResponse.status === 200) {
          return;
        }
      } catch (error) {
        // Instance not ready yet
      }
      
      await new Promise(resolve => setTimeout(resolve, retryDelay));
    }
    
    throw new Error(`Instance ${instanceName} did not become ready within ${maxRetries * retryDelay}ms`);
  }
});
```

#### Performance Testing
```yaml
# k6/performance-test.js
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

const errorRate = new Rate('errors');
const baseUrl = __ENV.BASE_URL || 'http://localhost:8080';
const apiKey = __ENV.API_KEY || 'test-api-key';

export const options = {
  stages: [
    { duration: '2m', target: 100 }, // Ramp up to 100 users
    { duration: '5m', target: 100 }, // Steady state
    { duration: '2m', target: 200 }, // Ramp up to 200 users
    { duration: '5m', target: 200 }, // Steady state
    { duration: '2m', target: 0 },   // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'], // 95% of requests must complete below 500ms
    errors: ['rate<0.1'],             // Error rate must be below 10%
  },
};

export default function () {
  const instanceName = 'perf-test-instance';
  const testKey = `perf:key:${Math.random()}`;
  const testValue = `value:${Math.random()}`;
  
  const headers = {
    'Authorization': `Bearer ${apiKey}`,
    'Content-Type': 'application/json',
  };

  // Test SET operation
  const setResponse = http.post(
    `${baseUrl}/instances/${instanceName}/keys/${testKey}`,
    JSON.stringify({
      value: testValue,
      ttl_seconds: 3600
    }),
    { headers }
  );
  
  check(setResponse, {
    'SET request successful': (r) => r.status === 200,
    'SET response time < 200ms': (r) => r.timings.duration < 200,
  }) || errorRate.add(1);

  // Test GET operation
  const getResponse = http.get(
    `${baseUrl}/instances/${instanceName}/keys/${testKey}`,
    { headers }
  );
  
  check(getResponse, {
    'GET request successful': (r) => r.status === 200,
    'GET response time < 100ms': (r) => r.timings.duration < 100,
    'GET returns correct value': (r) => JSON.parse(r.body).value === testValue,
  }) || errorRate.add(1);

  // Test DELETE operation
  const deleteResponse = http.del(
    `${baseUrl}/instances/${instanceName}/keys/${testKey}`,
    null,
    { headers }
  );
  
  check(deleteResponse, {
    'DELETE request successful': (r) => r.status === 200,
    'DELETE response time < 100ms': (r) => r.timings.duration < 100,
  }) || errorRate.add(1);

  sleep(0.1); // Brief pause between iterations
}

export function handleSummary(data) {
  return {
    'performance-results.json': JSON.stringify(data),
    'performance-results.html': htmlReport(data),
  };
}
```

#### Security Testing
```python
# security/security_tests.py
import requests
import json
import pytest
from urllib.parse import quote

class TestSecurityVulnerabilities:
    def __init__(self):
        self.base_url = "http://localhost:8080"
        self.api_key = "test-api-key"
        self.headers = {"Authorization": f"Bearer {self.api_key}"}

    def test_sql_injection_attempts(self):
        """Test for SQL injection vulnerabilities"""
        injection_payloads = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "'; SELECT * FROM secrets; --",
        ]
        
        for payload in injection_payloads:
            response = requests.get(
                f"{self.base_url}/instances/test/keys/{quote(payload)}",
                headers=self.headers
            )
            # Should not cause internal server errors
            assert response.status_code != 500

    def test_command_injection_attempts(self):
        """Test for command injection in Redis operations"""
        dangerous_commands = [
            "FLUSHDB",
            "FLUSHALL", 
            "CONFIG SET",
            "SHUTDOWN",
            "EVAL",
        ]
        
        for cmd in dangerous_commands:
            response = requests.post(
                f"{self.base_url}/instances/test/raw-command",
                headers=self.headers,
                json={"command": cmd, "args": []}
            )
            # Dangerous commands should be rejected
            assert response.status_code == 400

    def test_xss_prevention(self):
        """Test for XSS vulnerability prevention"""
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
        ]
        
        for payload in xss_payloads:
            response = requests.post(
                f"{self.base_url}/instances/test/keys/xss-test",
                headers=self.headers,
                json={"value": payload}
            )
            
            if response.status_code == 200:
                get_response = requests.get(
                    f"{self.base_url}/instances/test/keys/xss-test",
                    headers=self.headers
                )
                # Response should properly escape dangerous content
                assert "<script>" not in get_response.text

    def test_authentication_bypass_attempts(self):
        """Test for authentication bypass vulnerabilities"""
        bypass_attempts = [
            {},  # No auth header
            {"Authorization": "Bearer fake-token"},
            {"Authorization": "Basic fake-basic"},
            {"X-API-Key": "fake-key"},
        ]
        
        for auth in bypass_attempts:
            response = requests.get(
                f"{self.base_url}/instances/test/keys/test",
                headers=auth
            )
            # Should be unauthorized
            assert response.status_code == 401

    def test_path_traversal_attempts(self):
        """Test for path traversal vulnerabilities"""
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ]
        
        for payload in traversal_payloads:
            response = requests.get(
                f"{self.base_url}/instances/test/keys/{quote(payload)}",
                headers=self.headers
            )
            # Should not expose system files
            assert "root:" not in response.text
            assert response.status_code in [400, 404]

    def test_rate_limiting(self):
        """Test rate limiting implementation"""
        # Send many requests rapidly
        responses = []
        for i in range(100):
            response = requests.get(
                f"{self.base_url}/instances/test/keys/rate-test-{i}",
                headers=self.headers
            )
            responses.append(response.status_code)
        
        # Should see some rate limit responses
        rate_limited = [r for r in responses if r == 429]
        assert len(rate_limited) > 0

if __name__ == "__main__":
    pytest.main([__file__])
```

#### CI/CD Pipeline Integration
```yaml
# .github/workflows/test.yml
name: Test Suite

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup Rust
      uses: actions-rs/toolchain@v1
      with:
        toolchain: stable
        
    - name: Run unit tests
      run: |
        cd gateway
        cargo test --lib
        
    - name: Generate coverage report
      run: |
        cargo install cargo-tarpaulin
        cargo tarpaulin --out xml --output-dir coverage
        
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        files: ./coverage/cobertura.xml

  integration-tests:
    runs-on: ubuntu-latest
    services:
      redis:
        image: redis:7-alpine
        ports:
          - 6379:6379
          
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup Rust
      uses: actions-rs/toolchain@v1
      with:
        toolchain: stable
        
    - name: Run integration tests
      run: |
        cd gateway
        cargo test --test integration
        
  e2e-tests:
    runs-on: ubuntu-latest
    needs: [unit-tests, integration-tests]
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup Kind
      uses: helm/kind-action@v1.4.0
      
    - name: Build and load images
      run: |
        make docker-build
        kind load docker-image redis-gateway:latest
        
    - name: Deploy to Kind
      run: |
        kubectl apply -f k8s/
        kubectl wait --for=condition=ready pod -l app=redis-gateway --timeout=300s
        
    - name: Run E2E tests
      run: |
        cd e2e
        npm install
        npm run test
        
  performance-tests:
    runs-on: ubuntu-latest
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup k6
      run: |
        sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
        echo "deb https://dl.k6.io/deb stable main" | sudo tee /etc/apt/sources.list.d/k6.list
        sudo apt-get update
        sudo apt-get install k6
        
    - name: Run performance tests
      run: |
        k6 run k6/performance-test.js
        
  security-tests:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
        
    - name: Install dependencies
      run: |
        pip install pytest requests
        
    - name: Run security tests
      run: |
        python -m pytest security/security_tests.py
```

### Definition of Done
- Unit tests achieve >80% code coverage for critical components
- Integration tests validate all external dependencies
- End-to-end tests cover complete user workflows
- Performance tests establish baseline metrics and SLAs
- Security tests validate authentication, authorization, and input validation
- All tests run automatically in CI/CD pipeline
- Test results are reported and tracked over time
- Test failures block deployments to production

### Dependencies
- Issue #8 (HTTP Gateway Core)
- Issue #13 (JWT Authentication)
- Issue #16 (Observability)

### Additional Context
- Consider implementing mutation testing for test quality
- Plan for browser-based testing for web UI components
- Implement chaos engineering tests with tools like Chaos Monkey
- Consider contract testing for API versioning
- Plan for accessibility testing for web interfaces