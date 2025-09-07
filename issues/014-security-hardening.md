# Issue #14: Security Hardening and Encryption

**Priority**: High  
**Labels**: security, encryption, tls  
**Milestone**: Phase 4 - Security & Authentication  
**Estimated Effort**: 3-4 days

## Summary
Implement comprehensive security hardening including TLS encryption, Redis authentication, input validation, and security headers to protect against common attacks.

## Motivation
Production deployments require robust security measures to protect data in transit and at rest, prevent injection attacks, and ensure compliance with security standards.

## Detailed Description

### Technical Requirements
- TLS/SSL encryption for all HTTP communications
- Redis AUTH for backend connections
- Input validation and sanitization
- Security headers (HSTS, CSP, etc.)
- Request size limits and DoS protection
- Secrets management integration
- Security scanning and vulnerability assessment

### Acceptance Criteria
- [ ] TLS certificate management with automatic renewal
- [ ] Redis connection encryption and authentication
- [ ] Comprehensive input validation for all endpoints
- [ ] Security headers implementation
- [ ] Request/response size limits
- [ ] SQL/NoSQL injection prevention
- [ ] Cross-origin request controls
- [ ] Integration with Kubernetes secrets for sensitive data

### Implementation Details

#### TLS Configuration
```rust
// src/tls/mod.rs
use axum_server::tls_rustls::RustlsConfig;
use std::path::PathBuf;
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};
use x509_parser::prelude::*;

pub struct TlsManager {
    config: TlsConfig,
}

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub ca_cert_path: Option<PathBuf>,
    pub auto_reload: bool,
    pub reload_interval_seconds: u64,
}

impl TlsManager {
    pub async fn new(config: TlsConfig) -> Result<Self, TlsError> {
        let manager = Self { config };
        manager.validate_certificates().await?;
        Ok(manager)
    }

    pub async fn create_rustls_config(&self) -> Result<RustlsConfig, TlsError> {
        let cert_chain = self.load_cert_chain().await?;
        let private_key = self.load_private_key().await?;

        let mut server_config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .map_err(|e| TlsError::ConfigurationError(e.to_string()))?;

        // Security hardening
        server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        
        Ok(RustlsConfig::from_config(Arc::new(server_config)))
    }

    async fn load_cert_chain(&self) -> Result<Vec<Certificate>, TlsError> {
        let cert_data = tokio::fs::read(&self.config.cert_path).await?;
        let cert_chain = rustls_pemfile::certs(&mut cert_data.as_slice())
            .map_err(|e| TlsError::CertificateError(e.to_string()))?
            .into_iter()
            .map(Certificate)
            .collect();
        Ok(cert_chain)
    }

    async fn load_private_key(&self) -> Result<PrivateKey, TlsError> {
        let key_data = tokio::fs::read(&self.config.key_path).await?;
        let mut reader = key_data.as_slice();
        
        // Try different key formats
        if let Ok(keys) = rustls_pemfile::rsa_private_keys(&mut reader) {
            if !keys.is_empty() {
                return Ok(PrivateKey(keys[0].clone()));
            }
        }
        
        reader = key_data.as_slice();
        if let Ok(keys) = rustls_pemfile::pkcs8_private_keys(&mut reader) {
            if !keys.is_empty() {
                return Ok(PrivateKey(keys[0].clone()));
            }
        }
        
        Err(TlsError::KeyError("No valid private key found".to_string()))
    }

    async fn validate_certificates(&self) -> Result<(), TlsError> {
        let cert_data = tokio::fs::read(&self.config.cert_path).await?;
        let (_, cert) = X509Certificate::from_der(&cert_data)
            .map_err(|e| TlsError::CertificateError(e.to_string()))?;

        // Check expiration
        let now = chrono::Utc::now();
        let not_after = cert.validity().not_after.to_datetime();
        
        if now > not_after {
            return Err(TlsError::CertificateExpired);
        }

        // Warn if certificate expires within 30 days
        let thirty_days = chrono::Duration::days(30);
        if now + thirty_days > not_after {
            tracing::warn!("TLS certificate expires within 30 days: {:?}", not_after);
        }

        Ok(())
    }

    pub fn start_auto_reload(&self) -> tokio::task::JoinHandle<()> {
        if !self.config.auto_reload {
            return tokio::spawn(async {});
        }

        let config = self.config.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                std::time::Duration::from_secs(config.reload_interval_seconds)
            );
            
            loop {
                interval.tick().await;
                
                // Check if certificates have changed
                if let Err(e) = Self::check_certificate_changes(&config).await {
                    tracing::error!("Certificate reload check failed: {}", e);
                }
            }
        })
    }

    async fn check_certificate_changes(config: &TlsConfig) -> Result<(), TlsError> {
        // Implementation would check file modification times and reload if needed
        // This is a simplified version
        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum TlsError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Certificate error: {0}")]
    CertificateError(String),
    
    #[error("Private key error: {0}")]
    KeyError(String),
    
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("Certificate expired")]
    CertificateExpired,
}
```

#### Security Middleware
```rust
// src/middleware/security.rs
use axum::{
    extract::Request,
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    middleware::Next,
    response::Response,
};
use std::collections::HashMap;

pub struct SecurityMiddleware {
    config: SecurityConfig,
}

#[derive(Debug, Clone)]
pub struct SecurityConfig {
    pub max_request_size: usize,
    pub security_headers: HashMap<String, String>,
    pub cors_config: CorsConfig,
    pub rate_limiting: bool,
}

#[derive(Debug, Clone)]
pub struct CorsConfig {
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub max_age: u64,
    pub credentials: bool,
}

impl SecurityMiddleware {
    pub fn new(config: SecurityConfig) -> Self {
        Self { config }
    }

    pub async fn process_request(
        &self,
        mut request: Request,
        next: Next,
    ) -> Result<Response, StatusCode> {
        // Request size validation
        if let Some(content_length) = request.headers().get("content-length") {
            if let Ok(size) = content_length.to_str().and_then(|s| s.parse::<usize>()) {
                if size > self.config.max_request_size {
                    return Err(StatusCode::PAYLOAD_TOO_LARGE);
                }
            }
        }

        // Input validation (basic)
        self.validate_headers(request.headers())?;

        let mut response = next.run(request).await;
        
        // Add security headers
        self.add_security_headers(response.headers_mut());
        
        Ok(response)
    }

    fn validate_headers(&self, headers: &HeaderMap) -> Result<(), StatusCode> {
        // Check for suspicious headers
        for (name, value) in headers.iter() {
            let name_str = name.as_str().to_lowercase();
            let value_str = value.to_str().unwrap_or("");

            // Basic injection detection
            if self.contains_suspicious_content(value_str) {
                tracing::warn!("Suspicious header detected: {} = {}", name_str, value_str);
                return Err(StatusCode::BAD_REQUEST);
            }

            // Check for oversized headers
            if value_str.len() > 8192 {
                return Err(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
            }
        }

        Ok(())
    }

    fn contains_suspicious_content(&self, content: &str) -> bool {
        let suspicious_patterns = [
            "<script", "</script>", "javascript:", "vbscript:",
            "onload=", "onerror=", "onclick=", "onmouseover=",
            "eval(", "expression(", "url(", "import(",
            "../", "..\\", "/etc/passwd", "cmd.exe",
        ];

        let content_lower = content.to_lowercase();
        suspicious_patterns.iter().any(|pattern| content_lower.contains(pattern))
    }

    fn add_security_headers(&self, headers: &mut HeaderMap) {
        // Default security headers
        let default_headers = [
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("X-XSS-Protection", "1; mode=block"),
            ("Referrer-Policy", "strict-origin-when-cross-origin"),
            ("Permissions-Policy", "geolocation=(), microphone=(), camera=()"),
            (
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains; preload"
            ),
            (
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"
            ),
        ];

        for (name, value) in default_headers.iter() {
            if let (Ok(header_name), Ok(header_value)) = (
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            ) {
                headers.insert(header_name, header_value);
            }
        }

        // Custom headers from config
        for (name, value) in &self.config.security_headers {
            if let (Ok(header_name), Ok(header_value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(header_name, header_value);
            }
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_request_size: 1_048_576, // 1MB
            security_headers: HashMap::new(),
            cors_config: CorsConfig::default(),
            rate_limiting: true,
        }
    }
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: vec!["*".to_string()],
            allowed_methods: vec!["GET".to_string(), "POST".to_string(), "DELETE".to_string()],
            allowed_headers: vec!["Content-Type".to_string(), "Authorization".to_string()],
            max_age: 3600,
            credentials: false,
        }
    }
}
```

#### Input Validation
```rust
// src/validation/mod.rs
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub struct InputValidator {
    patterns: HashMap<String, Regex>,
}

impl InputValidator {
    pub fn new() -> Self {
        let mut patterns = HashMap::new();
        
        // Common validation patterns
        patterns.insert(
            "redis_key".to_string(),
            Regex::new(r"^[a-zA-Z0-9:._-]{1,512}$").unwrap()
        );
        patterns.insert(
            "instance_name".to_string(),
            Regex::new(r"^[a-z0-9-]{1,63}$").unwrap()
        );
        patterns.insert(
            "field_name".to_string(),
            Regex::new(r"^[a-zA-Z0-9:._-]{1,256}$").unwrap()
        );
        
        Self { patterns }
    }

    pub fn validate_redis_key(&self, key: &str) -> Result<(), ValidationError> {
        if key.is_empty() {
            return Err(ValidationError::EmptyValue("Redis key cannot be empty".to_string()));
        }

        if key.len() > 512 {
            return Err(ValidationError::TooLong("Redis key too long".to_string()));
        }

        if let Some(pattern) = self.patterns.get("redis_key") {
            if !pattern.is_match(key) {
                return Err(ValidationError::InvalidFormat(
                    "Redis key contains invalid characters".to_string()
                ));
            }
        }

        // Check for null bytes and control characters
        if key.contains('\0') || key.chars().any(|c| c.is_control()) {
            return Err(ValidationError::InvalidFormat(
                "Redis key contains invalid control characters".to_string()
            ));
        }

        Ok(())
    }

    pub fn validate_instance_name(&self, name: &str) -> Result<(), ValidationError> {
        if name.is_empty() {
            return Err(ValidationError::EmptyValue("Instance name cannot be empty".to_string()));
        }

        if let Some(pattern) = self.patterns.get("instance_name") {
            if !pattern.is_match(name) {
                return Err(ValidationError::InvalidFormat(
                    "Instance name must contain only lowercase letters, numbers, and hyphens".to_string()
                ));
            }
        }

        Ok(())
    }

    pub fn validate_redis_value(&self, value: &str) -> Result<(), ValidationError> {
        // Check size limits
        if value.len() > 512 * 1024 * 1024 { // 512MB limit
            return Err(ValidationError::TooLong("Redis value too large".to_string()));
        }

        // Check for suspicious patterns
        if self.contains_injection_patterns(value) {
            return Err(ValidationError::SecurityViolation(
                "Value contains potentially malicious content".to_string()
            ));
        }

        Ok(())
    }

    fn contains_injection_patterns(&self, input: &str) -> bool {
        let suspicious_patterns = [
            // Redis command injection
            r"(?i)\bFLUSHDB\b", r"(?i)\bFLUSHALL\b", r"(?i)\bCONFIG\b",
            r"(?i)\bEVAL\b", r"(?i)\bSCRIPT\b", r"(?i)\bSHUTDOWN\b",
            
            // Common injection patterns
            r"(?i)\bunion\s+select\b", r"(?i)\bdrop\s+table\b",
            r"(?i)\binsert\s+into\b", r"(?i)\bdelete\s+from\b",
            
            // Script injection
            r"<script[^>]*>", r"javascript:", r"vbscript:",
            r"(?i)\bon\w+\s*=", r"(?i)expression\s*\(",
        ];

        for pattern_str in suspicious_patterns.iter() {
            if let Ok(pattern) = Regex::new(pattern_str) {
                if pattern.is_match(input) {
                    return true;
                }
            }
        }

        false
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ValidationError {
    #[error("Empty value: {0}")]
    EmptyValue(String),
    
    #[error("Value too long: {0}")]
    TooLong(String),
    
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
    
    #[error("Security violation: {0}")]
    SecurityViolation(String),
}
```

#### Redis Security Configuration
```rust
// src/redis/security.rs
use redis::{Client, ConnectionInfo, RedisConnectionInfo};
use std::time::Duration;

pub struct SecureRedisConfig {
    pub username: Option<String>,
    pub password: Option<String>,
    pub tls_enabled: bool,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub ca_cert_path: Option<String>,
    pub verify_peer: bool,
    pub connection_timeout: Duration,
    pub response_timeout: Duration,
}

impl SecureRedisConfig {
    pub fn build_connection_info(&self, host: &str, port: u16) -> Result<ConnectionInfo, redis::RedisError> {
        let redis_info = RedisConnectionInfo {
            db: 0,
            username: self.username.clone(),
            password: self.password.clone(),
        };

        let mut conn_info = if self.tls_enabled {
            ConnectionInfo {
                addr: redis::ConnectionAddr::TcpTls {
                    host: host.to_string(),
                    port,
                    insecure: !self.verify_peer,
                    tls_params: None, // Would configure TLS params here
                },
                redis: redis_info,
            }
        } else {
            ConnectionInfo {
                addr: redis::ConnectionAddr::Tcp(host.to_string(), port),
                redis: redis_info,
            }
        };

        Ok(conn_info)
    }
}
```

### Definition of Done
- TLS encryption works for all HTTP traffic
- Redis connections use authentication and encryption
- All input is validated and sanitized
- Security headers are properly set
- Request size limits prevent DoS attacks
- Integration with Kubernetes secrets works
- Security scanning passes without critical issues

### Dependencies
- Issue #8 (HTTP Gateway Core)
- Issue #13 (JWT Authentication)

### Additional Context
- Consider integrating with security scanning tools like Falco
- Implement certificate rotation automation
- Add security audit logging
- Plan for compliance with security standards (SOC2, ISO27001)
- Consider implementing mTLS for service-to-service communication