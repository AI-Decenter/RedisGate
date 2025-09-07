# Issue #17: Alerting Rules and Incident Response

**Priority**: Medium  
**Labels**: alerting, monitoring, operations  
**Milestone**: Phase 5 - Operations & Monitoring  
**Estimated Effort**: 2-3 days

## Summary
Implement comprehensive alerting rules, runbooks, and incident response procedures to ensure rapid detection and resolution of system issues.

## Motivation
Proactive monitoring and alerting are essential for maintaining system reliability. Well-defined alert rules and runbooks enable quick incident response and reduce mean time to recovery (MTTR).

## Detailed Description

### Technical Requirements
- Prometheus alerting rules for critical conditions
- AlertManager configuration with routing and notification
- Grafana alert annotations and dashboards
- Runbook documentation for common issues
- Integration with incident management systems
- Service level objective (SLO) monitoring

### Acceptance Criteria
- [ ] Prometheus alerting rules cover critical system conditions
- [ ] AlertManager routes alerts to appropriate channels
- [ ] Runbooks provide step-by-step incident response procedures
- [ ] SLO monitoring tracks service reliability
- [ ] Alert fatigue is minimized through proper thresholds
- [ ] Integration with PagerDuty or similar incident management
- [ ] Alert acknowledgment and escalation procedures
- [ ] Post-incident review process and documentation

### Implementation Details

#### Prometheus Alerting Rules
```yaml
# k8s/monitoring/alerting-rules.yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: redis-gateway-alerts
  namespace: redis-system
  labels:
    app: redis-gateway
spec:
  groups:
  - name: redis-gateway.rules
    interval: 30s
    rules:
    # High Error Rate Alert
    - alert: RedisGatewayHighErrorRate
      expr: |
        (
          rate(redis_gateway_requests_failed_total[5m]) / 
          rate(redis_gateway_requests_total[5m])
        ) > 0.05
      for: 2m
      labels:
        severity: critical
        service: redis-gateway
        team: platform
      annotations:
        summary: "Redis Gateway has high error rate"
        description: |
          Redis Gateway error rate is {{ $value | humanizePercentage }} which is above the 5% threshold.
          Instance: {{ $labels.instance }}
          Method: {{ $labels.method }}
          Endpoint: {{ $labels.endpoint }}
        runbook_url: "https://docs.company.com/runbooks/redis-gateway/high-error-rate"

    # High Latency Alert  
    - alert: RedisGatewayHighLatency
      expr: |
        histogram_quantile(0.95, 
          rate(redis_gateway_request_duration_seconds_bucket[5m])
        ) > 1.0
      for: 3m
      labels:
        severity: warning
        service: redis-gateway
        team: platform
      annotations:
        summary: "Redis Gateway has high request latency"
        description: |
          Redis Gateway 95th percentile latency is {{ $value }}s which is above the 1s threshold.
          Instance: {{ $labels.instance }}
        runbook_url: "https://docs.company.com/runbooks/redis-gateway/high-latency"

    # Redis Connection Issues
    - alert: RedisConnectionFailure
      expr: redis_gateway_redis_pool_active == 0
      for: 1m
      labels:
        severity: critical
        service: redis-gateway
        team: platform
      annotations:
        summary: "Redis instance has no active connections"
        description: |
          Redis instance {{ $labels.instance }} has no active connections in the pool.
          This indicates a connection failure or Redis instance being down.
        runbook_url: "https://docs.company.com/runbooks/redis-gateway/redis-connection-failure"

    # Service Down Alert
    - alert: RedisGatewayDown
      expr: up{job="redis-gateway"} == 0
      for: 1m
      labels:
        severity: critical
        service: redis-gateway
        team: platform
      annotations:
        summary: "Redis Gateway instance is down"
        description: |
          Redis Gateway instance {{ $labels.instance }} has been down for more than 1 minute.
        runbook_url: "https://docs.company.com/runbooks/redis-gateway/service-down"

    # Memory Usage Alert
    - alert: RedisGatewayHighMemoryUsage
      expr: |
        (
          process_resident_memory_bytes{job="redis-gateway"} / 
          (1024 * 1024 * 1024)
        ) > 2.0
      for: 5m
      labels:
        severity: warning
        service: redis-gateway
        team: platform
      annotations:
        summary: "Redis Gateway high memory usage"
        description: |
          Redis Gateway instance {{ $labels.instance }} is using {{ $value }}GB of memory.
        runbook_url: "https://docs.company.com/runbooks/redis-gateway/high-memory-usage"

    # Redis Pool Exhaustion
    - alert: RedisPoolExhaustion
      expr: |
        (
          redis_gateway_redis_pool_active / 
          redis_gateway_redis_pool_size
        ) > 0.9
      for: 3m
      labels:
        severity: warning
        service: redis-gateway
        team: platform
      annotations:
        summary: "Redis connection pool near exhaustion"
        description: |
          Redis connection pool for instance {{ $labels.instance }} is {{ $value | humanizePercentage }} full.
        runbook_url: "https://docs.company.com/runbooks/redis-gateway/pool-exhaustion"

    # SLO Burn Rate Alerts
    - alert: RedisGatewaySLOBurnRateHigh
      expr: |
        (
          1 - (
            rate(redis_gateway_requests_total[1h]) - 
            rate(redis_gateway_requests_failed_total[1h])
          ) / rate(redis_gateway_requests_total[1h])
        ) > (14.4 * (1 - 0.999))
      for: 2m
      labels:
        severity: critical
        service: redis-gateway
        team: platform
        slo: availability
      annotations:
        summary: "High burn rate on availability SLO"
        description: |
          The availability SLO is burning at a high rate. At this rate, the monthly SLO will be exhausted soon.
          Current error budget burn rate: {{ $value | humanizePercentage }}
        runbook_url: "https://docs.company.com/runbooks/redis-gateway/slo-burn-rate"

  - name: redis-instances.rules  
    interval: 30s
    rules:
    # Redis Instance Down
    - alert: RedisInstanceDown
      expr: |
        up{job="redis-instance"} == 0
      for: 1m
      labels:
        severity: critical
        service: redis
        team: platform
      annotations:
        summary: "Redis instance is down"
        description: |
          Redis instance {{ $labels.instance }} in namespace {{ $labels.namespace }} is down.
        runbook_url: "https://docs.company.com/runbooks/redis/instance-down"

    # Redis High Memory Usage
    - alert: RedisInstanceHighMemoryUsage
      expr: |
        redis_memory_used_bytes / redis_memory_max_bytes > 0.8
      for: 5m
      labels:
        severity: warning
        service: redis
        team: platform
      annotations:
        summary: "Redis instance memory usage high"
        description: |
          Redis instance {{ $labels.instance }} memory usage is {{ $value | humanizePercentage }}.
        runbook_url: "https://docs.company.com/runbooks/redis/high-memory-usage"
```

#### AlertManager Configuration
```yaml
# k8s/monitoring/alertmanager-config.yaml
apiVersion: v1
kind: Secret
metadata:
  name: alertmanager-config
  namespace: redis-system
type: Opaque
stringData:
  alertmanager.yml: |
    global:
      smtp_smarthost: 'smtp.company.com:587'
      smtp_from: 'alerts@company.com'
      slack_api_url: 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK'
      pagerduty_url: 'https://events.pagerduty.com/v2/enqueue'

    templates:
    - '/etc/alertmanager/templates/*.tmpl'

    route:
      group_by: ['alertname', 'cluster', 'service']
      group_wait: 10s
      group_interval: 10s
      repeat_interval: 12h
      receiver: 'default'
      routes:
      # Critical alerts go to PagerDuty immediately
      - match:
          severity: critical
        receiver: 'pagerduty-critical'
        group_wait: 0s
        group_interval: 5m
        repeat_interval: 30m
      
      # Warning alerts go to Slack
      - match:
          severity: warning
        receiver: 'slack-warnings'
        group_wait: 30s
        group_interval: 5m
        repeat_interval: 2h

      # SLO alerts have special handling
      - match:
          slo: availability
        receiver: 'slo-alerts'
        group_wait: 0s
        repeat_interval: 15m

    receivers:
    - name: 'default'
      slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK'
        channel: '#alerts'
        title: 'Alert: {{ .GroupLabels.alertname }}'
        text: |
          {{ range .Alerts }}
          *Alert:* {{ .Annotations.summary }}
          *Description:* {{ .Annotations.description }}
          *Runbook:* {{ .Annotations.runbook_url }}
          {{ end }}

    - name: 'pagerduty-critical'
      pagerduty_configs:
      - routing_key: 'YOUR_PAGERDUTY_INTEGRATION_KEY'
        description: '{{ .GroupLabels.alertname }}: {{ .Annotations.summary }}'
        details:
          firing: '{{ .Alerts.Firing | len }}'
          resolved: '{{ .Alerts.Resolved | len }}'
          runbook_url: '{{ .Annotations.runbook_url }}'

    - name: 'slack-warnings'
      slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK'
        channel: '#redis-gateway-warnings'
        title: 'Warning: {{ .GroupLabels.alertname }}'
        text: |
          {{ range .Alerts }}
          *Alert:* {{ .Annotations.summary }}
          *Description:* {{ .Annotations.description }}
          *Severity:* {{ .Labels.severity }}
          *Runbook:* {{ .Annotations.runbook_url }}
          {{ end }}
        color: 'warning'

    - name: 'slo-alerts'
      slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK'
        channel: '#slo-alerts'
        title: 'SLO Alert: {{ .GroupLabels.alertname }}'
        text: |
          {{ range .Alerts }}
          *SLO:* {{ .Labels.slo }}
          *Alert:* {{ .Annotations.summary }}
          *Description:* {{ .Annotations.description }}
          *Runbook:* {{ .Annotations.runbook_url }}
          {{ end }}
        color: 'danger'

    inhibit_rules:
    - source_match:
        severity: 'critical'
      target_match:
        severity: 'warning'
      equal: ['alertname', 'instance']
```

#### Runbook Documentation
```markdown
# Redis Gateway Runbook

## High Error Rate Alert

### Symptoms
- Error rate above 5% for more than 2 minutes
- Users experiencing failed requests
- Potential data inconsistency

### Investigation Steps
1. **Check Gateway Health**
   ```bash
   kubectl get pods -n redis-system -l app=redis-gateway
   kubectl logs -n redis-system -l app=redis-gateway --tail=100
   ```

2. **Check Redis Connectivity**
   ```bash
   # Check Redis instance status
   kubectl get redishttpinstances --all-namespaces
   
   # Check Redis pods
   kubectl get pods --all-namespaces -l app=redis
   ```

3. **Analyze Error Patterns**
   - Check Grafana dashboard for error breakdown by endpoint
   - Look for specific error codes in logs
   - Identify if errors are concentrated on specific Redis instances

### Resolution Steps
1. **If Redis instances are down:**
   ```bash
   # Restart Redis pods
   kubectl delete pod -n <tenant-namespace> -l app=redis,instance=<instance-name>
   ```

2. **If Gateway pods are failing:**
   ```bash
   # Restart Gateway pods
   kubectl rollout restart deployment/redis-gateway -n redis-system
   ```

3. **If authentication issues:**
   - Check API key validity
   - Verify JWT token expiration
   - Review authentication logs

### Escalation
- If error rate doesn't decrease within 15 minutes, escalate to senior engineer
- For production systems, consider failing over to backup region

## High Latency Alert

### Symptoms
- 95th percentile latency above 1 second
- Slow response times for users
- Potential timeout errors

### Investigation Steps
1. **Check System Resources**
   ```bash
   kubectl top pods -n redis-system
   kubectl top nodes
   ```

2. **Check Redis Performance**
   ```bash
   # Connect to Redis and check slow log
   kubectl exec -it <redis-pod> -- redis-cli
   > SLOWLOG GET 10
   ```

3. **Check Network Issues**
   - Review network policies
   - Check for DNS resolution issues
   - Verify service endpoints

### Resolution Steps
1. **Scale up if resource constrained:**
   ```bash
   kubectl scale deployment/redis-gateway -n redis-system --replicas=5
   ```

2. **Optimize Redis configuration:**
   - Increase connection pool size
   - Optimize Redis memory settings
   - Consider Redis clustering

3. **Check for inefficient queries:**
   - Review slow query logs
   - Optimize application queries
   - Implement caching where appropriate

## Redis Connection Failure

### Symptoms
- No active connections to Redis instance
- Connection timeout errors
- Redis operations failing

### Investigation Steps
1. **Check Redis Instance Status**
   ```bash
   kubectl get pods -n <tenant-namespace> -l app=redis
   kubectl describe pod <redis-pod>
   ```

2. **Check Network Connectivity**
   ```bash
   # Test connectivity from gateway pod
   kubectl exec -it <gateway-pod> -- nc -zv <redis-service> 6379
   ```

3. **Review Redis Logs**
   ```bash
   kubectl logs <redis-pod> --tail=100
   ```

### Resolution Steps
1. **Restart Redis instance:**
   ```bash
   kubectl delete pod <redis-pod>
   ```

2. **Check persistent volume:**
   ```bash
   kubectl get pvc -n <tenant-namespace>
   kubectl describe pvc <redis-pvc>
   ```

3. **Verify network policies:**
   ```bash
   kubectl get networkpolicy -n <tenant-namespace>
   ```

## Service Level Objective Monitoring

### SLO Definitions
- **Availability SLO**: 99.9% uptime (43.2 minutes downtime per month)
- **Latency SLO**: 95% of requests < 500ms
- **Error Rate SLO**: < 0.1% error rate

### Error Budget Calculation
```
Error Budget = (1 - SLO) × Total Requests
Burn Rate = Actual Errors / Error Budget
```

### SLO Alert Response
1. **Immediate Actions:**
   - Acknowledge alert within 5 minutes
   - Assess current system state
   - Determine if incident response is needed

2. **Investigation:**
   - Check error budget consumption rate
   - Identify root cause of SLO violation
   - Implement immediate fixes if available

3. **Long-term Actions:**
   - Review and adjust SLO targets if needed
   - Implement preventive measures
   - Update runbooks based on learnings
```

#### SLO Monitoring Dashboard
```rust
// src/slo/mod.rs
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Duration, Utc};

#[derive(Debug, Serialize, Deserialize)]
pub struct SLOConfig {
    pub availability_target: f64, // e.g., 0.999 for 99.9%
    pub latency_target_ms: u64,   // e.g., 500 for 500ms
    pub error_rate_target: f64,   // e.g., 0.001 for 0.1%
    pub measurement_window: Duration,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SLOStatus {
    pub slo_name: String,
    pub current_value: f64,
    pub target_value: f64,
    pub error_budget_remaining: f64,
    pub burn_rate: f64,
    pub status: SLOHealth,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SLOHealth {
    Healthy,
    Warning,
    Critical,
    Exhausted,
}

pub struct SLOMonitor {
    config: SLOConfig,
    metrics_client: PrometheusClient,
}

impl SLOMonitor {
    pub async fn calculate_availability_slo(&self) -> SLOStatus {
        let total_requests = self.get_total_requests().await;
        let failed_requests = self.get_failed_requests().await;
        
        let current_availability = if total_requests > 0 {
            (total_requests - failed_requests) as f64 / total_requests as f64
        } else {
            1.0
        };

        let error_budget_total = (1.0 - self.config.availability_target) * total_requests as f64;
        let error_budget_consumed = failed_requests as f64;
        let error_budget_remaining = (error_budget_total - error_budget_consumed) / error_budget_total;
        
        let burn_rate = if error_budget_total > 0.0 {
            error_budget_consumed / error_budget_total
        } else {
            0.0
        };

        let status = match error_budget_remaining {
            r if r > 0.5 => SLOHealth::Healthy,
            r if r > 0.1 => SLOHealth::Warning,
            r if r > 0.0 => SLOHealth::Critical,
            _ => SLOHealth::Exhausted,
        };

        SLOStatus {
            slo_name: "availability".to_string(),
            current_value: current_availability,
            target_value: self.config.availability_target,
            error_budget_remaining,
            burn_rate,
            status,
            last_updated: Utc::now(),
        }
    }

    async fn get_total_requests(&self) -> u64 {
        // Query Prometheus for total requests in the measurement window
        // Implementation would use actual Prometheus client
        0
    }

    async fn get_failed_requests(&self) -> u64 {
        // Query Prometheus for failed requests in the measurement window
        // Implementation would use actual Prometheus client
        0
    }
}
```

### Definition of Done
- Alert rules cover all critical system conditions
- AlertManager properly routes alerts to correct channels
- Runbooks provide clear step-by-step procedures
- SLO monitoring tracks service reliability
- Alert fatigue is minimized through proper configuration
- Incident response procedures are documented and tested
- Integration with external incident management works
- Post-incident review process is established

### Dependencies
- Issue #16 (Observability and Monitoring Stack)
- Issue #8 (HTTP Gateway Core)

### Additional Context
- Consider implementing alert clustering to reduce noise
- Plan for alert testing and validation procedures
- Implement escalation policies for different severity levels
- Consider integrating with ChatOps for collaborative incident response
- Plan for automated incident response where appropriate