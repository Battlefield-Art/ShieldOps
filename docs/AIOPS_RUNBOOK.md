# ShieldOps AI Security — Operational Runbook

This runbook covers day-to-day monitoring, alerting, and troubleshooting
for the AI Security Control Plane in production.

## 1. Agent Firewall Operations

### Key Metrics to Monitor

| Metric | Normal Range | Warning | Critical |
|--------|-------------|---------|----------|
| Calls intercepted/sec | 50-500 | >1000 | >5000 |
| Block rate | <5% | 5-15% | >15% |
| Anomaly rate | <2% | 2-10% | >10% |
| Circuit breakers open | 0 | 1 | >2 |
| p95 latency | <50ms | 50-100ms | >100ms |

### Grafana Dashboard

- Overview: `/grafana/d/shieldops-ai-security`
- Detail: `/grafana/d/agent-firewall-detail`

### Alert Response: High Block Rate

1. Check `/app/agent-firewall` -> Anomalies tab
2. Identify which agents are being blocked
3. Determine if blocks are true positives or false positives
4. If false positives: adjust firewall policies or baselines
5. If true positives: investigate agent compromise, consider kill switch

### Alert Response: Circuit Breaker Tripped

1. Check which agent tripped: `shieldops firewall status`
2. Review anomaly history for the agent
3. If legitimate: reset circuit breaker via dashboard or CLI
4. If compromise: keep open, revoke credentials, investigate

### Emergency: Kill Switch Activation

1. Confirm the kill switch was intentional (check audit log)
2. Verify all tokens/sessions revoked
3. Notify dependent services
4. Investigate root cause
5. Recovery: `shieldops firewall reset --agent-id <id>`

## 2. NHI Registry Operations

### Key Metrics

| Metric | Normal | Warning | Critical |
|--------|--------|---------|----------|
| Total NHIs | Baseline +/-10% | +/-20% | +/-50% |
| Orphaned | <5% | 5-15% | >15% |
| Shadow AI detected | 0 | 1-3 | >3 |
| Over-privileged | <10% | 10-25% | >25% |

### Scan Schedule

- Default: every 6 hours
- Override: `shieldops nhi scan --provider aws`

### Alert Response: Shadow AI Detected

1. Check `/app/nhi-registry` -> Shadow AI section
2. Identify calling service and API provider
3. Contact service owner to register or block
4. If unauthorized: block at network level, create incident

### Alert Response: Orphaned Identities

1. Review orphaned NHIs in dashboard
2. Determine if owner left the org or service decommissioned
3. Revoke credentials for confirmed orphans
4. Update CMDB/ownership records

## 3. MCP Security Operations

### Key Metrics

| Metric | Normal | Warning | Critical |
|--------|--------|---------|----------|
| God Key risks | 0 | 1-2 | >2 |
| Zero-trust compliance | >90% | 70-90% | <70% |
| Supply chain vulns | 0 critical | 1 critical | >1 critical |
| Gateway latency p95 | <20ms | 20-50ms | >50ms |

### Alert Response: God Key Detected

1. Check `/app/mcp-security` -> God Keys tab
2. Identify the MCP server and its downstream resources
3. Scope down permissions immediately
4. Split server into multiple scoped servers if needed

### Alert Response: Supply Chain Vulnerability

1. Review CVE details in Supply Chain tab
2. Check if fix is available
3. If critical: quarantine component, apply patch
4. If no fix: mitigate with gateway policy (block affected tool calls)

## 4. SOC Brain Operations

### Key Metrics

| Metric | Target | Warning | Critical |
|--------|--------|---------|----------|
| MTTD | <5 min | 5-15 min | >15 min |
| MTTA | <2 min | 2-10 min | >10 min |
| MTTR | <30 min | 30-60 min | >60 min |
| Auto-resolved % | >60% | 40-60% | <40% |
| Situations pending | <20 | 20-50 | >50 |

### Alert Response: High MTTR

1. Review situation queue for bottlenecks
2. Check if approvals are timing out (increase timeout or adjust thresholds)
3. Check vendor connector health (CrowdStrike, Defender, Wiz)
4. Consider lowering auto-execute threshold temporarily

### Alert Response: Situation Storm

1. Check for common source (single vendor flooding)
2. Enable deduplication if not active
3. Increase correlation window
4. Consider rate-limiting vendor webhook intake

## 5. Vendor Connector Health

### CrowdStrike Falcon

- Health check: `GET /agent-firewall/health`
- Common issues: OAuth token expiry (auto-refreshes, check logs)
- Escalation: CrowdStrike support portal

### Microsoft Defender

- Health check: `GET /situations/health`
- Common issues: Azure AD token refresh, KQL query timeout
- Escalation: Microsoft security support

### Wiz

- Health check: `GET /mcp-security/health`
- Common issues: GraphQL rate limiting, API token rotation
- Escalation: Wiz support

## 6. Escalation Matrix

| Severity | Response Time | Escalation |
|----------|--------------|------------|
| P1 (Critical) | 15 min | On-call -> Eng Manager -> CTO |
| P2 (High) | 1 hour | On-call -> Eng Manager |
| P3 (Medium) | 4 hours | On-call |
| P4 (Low) | Next business day | Ticket |

## 7. Common Troubleshooting

### Firewall Not Intercepting Calls

- Check SDK callback is registered
- Verify API endpoint connectivity
- Check Redis cache (may be serving stale decisions)
- Verify mode is "audit" or "enforce" (not "disabled")

### NHI Scan Returns Empty

- Check cloud provider credentials
- Verify IAM permissions for scanning
- Check network connectivity to cloud APIs
- Review scan logs: `shieldops nhi scan --verbose`

### MCP Gateway 502 Errors

- Check MCP server is running
- Verify gateway proxy is healthy
- Check network policy allows traffic
- Review gateway logs for upstream errors

### SOC Brain Not Creating Situations

- Check Kafka consumer is running
- Verify webhook events are being received
- Check correlation rules are configured
- Review SOC Brain agent logs

## 8. Maintenance Procedures

### Rotating Vendor API Keys

1. Generate new key in vendor portal
2. Update Kubernetes secret: `kubectl edit secret shieldops-vendor-keys`
3. Restart affected pods: `kubectl rollout restart deployment/shieldops-api`
4. Verify health endpoints return 200

### Updating Firewall Baselines

1. Export current baselines: `shieldops firewall baselines export`
2. Review agent behavior over the past 7 days
3. Update baselines: `shieldops firewall baselines update --lookback 7d`
4. Verify no false positives in the next 24 hours

### Database Maintenance

- Agent firewall events are retained for 90 days by default
- NHI scan history is retained for 180 days
- Situation records are retained for 1 year
- Run cleanup: `shieldops maintenance cleanup --dry-run` then without `--dry-run`

## 9. Disaster Recovery

### Agent Firewall Down

1. Agents fall back to local policy cache (30-min TTL)
2. Restore API: check database connectivity, restart pods
3. If extended outage: switch to "audit-only" mode to avoid blocking legitimate traffic

### NHI Registry Unavailable

1. Scans will queue and retry automatically
2. Shadow AI detection pauses (alerts will note gap)
3. Restore: check cloud provider API connectivity, restart scan workers

### SOC Brain Backlog

1. If Kafka consumer lag exceeds 10,000 messages, scale consumer group
2. If correlation engine is slow, increase memory allocation
3. If vendor webhooks are backing up, enable overflow queue

## 10. Runbook Change Log

| Date | Change | Author |
|------|--------|--------|
| 2026-03-25 | Initial runbook created | ShieldOps SRE |
