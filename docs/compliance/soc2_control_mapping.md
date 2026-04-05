# SOC 2 Type I Control Mapping — ShieldOps

## Trust Service Criteria → ShieldOps Controls

### CC1: Control Environment
| Control | ShieldOps Implementation | Evidence Source |
|---------|------------------------|-----------------|
| CC1.1 | OPA policy engine enforces governance on all agent actions | `playbooks/policies/shieldops.rego` |
| CC1.2 | Role-based access control (ADMIN/ANALYST/VIEWER) | `api/auth/dependencies.py` |
| CC1.3 | Agent fitness tracking + automatic promotion/demotion | `utils/fitness_tracker.py` |

### CC2: Communication and Information
| Control | ShieldOps Implementation | Evidence Source |
|---------|------------------------|-----------------|
| CC2.1 | Structured audit logging for all API requests | `api/middleware/compliance.py` |
| CC2.2 | Agent execution audit trail (immutable AuditLog table) | `db/models.py:AuditLog` |

### CC3: Risk Assessment
| Control | ShieldOps Implementation | Evidence Source |
|---------|------------------------|-----------------|
| CC3.1 | Agent risk scoring (0-1.0 scale) on all actions | `agents/policy_gate.py` |
| CC3.2 | Blast-radius limits per environment (dev:10, staging:5, prod:3) | `agents/remediation/tools.py` |
| CC3.3 | Vulnerability EPSS scoring and prioritization | `agents/vulnerability_manager/tools.py` |

### CC5: Control Activities
| Control | ShieldOps Implementation | Evidence Source |
|---------|------------------------|-----------------|
| CC5.1 | OPA deny list: delete_database, drop_table, modify_iam_root | `playbooks/policies/actions.rego` |
| CC5.2 | Approval workflow: auto >0.85, human 0.5-0.85, escalate <0.5 | `agents/remediation/tools.py` |
| CC5.3 | Rate limiting per user/role/IP | `api/middleware/rate_limiter.py` |

### CC6: Logical and Physical Access
| Control | ShieldOps Implementation | Evidence Source |
|---------|------------------------|-----------------|
| CC6.1 | JWT + API key authentication on all endpoints | `api/auth/` |
| CC6.2 | OIDC/SSO integration for enterprise | `api/auth/oidc.py` |
| CC6.3 | Tenant isolation via org_id middleware | `api/middleware/tenant.py` |
| CC6.4 | NHI identity governance and risk scoring | `agents/identity_graph/tools.py` |
| CC6.5 | Agent Firewall SDK blocks unauthorized tool calls | `sdk/interceptor.py` |

### CC7: System Operations
| Control | ShieldOps Implementation | Evidence Source |
|---------|------------------------|-----------------|
| CC7.1 | Health checks on all services (/health, /ready) | `api/routes/health*.py` |
| CC7.2 | Prometheus + Grafana monitoring with 6 dashboards | `infrastructure/monitoring/` |
| CC7.3 | Graceful shutdown middleware | `api/middleware/shutdown.py` |
| CC7.4 | Incident response automation via IR agent | `agents/incident_response/tools.py` |
| CC7.5 | PagerDuty + Slack alerting integration | `connectors/pagerduty/`, Slack webhook |

### CC8: Change Management
| Control | ShieldOps Implementation | Evidence Source |
|---------|------------------------|-----------------|
| CC8.1 | CI/CD with 7 GitHub Actions workflows | `.github/workflows/` |
| CC8.2 | Alembic database migrations (18 versioned) | `db/migrations/` |
| CC8.3 | GitOps sync for Kubernetes deployments | `.github/workflows/gitops-sync.yml` |

### CC9: Risk Mitigation
| Control | ShieldOps Implementation | Evidence Source |
|---------|------------------------|-----------------|
| CC9.1 | Compliance auditor agent checks HIPAA/SOC2/PCI controls | `agents/compliance_auditor/tools.py` |
| CC9.2 | Evidence generation for audit trails | Compliance middleware + AuditLog |

## Data Protection Controls

| Control | Implementation | Evidence |
|---------|---------------|----------|
| Encryption at rest | RDS encrypted (AES-256), S3 SSE | Terraform config |
| Encryption in transit | TLS 1.3 via ALB + ACM | Infrastructure |
| PII detection + redaction | Compliance middleware scans responses | `api/middleware/compliance.py` |
| Data retention policies | Configurable per tier (30/90/365 days) | `ingest/storage.py` |
| Backup strategy | RDS automated snapshots + PITR | Terraform config |

## Audit Evidence Collection

Evidence is automatically collected from:
1. **AuditLog table** — immutable, append-only log of all agent actions
2. **Compliance middleware** — logs every API request with PII scan results
3. **OPA policy evaluations** — logged with agent, action, result, reasons
4. **Agent fitness data** — tracks accuracy, safety, cost over time
5. **Prometheus metrics** — request rates, error rates, latency percentiles
