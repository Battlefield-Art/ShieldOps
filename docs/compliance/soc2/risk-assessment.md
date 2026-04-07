# Risk Assessment

ShieldOps' formal risk assessment, refreshed quarterly. Maps assets and
threats to mitigation status. Used as primary input for the SOC 2 audit
risk-management criteria (CC3.1–CC3.4).

## Asset inventory

| Asset class | Examples | Confidentiality | Integrity | Availability |
|---|---|---|---|---|
| Customer Data | Ingested security events, OCSF records | High | High | High |
| Authentication credentials | Password hashes, API keys (hashed), JWT secrets | High | High | High |
| Source code | Private repo, build artifacts | High | High | Medium |
| Customer PII | Email, name, billing | High | High | Medium |
| Service configuration | Helm values, Terraform state, OPA policies | High | High | High |
| Operational telemetry | Metrics, traces, logs | Medium | Medium | Medium |
| Public marketing content | Website, blog | Low | Medium | Medium |

## Threat catalog

### External attacker
| Threat | Likelihood | Impact | Risk | Mitigation |
|---|---|---|---|---|
| Credential stuffing | High | High | Critical | MFA required, rate limit on login (`token_bucket` middleware), CAPTCHAs |
| API key theft | Medium | High | High | Hashed at rest, rotation procedure, scope limits |
| Cross-tenant data leak via API bug | Low | Critical | High | Tenant isolation tests in CI; pentest annually; bug bounty |
| SQL injection | Low | Critical | High | ORM-only queries; SQL allowlist in NL query agent |
| RCE via dependency | Low | Critical | High | Dependabot; weekly scans; minimal dependencies |
| DDoS | High | Medium | High | AWS Shield Standard; WAF; rate limiting at ALB + middleware |
| Phishing of customers | Medium | High | High | Customer education; clear branding; SPF/DKIM/DMARC |
| Supply chain attack (PyPI) | Low | Critical | High | Dependency pinning; lock files; SBOM; signed releases |
| LLM prompt injection | Medium | High | High | Output sanitization; sandboxed exec; agent firewall enforce mode |

### Insider
| Threat | Likelihood | Impact | Risk | Mitigation |
|---|---|---|---|---|
| Disgruntled engineer exfiltrates code | Low | High | Medium | Pre-employment background check; offboarding revocation; audit log |
| Accidental misuse of admin access | Medium | High | High | Least privilege; 4-eye principle on prod changes; audit log |
| Compromised laptop | Medium | Medium | Medium | FDE required; MDM-managed; auto-lock; anti-malware |
| Lost MFA device | Medium | Low | Low | Backup codes; identity verification before re-issue |

### Vendor / supply chain
| Threat | Likelihood | Impact | Risk | Mitigation |
|---|---|---|---|---|
| AWS region outage | Low | High | Medium | Multi-AZ; documented RPO/RTO; quarterly DR drill |
| Stripe downtime | Low | Low | Low | Account creation works without billing; queue-and-retry |
| Anthropic API outage | Medium | Medium | Medium | LLM router with fallback (OpenAI, heuristic); cache |
| GitHub outage | Medium | Low | Low | Local builds work; CI delayed but recoverable |
| Sub-processor breach | Low | High | Medium | Vendor risk review annually; DPA; breach notification |

### Operational / process
| Threat | Likelihood | Impact | Risk | Mitigation |
|---|---|---|---|---|
| Bad deploy → outage | Medium | Medium | Medium | Staging gate; canary; rollback runbook |
| Database migration failure | Low | High | Medium | Tested in staging; reversible migrations; backup-restore tests |
| Secrets in source control | Low | High | Medium | Pre-commit hook (`detect-private-key`); GitHub secret scanning |
| Misconfiguration of WAF | Low | Medium | Low | Terraform-managed; CI validates; manual review |
| Drift in OPA policies | Low | Medium | Low | Policy versioning; CI compares against baseline |

## Risk scoring

We use a 5×5 likelihood × impact matrix:

|  | Negligible | Low | Medium | High | Critical |
|---|---|---|---|---|---|
| **Very Likely** | Low | Medium | High | Critical | Critical |
| **Likely** | Low | Medium | High | High | Critical |
| **Possible** | Low | Low | Medium | High | High |
| **Unlikely** | Low | Low | Low | Medium | High |
| **Rare** | Negligible | Low | Low | Medium | Medium |

## Top 5 risks (Q2 2026)

1. **Cross-tenant data leak via API bug** — mitigated by automated tenant
   isolation tests + annual pentest
2. **LLM prompt injection through agent tool inputs** — mitigated by
   agent firewall in enforce mode + output sanitization
3. **Credential stuffing attacks** — mitigated by MFA + rate limit
4. **Supply chain attack via Python dependency** — mitigated by
   Dependabot + lock files + SBOM
5. **Bad deploy causing customer-facing outage** — mitigated by staging
   gate + canary + rollback runbook (tested quarterly)

## Risk acceptance

Risks accepted by leadership without further mitigation:
- Theoretical attacks against AWS data center physical security
- Legal seizure of US-hosted data (mitigated by EU-region option for
  Enterprise customers)
- Social engineering that bypasses MFA (mitigated by ongoing training,
  but no perfect technical control)

## Review cadence

- **Quarterly:** full risk register review, top-5 priority list
- **Annually:** complete reassessment with external advisor
- **Trigger-based:** after any incident, vendor change, or major feature

## Owners

- **Risk register owner:** Head of Security
- **Reviewer:** CTO + outside advisor
- **Last review:** 2026-04-06
- **Next review:** 2026-07-06
