# Access Control Policy

**Document ID:** SHIELDOPS-POL-AC-001
**Version:** 1.2
**Owner:** Head of Security (interim: CTO)
**Approved By:** CEO
**Effective Date:** 2026-01-15
**Last Reviewed:** 2026-04-01
**Next Review:** 2026-10-01
**Applies To:** All ShieldOps employees, contractors, and service accounts with access to production, staging, or corporate systems.

## 1. Purpose

This policy defines how ShieldOps grants, manages, monitors, and revokes access to information systems and data. It supports SOC 2 Trust Service Criteria **CC6.1, CC6.2, CC6.3, CC6.6, CC6.7** and is a prerequisite for all other security controls in this policy set.

## 2. Scope

In scope:

- Production ShieldOps SaaS environment (AWS accounts, Kubernetes clusters, PostgreSQL, Redis, Kafka).
- Staging and development environments.
- Source code (GitHub organization `shieldops`).
- Internal tooling: Notion, Linear, Slack, 1Password, Google Workspace, Vanta.
- Customer-facing dashboard, API, and CLI.
- Service accounts, machine identities, and CI/CD credentials.

Out of scope: personal devices used exclusively for non-work activity.

## 3. Principles

1. **Least privilege.** Every principal (human or machine) receives the minimum access required to perform their role.
2. **Segregation of duties.** No single individual can author, approve, and deploy a production change without a second reviewer.
3. **Default deny.** Access is explicitly granted; no implicit or inherited permissions across environments.
4. **Just-in-time elevation.** Production write access is time-boxed and requires a ticket reference.
5. **Auditability.** Every access grant, use, and revocation is logged to the immutable audit log.

## 4. Role-Based Access Control (RBAC)

ShieldOps enforces RBAC through three canonical platform roles, defined in `src/shieldops/auth/rbac.py` and mapped into OPA policy at `policies/opa/rbac.rego`.

| Role      | Description                               | Representative Permissions                                                                     |
|-----------|-------------------------------------------|------------------------------------------------------------------------------------------------|
| `admin`    | Full platform administration             | Manage users, rotate keys, configure tenants, view audit log, execute high-risk agent actions |
| `operator` | Day-to-day SOC operator                  | Run agents, approve/deny remediations, acknowledge alerts, view dashboards                     |
| `viewer`   | Read-only stakeholder (auditor, exec)    | View dashboards, read reports, export non-sensitive data                                       |

Role assignment is stored on the `users.role` column (see `src/shieldops/db/models.py:UserRecord`). Role changes are recorded in the `audit_log` table as `action="role_change"`.

Custom roles and scoped API keys are supported through the `api_keys.scopes` column (see `src/shieldops/db/models.py:APIKeyRecord`). Scope definitions live in `src/shieldops/auth/scopes.py`.

## 5. Authentication

### 5.1 Human authentication

- **Primary factor:** Email + password, or SSO via OIDC (Google Workspace is the IdP of record).
- **Second factor:** TOTP (RFC 6238) or WebAuthn. MFA is **mandatory** for all employees and contractors. Enforcement is checked in `src/shieldops/api/middleware/mfa_enforce.py`.
- **Session tokens:** JWT (HS256) with 1-hour access token TTL and 14-day refresh token TTL. Refresh tokens are rotated on use.
- **Passwords:** Minimum 14 characters, must pass zxcvbn strength score >=3, hashed with Argon2id (memory=64MB, iterations=3, parallelism=4). No reuse of last 10 passwords.
- **Account lockout:** 10 failed attempts within 15 minutes triggers a 30-minute lockout. After 3 consecutive lockouts, the account is disabled pending security review.

### 5.2 Machine authentication

- **API keys:** Prefixed (`sk_live_`, `sk_test_`), 32 bytes of CSPRNG entropy, stored as SHA-256 hash in `api_keys.key_hash`. Keys are displayed exactly once at creation.
- **Service-to-service:** Mutual TLS inside the cluster, OIDC federation for cloud connectors (no long-lived cloud credentials in production).
- **Expiry:** API keys default to 90 days; maximum 365 days. See `procedures/secrets-rotation.md`.

### 5.3 Single Sign-On (SSO)

Enterprise customers may federate via OIDC or SAML 2.0. Configuration is per-tenant (`organizations.settings.sso`). SSO-enforced tenants disable password login entirely.

## 6. Authorization

All authenticated requests pass through:

1. **Tenant isolation middleware** (`src/shieldops/api/middleware/tenant_isolation.py`) — rewrites the SQL filter to `org_id = :current_org`.
2. **RBAC enforcement** on the route decorator (`@require_role("operator")`).
3. **OPA policy evaluation** for agent actions, using the JSON input documented in `docs/policy/opa-inputs.md`.

Agent actions additionally apply **confidence gating**:

| Confidence | Behavior                                              |
|-----------:|-------------------------------------------------------|
| >= 0.85    | Autonomous execution permitted                        |
| 0.50–0.85  | Human approval required (operator or admin)          |
| < 0.50     | Escalated; no execution                              |

## 7. Access Provisioning and Revocation

- **Provisioning:** Triggered by a Linear ticket on employee start or role change. Required fields: employee name, role, manager approval, systems requested, business justification. See `procedures/employee-onboarding.md`.
- **Revocation:** Access must be fully removed within **4 business hours** of termination for standard separations and within **1 hour** for involuntary separations. See `procedures/employee-offboarding.md`.
- **Access reviews:** Conducted quarterly by the Head of Security. Evidence produced by `scripts/audit/collect_evidence.py`. See `procedures/access-review.md`.

## 8. Privileged Access

- Production shell access is limited to on-call engineers and is brokered through AWS SSM Session Manager. No long-lived SSH keys exist in production.
- Database superuser access is limited to two named individuals plus the break-glass account stored in 1Password (shared vault: `prod-break-glass`).
- All privileged sessions are recorded and retained for 1 year. Recordings are stored in the `shieldops-audit-recordings` S3 bucket with object lock enabled.

## 9. Monitoring and Logging

Every authentication attempt, authorization decision, and access grant is logged:

- **Auth events** → `audit_log` table (see `db/models.py:AuditLog`) and emitted to the SIEM via the OTel pipeline.
- **Failed auth alerts** → Paged to on-call when: >50 failed logins per minute globally, >10 per account per hour, or any successful login from a new country for an admin account.

See `policies/incident-response.md` for handling of identified access anomalies.

## 10. Exceptions

Exceptions require written approval from the Head of Security and are recorded in `docs/compliance/soc2/exceptions.md`. Exceptions are time-boxed (maximum 90 days) and reviewed at every quarterly access review.

## 11. Enforcement

Violations of this policy may result in disciplinary action up to and including termination, and — for intentional or negligent acts — civil or criminal liability. See `policies/acceptable-use.md`.

## 12. References

- `policies/encryption.md` — protection of credentials at rest and in transit.
- `policies/incident-response.md` — response to access incidents.
- `procedures/access-review.md` — quarterly review procedure.
- `procedures/secrets-rotation.md` — credential lifecycle.
- SOC 2 TSC: CC6.1, CC6.2, CC6.3, CC6.6, CC6.7.
