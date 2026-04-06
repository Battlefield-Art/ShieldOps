# Procedure: Secrets Rotation

**Document ID:** SHIELDOPS-PROC-EN-001
**Version:** 1.1
**Owner:** Head of Security (interim: CTO)
**Related Policy:** `policies/encryption.md`, `policies/access-control.md`
**Last Reviewed:** 2026-04-01

## 1. Purpose

Define how cryptographic keys, API credentials, and other secrets are rotated at ShieldOps — both routinely and in emergencies.

## 2. Inventory

All production secrets are inventoried in AWS Secrets Manager (primary) and listed in `docs/compliance/soc2/key-inventory.yaml`. Each entry records: name, purpose, owner, rotation cadence, last rotation date, next rotation due date.

## 3. Routine Rotation Schedule

| Secret                                         | Cadence     | Owner                 | Mechanism                                  |
|------------------------------------------------|:-----------:|-----------------------|--------------------------------------------|
| JWT signing key                                | Quarterly   | Head of Security      | `scripts/rotation/rotate_jwt_key.py`       |
| Database master credentials                    | Quarterly   | Head of Engineering   | Secrets Manager automatic rotation         |
| Service account credentials (internal)        | 90 days     | Service owner         | `scripts/rotation/rotate_service_account.py` |
| Customer-facing API keys                       | Max 365 d   | Customer (self-serve) | Dashboard or API                           |
| Third-party vendor API keys (Stripe, etc.)     | Annual      | Vendor owner          | Vendor-specific procedure + `scripts/rotation/` |
| TLS certificates                               | Automatic   | Platform              | ACME / ACM                                  |
| KMS customer-managed keys                      | Annual      | Head of Security      | KMS key rotation feature                    |
| 1Password break-glass vault items              | Quarterly   | Head of Security      | Manual, dual-approver                       |
| GitHub Actions OIDC trust relationship         | Annual      | Head of Engineering   | Terraform apply                             |

Next-rotation dates are tracked by Vanta; alerts fire 14 days before due date to `#security`.

## 4. Rotation Workflow (Standard)

Use this workflow for anything without automatic rotation.

1. **Plan.** Open a Linear ticket `rotate-<secret>-<YYYYMMDD>`. Identify dependencies: which services, which configs, which customers.
2. **Generate.** Produce the new secret using a CSPRNG. Store it in AWS Secrets Manager alongside the old one (so both are valid simultaneously during the transition).
3. **Deploy.** Update services to read the new secret. For keys with a `kid` header (JWT), deploy the new key as an additional verifier first.
4. **Cut over.** Make the new secret the active one. For JWT, promote the new `kid` to signer.
5. **Verify.** Confirm all services are using the new secret. Watch error rates for 30 minutes.
6. **Revoke.** Disable the old secret. For JWT, remove the old `kid` from the verifier set after the refresh-token TTL has expired (14 days).
7. **Audit.** Write an entry in `audit_log` (`action="secret_rotated"`, `target_resource=<secret name>`). Close the Linear ticket.

Two people are required: an implementer and an approver. Segregation-of-duties enforced by the Secrets Manager resource policy (rotation requires two IAM principals to approve).

## 5. Emergency Rotation

Triggered when there is any evidence or reasonable suspicion of compromise:

- Accidentally committed to git, pasted to a log, posted to Slack, emailed externally.
- Included in a vendor breach disclosure.
- Found in a leaked credentials feed.
- Held by a departing employee where automated revocation is not feasible.

### 5.1 Decision

- Any engineer can trigger an emergency rotation. **No approval required to start.** The default is to rotate; think later.
- The Head of Security is notified immediately.

### 5.2 Execution

1. Treat as a security incident. Declare via `/incident` with `sev2` unless customer data is at confirmed risk, in which case `sev1`.
2. Follow the standard workflow, compressed: the dual-key overlap window may be shortened to minutes rather than hours if necessary, accepting a brief disruption window.
3. Revoke the old secret as fast as possible. For JWT: invalidate all sessions.
4. Page the Communications Lead if customer impact is expected.
5. After rotation, perform a forensic search for usage of the old secret before and after the suspected compromise.

### 5.3 Post-rotation

- Write a post-mortem covering root cause, detection, response, and prevention.
- If the compromise was via a recurring pattern (e.g., commit hook missed it), file an improvement ticket.
- Update this procedure if gaps were found.

## 6. Customer API Key Rotation (Self-Serve)

Customers rotate their own API keys via the dashboard or API:

- Endpoint: `POST /api/v1/keys/{id}/rotate`.
- New key is returned once; old key remains valid for 24 hours (configurable 1h–30d).
- Rotation is logged in `audit_log` for the customer's tenant.

## 7. Secrets in Source Control

Secrets must never be in source control. Enforcement:

- Pre-commit hook: `detect-secrets`.
- CI scanner: Gitleaks on every PR.
- GitHub secret scanning: enabled org-wide with push protection.
- If a secret is committed: treat as emergency rotation, even if the commit was reverted. Git history is forever.

## 8. Break-Glass Secrets

Production break-glass credentials live in the 1Password shared vault `prod-break-glass`. Accessing any item:

- Requires two concurrent approvers (1Password permission).
- Triggers an automated notification to `#security`.
- Triggers a rotation of that item within 24 hours, regardless of whether the use was benign.

## 9. Evidence Collected

- Secrets Manager rotation history (API).
- `audit_log` entries (`action="secret_rotated"`).
- Linear rotation tickets with dual-approver signatures.
- Break-glass vault access log.
- `scripts/audit/collect_evidence.py --section secrets_rotation` aggregates these for SOC 2.
