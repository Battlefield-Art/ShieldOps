# Data Classification and Handling Policy

**Document ID:** SHIELDOPS-POL-DC-001
**Version:** 1.1
**Owner:** Head of Security (interim: CTO)
**Approved By:** CEO
**Effective Date:** 2026-01-15
**Last Reviewed:** 2026-04-01
**Next Review:** 2026-10-01

## 1. Purpose

This policy establishes how ShieldOps classifies, labels, stores, transmits, and disposes of data. It supports SOC 2 criteria **CC6.1, CC6.5, C1.1, C1.2** (Confidentiality) and **P1–P8** (Privacy, where applicable).

## 2. Classification Tiers

ShieldOps uses four classification tiers. Every data asset, table, S3 bucket, and Kafka topic must carry exactly one label.

### 2.1 Public

- **Definition:** Information intentionally released for external consumption.
- **Examples:** Marketing pages, open-source code in `oss/`, public blog posts, published documentation on `docs.shieldops.io`.
- **Handling:** No restrictions on copying or sharing. Must still pass brand review before publication.

### 2.2 Internal

- **Definition:** Information whose disclosure would cause minor operational inconvenience but not harm.
- **Examples:** Internal runbooks, team-only wiki pages, aggregated product metrics, engineering design docs without customer data.
- **Handling:** Restricted to employees and contractors under NDA. Storage in Notion, Google Workspace, or the private GitHub organization is acceptable. Do not share externally without approval.

### 2.3 Confidential

- **Definition:** Information whose disclosure could cause meaningful harm to ShieldOps or a customer.
- **Examples:** Customer tenant configuration, source code, architecture diagrams identifying production components, financial forecasts, security findings, non-published incident reports, vendor agreements.
- **Handling:**
  - Encrypted at rest (AES-256) and in transit (TLS 1.3). See `policies/encryption.md`.
  - Access restricted by role (`operator` or `admin`).
  - Must not be copied to personal devices or personal accounts.
  - Sharing with third parties requires an executed NDA.

### 2.4 Restricted

- **Definition:** The highest-sensitivity data. Disclosure could cause severe harm, legal liability, or regulatory action.
- **Examples:**
  - Customer telemetry containing PII (names, emails, IP addresses from customer environments).
  - Credentials (API keys, cloud credentials ingested from customer connectors).
  - Session tokens, password hashes, MFA secrets.
  - Private keys, certificates, signing keys.
  - Audit log contents.
  - Payment card data (ShieldOps does **not** store PAN; Stripe is the PCI vault of record, but Stripe webhook payloads fall here).
- **Handling:**
  - Encrypted at rest with envelope encryption and customer-managed keys where contractually required.
  - Field-level encryption for sensitive columns (see `src/shieldops/compliance/field_encryption.py`).
  - Access logged to `audit_log` on every read (not just write).
  - Never written to application logs or error messages. `structlog` redaction rules enforce this — see `src/shieldops/utils/logging.py`.
  - Never leaves the production VPC without explicit security review.

## 3. Labeling

- **Database columns** containing Confidential or Restricted data carry a `sensitivity` comment. Alembic migrations must set it. Example: `Column("email", String, comment="sensitivity=restricted, pii=true")`.
- **S3 buckets** carry the tag `shieldops:classification = {public|internal|confidential|restricted}`.
- **Kafka topics** prefix: `pub.`, `int.`, `conf.`, `rest.`.
- **Documents** in Google Workspace use the classification dropdown in the document header template.

## 4. Personally Identifiable Information (PII)

PII is any data that identifies or can be used to identify a natural person. ShieldOps processes PII on behalf of customers (data processor role under GDPR Art. 28).

Categories handled:

- Direct identifiers: name, email, phone, employee ID (from customer identity graph).
- Indirect identifiers: IP address, device fingerprint, session ID.
- Special category: none intentionally collected. If encountered (e.g., via SIEM log ingest), it is classified Restricted.

PII detection is automated via `src/shieldops/compliance/pii_detector.py`. On ingestion, telemetry passes through the PII scanner before being written to the event store. Configurable per-tenant redaction modes: `off`, `mask`, `drop`.

## 5. Data Residency

- Default residency is **United States** (AWS us-east-1 + us-west-2).
- Enterprise customers may elect **EU** residency (AWS eu-west-1 + eu-central-1). Data never crosses elected region boundaries except where explicitly approved in writing.
- Residency is enforced by the tenant router (`src/shieldops/api/middleware/residency.py`), which rejects any cross-region read attempt at the SQL layer.
- Backups honor the same residency constraint.

## 6. Retention

| Data                        | Classification | Retention                        | Disposal                                  |
|-----------------------------|---------------:|----------------------------------|-------------------------------------------|
| Customer telemetry (raw)    | Restricted     | 90 days rolling                  | Automated delete job, daily               |
| Customer telemetry (aggreg) | Confidential   | 13 months                        | Automated delete job, daily               |
| Audit log                   | Restricted     | 7 years                          | S3 Object Lock, legal hold before delete  |
| Application logs            | Confidential   | 30 days hot, 1 year cold         | S3 lifecycle expire                       |
| Backup snapshots            | Varies         | 35 days                          | Automated snapshot expiry                 |
| Source code / git history   | Confidential   | Indefinite                       | N/A                                       |
| Employee records            | Confidential   | 7 years after termination        | HRIS deletion workflow                    |
| Business records (tax, SOX) | Confidential   | 7 years                          | Accounting firm retention schedule        |

Retention is enforced by `src/shieldops/compliance/data_retention.py`. Deviations require Head of Security approval.

## 7. Data in Non-Production

Production data must not be copied to staging or development without irreversible anonymization. The only approved pipeline is `scripts/anonymize_dump.py`, which:

1. Pseudonymizes all direct identifiers with a keyed HMAC.
2. Drops Restricted columns entirely.
3. Shuffles foreign-key relationships to break record linkage.

## 8. Disposal

- **Digital:** Cryptographic erasure for encrypted volumes (destroy the KEK), followed by overwrite where the underlying storage supports it. AWS EBS snapshot delete is sufficient for non-Restricted data.
- **Physical (laptops):** Wiped to DoD 5220.22-M at offboarding; see `procedures/employee-offboarding.md`.

## 9. Customer Data Subject Rights

For GDPR/CCPA data subject requests forwarded by customers (who remain the data controller):

- Access and export: fulfilled via API endpoint `POST /api/v1/privacy/export`.
- Erasure: fulfilled via `POST /api/v1/privacy/erase`. Erasure propagates to backups within 35 days (end of retention cycle) — this is disclosed in the DPA.
- Response SLA: 7 days to acknowledge, 30 days to fulfill.

## 10. Exceptions and Enforcement

See `policies/access-control.md` §10 and §11.

## 11. References

- `policies/encryption.md`
- `policies/access-control.md`
- `policies/incident-response.md`
- `procedures/employee-offboarding.md`
- SOC 2 TSC: CC6.1, CC6.5, C1.1, C1.2.
