# Privacy Policy

**Effective Date:** 2026-04-06
**Last Updated:** 2026-04-06

ShieldOps, Inc. ("ShieldOps", "we", "us") respects your privacy. This Privacy
Policy explains what data we collect, how we use it, who we share it with,
and what rights you have.

This policy covers:
- The ShieldOps SaaS platform at `app.shieldops.io`
- The ShieldOps API at `api.shieldops.io`
- The `shieldops-sdk` Python package
- Marketing pages at `shieldops.io`

## 1. Data we collect

### 1.1 Account information
- Name, work email, organization name, password hash
- Billing details (handled by Stripe; we never store full card numbers)
- Communication preferences

### 1.2 Service telemetry
- Agent execution events: agent name, duration, success/failure, token usage
- Tool-call interceptions (when SDK is configured): tool name, arguments hash,
  decision (allow/review/block), risk score
- API request metadata: timestamp, method, path, status code, latency
- Error logs (without PII)

### 1.3 Customer-ingested data
- Whatever you choose to send via `/api/v1/ingest/*` (CloudTrail, CrowdStrike,
  syslog, OTel, etc.)
- We treat this as **Customer Data** under the Data Processing Agreement
- We never read it for ML training or analytics on our side
- It is stored in your tenant-isolated database partition

### 1.4 Cookies
- Session cookies (authentication only, HttpOnly, Secure, SameSite=Lax)
- We do not use third-party advertising cookies

## 2. How we use your data

| Purpose | Legal basis (GDPR) |
|---|---|
| Provide the service | Contract |
| Authenticate users | Contract / legitimate interest |
| Send service notifications (incidents, billing) | Contract |
| Improve the product (aggregated, anonymized) | Legitimate interest |
| Prevent abuse and secure the service | Legitimate interest |
| Compliance with law (subpoena, audit) | Legal obligation |

We do **not**:
- Sell your data
- Train ML models on Customer Data
- Share Customer Data with advertisers
- Use Customer Data outside of providing the service

## 3. Sub-processors

We use the following third parties to deliver the service. Each is bound
by a Data Processing Agreement:

| Sub-processor | Purpose | Region |
|---|---|---|
| Amazon Web Services | Hosting (compute, storage, database) | US-East / EU-West |
| Stripe, Inc. | Payment processing | US |
| Anthropic, PBC | LLM inference (Claude) | US |
| OpenAI, Inc. | LLM inference (GPT, fallback) | US |
| Datadog (optional) | Application monitoring | US |
| Auth0 / Okta (enterprise SSO) | Identity provider | US / EU |

The current list is published at https://shieldops.io/sub-processors and
notification of additions / changes is provided 30 days in advance.

## 4. Sharing of personal data

We disclose personal data only:
- To the sub-processors listed above (under DPA)
- When required by law (subpoena, court order, legal process)
- To protect the rights, safety, or property of ShieldOps or our users
- During a corporate transaction (merger, acquisition) — with notice

## 5. Data retention

| Data type | Retention |
|---|---|
| Account information | Until account deletion + 30 days |
| Authentication logs | 1 year |
| Billing records | 7 years (tax requirement) |
| Customer-ingested security data | Per tenant tier (30 / 90 / 365 days) |
| Backups | Encrypted, 30 days |
| Aggregated/anonymized telemetry | Indefinite |

## 6. Your rights

Depending on where you live, you may have the following rights:

### EU / EEA (GDPR)
- Right of access (Article 15)
- Right to rectification (Article 16)
- Right to erasure / "right to be forgotten" (Article 17)
- Right to restriction of processing (Article 18)
- Right to data portability (Article 20)
- Right to object (Article 21)
- Right to lodge a complaint with a supervisory authority

### California (CCPA / CPRA)
- Right to know what personal information is collected
- Right to delete personal information
- Right to opt out of sale (we do not sell)
- Right to non-discrimination

### UK (UK GDPR)
- Substantially the same rights as EU GDPR

### Brazil (LGPD), Canada (PIPEDA), Australia (Privacy Act), India (DPDPA)
- Equivalent rights — exercise via the email below

To exercise any right, email **privacy@shieldops.io** with your request.
We will respond within 30 days.

## 7. Security

We protect personal data with:
- TLS 1.3 in transit
- AES-256 encryption at rest
- Tenant isolation at the database, query, and WebSocket layers
- Multi-factor authentication for all employee access
- Annual third-party penetration testing
- SOC 2 Type II audit (in progress; Type I in 2026)
- Vendor risk reviews
- Incident response plan with 72-hour notification SLA

See our [Vulnerability Disclosure Policy](../security/vulnerability-disclosure-policy.md)
for how to report security issues.

## 8. International transfers

ShieldOps is a US company. Personal data of EU/EEA residents is
transferred to the US under Standard Contractual Clauses (SCCs) approved
by the European Commission. Customers may request EU-region hosting via
their DPA addendum.

## 9. Children

The service is not directed to children under 16. We do not knowingly
collect personal data from children. If you believe we have collected
data from a child, contact privacy@shieldops.io for immediate deletion.

## 10. Changes

We may update this policy. Material changes will be notified via email
and a banner in the dashboard at least 30 days before they take effect.
The "Effective Date" at the top will be updated.

## 11. Contact

- **Email:** privacy@shieldops.io
- **Data Protection Officer:** dpo@shieldops.io
- **Postal:** ShieldOps, Inc., [Address Placeholder], United States
- **EU Representative:** [GDPR Article 27 representative placeholder]
