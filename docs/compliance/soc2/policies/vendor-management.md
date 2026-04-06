# Vendor (Third-Party) Risk Management Policy

**Document ID:** SHIELDOPS-POL-VM-001
**Version:** 1.1
**Owner:** Head of Security (interim: CTO)
**Approved By:** CEO
**Effective Date:** 2026-02-01
**Last Reviewed:** 2026-04-01
**Next Review:** 2027-02-01

## 1. Purpose

This policy defines how ShieldOps evaluates, onboards, monitors, and offboards third-party vendors whose products or services process, store, or have access to ShieldOps or customer data. It supports SOC 2 criterion **CC9.2** and the supply-chain aspects of CC7.1.

## 2. Scope

All external vendors fall into one of four tiers based on data access and operational criticality.

| Tier | Criteria                                                                                          | Examples                                                              | Review cadence |
|:----:|----------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------|:--------------:|
| 1    | Processes Restricted customer data, or hosts primary production infrastructure                    | AWS, Anthropic, Stripe, Datadog, Auth0/Clerk                          | Annual         |
| 2    | Processes Confidential data, or a SEV2 outage on this vendor would impact customers               | GitHub, Sentry, PagerDuty, Slack, LaunchDarkly, Linear, Notion        | Annual         |
| 3    | Internal-only tools, no customer data access, commodity SaaS                                       | Figma, Zoom, Google Workspace, HRIS, Carta                            | Biennial       |
| 4    | One-off tools or free accounts, no sensitive data                                                  | Free trial evaluations, public APIs                                   | On change only |

## 3. Onboarding

Before a vendor is approved for use with production or customer data, the requesting team must complete the Vendor Intake Form (Linear template `vendor-intake`). The intake captures:

- Vendor name, website, primary contact.
- Business justification and alternatives considered.
- Data categories the vendor will access (see `policies/data-classification.md`).
- Integration surface (API, OAuth scopes, SSO, data export).
- Expected annual spend.

The Head of Security reviews and either approves, rejects, or requests additional information. For Tier 1 and Tier 2 vendors, approval additionally requires:

1. **Security review artifacts:**
   - Current SOC 2 Type II report (or ISO 27001 certificate, or equivalent).
   - Pen test summary dated within the last 12 months, if applicable.
   - Data Processing Agreement (DPA) executed with ShieldOps-acceptable terms.
   - Sub-processor list, which is cross-referenced against the ShieldOps DPA.
   - Breach notification terms (we require <= 72h notification).
2. **Security questionnaire:** ShieldOps uses an abbreviated SIG Lite; the filled questionnaire is stored in Vanta.
3. **Contract review** by Legal (or the CEO, until Legal is hired).
4. **Architecture review** if the vendor integrates inbound (webhooks) or receives customer data.

## 4. Approved Vendor Register

The authoritative list of approved vendors lives in `docs/compliance/soc2/vendor-register.yaml` (tracked in Vanta as the system of record). Each entry includes:

```yaml
- name: Anthropic
  tier: 1
  service: Claude API (primary LLM)
  data_shared: customer telemetry summaries (hashed/redacted), agent prompts
  data_residency: US
  soc2_type: Type II
  soc2_report_date: 2025-11-15
  dpa_signed: 2026-01-20
  sub_processors_reviewed: true
  owner: CTO
  review_due: 2027-01-20
  criticality: high
  failover: OpenAI GPT-4 via utils/llm_router.py
```

## 5. Monitoring

- **Trust center watch:** Security subscribes to public trust centers / status pages of all Tier 1 and Tier 2 vendors. Status degradations are forwarded to the on-call engineer.
- **Continuous monitoring:** Vanta continuously checks for expired SOC 2 reports and DPAs. Alerts 30 days before expiry.
- **Financial and legal health:** Reviewed annually or on material change (acquisition, news of breach, bankruptcy filing).
- **Breach notifications from vendors:** Treated as a ShieldOps security event. Routed through the incident response process (`policies/incident-response.md`). A vendor breach involving ShieldOps data is at least SEV2.

## 6. Annual Review

Every Tier 1 and Tier 2 vendor is reviewed annually. The review:

1. Refreshes the SOC 2 / ISO report on file.
2. Confirms DPA is still in force and sub-processors are unchanged.
3. Reassesses the vendor tier.
4. Confirms an internal business owner is still using the service (otherwise, trigger offboarding).
5. Reviews any security incidents involving the vendor during the year.

Evidence of each annual review is stored in Vanta and referenced in the SOC 2 audit.

## 7. Offboarding

When a vendor is no longer used:

1. Disable the integration (revoke API keys, rotate OAuth clients, delete webhook endpoints).
2. Request deletion of all ShieldOps and customer data held by the vendor. Obtain written confirmation.
3. Cancel the contract or downgrade per contractual terms.
4. Remove from the vendor register.
5. Record offboarding in the `audit_log` (`action="vendor_offboarded"`).

## 8. Sub-Processors and Customer Transparency

ShieldOps publishes the list of sub-processors at `https://shieldops.io/subprocessors`. Customers are notified of new sub-processors at least **30 days** before they begin processing customer data, per the standard DPA.

## 9. Prohibited Vendors

- Vendors hosted in jurisdictions subject to US sanctions (OFAC SDN).
- Vendors that refuse to sign a DPA when processing customer data.
- Vendors with an unresolved ShieldOps-impacting breach in the last 24 months.

## 10. Enforcement and Exceptions

See `policies/access-control.md` §10 and §11. Exceptions require CEO sign-off for Tier 1 and Tier 2 vendors.

## 11. References

- `policies/data-classification.md`
- `policies/incident-response.md`
- `docs/compliance/soc2/vendor-register.yaml`
- SOC 2 TSC: CC9.2.
