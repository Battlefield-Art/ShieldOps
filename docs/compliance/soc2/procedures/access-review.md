# Procedure: Quarterly Access Review

**Document ID:** SHIELDOPS-PROC-AC-001
**Version:** 1.1
**Owner:** Head of Security (interim: CTO)
**Related Policy:** `policies/access-control.md`
**Last Reviewed:** 2026-04-01

## 1. Purpose

Verify that every person, service account, and API key currently with access to ShieldOps production has a continued business need, and revoke anything that does not.

## 2. Cadence

- **Quarterly** (Jan, Apr, Jul, Oct) — full review.
- **Event-driven** — additional targeted review on any SEV1 access-related incident, organizational change, or acquisition.

## 3. Scope

- Human users in the `users` table (all tenants + internal).
- API keys in the `api_keys` table.
- Service accounts across AWS, GitHub, SaaS vendors.
- RBAC role assignments (`users.role`).
- Membership in privileged groups: AWS Admin, GitHub org owner, 1Password admin, Vanta admin, PagerDuty admin, Google Workspace super-admin.

## 4. Procedure

Owner: Head of Security. Target duration: one week.

### 4.1 Day 1 — Gather evidence

Run the evidence collection script:

```
python scripts/audit/collect_evidence.py \
  --section access \
  --window quarterly \
  --out artifacts/access-review-YYYYQX/
```

The script produces:

- `users.csv` — all active users with role, last login, MFA status, email hash.
- `api_keys.csv` — all active API keys with owner, scopes, last used, expiry.
- `admins.csv` — current members of each privileged group.
- `audit_summary.md` — high-level stats (new accounts, disabled accounts, stale accounts).

### 4.2 Day 1–3 — Manager attestation

- For each active **employee**, send the user's current access list to their manager via a Google Form.
- Manager must respond with: **keep**, **reduce**, **revoke** for each entry.
- Non-response after 3 business days auto-escalates to the Head of Engineering.

### 4.3 Day 2–3 — Stale account sweep

Automatically flag and propose revocation for:

- Users with no login in 90+ days.
- API keys with no use in 60+ days.
- Service accounts with no use in 30+ days.

The Head of Security reviews the flagged list and approves or defers.

### 4.4 Day 3–4 — Privileged group review

- Inspect each member of each privileged group (see scope §3).
- Reconfirm each admin is still in the correct role.
- Break-glass accounts: confirm not used routinely; if used, confirm the use was approved.

### 4.5 Day 4–5 — Execute changes

- Apply all approved revocations and reductions.
- Each change is a `audit_log` entry (`action="access_revoked"` or `action="role_reduced"`).
- API key revocations trigger notifications to the key owner.

### 4.6 Day 5 — Sample change verification

- Pick 10 random changes deployed in the quarter.
- Verify each has: a linked ticket, a non-author approver, a green CI run, an `audit_log` deployment entry.
- This is the SOC 2 CC8.1 sample test done quarterly rather than waiting for the audit.

### 4.7 Day 5 — Sign off

- Head of Security signs the review certificate: `artifacts/access-review-YYYYQX/signoff.md`.
- Uploaded to Vanta as audit evidence.
- Results summarized in `#security` Slack channel.

## 5. Evidence Retained

- All CSV and markdown outputs from the script.
- Manager attestations (Google Form responses).
- Sign-off certificate.
- Audit log entries for executed changes.
- Retained for 7 years in `s3://shieldops-audit-exports/access-reviews/`.

## 6. Exceptions

Any access that is flagged for revocation but not revoked (because the manager objects, for example) must be logged as an exception in `docs/compliance/soc2/exceptions.md` with justification and expiry.

## 7. Effectiveness Tracking

Each review records:

- Total users reviewed.
- Accounts revoked.
- Roles reduced.
- Stale accounts swept.
- Exceptions raised.
- Duration in business days.

These metrics are reviewed at the annual security program review.
