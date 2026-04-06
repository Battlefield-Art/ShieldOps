# Procedure: Employee Offboarding

**Document ID:** SHIELDOPS-PROC-HR-002
**Version:** 1.1
**Owner:** People Ops (interim: CEO) + Head of Security
**Related Policy:** `policies/access-control.md`
**Last Reviewed:** 2026-04-01

## 1. Purpose

Ensure timely and complete revocation of access when an employee or contractor leaves ShieldOps.

## 2. Target Times

- **Standard (voluntary) separation:** Access fully revoked within **4 business hours** of end time.
- **Involuntary separation:** Access fully revoked within **1 hour** of decision, before the departing person is informed where feasible.
- **Contractor end-of-engagement:** Within 24 hours of the contract end date.

## 3. Trigger

- HRIS status change to "Terminated" OR
- People Ops opens a Linear ticket `offboard-<name>` using the Offboarding template.

The Linear ticket is the audit trail.

## 4. Immediate Actions (T + 0 to T + 1 hour)

Owner: Head of Security (or on-call security engineer for involuntary cases).

- [ ] Disable Google Workspace account (suspend, do not delete).
- [ ] Revoke SSO sessions everywhere via Google Workspace "Sign user out of all sessions".
- [ ] Disable the ShieldOps platform user (`users.is_active = false`). This cascades to invalidating JWTs on next refresh.
- [ ] Revoke all API keys the user created (`api_keys.is_active = false`).
- [ ] Remove from GitHub org.
- [ ] Remove from 1Password teams/shared vaults.
- [ ] Remove from Slack (downgrade to single-channel guest first if they need to hand off; otherwise deactivate).
- [ ] Remove from AWS IAM Identity Center and any IAM roles.
- [ ] Remove from PagerDuty; reassign their on-call shifts.
- [ ] Remove from Vanta users.
- [ ] If an admin: rotate the JWT signing key and any shared production credentials they had access to. This is mandatory regardless of cause.
- [ ] Lock or remote-wipe the company laptop via MDM.

## 5. Same-Day Actions (T + 1 to T + 8 hours)

Owner: People Ops.

- [ ] Collect the laptop, YubiKeys, badges, and any other company equipment. Log return in the asset register.
- [ ] Collect signed termination / end-of-contract acknowledgment if applicable.
- [ ] Remove from email distribution lists (security-alerts@, oncall@, etc.).
- [ ] Forward email for 30 days to the hiring manager; auto-reply set.
- [ ] Transfer ownership of any Google Drive, Notion pages, Linear projects to the hiring manager.
- [ ] Re-assign owned Linear/Jira issues.

## 6. Exit Interview

For voluntary separations. Conducted by People Ops within 3 business days. Topics:

- Reasons for leaving.
- Feedback on security culture and processes (specifically: did you feel friction from security controls that affected your work?).
- Reminder of ongoing confidentiality obligations under the NDA.
- Confirmation that no ShieldOps or customer data remains on personal devices or personal accounts.

Documented in the HRIS. Not part of SOC 2 evidence but informs policy improvements.

## 7. Week-1 Verification

Owner: Head of Security.

- [ ] Run `scripts/audit/collect_evidence.py --check-user <email>` to confirm no active sessions, no active keys, no recent login.
- [ ] Search GitHub for any pending PRs authored by the departing person; reassign or close.
- [ ] Confirm the laptop wipe completed and the device is returned to inventory.
- [ ] Close the Linear offboarding ticket.

## 8. 30-Day Verification

Owner: Head of Security.

- [ ] During the next monthly review, confirm the departed user does not appear in any access list.
- [ ] Confirm the mail forward is disabled and the mailbox is archived per retention policy.

## 9. Evidence Collected

- Closed Linear offboarding ticket with all checkboxes.
- `audit_log` entries for each revocation (`action="access_revoked"`).
- Laptop return confirmation in the asset register.
- Secrets rotated (ticket reference).

## 10. Special Cases

- **Death of an employee:** Handled with sensitivity; People Ops coordinates with the CEO and Legal. Access revocation proceeds under the standard timeline to protect company and customer data. Exit interview is skipped.
- **Unreachable contractor:** Revoke all access; do not attempt to retrieve equipment without legal guidance.
- **Transition to advisor:** Full offboarding first, then re-onboard with advisor scope (no production access).
