# Procedure: Employee Onboarding

**Document ID:** SHIELDOPS-PROC-HR-001
**Version:** 1.1
**Owner:** People Ops (interim: CEO) + Head of Security
**Related Policy:** `policies/access-control.md`, `policies/acceptable-use.md`
**Last Reviewed:** 2026-04-01

## 1. Purpose

Ensure every new employee, contractor, or intern ("new hire") receives the right access, training, and agreements before touching ShieldOps systems.

## 2. Pre-Start (Day -5 to Day -1)

Owner: People Ops.

- [ ] Issue offer letter and executed employment / contractor agreement.
- [ ] Have the new hire sign the NDA (counter-signed by an officer).
- [ ] Have the new hire sign the IP assignment agreement.
- [ ] Collect legally required tax and I-9 documentation (US) or equivalent.
- [ ] Open a Linear ticket `onboard-<name>` using the Onboarding template. This is the audit trail.
- [ ] Order a company laptop with MDM pre-enrolled and FileVault/BitLocker enforced.
- [ ] Reserve a start-date slot on the hiring manager's calendar for day-1 kickoff.

## 3. Day 1

Owner: Hiring manager + People Ops + IT/Security (combined in a 60-minute block).

- [ ] Provision Google Workspace account (`firstname@shieldops.io`).
- [ ] Add to Slack, Linear, Notion, GitHub org, 1Password team, Vanta.
- [ ] Enroll in MFA on Google Workspace and GitHub. Issue a YubiKey for engineers touching production.
- [ ] Assign RBAC role based on `policies/access-control.md`:
  - Non-engineering: `viewer` on ShieldOps.
  - Engineering (non-prod): `viewer` on production, `operator` on staging.
  - Engineering (prod-eligible, after orientation + mentorship): `operator` on production.
  - Admin: only CTO and Head of Security by default.
- [ ] Walk through `policies/acceptable-use.md`. New hire signs acknowledgment in the HRIS.
- [ ] Walk through `policies/data-classification.md` and `policies/incident-response.md`.
- [ ] Complete security awareness training (Vanta / KnowBe4). Required before first access to customer data.
- [ ] Link the new user record to the Linear onboarding ticket.

## 4. Week 1

Owner: Hiring manager + buddy.

- [ ] Pair on one real PR to ensure the new hire understands the code review and CI process.
- [ ] Complete "Production Access Orientation" for engineers: review `procedures/deployment-approval.md`, `procedures/incident-escalation.md`, and do a dry-run of `/incident` in a sandbox.
- [ ] Confirm the new hire can page on-call without actually paging (test channel).
- [ ] Buddy confirms onboarding in the Linear ticket with a checklist.

## 5. 30-Day Checkpoint

Owner: Hiring manager.

- [ ] Review access granted so far against what the new hire actually used. Revoke anything unused.
- [ ] Confirm security training completion. Non-completion blocks production access.
- [ ] Note onboarding completion in the Linear ticket; close the ticket. The closed ticket is the audit artifact referenced during SOC 2 access reviews.

## 6. Evidence Collected

- Signed NDA + IP agreement (stored in the HRIS).
- Signed acceptable use acknowledgment (HRIS).
- Completed security training certificate (Vanta).
- Closed Linear onboarding ticket (Linear).
- Audit log entries for account creation and role assignment (`audit_log` table).

## 7. Common Issues

- **Contractor without a laptop:** Do not grant production access without a managed device. If the contractor uses their own device, they get scoped read-only access to non-production only, with a time-boxed API key.
- **Rehire:** Create a new user record; do not reactivate an old one. Old records are kept for audit.
- **Cross-role transfer:** Treat as onboarding + offboarding for the old role. Do not accumulate roles.
