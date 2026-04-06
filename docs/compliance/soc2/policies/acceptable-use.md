# Acceptable Use Policy

**Document ID:** SHIELDOPS-POL-AU-001
**Version:** 1.0
**Owner:** Head of Security (interim: CTO)
**Approved By:** CEO
**Effective Date:** 2026-01-15
**Last Reviewed:** 2026-04-01
**Next Review:** 2027-01-15
**Applies To:** All ShieldOps employees, contractors, interns, advisors with access credentials, and anyone using ShieldOps equipment or accounts.

## 1. Purpose

This policy defines acceptable and unacceptable use of ShieldOps information systems, data, devices, accounts, and networks. Every person in scope must acknowledge this policy at onboarding and annually thereafter.

## 2. Principle

ShieldOps provides systems and accounts to enable you to do your job securely. You must use them lawfully, ethically, and in alignment with our security policies. When in doubt, ask Security (`#security` in Slack or `security@shieldops.io`).

## 3. Your Responsibilities

You must:

1. **Protect your credentials.** Never share passwords, API keys, MFA tokens, or session cookies. Never reuse your ShieldOps password on any other service. Store secrets in 1Password, not in code, notes, email, or Slack.
2. **Lock your device** when unattended. Full-disk encryption must be enabled (enforced by MDM). Screen lock timeout: 5 minutes.
3. **Use MFA** on every account that supports it. MFA is mandatory on ShieldOps, GitHub, AWS, Google Workspace, 1Password, and every Tier 1/2 vendor.
4. **Keep software up to date.** Accept security patches within 7 days. Critical patches within 24 hours.
5. **Report suspected incidents immediately** via `#security` or `security@shieldops.io`. Reporting a mistake you made is explicitly encouraged — we do not punish honest reports.
6. **Handle customer data** according to `policies/data-classification.md`. Restricted data stays in production systems.
7. **Follow change management** (`policies/change-management.md`) for any change touching production.

## 4. Prohibited Activities

You must not:

1. Access, attempt to access, or encourage others to access data or systems beyond what your role requires.
2. Use customer data for any purpose other than operating the ShieldOps platform on the customer's behalf. Browsing customer data out of curiosity is a terminable offense.
3. Copy Confidential or Restricted data to personal devices, personal cloud accounts, personal email, personal Git repositories, or any unmanaged location.
4. Install unapproved software on ShieldOps-managed devices. The approved list is maintained in Notion; request additions via `#it`.
5. Use ShieldOps accounts, compute, or API credits for personal projects, cryptocurrency mining, running unrelated AI workloads, or any commercial activity not sanctioned by the company.
6. Bypass, disable, or weaken any security control (MDM, EDR, MFA, VPN, SSO) without Security's explicit written approval.
7. Post Confidential or Restricted information to external LLMs, search engines, forums, or social media. Using the ShieldOps-approved LLM wrapper (`utils/llm.py`) is fine; pasting code into ChatGPT.com is not.
8. Engage in harassment, discrimination, or unlawful activity using ShieldOps systems.
9. Use ShieldOps systems to attack, probe, or interfere with third parties — including red-team activities against customers — without written authorization from the customer and a rules-of-engagement document signed by Security.
10. Circumvent license terms of any third-party software.

## 5. BYOD and Personal Devices

Personal devices may be used only for:

- Checking email and Slack via a managed mobile app with a device passcode and remote wipe enabled.
- Approving MFA prompts.

Personal devices **must not** access source code, customer data, production systems, or admin interfaces. Engineers receive a company laptop for that purpose.

## 6. Physical Security

- Do not tailgate or hold doors open for people you do not recognize at any office.
- Screens must not be visible through windows or to shoulder surfers in public places.
- Do not leave laptops in vehicles. If traveling, laptops stay with you.
- Hardware keys, YubiKeys, backup MFA devices: kept physically secure.

## 7. Communications

- Assume customer information is Confidential by default.
- Never commit credentials, tokens, or customer data to Git — not even briefly. If you do, treat it as an incident (`policies/incident-response.md`) and rotate the secret immediately.
- Public statements about ShieldOps security posture are made only by authorized spokespeople.

## 8. Monitoring

ShieldOps monitors the use of company-owned systems and accounts to the extent permitted by law. Monitoring is conducted for security, operations, and compliance purposes only. You should have no expectation of privacy when using company systems for non-personal purposes.

## 9. Leaving ShieldOps

On termination (voluntary or otherwise), you must return all ShieldOps equipment and credentials, and stop using all ShieldOps accounts. See `procedures/employee-offboarding.md`.

## 10. Violations

Violations may result in any or all of:

- Coaching and retraining.
- Revocation of specific access.
- Suspension.
- Termination.
- Civil or criminal liability.

Severity of response is proportional to the severity of the violation and intent. Honest mistakes reported promptly are handled supportively.

## 11. Acknowledgment

By signing this policy (digitally via the HR onboarding flow), you confirm that you have read, understood, and agree to comply. The signed acknowledgment is retained in the employee record.

## 12. References

- `policies/access-control.md`
- `policies/data-classification.md`
- `policies/incident-response.md`
- `procedures/employee-onboarding.md`
- `procedures/employee-offboarding.md`
