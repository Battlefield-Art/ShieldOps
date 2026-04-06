# Certification Process

> **Status:** Design (future) — Issue #232
> **See also:** [design.md](./design.md), [agent-spec.md](./agent-spec.md)

Certification is how the ShieldOps Marketplace earns and maintains customer trust.
Because marketplace agents execute actions against real infrastructure via OPA-
governed connectors, we cannot rely on "caveat emptor." Every agent passes through
automated and (for higher tiers) manual review before it reaches customers.

## 1. Certification Tiers

| | **Community** | **Verified** | **Premier** |
|---|---|---|---|
| **Badge** | Gray | Blue check | Gold shield |
| **Review** | Automated only | Automated + manual | Continuous + partnership |
| **Turnaround** | <15 min | 3-10 business days | Ongoing relationship |
| **Connectors** | Read-only, non-destructive | Any declared in manifest | Any, incl. admin-scope |
| **Cost to author** | Free | Free | Partnership agreement |
| **Support SLA** | Best-effort | 24h | 4h |
| **Liability** | "As-is" | Author backed | Author + ShieldOps co-signed |
| **Billing** | Free or paid | Free or paid | Typically paid / enterprise |
| **Revocation** | Auto on abuse report threshold | Manual with author notice | Contractual |
| **Visibility** | Public catalog | Public catalog + "Verified" filter | Public catalog + editor's picks |
| **Example** | Community threat feed ingestor | SWIFT Fraud Hunter | CrowdStrike Falcon Integration |

### Community tier
Anyone can publish. The pipeline runs automated checks and, if they pass, publishes
immediately. Agents are sandboxed to read-only, non-destructive connectors, and all
actions are dry-run by default for the first 100 executions at each customer. Good
fit for: community tools, research agents, threat feed converters, free connectors
for niche data sources.

### Verified tier
Author submits for manual review. A ShieldOps reviewer runs the full checklist
(below) and signs off. Verified agents can request elevated connector scopes in
their manifest (write access, admin access) with justification. The "Verified"
badge is a trust signal shown throughout the UI. Good fit for: commercial vertical
agents, MSSP offerings, enterprise security tools.

### Premier tier
Reserved for partners with a formal agreement. Requires:
- Signed partnership contract (legal, liability, co-marketing).
- Joint security review (ShieldOps + partner's security team).
- Dedicated technical account manager.
- SLA commitments on response time, CVE patching, and breaking change notice.
- Continuous monitoring: fitness scores reviewed quarterly, any regression
  triggers a joint RCA.

Good fit for: CrowdStrike, Wiz, Splunk, Palo Alto, Snyk-scale vendors.

## 2. Automated Checks

Runs on every submission to every tier. Community tier stops here if all pass.

### 2.1 Lint & format
- `ruff check` with the ShieldOps project config.
- `ruff format --check`.
- Fails on errors, warns on style issues.

### 2.2 Type check
- `mypy --strict` on the agent package.
- All public functions must have type hints (ShieldOps convention).

### 2.3 Manifest validation
- JSON Schema validation of `agent.yaml`.
- Cross-references: declared connectors exist; declared OPA policies parse;
  entrypoint resolves; SPDX license is valid.

### 2.4 OPA policy validation
- `opa check` on all bundled `.rego` files.
- Policy dry-run against a battery of synthetic inputs to catch overly permissive
  rules (e.g., `default allow = true` is rejected).

### 2.5 Dependency scan
- `pip-audit` and `safety check` against the agent's declared dependencies.
- Any CVE with CVSS ≥ 7.0 blocks publication. CVSS 4.0-6.9 produces a warning and
  requires author acknowledgement.
- License compliance: reject GPL/AGPL unless the agent itself is GPL/AGPL-licensed
  (viral license containment).

### 2.6 Malicious-pattern scan
Custom semgrep rules plus ShieldOps in-house detections:
- Network egress outside declared connectors (e.g., `requests.get("http://evil.sh")`).
- `eval`, `exec`, `pickle.loads`, `subprocess` without justification.
- Hardcoded credentials, tokens, private keys (entropy detector).
- Obfuscated code (high entropy strings, base64-decoded code paths).
- Crypto-mining patterns.
- Prompt injection attempts against the ShieldOps meta-prompt.
- Data exfil patterns (reading env vars + writing to network).

### 2.7 Sandbox execution
- Deploy the agent to the sandbox tenant.
- Run every example in `spec.tests.examples`.
- Assert expected outcomes match.
- Measure actual latency, memory, LLM token usage vs declared resources. Declared
  values must be within 20% of observed.
- Run fitness tracker for N=50 synthetic inputs and record baseline fitness.

### 2.8 SBOM generation
- Generate SPDX 2.3 SBOM for the agent package.
- Store alongside the signed artifact for customer download.

### Decision
- All checks green → **Community tier published automatically.** Verified/Premier
  submissions advance to the manual review queue.
- Any check red → submission rejected with detailed report; author fixes and resubmits.

## 3. Manual Review Checklist (Verified & Premier)

Reviewers use the Reviewer Dashboard to work through this checklist. Each item is
either ✅ pass, ⚠️ waived with justification, or ❌ fail.

### 3.1 Behavior verification
- [ ] Agent description matches actual behavior observed in sandbox.
- [ ] All declared connectors are actually used; no silent scope creep.
- [ ] Examples cover happy path, edge cases, and at least one adversarial input.
- [ ] Idempotency: re-running the same input produces the same result (or
      deterministically-described variation).
- [ ] Failure modes are graceful (no unhandled exceptions, timeout respected).

### 3.2 Security audit
- [ ] Code review by a ShieldOps security engineer (diff walk, focus on tool
      functions and prompt construction).
- [ ] Prompt injection resistance: test with the ShieldOps prompt-injection corpus.
- [ ] Secrets handling: no secrets in logs, tracebacks, or telemetry.
- [ ] PII handling: aligned with declared `compliance.data_residency`.
- [ ] OPA policies reviewed for overbroad permissions.
- [ ] Dependency tree manually reviewed for known bad actors or abandoned packages.

### 3.3 Performance benchmark
- [ ] Median latency at or below declared `expected_latency_ms`.
- [ ] p99 latency within 3x median.
- [ ] Memory usage within declared budget under load (10x concurrent).
- [ ] LLM token usage within declared budget across 100 runs.
- [ ] Baseline fitness score ≥ 0.70 across the sandbox test corpus.

### 3.4 Documentation completeness
- [ ] README explains what the agent does, when to use it, when not to use it.
- [ ] Each required connector has configuration instructions.
- [ ] Input/output schemas documented with examples.
- [ ] Runbook: what to do if the agent misbehaves, how to roll back.
- [ ] Changelog for this version.
- [ ] Support contact is responsive (reviewer pings test email, expects reply
      within declared SLA).

### 3.5 Legal & compliance
- [ ] License is appropriate for the claimed pricing model.
- [ ] Author identity verified (for paid agents: tax forms, Stripe Connect KYC).
- [ ] Trademark check on agent name.
- [ ] Export control review if `compliance.export_controls` is declared.
- [ ] Third-party attribution in NOTICE file if applicable.

## 4. Reviewer Workflow

1. Submission enters review queue with status `automated_checks_passed`.
2. Round-robin assignment to available reviewer (load-balanced by open queue size).
3. Reviewer kicks off the Reviewer Dashboard for the submission. The dashboard
   shows:
   - Manifest + diff from any previous version.
   - Automated check results (collapsible).
   - Sandbox execution traces.
   - Manual checklist (section 3).
   - Code viewer with semgrep findings highlighted.
4. Reviewer completes checklist. Any ❌ fail triggers a structured rejection email
   to the author with the specific items, code locations, and suggested fixes.
5. On all-pass, reviewer clicks "Certify." Second reviewer (two-person rule) must
   countersign for Premier tier and for Verified agents requesting `admin`-scope
   connector access.
6. Artifact is signed by the ShieldOps signing key (HSM-backed), written to the
   registry, and published.
7. Author is notified; agent appears in the catalog.
8. Submission telemetry (time-to-review, reviewer, findings count) is logged for
   quality metrics.

### SLA and escalation
- Verified review SLA: initial reviewer engagement within 2 business days,
  decision within 10 business days.
- Escalation path: reviewer → review lead → head of platform.
- If an author believes a rejection was incorrect, they may file an appeal; a
  different reviewer re-runs the checklist.

## 5. Revocation Policy

Certification can be revoked — even for Premier agents — under any of the
following conditions.

### 5.1 CVE in a dependency
- **CVSS ≥ 9.0 (Critical):** agent is soft-revoked immediately (no new installs);
  author has 48 hours to patch before hard-revoke (existing installs disabled).
- **CVSS 7.0-8.9 (High):** author has 7 days to patch.
- **CVSS 4.0-6.9 (Medium):** author has 30 days to patch.
- Soft-revoke shows a red banner to customers; hard-revoke stops execution on
  next heartbeat.

### 5.2 Malicious behavior
If ShieldOps confirms the agent is behaving maliciously (data exfil, policy bypass,
credential theft):
- Immediate hard-revoke across all tenants.
- Post-mortem published within 7 days.
- Author account suspended pending investigation.
- Customer notification with incident details and remediation steps.
- Criminal/civil referral if warranted.

### 5.3 Abuse reports
Customers can file abuse reports from the agent detail page. Thresholds:
- 5 substantiated reports in 30 days → auto-flag for review.
- 10 substantiated reports → soft-revoke pending investigation.
- Unsubstantiated or clearly bad-faith reports do not count.

### 5.4 Fitness regression
If aggregate fitness score drops below 0.50 for more than 14 consecutive days:
- Author notified with fitness breakdown and affected tenants.
- Agent tagged "under review" in the catalog.
- 30 days to remediate or the agent is unlisted (existing installs continue but
  are flagged).

### 5.5 Author abandonment
If the author is unreachable for 90+ days and critical issues are outstanding:
- Agent marked "abandoned."
- 60-day deprecation notice to installed customers.
- Removed from catalog thereafter.

### 5.6 Policy violation
Any violation of the ShieldOps Marketplace Terms of Service (harassment, trademark
infringement, fraud, etc.) results in revocation per the ToS escalation procedure.

## 6. Reinstatement

A revoked agent can be reinstated after the author demonstrates remediation. The
reinstatement flow is the same as a new submission, but with an additional review
item: "Root cause of revocation is addressed and verified." Premier-tier
reinstatement requires approval from the head of platform.
