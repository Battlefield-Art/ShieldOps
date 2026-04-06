# Procedure: Code Review

**Document ID:** SHIELDOPS-PROC-CM-001
**Version:** 1.1
**Owner:** Head of Engineering (interim: CTO)
**Related Policy:** `policies/change-management.md`
**Last Reviewed:** 2026-04-01

## 1. Purpose

Define how code is reviewed before it merges to `main` and becomes eligible for production deployment.

## 2. Pull Request Requirements

Every PR must:

1. Target `main` (no long-lived feature branches that skip review).
2. Link to a Linear ticket or GitHub issue in the PR body.
3. Describe **what** changed, **why**, and **how it was tested**.
4. Include automated tests for new behavior. Coverage must not drop below 80% on changed files.
5. Pass CI: ruff (lint + format), mypy strict, bandit, pytest, pre-commit hooks.
6. Include at least one approval from a code owner who is **not** the author.
7. Be up to date with `main` before merge. Squash-merge is the default.

## 3. PR Template

The `.github/pull_request_template.md` enforces this structure:

```markdown
## Summary

<one paragraph: what this change does and why>

## Testing

<how you verified correctness; include commands and results>

## Risk assessment

- Blast radius: <local | service | platform>
- Rollback plan: <how to undo within 15 minutes>
- Data migration: <yes | no; if yes, link Alembic revision>
- Security-sensitive paths touched: <yes | no; if yes, tag @security-reviewers>

## Checklist

- [ ] Tests added / updated
- [ ] Docs updated
- [ ] Backward compatible (or explicitly called out above)
- [ ] No secrets, tokens, or customer data in diff
- [ ] Ticket linked
```

## 4. Reviewer Checklist

A reviewer should verify **all** of the following before approving.

### 4.1 Correctness

- Does the change do what the PR description says?
- Are edge cases handled (empty input, null, boundary values, concurrency)?
- Are errors handled explicitly? Avoid bare `except:` and `except Exception:` without a reason.

### 4.2 Tests

- Are there tests for the new behavior?
- Do tests cover failure paths, not just the happy path?
- Are tests deterministic? No sleeps, no real network, no real time unless necessary.

### 4.3 Security

- No secrets or credentials in the diff.
- User input is validated (Pydantic models, not raw dicts).
- SQL uses the repository pattern or parameterized queries; no string interpolation.
- Shell / subprocess calls are absent or use `shell=False` with a list argument.
- Deserialization (`pickle`, `yaml.load`) is safe.
- Authorization is enforced on every new route (`@require_role(...)` or explicit OPA call).
- If the PR touches auth, policy, or audit logging: request a review from `@security-reviewers`.

### 4.4 Observability

- New code emits structured logs with appropriate context.
- New metrics and traces are added for user-visible behavior.
- Audit-worthy actions write to `audit_log`.

### 4.5 Performance and Cost

- Any new loops over customer data are bounded.
- Any new external API calls have timeouts and retries with backoff.
- LLM calls use the router (`utils/llm_router.py`) rather than hard-coding the largest model.

### 4.6 Style and Maintainability

- Type hints on all public functions.
- Naming is consistent with the rest of the package.
- Code is discoverable: fits the existing package layout, does not create a new top-level package lightly.
- No commented-out code, no TODOs without a linked ticket.

## 5. Security Review Triggers

A **security review** by the Head of Security or a designated security engineer is required when the PR touches any of:

- `src/shieldops/auth/`
- `src/shieldops/policy/` or `policies/opa/`
- `src/shieldops/api/middleware/` (any change to authentication, authorization, or tenant isolation)
- `src/shieldops/db/migrations/` for tables with sensitivity labels Confidential or Restricted
- `src/shieldops/sdk/` (the Agent Firewall SDK — customer-exposed)
- Cryptographic operations (`src/shieldops/compliance/field_encryption.py`, anything touching `secrets` or `hashlib`)
- Addition of a new third-party dependency
- CI/CD workflow changes

The `CODEOWNERS` file automatically requests security reviewers for these paths.

## 6. Review SLAs

- First response within 1 business day for normal PRs.
- First response within 2 hours for PRs tagged `blocker` or tied to an active incident.
- A PR older than 5 business days without review is escalated to the Head of Engineering.

## 7. After Merge

- CI deploys to staging automatically.
- The author is responsible for verifying the staging deploy smoke test passes.
- Production promotion follows `procedures/deployment-approval.md`.

## 8. Evidence Collected (for SOC 2)

- Every merged PR is indelibly recorded by GitHub: author, reviewers, timestamps, commits, check results.
- `scripts/audit/collect_evidence.py` samples merged PRs in the audit window and verifies each has: a linked ticket, at least one non-author approval, and a passing CI run.
- Violations (force-pushes to main, direct commits, admin merges) are flagged and investigated.

## 9. Exceptions

Bypassing review requires Head of Engineering approval and is logged in `docs/compliance/soc2/exceptions.md`. Emergency changes during a SEV1/SEV2 may merge with single-approver + IC sign-off, but must be retroactively reviewed within 2 business days.
