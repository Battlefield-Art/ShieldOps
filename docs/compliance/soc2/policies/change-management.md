# Change Management Policy

**Document ID:** SHIELDOPS-POL-CM-001
**Version:** 1.2
**Owner:** Head of Engineering (interim: CTO)
**Approved By:** CEO
**Effective Date:** 2026-01-15
**Last Reviewed:** 2026-04-01
**Next Review:** 2026-10-01

## 1. Purpose

This policy ensures that all changes to ShieldOps production systems, code, configuration, and infrastructure are authorized, tested, reviewed, and reversible. It supports SOC 2 criteria **CC8.1** and the change-risk sub-controls of CC6 and CC7.

## 2. Scope

Changes in scope include:

- Application code (`src/shieldops/` and `dashboard-ui/`).
- Infrastructure-as-code (`infrastructure/terraform/`, `infrastructure/kubernetes/`, `infrastructure/helm/`).
- Database schema (Alembic migrations in `alembic/versions/`).
- Policy code (`policies/opa/*.rego`).
- CI/CD workflow definitions (`.github/workflows/`).
- Production secrets rotation (see `procedures/secrets-rotation.md`).
- Third-party dependencies (`pyproject.toml`, `package.json`).

Out of scope: content-only changes to marketing pages, internal documentation edits that do not touch production runtime.

## 3. Change Types

- **Standard change.** Pre-approved, low-risk, frequently executed. Examples: routine dependency bumps by Dependabot, auto-scaling parameter changes within defined bounds. Requires code review but no separate change ticket.
- **Normal change.** Most changes. Requires a pull request, review, CI pass, and staging verification before production deploy.
- **Emergency change.** Needed to resolve or prevent a SEV1/SEV2 incident. May bypass staging with IC approval, but must be documented in the incident war room and retroactively reviewed within 2 business days.

## 4. Pull Request Requirements

Every PR into the `main` branch must:

1. Be opened against an issue or ticket (PR body must link it).
2. Pass the full CI pipeline: ruff, mypy, bandit, pytest, coverage >= 80% on changed lines, pre-commit hooks.
3. Have **at least one** approving review from a code owner who is not the author.
4. For changes touching `src/shieldops/auth/`, `src/shieldops/policy/`, `src/shieldops/db/migrations/`, or `policies/opa/`: **a security review** by the Head of Security or delegate is additionally required. The `code-owners` file enforces this.
5. Be rebased onto a current `main` (no merge commits).
6. Include tests for new behavior. Infrastructure changes include a `terraform plan` artifact attached to the PR.

See `procedures/code-review.md` for the reviewer checklist.

## 5. CI/CD Pipeline

The platform uses 7 GitHub Actions workflows in `.github/workflows/`. The canonical promotion path is:

```
feature branch -> PR -> CI -> merge to main ->
  cd-staging (auto) -> smoke + integration tests ->
    cd-production (manual approval) -> post-deploy checks
```

- **Promotion to staging is automatic** on merge to `main`.
- **Promotion to production requires manual approval** by an engineer with the `deploy:prod` permission in the GitHub environment `production`. The approver must not be the PR author (segregation of duties).
- All production deploys emit an `audit_log` entry with `action="deployment"`.

See `procedures/deployment-approval.md` for the step-by-step procedure.

## 6. Database Changes

- All schema changes are Alembic migrations. No manual SQL on production.
- Migrations are reviewed with extra scrutiny: a second engineer must sign off on any migration that drops a column, renames a column, or adds a non-null column without a default.
- Destructive migrations (DROP TABLE, DROP COLUMN) require CTO approval and must be paired with a preceding deprecation release.
- Migrations run during the staging deploy. Production migrations run in a dedicated job that can be rolled back via `alembic downgrade`.

## 7. Infrastructure Changes

- Terraform is the source of truth for cloud resources. Click-ops is prohibited in production. Drift is detected by `scripts/terraform_drift_check.py`, which runs nightly.
- `terraform plan` output is posted as a PR comment by CI. The plan must be empty of destructive operations unless explicitly called out in the PR body.
- `terraform apply` runs in the `cd-production` workflow after manual approval.

## 8. Rollback

- Every production deploy must be rollback-able within 15 minutes.
- Rollback path: previous container image tag + previous migration revision. For irreversible migrations, a forward-fix release is prepared before the original change lands (feature flagged).
- Feature flags (LaunchDarkly or the internal `config/feature_flags.py`) are the preferred rollback mechanism for behavioral changes.
- Rollback is an IC decision during an incident; outside incidents, it is the on-call engineer's decision with one additional approver.

## 9. Freeze Windows

- **Holiday freeze:** December 20 through January 2. Only emergency changes permitted.
- **Pre-audit freeze:** 48 hours before an external audit evidence collection window.
- **Customer-specific:** Enterprise contracts may specify freeze windows; these are honored via per-tenant deploy guards.

## 10. Audit Trail

Every change produces durable artifacts:

- Git history on the `main` branch (signed commits required for production deploy eligibility).
- PR metadata retained by GitHub (author, reviewers, timestamps, CI results).
- Deploy records in the `audit_log` table.
- Terraform state and plan archives in `s3://shieldops-terraform-state/`, versioned.

The quarterly access review (`procedures/access-review.md`) includes a sample review of changes to validate the process.

## 11. Enforcement and Exceptions

See `policies/access-control.md` §10 and §11.

## 12. References

- `policies/access-control.md`
- `policies/incident-response.md`
- `procedures/code-review.md`
- `procedures/deployment-approval.md`
- `procedures/backup-and-restore.md`
- SOC 2 TSC: CC8.1.
