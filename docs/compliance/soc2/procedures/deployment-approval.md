# Procedure: Deployment Approval

**Document ID:** SHIELDOPS-PROC-CM-002
**Version:** 1.1
**Owner:** Head of Engineering (interim: CTO)
**Related Policy:** `policies/change-management.md`
**Last Reviewed:** 2026-04-01

## 1. Purpose

Define how changes are promoted from `main` to staging and from staging to production, including who approves, what they check, and how the approval is recorded.

## 2. Environments

| Environment | URL                         | Purpose                               | Promotion trigger                       |
|-------------|-----------------------------|---------------------------------------|-----------------------------------------|
| Development | per-dev ephemeral           | Individual developer testing          | Manual                                  |
| Staging     | `staging.shieldops.io`      | Integration testing, smoke tests      | Automatic on merge to `main`            |
| Production  | `api.shieldops.io`          | Customer-serving                      | Manual approval from the production env |

## 3. Staging Deploy (Automatic)

Triggered by the GitHub Actions workflow `cd-staging.yml` on push to `main`.

Steps (enforced by CI):

1. Build container image, tag with commit SHA, push to ECR.
2. Run Alembic migrations against the staging database.
3. `kubectl rollout restart deploy/shieldops-api -n staging`.
4. Wait for rollout readiness.
5. Run the smoke test suite (`pytest tests/smoke/ -m staging`).
6. Run the integration suite (`pytest tests/integration/ -m staging`) against a scratch tenant.
7. Post the commit SHA, PR link, and test results to `#deploys` in Slack.

A red smoke or integration run blocks production promotion until resolved.

## 4. Production Deploy (Manual Approval)

Triggered by the GitHub Actions workflow `cd-production.yml`.

### 4.1 Who can approve

- Any engineer with the `deploy:prod` GitHub team membership.
- The approver **must not** be the author of any commit included in the deploy. Segregation of duties is enforced by the workflow itself.
- Emergency deploys during a SEV1/SEV2 may waive the author restriction with IC sign-off; the waiver is logged.

### 4.2 Pre-deploy checks

Before clicking approve, the approver verifies:

- [ ] Staging deploy of the same SHA is green.
- [ ] No active SEV1 or SEV2 incidents.
- [ ] Not inside a freeze window (`policies/change-management.md` §9).
- [ ] No destructive Alembic operations in the included migrations; or, if present, there is a preceding deprecation release and CTO sign-off.
- [ ] The Terraform plan attached to the PR (if infra change) is non-destructive or explicitly called out.
- [ ] On-call engineer is aware and available for the next 2 hours.

### 4.3 Deploy steps (enforced by CI)

1. Record a `audit_log` entry: `action="deployment_start"`, `actor=<approver>`, target commit SHA, list of included PRs.
2. Run Alembic migrations against production (in a job that can be canceled).
3. Blue/green rollout of the API and worker deployments (Kubernetes rolling update with `maxSurge=25%`, `maxUnavailable=0`).
4. Wait for `/healthz` to return 200 on all new pods.
5. Run the post-deploy smoke test.
6. Record `action="deployment_complete"` with duration, status, and error if any.
7. Update Sentry release marker.
8. Post to `#deploys` with a summary and a rollback command.

### 4.4 Post-deploy monitoring

The approver or the author (whichever is on deck) watches:

- Error rates in Sentry and Datadog for 30 minutes after deploy.
- Latency p95/p99 and saturation metrics on the dashboards.
- Customer-reported issues in `#support`.

If any metric degrades, the on-deck engineer triggers rollback (below).

## 5. Rollback

Rollback must be possible within 15 minutes.

### 5.1 Code rollback

```
gh workflow run cd-production.yml \
  -f commit_sha=<previous-sha> \
  -f reason="rollback: <short reason>"
```

This reuses the cd-production workflow but skips the manual approval gate only when `reason` starts with `rollback:` and the specified SHA is the immediately previous production deploy.

### 5.2 Migration rollback

```
alembic downgrade -1
```

Only when the migration is reversible. Irreversible migrations require forward-fix releases.

### 5.3 Feature flag rollback

Preferred for behavioral regressions. Toggle the flag in LaunchDarkly or the internal `config/feature_flags.py`. No deploy required.

## 6. Audit Trail

Every production deploy leaves a durable record:

- GitHub Actions run (1-year retention by default; extended to 7 years via export to S3 via `scripts/gh_actions_archive.py`).
- `audit_log` entries (7-year retention).
- PagerDuty change event (for correlation with alerts).
- Sentry release marker.

`scripts/audit/collect_evidence.py --section deployments` produces the deployment history for the audit window.

## 7. Exceptions

Any deviation from this procedure is recorded in `docs/compliance/soc2/exceptions.md` with justification and compensating controls.
