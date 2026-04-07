# ShieldOps Runbooks

Operational runbooks for ShieldOps platform engineers, customer success engineers, and on-call operators. Each runbook is a tested, step-by-step procedure with clear prerequisites, commands, exit criteria, and a rollback path.

## Index

### Platform operations

| Runbook | Purpose |
|---|---|
| [`deploy-new-version.md`](deploy-new-version.md) | Deploy a new version of the ShieldOps API / worker / dashboard to production ECS |
| [`rollback-deployment.md`](rollback-deployment.md) | Roll back a failed deployment |
| [`scale-up-down.md`](scale-up-down.md) | Manually scale services in response to load |
| [`investigate-high-error-rate.md`](investigate-high-error-rate.md) | Triage and root-cause an elevated error rate |
| [`database-backup-restore.md`](database-backup-restore.md) | Backup and restore PostgreSQL |
| [`rds-failover.md`](rds-failover.md) | Failover RDS to a standby |
| [`redis-flush.md`](redis-flush.md) | Flush Redis caches safely |
| [`kafka-topic-management.md`](kafka-topic-management.md) | Create, alter, and delete Kafka topics |

### SIEM migration (design partner engagements — issue #240)

For customer migrations from Splunk Enterprise Security to ShieldOps. These runbooks are the authoritative AFK artifacts for the design-partner SIEM cutover engagements; the live cutover is human-led.

| Runbook | Purpose |
|---|---|
| [`siem-migration.md`](siem-migration.md) | End-to-end 6–8 week Splunk → ShieldOps migration playbook (7 phases) |
| [`siem-cutover-checklist.md`](siem-cutover-checklist.md) | Tick-by-tick cutover checklist + 15-minute rollback plan |
| [`siem-cost-comparison.md`](siem-cost-comparison.md) | ROI worksheet with worked example for a 100 GB/day customer |

Companion artifacts:
- [`../../scripts/migration/parallel_run_validator.py`](../../scripts/migration/parallel_run_validator.py) — Splunk ↔ ShieldOps parity validator (used in phases 1, 2, 6). Supports live mode with real Splunk REST + ShieldOps NL Query API and mock fallback for offline previews.
- [`../../scripts/migration/queries.sample.json`](../../scripts/migration/queries.sample.json) — Sample query set for the validator
- [`../customer-stories/siem-migration-template.md`](../customer-stories/siem-migration-template.md) — Post-migration customer success story template (legal review required before publication)

Quickstart for a parity preview without credentials:
```bash
python scripts/migration/parallel_run_validator.py \
    --mock \
    --queries scripts/migration/queries.sample.json \
    --out reports/parity-preview.md
```

## Conventions

- Every runbook starts with: purpose, when to use, prerequisites, steps, rollback, references.
- Every command is copy-pasteable. Substitute placeholders are wrapped in `<ANGLE_BRACKETS>`.
- Every destructive command is preceded by a verification step.
- Every runbook references the specific code paths in `src/shieldops/` it touches.
- Update the changelog at the bottom of each runbook on every meaningful change.

## Contributing

When you add or update a runbook:
1. Validate every command on a non-production environment.
2. Add the runbook to the index above.
3. Get a peer review from someone who has not run the procedure before.
4. Link the runbook from the relevant agent / engine / connector code via a `# RUNBOOK:` comment.
