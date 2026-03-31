# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ShieldOps is an AI Security Control Plane that governs, monitors, and responds to AI agent activity across enterprise infrastructure. The platform deploys autonomous security agents for runtime interception, non-human identity governance, MCP ecosystem security, and SOC automation — across multi-cloud (AWS/GCP/Azure) and on-premise environments.

**Core thesis:** The security control plane for AI agents. Intercepts tool calls, governs non-human identities, secures MCP ecosystems, and automates SOC operations — with policy gates at every layer.

## Build & Development Commands

```bash
# Install dependencies
pip install -e ".[dev]"

# Run all tests
python3 -m pytest tests/ -v --tb=short

# Run a single test file
python3 -m pytest tests/unit/test_<module>.py -v

# Run tests with coverage
python3 -m pytest tests/ -v --cov=src/shieldops

# Linting and formatting
ruff check src/ tests/ --fix
ruff format src/ tests/

# Type checking
mypy src/shieldops/

# Security scan
bandit -c pyproject.toml -ll -r src/

# Pre-commit hooks (ruff lint+format, mypy, bandit, trailing whitespace, etc.)
pre-commit run --all-files

# Start API server
uvicorn shieldops.api.main:app --reload

# CLI
shieldops --help
```

## Architecture

### Four Layers
1. **Connector Layer** — 17 connectors across cloud, EDR, SIEM, observability, incident, and ITSM platforms (`src/shieldops/connectors/{provider}/`)
2. **Observability Ingestion** — Vendor-neutral OpenTelemetry (Splunk, Datadog, Prometheus)
3. **Agent Orchestration** — LangGraph-based agents with graph→nodes→tools pattern
4. **Policy & Safety** — OPA policies, approval workflows, rollback, compliance

### Agent Architecture (LangGraph)
Each agent in `src/shieldops/agents/{type}/` follows this structure:
```
graph.py      # LangGraph StateGraph definition — nodes + edges + routing
nodes.py      # Node function implementations (investigate, act, validate)
tools.py      # Tool functions called by nodes (API calls, infra ops)
models.py     # Pydantic state/input/output models
prompts.py    # LLM prompt templates
runner.py     # Entry point — lifecycle management, execution
policy.py     # OPA policy integration (optional)
```

There are 451 LangGraph agents across security, observability, operations, compliance, and intelligence domains. Key agents include: investigation, remediation, security, learning, supervisor, soc_analyst, threat_hunter, forensics, deception, incident_response, attack_surface, ml_governance, finops_intelligence, zero_trust, threat_automation, soar_orchestration, itdr, auto_remediation, observability_intelligence, xdr, intelligent_automation, platform_intelligence, security_convergence, autonomous_defense, chatops, enterprise_integration, automation_orchestrator, cost, prediction, otel_pipeline, risk_scoring, auto_learning, security_automation, gitops, telemetry_optimizer, threat_intel, incident_commander, compliance_auditor, otel_collector_manager, adaptive_security, otel_deployer, security_posture, otel_semantic, soar_workflow, otel_tail_sampling, detection_engineering, otel_metrics_pipeline, security_testing, otel_logs_pipeline, threat_modeling, ai_runtime_defense, soc_brain, identity_graph, ai_red_team, ai_blue_team, agent_firewall, nhi_registry, mcp_security, data_pipeline_security, credential_lifecycle, vendor_normalizer, attack_campaign, situation_composer, compliance_reporter, oauth_analyzer, lateral_movement, shadow_ai_discovery, secrets_scanner, api_security, policy_engine, cloud_posture, container_security, supply_chain_security, incident_triage, change_risk_analyzer, cost_anomaly, adversarial_validation, mcp_gateway, service_account_tracker, data_classification, access_review, runbook_automation, capacity_planner, disaster_recovery, log_analyzer, chaos_engineering, sla_monitor, config_validator, network_segmentation, workflow_engine, alert_correlation, performance_profiler, anomaly_detector, certificate_manager, dns_security, backup_validator, vulnerability_manager, compliance_scanner, threat_response, agent_governance, model_security, prompt_shield, multi_agent_security, ai_compliance, digital_twin_security, agentic_mdr, breakout_defender, ai_triage_accelerator, soc_transformation, cloud_risk_ranker, data_loss_prevention, autonomous_xdr, autonomous_soc, cnapp_analyzer, zero_trust_network, intelligent_soar, malware_analyzer, cyber_recovery, data_threat_hunting, sensitive_data_monitor, identity_protection, exposure_management, ai_soc_assistant, log_intelligence, insider_threat, ransomware_forensics, threat_intelligence_platform, code_security_scanner, data_resilience, managed_threat_hunting, vulnerability_intelligence, file_integrity_monitor, iot_ot_security, security_app_builder, air_gap_vault, agent_memory_store, reflection_engine, supply_chain_scanner, cross_vendor_correlator, situation_manager, trust_relationship_mapper, it_asset_intelligence, ai_runtime_guardian, data_intelligence, endpoint_dlp, unified_cloud_security, backup_security_posture, access_remediation, adversary_emulator, agent_fleet_optimizer, ai_bias_scanner, alert_enrichment_engine, anomaly_prediction_engine, api_gateway_security, api_pentest, api_rate_limiter, apt_emulator, artifact_integrity_checker, asset_inventory, attack_path_analyzer, attack_readiness_assessor, audit_trail_analyzer, auto_ticket_manager, automated_pentest, bandwidth_anomaly_detector, behavioral_analytics_engine, brand_protection_scanner, browser_isolation, building_management_security, calibration, capacity_intelligence, cctv_analytics, ci_cd_security_auditor, cloud_audit_logger, cloud_cost_optimizer, cloud_identity_federation, cloud_migration_planner, cloud_pentest, cloud_permission_auditor, cloud_storage_scanner, cloud_workload_protector, communication_auditor, compliance_automation_engine, compliance_gap_analyzer, compliance_workflow, config_remediation, configuration_auditor, consent_manager, container_image_scanner, continuous_scanner, credential_rotation_manager, credential_tester, crypto_agility_manager, custom, custom_agent_factory, dark_web_monitor, dast_runner, data_breach_responder, data_encryption_monitor, data_lineage_tracker, data_masking_engine, data_pipeline_protector, data_retention_enforcer, data_sovereignty_enforcer, database_security_scanner, deepfake_detector, defense_in_depth_auditor, dependency_graph_analyzer, deployment_guardian, detection_gap_finder, email_dlp_monitor, email_gateway_analyzer, endpoint_behavior_monitor, endpoint_forensics, endpoint_protection_manager, environmental_monitor, evidence_automation_engine, evidence_collector, evolution, executive_reporter, federated_learning_security, finding_correlator, finops_forecaster, firewall_rule_auditor, gdpr_processor, governance_dashboard, health_check_orchestrator, hipaa_monitor, hunt_hypothesis_generator, iac_security_scanner, iam_policy_analyzer, incident_communicator, incident_cost_calculator, incident_escalation_engine, incident_playbook_engine, incident_playbook_generator, incident_prediction_engine, incident_similarity_engine, incident_simulator, incident_timeline_builder, industrial_protocol_analyzer, inference_attack_detector, infrastructure_drift_detector, ioc_enrichment_engine, ioc_lifecycle, ir_playbook_engine, iso27001_assessor, just_in_time_access, key_lifecycle_manager, kill_chain_analyzer, micro_segmentation_planner, mitre_coverage_analyzer, mobile_device_manager, model_drift_detector, model_explainability_auditor, multi_cloud_compliance, multi_cloud_orchestrator, network_forensics, network_pentest, network_traffic_analyzer, nist_framework_mapper, observability_pipeline_optimizer, on_call_optimizer, open_source_license_scanner, orphan_account_detector, packet_inspector, patch_compliance_checker, patch_orchestrator, pci_scanner, performance_baseline_engine, permission_creep_analyzer, phishing_email_analyzer, phishing_simulator, physical_access_monitor, playbook_optimizer, post_incident_analyzer, postmortem_generator, predictive_scaler, privacy_consent_manager, privacy_engineering, privacy_impact_assessor, privilege_escalation_detector, privileged_session_recorder, purple_team_orchestrator, quantum_risk_assessor, rate_limit_enforcer, regulatory_change_tracker, remediation_orchestrator, remediation_verifier, resource_rightsizer, response_automation_engine, risk_prioritizer, risk_quantification_engine, root_cause_analyzer, runbook_knowledge_base, sast_scanner, sbom_analyzer, sca_dependency_checker, scada_security_analyzer, secret_rotation_manager, secrets_in_code_detector, security_app_builder, security_architecture_reviewer, security_awareness, security_awareness_engine, security_awareness_trainer, security_control_mapper, security_copilot, security_dashboard_aggregator, security_data_lake, security_metrics_collector, security_pipeline, security_scorecard, sensitive_data_monitor, serverless_security, service_dependency_mapper, service_health_monitor, session_hijack_detector, session_manager, shift_handoff_manager, sla_breach_predictor, sla_violation_detector, soc_metrics_analyzer, soc_metrics_dashboard, social_engineering_detector, sox_auditor, spam_filter_manager, stakeholder_notifier, threat_attribution, threat_brief_generator, threat_correlation_engine, threat_feed_aggregator, threat_feed_manager, threat_hunt_automation, threat_landscape_mapper, threat_scenario_runner, threat_surface_minimizer, ticket_automation, tokenization_manager, training_data_validator, usb_device_controller, vendor_compliance_assessor, vendor_risk_assessor, vulnerability_lifecycle, vulnerability_prioritizer, vulnerability_remediation, waf_manager, war_gaming_simulator, war_room_automator, war_room_coordinator, web_app_scanner, zero_trust_validator.

### Engine Module Pattern
The bulk of the codebase (~1,780+ modules) are analytics/intelligence engines across 13 packages. Each follows a strict pattern:
```python
# 3 StrEnum classes, 3 Pydantic models (Record, Analysis, Report)
# Engine class with: add_record()/record_item(), process(key),
#   generate_report(), get_stats(), clear_data(), 3 domain methods
# Ring-buffer storage with max_records eviction
```
- `add_record(**kwargs)` for: analytics, observability, security, knowledge, sla, billing, incidents, compliance
- `record_item(**kwargs)` for: changes, operations, topology

### Key Packages
| Package | Purpose | Count |
|---------|---------|-------|
| `security/` | Threat detection, SOAR, XDR, identity, AI security, DLP, agent governance, model security, prompt defense, multi-agent trust, ransomware forensics, vulnerability intelligence | 551 |
| `analytics/` | DORA, AIOps, root cause, agent benchmarking, swarm intelligence, hunt analytics, productivity metrics | 276 |
| `observability/` | Alert intelligence, telemetry, SLI/SLO, OTel pipeline, sampling, cardinality, eBPF, collector fleet, backpressure, span-to-metric | 232 |
| `operations/` | Runbooks, automation, chaos, capacity, SIEM migration, playbook effectiveness, app deployment | 177 |
| `compliance/` | Evidence, audit, regulatory, AI compliance (EU AI Act, NIST AI RMF, ISO 42001), data encryption | 116 |
| `incidents/` | Triage, escalation, postmortem, on-call burden, notification | 88 |
| `billing/` | FinOps, cost optimization, RI planning, waste classification | 87 |
| `changes/` | GitOps, IaC validation, deployment intelligence, canary | 66 |
| `topology/` | Service mesh, dependencies, API lifecycle, traffic patterns | 65 |
| `sla/` | SLO tracking, error budgets, reliability, API SLA compliance | 54 |
| `audit/` | Audit trails, evidence, compliance mapping, governance | 30 |
| `knowledge/` | Knowledge base, onboarding, feedback, agent knowledge distillation | 27 |
| `config/` | Feature flags, drift analysis, validation | 11 |

### API & Dashboard
- FastAPI at `src/shieldops/api/` — RESTful, versioned `/api/v1/`, JWT auth, OpenAPI auto-gen
- React + TypeScript + Tailwind dashboard at `dashboard-ui/`
- **Design System**: Surface-based depth hierarchy (surface-0 through surface-4), opacity-based borders (`rgba(255,255,255,0.XX)`), brand cyan accent, Inter + JetBrains Mono typography. Premium component library: `btn-primary` (gradient + glow), `btn-secondary`, `card-surface`, `card-interactive` (hover-lift), `tab-bar`, `section-heading`. CSS custom properties for `--border-subtle/default/strong` and `--surface-*` tokens.
- Situations Queue (outcome-centric UX replacing widget dashboards)
- Agent Firewall SDK at `src/shieldops/sdk/` — Python SDK for LangChain, CrewAI, LlamaIndex interception
- Agent Firewall Monitor (runtime tool call interception dashboard)
- NHI Registry (non-human identity inventory and risk dashboard)
- MCP Security (MCP ecosystem security with God Key detection)
- Notification integrations: Slack, Teams, PagerDuty, email, SMS, voice, webhooks

### SDK
- Agent Firewall SDK at `src/shieldops/sdk/` — one-line integration with AI agent frameworks
- Supports: LangChain (`ShieldOpsCallbackHandler`), CrewAI (`ShieldOpsCrewAIWrapper`), LlamaIndex
- Modes: audit (observe only) or enforce (block risky calls)
- OTEL-compatible telemetry export to any collector (Splunk, Datadog, etc.)

### Connectors (17 total)
- **Cloud**: AWS (`connectors/aws/`), GCP, Azure, Kubernetes, Linux, Windows
- **Security**: CrowdStrike (OAuth2 + RTR), Microsoft Defender (MSAL + KQL), Wiz (GraphQL + attack paths)
- **Observability**: Splunk (REST + HEC + SPL + ITSI), Elastic (DSL + EQL + SIEM), Datadog (metrics + logs + monitors), New Relic (NerdGraph + NRQL + SLIs)
- **Incident**: PagerDuty (REST + Events API v2), OpsGenie (alerts + on-call)
- **ITSM**: ServiceNow (Table API + CMDB + change requests), Jira (REST v3 + JQL)

### Self-Evolution Framework
Agents can self-improve via a closed-loop evolution system in `src/shieldops/utils/`:
- **`deep_agent.py`** — `DeepAgentMixin` gives any agent self-evolving capabilities (pre/post-execute hooks, fitness tracking, prompt mutation)
- **`fitness_tracker.py`** — Multi-dimensional fitness scoring (accuracy 0.30, safety 0.30, speed 0.15, learning_rate 0.15, cost 0.10) with rolling windows and trend detection
- **`prompt_evolution.py`** — Prompt versioning, A/B testing (champion vs challenger), automatic promotion/demotion, lineage tracking
- **`learning_bus.py`** — Cross-agent pub/sub learning propagation with 10 event types and 4 scopes (SELF_ONLY → FLEET_WIDE)
- **`evolution/`** agent — Orchestrates evolution cycles: measure fitness → analyze patterns → evolve prompts → propagate learnings → deploy → validate
- API routes at `src/shieldops/api/routes/evolution.py` (fitness leaderboard, prompt lineage, A/B tests, learning events)

## Tech Stack
- Python 3.12+, LangGraph, LangChain, Anthropic Claude (primary LLM)
- Multi-cloud LLM: Anthropic (direct), AWS Bedrock (Strands SDK), Google Vertex AI, Azure OpenAI
- FastAPI, Pydantic v2, SQLAlchemy (async), PostgreSQL, Redis, Kafka
- OpenTelemetry, LangSmith, structlog
- OPA (Open Policy Agent) for policy enforcement
- Terraform/OpenTofu, Kubernetes
- React, TypeScript, Tailwind CSS (dashboard)
- pytest, pytest-asyncio, playwright (e2e)
- GitHub Actions CI/CD

## Development Conventions

### Code Standards
- **Ruff** for lint + format (line-length=100, target py312)
- **mypy** strict mode — type hints required on all public functions
- **Pydantic v2** models for all data structures
- **structlog** for structured logging
- **async/await** for all I/O operations
- Pre-commit hooks: ruff, ruff-format, mypy, bandit, trailing-whitespace, end-of-file-fixer

### Testing
- Unit tests: `tests/unit/` (mirror source structure)
- Integration tests: `tests/integration/` (require Docker)
- Agent simulations: `tests/agents/` (replay historical incidents)
- Minimum 80% coverage on new code

### Git
- Branch naming: `feat/`, `fix/`, `chore/`, `docs/`
- Commit messages: conventional commits (`feat:`, `fix:`, `chore:`, `docs:`)
- PRs require passing CI + 1 review

### Security (Non-Negotiable)
- Never hardcode credentials — use env vars or secret managers
- All agent actions must pass OPA policy evaluation before execution
- Audit trail for every infrastructure change (immutable log)
- Blast-radius limits enforced per environment (dev/staging/prod)
- No agent can delete databases, drop tables, or modify IAM root policies
- Confidence thresholds: autonomous >0.85, human approval 0.5-0.85, escalate <0.5

## Infrastructure
- **CI/CD**: 7 GitHub Actions workflows (ci.yml, cd-backend.yml, cd-dashboard.yml, cd-staging.yml, cd-production.yml, gitops-sync.yml)
- **Kubernetes**: 16 manifests in `infrastructure/kubernetes/` (deployment, HPA, ingress, network policies, PDB, Kafka, Redis, OPA sidecar, secrets, configmaps)
- **Terraform**: `infrastructure/terraform/{aws,gcp,azure}/` — validated in CI
- **Docker**: `infrastructure/docker/Dockerfile` + `docker-compose.yml`
- **Helm**: `infrastructure/helm/` — chart for self-hosted deployments
- **Database**: `src/shieldops/db/` — SQLAlchemy models, Alembic migrations, async sessions, repository pattern
- **Monitoring**: `infrastructure/monitoring/`

## Productionization Status
- **Phase AZ (latest)**: 451 agents, 1,780 engine modules, 888 API routes, 455 dashboard pages
- **LLM Wiring**: Done — all agents wired with `llm_structured()` via `src/shieldops/utils/llm.py`
- **Self-Evolution**: Agent fitness tracking, prompt A/B testing, cross-agent learning bus
- LLM Router at `src/shieldops/utils/llm_router.py` (Haiku/Sonnet/Opus complexity routing)
- Cloud connectors have real SDK implementations (boto3, google-cloud, azure, kubernetes-client)
- 14 API middleware modules (rate limiter, tenant isolation, billing enforcement, security headers)
- See `docs/tasks.md` for remaining GA checklist (integration tests, pentest, SOC 2, docs site)

## Environment Variables
```
ANTHROPIC_API_KEY=     # Claude API key (primary LLM)
OPENAI_API_KEY=        # Fallback LLM
DATABASE_URL=          # PostgreSQL connection
REDIS_URL=             # Redis connection
KAFKA_BROKERS=         # Kafka broker list
OPA_ENDPOINT=          # OPA policy engine URL
LANGSMITH_API_KEY=     # Agent tracing
STRIPE_SECRET_KEY=     # Billing integration
STRIPE_WEBHOOK_SECRET= # Stripe webhooks
SLACK_BOT_TOKEN=       # ChatOps approvals
PAGERDUTY_API_KEY=     # Alert ingestion
VAULT_ADDR=            # Secret management
```

## Custom Slash Commands

### General Development
`/build`, `/test`, `/deploy`, `/scan`, `/review`, `/analyze`, `/design`, `/task`

### Agent Lifecycle
`/build-agent`, `/run-agent`, `/review-agent`, `/deploy-agent`, `/secure-agents`

### Security Operations
`/scan-security`, `/manage-soc`, `/hunt-threats`, `/respond-incident`, `/run-xdr`, `/run-redteam`, `/run-forensics`, `/orchestrate-soar`

### Governance & Compliance
`/audit-compliance`, `/manage-identity`, `/manage-mcp`, `/protect-data`, `/manage-vulns`

### Infrastructure & Platform
`/manage-otel`, `/manage-gitops`, `/manage-cloud`, `/manage-costs`, `/manage-sla`, `/check-health`

### Analytics & Intelligence
`/analyze-analytics`, `/analyze-topology`, `/manage-knowledge`

### Scaffolding & Integration
`/add-connector`, `/add-integration`, `/create-playbook`, `/design-system`, `/context-hub`
