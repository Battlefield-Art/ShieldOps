# Manage Knowledge Skill

Manage organizational knowledge — knowledge base, agent learning, onboarding, incident knowledge graphs, and expertise mapping.

## Usage
`/manage-knowledge <action> [--topic <name>] [--type <runbook|incident|procedure|onboarding>]`

Actions: `search`, `create`, `review`, `gaps`, `onboard`, `distill`, `status`

## Agents Used
- `knowledge` — Knowledge base management and retrieval
- `learning` — Agent learning and improvement
- `auto_learning` — Autonomous agent self-improvement loops
- `reflection_engine` — Self-evaluation and learning loops
- `agent_memory_store` — Persistent episodic memory across agents
- `incident_learning` — Incident-driven learning and pattern extraction

## Process

### Search (Knowledge Retrieval)
1. **Query**: Search across runbooks, incidents, procedures, compliance docs
2. **Rank**: Relevance-score results by context
3. **Enrich**: Add related context from incident history
4. **Serve**: Return knowledge with freshness indicators

```python
from shieldops.knowledge.article_manager import KnowledgeBaseManager

manager = KnowledgeBaseManager()
results = manager.search(
    query="OOMKilled pod remediation kubernetes",
    types=["runbook", "incident_history"],
    max_results=5,
)
```

### Gaps (Knowledge Gap Analysis)
1. **Detect gaps**: Identify topics with missing or stale documentation
2. **Prioritize**: Rank gaps by incident frequency and team impact
3. **Assign**: Suggest authors based on expertise mapping
4. **Track**: Monitor gap closure over time

```python
from shieldops.knowledge.knowledge_gap_detector import KnowledgeGapDetector

detector = KnowledgeGapDetector()
detector.add_record(
    topic="redis_connection_pool_tuning",
    incident_frequency=12, has_runbook=False,
    last_incident="2026-03-20",
)
report = detector.generate_report()
```

### Onboard (Developer Onboarding)
1. **Generate path**: Create personalized onboarding path for new team members
2. **Track progress**: Monitor onboarding completion
3. **Assess**: Knowledge checks at milestones
4. **Feedback**: Collect and incorporate onboarding feedback

```python
from shieldops.knowledge.developer_onboarding_engine import DeveloperOnboardingEngine

engine = DeveloperOnboardingEngine()
engine.add_record(
    developer="new-hire-1", team="platform",
    role="sre", start_date="2026-03-26",
    assigned_topics=["k8s_operations", "incident_response", "otel_pipelines"],
)
report = engine.generate_report()
```

### Distill (Agent Knowledge Distillation)
1. **Extract**: Pull patterns from agent decision history
2. **Generalize**: Identify reusable knowledge from specific incidents
3. **Codify**: Convert patterns into runbooks or detection rules
4. **Share**: Distribute distilled knowledge to all agents

```python
from shieldops.knowledge.agent_knowledge_distiller import AgentKnowledgeDistiller

distiller = AgentKnowledgeDistiller()
distiller.add_record(
    agent_type="soc_analyst", decision="escalate",
    context="repeated_failed_logins_from_tor",
    outcome="confirmed_attack", confidence=0.95,
)
report = distiller.generate_report()
```

### Review (Knowledge Quality)
1. **Freshness**: Identify stale articles not updated in >90 days
2. **Quality**: Score articles by completeness, accuracy, usage
3. **Decay**: Detect knowledge that's becoming less relevant
4. **Improve**: Generate improvement recommendations

## Key Files
- `src/shieldops/knowledge/` — 27 knowledge engines
- `src/shieldops/knowledge/article_manager.py` — Knowledge base manager
- `src/shieldops/knowledge/agent_knowledge_distiller.py` — Agent distillation
- `src/shieldops/knowledge/developer_onboarding_engine.py` — Onboarding engine
- `src/shieldops/knowledge/knowledge_gap_detector.py` — Gap detection
- `src/shieldops/knowledge/knowledge_decay.py` — Knowledge decay detection
- `src/shieldops/knowledge/knowledge_freshness_scorer.py` — Freshness scoring
- `src/shieldops/knowledge/knowledge_quality_assessor.py` — Quality assessment
- `src/shieldops/knowledge/incident_knowledge_graph_engine.py` — Incident knowledge graph
- `src/shieldops/knowledge/expertise_mapper.py` — Expertise mapping
- `src/shieldops/knowledge/platform_knowledge_graph_engine.py` — Platform knowledge graph
- `src/shieldops/knowledge/learning_feedback_loop_engine.py` — Learning feedback loops
- `src/shieldops/knowledge/knowledge_silo_detector.py` — Silo detection

## Related Agents
- `src/shieldops/agents/knowledge/` — Knowledge management agent
- `src/shieldops/agents/learning/` — Learning agent
- `src/shieldops/agents/auto_learning/` — Auto-learning agent
- `src/shieldops/agents/reflection_engine/` — Reflection engine agent
- `src/shieldops/agents/agent_memory_store/` — Memory store agent
- `src/shieldops/agents/incident_learning.py` — Incident learning module
- `src/shieldops/agents/knowledge_mesh.py` — Knowledge mesh module

## Conventions
- Knowledge articles must have: owner, last_reviewed, freshness_score
- Articles not reviewed in 90 days marked as stale automatically
- Agent knowledge distillation runs after every 100 agent decisions
- Onboarding paths must be completed within 30 days
- Knowledge gaps with >5 related incidents are flagged as critical
- All knowledge changes logged to audit trail
