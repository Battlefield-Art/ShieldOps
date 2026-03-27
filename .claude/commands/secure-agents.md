# Secure Agents Skill

Manage AI agent security — firewall policies, governance boundaries, prompt defense, model security, and multi-agent trust.

## Usage
`/secure-agents <action> [--agent <type>] [--policy <name>] [--mode <audit|enforce>]`

Actions: `firewall`, `govern`, `shield`, `model-check`, `trust`, `runtime`, `status`

## Agents Used
- `agent_firewall` — Runtime tool call interception and policy enforcement
- `agent_governance` — Capability boundaries, escalation chains, runtime policy
- `multi_agent_security` — Trust chains, communication auditing, impersonation detection
- `prompt_shield` — Multi-layer injection defense (regex + semantic + behavioral + LLM)
- `model_security` — Model integrity verification, backdoor detection, supply chain provenance
- `ai_runtime_defense` — Runtime AI defense with behavioral monitoring
- `ai_red_team` — Adversarial testing of AI agent behaviors
- `ai_blue_team` — Defensive monitoring and hardening of AI agents
- `agent_memory_store` — Persistent episodic memory security and governance

## Process

### Firewall (Agent Tool Call Interception)
1. **Configure policies**: Define allowed/blocked tool calls per agent type
2. **Set mode**: Audit (observe only) or Enforce (block risky calls)
3. **Deploy SDK**: Integrate `ShieldOpsCallbackHandler` into agent frameworks
4. **Monitor**: Track intercepted calls, policy violations, risk scores

```python
from shieldops.sdk.firewall import AgentFirewall, FirewallPolicy

firewall = AgentFirewall(mode="enforce")
firewall.add_policy(FirewallPolicy(
    agent_type="remediation",
    blocked_actions=["delete_database", "drop_table", "modify_iam_root"],
    max_blast_radius="single_pod",
    require_approval_above=0.7,
))
```

### Govern (Agent Governance)
1. **Define capabilities**: Set capability boundaries per agent type
2. **Configure escalation**: Define escalation chains for high-risk actions
3. **Set resource limits**: CPU, memory, API call budgets per agent
4. **Audit trail**: Enable comprehensive decision logging

```python
from shieldops.agents.agent_governance.runner import AgentGovernanceRunner

runner = AgentGovernanceRunner()
result = await runner.assess(
    agent_type="remediation",
    environment="production",
    check_capabilities=True,
    check_escalation=True,
)
```

### Shield (Prompt Defense)
1. **Scan prompts**: Multi-layer injection detection (regex, semantic, behavioral, LLM)
2. **Classify risk**: Score prompt risk (safe, suspicious, malicious)
3. **Block/sanitize**: Block malicious prompts, sanitize suspicious ones
4. **Track patterns**: Log jailbreak attempts for pattern analysis

```python
from shieldops.agents.prompt_shield.runner import PromptShieldRunner

runner = PromptShieldRunner()
result = await runner.scan(
    prompt="user input to check",
    context="agent_type=investigation",
    detection_layers=["regex", "semantic", "behavioral", "llm"],
)
```

### Model Check (Model Security)
1. **Verify integrity**: Check model hash against known-good registry
2. **Detect backdoors**: Run backdoor detection analysis
3. **Provenance**: Verify model supply chain and training data lineage
4. **Report**: Generate model security card

### Trust (Multi-Agent Security)
1. **Map trust chains**: Visualize agent-to-agent trust relationships
2. **Audit communications**: Review inter-agent message patterns
3. **Detect impersonation**: Identify unauthorized agent identity claims
4. **Enforce boundaries**: Validate agents only access authorized resources

## Key Files
- `src/shieldops/agents/agent_firewall/` — Agent firewall agent
- `src/shieldops/agents/agent_governance/` — Governance agent
- `src/shieldops/agents/multi_agent_security/` — Multi-agent security agent
- `src/shieldops/agents/prompt_shield/` — Prompt defense agent
- `src/shieldops/agents/model_security/` — Model security agent
- `src/shieldops/agents/ai_runtime_defense/` — Runtime defense agent
- `src/shieldops/agents/ai_red_team/` — Red team agent
- `src/shieldops/agents/ai_blue_team/` — Blue team agent
- `src/shieldops/sdk/` — Agent Firewall SDK (LangChain, CrewAI, LlamaIndex)
- `src/shieldops/security/prompt_injection_classifier.py` — Prompt injection engine
- `src/shieldops/security/agent_capability_tracker.py` — Capability tracking
- `src/shieldops/security/multi_agent_trust_engine.py` — Trust engine

## Conventions
- Agent firewall MUST be in enforce mode for production deployments
- All agent tool calls require OPA policy evaluation before execution
- Prompt shield scans mandatory for all user-facing agent inputs
- Model integrity checks required before deploying updated models
- Multi-agent trust boundaries must be explicitly defined (deny by default)
- Red team exercises required quarterly for production agents
