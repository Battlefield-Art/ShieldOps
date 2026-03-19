"""Agent Context Mixin — adds context retrieval to agent nodes.

Agents call `fetch_context()` at the start of their key decision node
to get relevant runbooks, historical incidents, and compliance requirements.
This is added to the reasoning chain so the LLM has real context, not just
training data.

Usage in an agent node:

    from shieldops.utils.agent_context_mixin import fetch_context_for_incident

    async def investigate_node(state: AgentState) -> AgentState:
        context = fetch_context_for_incident(
            alert_type=state.alert_type,
            service=state.service_name,
        )
        # Prepend context to the LLM prompt so it reasons with real docs
        prompt = context + build_investigation_prompt(state)
        result = await llm_structured(system_prompt, prompt, schema)
        ...
"""

from __future__ import annotations

from shieldops.utils.context_hub import ContextHub, ContextQuery, ContextType

# Global hub instance (initialized once, lazily)
_hub: ContextHub | None = None


def get_context_hub() -> ContextHub:
    """Get or create the global ContextHub singleton.

    On first call, loads default context entries (runbooks, compliance, etc.).
    """
    global _hub
    if _hub is None:
        _hub = ContextHub()
        _hub.load_default_contexts()
    return _hub


def reset_context_hub() -> None:
    """Reset the global hub (primarily for testing)."""
    global _hub
    _hub = None


def fetch_context_for_incident(
    alert_type: str,
    service: str = "",
    environment: str = "",
) -> str:
    """Fetch relevant context for an incident investigation.

    Searches runbooks and incident history matching the alert type,
    service name, and environment. Returns a formatted string ready
    to prepend to the LLM prompt.

    Args:
        alert_type: The type of alert (e.g., "OOMKilled", "high_cpu").
        service: The affected service name.
        environment: The environment (e.g., "production", "staging").

    Returns:
        Formatted context string, or empty string if no matches.
    """
    hub = get_context_hub()
    query_parts = [alert_type]
    if service:
        query_parts.append(service)
    if environment:
        query_parts.append(environment)

    query = ContextQuery(
        query=" ".join(query_parts),
        context_types=[ContextType.RUNBOOK, ContextType.INCIDENT_HISTORY],
        max_results=3,
    )
    results = hub.search(query)
    if not results:
        return ""

    lines = ["## Retrieved Context (from knowledge base, not training data)\n"]
    for entry in results:
        lines.append(f"### {entry.title} ({entry.context_type})")
        lines.append(f"Source: {entry.source} | Version: {entry.version}")
        lines.append(f"Relevance: {entry.relevance_score}")
        lines.append(f"\n{entry.content}\n")
    return "\n".join(lines)


def fetch_context_for_compliance(
    action_type: str,
    frameworks: list[str] | None = None,
) -> str:
    """Fetch compliance requirements before executing an action.

    Searches compliance context entries matching the action type and
    optional framework filters (e.g., ["hipaa", "soc2", "pci-dss"]).

    Args:
        action_type: The type of action being taken (e.g., "data_access",
            "deployment", "config_change").
        frameworks: Optional list of compliance framework tags to filter by.

    Returns:
        Formatted compliance context string, or empty string if no matches.
    """
    hub = get_context_hub()
    tags = frameworks or []
    query = ContextQuery(
        query=action_type,
        context_types=[ContextType.COMPLIANCE],
        tags=tags,
        max_results=5,
    )
    results = hub.search(query)
    if not results:
        return ""

    lines = ["## Compliance Requirements (applicable to this action)\n"]
    for entry in results:
        lines.append(f"### {entry.title}")
        lines.append(f"Framework: {entry.source} | Version: {entry.version}")
        lines.append(f"\n{entry.content}\n")
    return "\n".join(lines)


def fetch_context_for_remediation(
    action_type: str,
    target_resource: str = "",
) -> str:
    """Fetch relevant runbooks and past remediation results.

    Searches runbooks, playbooks, and incident history for context
    relevant to the planned remediation action.

    Args:
        action_type: The remediation action (e.g., "rollback", "scale",
            "restart", "config_change").
        target_resource: The resource being remediated (e.g., "deployment/api",
            "node/worker-3").

    Returns:
        Formatted remediation context string, or empty string if no matches.
    """
    hub = get_context_hub()
    query_parts = [action_type]
    if target_resource:
        query_parts.append(target_resource)

    query = ContextQuery(
        query=" ".join(query_parts),
        context_types=[
            ContextType.RUNBOOK,
            ContextType.PLAYBOOK,
            ContextType.INCIDENT_HISTORY,
        ],
        max_results=3,
    )
    results = hub.search(query)
    if not results:
        return ""

    lines = ["## Remediation Context (runbooks and past results)\n"]
    for entry in results:
        lines.append(f"### {entry.title} ({entry.context_type})")
        lines.append(f"Source: {entry.source}")
        lines.append(f"\n{entry.content}\n")
    return "\n".join(lines)
