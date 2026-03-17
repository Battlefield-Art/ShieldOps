"""ShieldOps Strands Agent -- AWS Bedrock-powered SRE assistant.

Deploys ShieldOps capabilities as a Strands Agent for use with
Amazon Bedrock, enabling natural language SRE operations.

Install: ``pip install strands-agents strands-agents-bedrock``

Usage::

    from shieldops.utils.strands_agent import create_shieldops_strands_agent

    agent = create_shieldops_strands_agent()
    result = agent("Investigate the high-CPU alert on api-gateway")
"""

from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger()

SHIELDOPS_SYSTEM_PROMPT = """\
You are ShieldOps, an autonomous Site Reliability Engineering (SRE) agent
deployed on AWS Bedrock. You help engineering teams investigate incidents,
run security scans, audit compliance, optimize telemetry pipelines, and
perform threat modeling.

Guidelines:
- Always start by gathering context before taking action.
- Explain your reasoning clearly at each step.
- For critical operations, confirm findings before recommending changes.
- Prioritize safety: never take destructive actions without explicit approval.
- Report confidence levels with every finding.

Available capabilities:
- investigate_incident: Correlate logs, metrics, traces to find root cause
- run_security_scan: Scan for vulnerabilities and misconfigurations
- check_compliance: Audit against SOC 2, HIPAA, PCI-DSS, ISO 27001
- optimize_telemetry: Analyze and reduce telemetry pipeline costs
- assess_threat_model: STRIDE analysis on service architectures
"""


def create_shieldops_strands_agent(
    model_id: str = "anthropic.claude-sonnet-4-20250514-v1:0",
    region: str = "us-east-1",
    temperature: float = 0.1,
    system_prompt: str = SHIELDOPS_SYSTEM_PROMPT,
) -> Any:
    """Create a Strands Agent with all ShieldOps tools.

    Args:
        model_id: Bedrock model identifier.
        region: AWS region for Bedrock.
        temperature: LLM sampling temperature.
        system_prompt: System prompt for the agent.

    Returns:
        A configured ``strands.Agent`` instance.

    Raises:
        RuntimeError: If strands-agents is not installed.
    """
    try:
        from strands import Agent
        from strands.models import BedrockModel
    except ImportError as exc:
        raise RuntimeError(
            "strands-agents is not installed. "
            "Run: pip install strands-agents strands-agents-bedrock"
        ) from exc

    from shieldops.utils.strands_tools import (
        assess_threat_model,
        check_compliance,
        investigate_incident,
        optimize_telemetry,
        run_security_scan,
    )

    model = BedrockModel(
        model_id=model_id,
        region_name=region,
        temperature=temperature,
    )

    agent = Agent(
        model=model,
        tools=[
            investigate_incident,
            run_security_scan,
            check_compliance,
            optimize_telemetry,
            assess_threat_model,
        ],
        system_prompt=system_prompt,
    )

    logger.info(
        "strands_agent.created",
        model_id=model_id,
        region=region,
        tool_count=5,
    )
    return agent
