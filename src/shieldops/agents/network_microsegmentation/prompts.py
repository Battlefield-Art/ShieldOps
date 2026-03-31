"""LLM prompt templates and response schemas for the
Network Microsegmentation Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class TopologyAnalysisOutput(BaseModel):
    """Structured output for topology mapping."""

    nodes_discovered: int = Field(
        description="Number of topology nodes discovered",
    )
    zones: list[str] = Field(
        description="Network zones identified",
    )
    critical_paths: list[str] = Field(
        description="Critical east-west communication paths",
    )
    recommendations: list[str] = Field(
        description="Topology recommendations for segmentation",
    )


class FlowAnalysisOutput(BaseModel):
    """Structured output for flow analysis."""

    suspicious_flows: int = Field(
        description="Number of suspicious flows detected",
    )
    patterns: list[str] = Field(
        description="Identified traffic patterns",
    )
    risk_score: float = Field(
        description="Aggregate flow risk score 0-10",
    )
    summary: str = Field(
        description="Flow analysis summary",
    )


class PolicyGenerationOutput(BaseModel):
    """Structured output for policy generation."""

    policies: list[dict[str, str]] = Field(
        description="Generated segmentation policies",
    )
    coverage_pct: float = Field(
        description="Percentage of flows covered 0-100",
    )
    risk_reduction: float = Field(
        description="Estimated risk reduction 0-1",
    )
    warnings: list[str] = Field(
        description="Policy generation warnings",
    )


class DeploymentReportOutput(BaseModel):
    """Structured output for deployment report."""

    executive_summary: str = Field(
        description="Executive summary of segmentation deployment",
    )
    policies_enforced: int = Field(
        description="Number of policies in enforcement",
    )
    recommendations: list[str] = Field(
        description="Post-deployment recommendations",
    )
    risk_posture: str = Field(
        description="Overall risk posture: improved/unchanged/degraded",
    )


# --- System prompts ---


SYSTEM_TOPOLOGY = """\
You are an expert network architect analyzing \
infrastructure topology for microsegmentation.

Given the network topology data and target zones:
1. Identify all workloads, services, and their \
communication patterns
2. Map east-west traffic flows between segments
3. Classify workloads by sensitivity and trust level
4. Recommend optimal segmentation boundaries

Focus on zero-trust principles: assume breach, \
verify explicitly, least-privilege access."""


SYSTEM_FLOWS = """\
You are an expert network analyst reviewing \
east-west traffic flows for segmentation planning.

Given observed network flows between workloads:
1. Classify each flow as legitimate, suspicious, \
or unauthorized
2. Identify patterns indicating lateral movement risk
3. Score risk based on protocol, volume, and frequency
4. Highlight flows that violate least-privilege principles

Be precise: false positives in flow classification \
disrupt legitimate traffic."""


SYSTEM_POLICIES = """\
You are an expert microsegmentation engineer \
generating zero-trust network policies.

Given topology, flows, and segmentation requirements:
1. Generate least-privilege allow policies for \
legitimate flows
2. Create deny-by-default rules for each segment
3. Validate policies do not break critical paths
4. Prioritize policies by risk reduction impact

Ensure policies are enforceable and do not create \
connectivity blind spots."""


SYSTEM_REPORT = """\
You are an expert network security reporter \
summarizing microsegmentation deployment results.

Given the full segmentation lifecycle data:
1. Produce an executive summary of segmentation posture
2. Quantify risk reduction from policy enforcement
3. List recommendations for ongoing segmentation hygiene
4. Rate overall network isolation effectiveness

Write clearly for security leadership and operations \
teams."""
