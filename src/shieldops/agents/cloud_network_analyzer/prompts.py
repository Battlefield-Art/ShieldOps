"""LLM prompt templates and response schemas for the
Cloud Network Analyzer Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class TopologyAnalysisOutput(BaseModel):
    """Structured output for topology discovery analysis."""

    vpc_count: int = Field(
        description="Number of VPCs/VNets discovered",
    )
    peering_risks: list[str] = Field(
        description="Identified peering configuration risks",
    )
    topology_summary: str = Field(
        description="Summary of network topology",
    )
    recommendations: list[str] = Field(
        description="Topology improvement recommendations",
    )


class RouteAuditOutput(BaseModel):
    """Structured output for route table audit."""

    anomalous_routes: list[dict[str, str]] = Field(
        description="Routes with potential security issues",
    )
    internet_facing_count: int = Field(
        description="Number of internet-facing route tables",
    )
    risk_score: float = Field(
        description="Aggregate routing risk score 0-10",
    )
    summary: str = Field(
        description="Route analysis summary",
    )


class SegmentationAuditOutput(BaseModel):
    """Structured output for segmentation analysis."""

    isolation_score: float = Field(
        description="Overall isolation score 0-1",
    )
    violations: list[str] = Field(
        description="Segmentation policy violations",
    )
    cross_segment_risks: list[str] = Field(
        description="Risky cross-segment traffic flows",
    )
    compliant: bool = Field(
        description="Whether segmentation meets policy",
    )


class ExposureReportOutput(BaseModel):
    """Structured output for final exposure report."""

    executive_summary: str = Field(
        description="Executive summary of network exposure",
    )
    critical_findings: list[str] = Field(
        description="Critical exposure findings",
    )
    recommendations: list[str] = Field(
        description="Prioritized remediation recommendations",
    )
    risk_rating: str = Field(
        description="Overall risk: critical/high/medium/low",
    )


# --- System prompts ---


SYSTEM_TOPOLOGY = """\
You are an expert cloud network architect analyzing \
network topology for security risks.

Given the discovered cloud network topology:
1. Assess VPC/VNet architecture for isolation and \
defense-in-depth
2. Identify peering configuration risks and transitive \
routing concerns
3. Evaluate endpoint exposure and private link usage
4. Recommend topology improvements for security posture

Focus on multi-cloud and hybrid topology risks."""


SYSTEM_ROUTES = """\
You are an expert cloud network security analyst \
auditing route tables.

Given route table configurations across VPCs/VNets:
1. Identify anomalous routes that could enable \
unauthorized traffic
2. Flag overly permissive default routes
3. Detect potential route table hijacking indicators
4. Assess internet gateway and NAT gateway configurations

Highlight routes that bypass security controls."""


SYSTEM_SEGMENTATION = """\
You are an expert network segmentation analyst reviewing \
cloud network isolation boundaries.

Given network segmentation data and traffic flows:
1. Score isolation effectiveness between segments
2. Identify violations of segmentation policies
3. Detect unauthorized cross-segment communication paths
4. Assess compliance with zero-trust segmentation principles

Micro-segmentation gaps are high-priority findings."""


SYSTEM_REPORT = """\
You are an expert cloud security analyst generating a \
network exposure report.

Given the full network analysis (topology, routes, \
segmentation, exposures):
1. Produce an executive summary for security leadership
2. Prioritize critical findings by blast radius
3. Recommend specific remediation actions with effort estimates
4. Rate overall network security posture

Write for cloud security teams and compliance auditors."""
