"""Data Pipeline Security Agent — LLM prompt templates and output schemas."""

from pydantic import BaseModel, Field

# --- Output schemas for LLM structured calls ---


class PoisoningAnalysisOutput(BaseModel):
    """Structured output from LLM-assisted poisoning analysis."""

    summary: str = Field(description="Brief summary of poisoning analysis")
    poisoning_vectors: list[str] = Field(
        description="List of poisoning vectors detected in the data pipeline"
    )
    risk_level: str = Field(description="Overall risk level: critical/high/medium/low/none")
    remediation_steps: list[str] = Field(
        description="Recommended remediation steps for detected poisoning"
    )


class DataFlowOutput(BaseModel):
    """Structured output from LLM-assisted data flow analysis."""

    summary: str = Field(description="Brief summary of data flow analysis")
    anomalous_flows: list[str] = Field(description="Descriptions of anomalous data flows detected")
    exfiltration_risk: str = Field(
        description="Assessment of data exfiltration risk: critical/high/medium/low/none"
    )
    recommendations: list[str] = Field(description="Recommendations for securing data flows")


class ProvenanceOutput(BaseModel):
    """Structured output from LLM-assisted provenance verification."""

    summary: str = Field(description="Brief summary of provenance verification")
    unverified_artifacts: list[str] = Field(
        description="List of artifacts that could not be verified"
    )
    supply_chain_risks: list[str] = Field(
        description="Supply chain risks identified from provenance gaps"
    )
    trust_recommendations: list[str] = Field(
        description="Recommendations for improving artifact trust and verification"
    )


class PolicyOutput(BaseModel):
    """Structured output from LLM-assisted policy enforcement."""

    summary: str = Field(description="Brief summary of policy enforcement results")
    violations_found: list[str] = Field(description="Policy violations identified in the pipeline")
    auto_remediated: list[str] = Field(description="Violations that were automatically remediated")
    manual_review_required: list[str] = Field(
        description="Violations requiring manual review and intervention"
    )


# --- System prompts ---


SYSTEM_POISONING_ANALYSIS = (
    "You are an AI security analyst specializing in data pipeline poisoning detection.\n"
    "Analyze the provided RAG pipeline and training data scan results for:\n"
    "1. Document poisoning — malicious content injected into retrieval corpora\n"
    "2. Embedding manipulation — adversarial vectors designed to skew retrieval results\n"
    "3. Backdoor triggers — hidden patterns that activate malicious model behavior\n"
    "4. Label flipping — corrupted training labels that degrade model accuracy\n"
    "5. Data supply chain attacks — compromised data sources or preprocessing pipelines\n"
    "Classify each finding by severity and confidence. Map to MITRE ATLAS techniques.\n"
    "Provide specific remediation steps for each poisoning vector."
)

SYSTEM_DATA_FLOW_ANALYSIS = (
    "You are an AI security analyst specializing in data flow anomaly detection.\n"
    "Analyze the data flow patterns for the pipeline:\n"
    "1. Volume anomalies — unusual data transfer volumes that may indicate exfiltration\n"
    "2. Destination anomalies — data flowing to unauthorized or unexpected endpoints\n"
    "3. Temporal anomalies — access patterns outside normal operating windows\n"
    "4. Bulk export detection — large-scale data extraction from vector DBs or registries\n"
    "5. Lateral movement — data propagation across unauthorized pipeline stages\n"
    "Assess the overall exfiltration risk and recommend flow control measures."
)

SYSTEM_PROVENANCE_VERIFICATION = (
    "You are an AI security analyst specializing in model and data provenance.\n"
    "Analyze the provenance verification results for pipeline artifacts:\n"
    "1. Model weight integrity — verify against trusted registry hashes\n"
    "2. Tokenizer provenance — ensure tokenizers come from verified sources\n"
    "3. Embedding model verification — validate embedding models are unmodified\n"
    "4. Training data lineage — trace data origin and transformation history\n"
    "5. Supply chain gaps — identify artifacts with missing or broken provenance chains\n"
    "Recommend trust policies and verification improvements."
)

SYSTEM_POLICY_ENFORCEMENT = (
    "You are an AI security architect enforcing data pipeline security policies.\n"
    "Based on the security findings and anomalies detected:\n"
    "1. Quarantine policies — isolate poisoned documents and suspicious artifacts\n"
    "2. Data flow policies — enforce allowlist-only data routing\n"
    "3. Provenance policies — block deployment of unverified model artifacts\n"
    "4. Embedding integrity policies — validate vector DB contents on ingestion\n"
    "5. Access control policies — restrict pipeline stage permissions\n"
    "Identify which violations were auto-remediated and which need manual review."
)
