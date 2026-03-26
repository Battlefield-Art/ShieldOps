"""LLM prompt templates and response schemas for the Air-Gap Vault Agent."""

from pydantic import BaseModel, Field

# --- Response schemas for structured LLM output ---


class TamperAnalysisResult(BaseModel):
    """Structured output from LLM tamper analysis."""

    risk_level: str = Field(description="Overall risk: low, medium, high, critical")
    attack_vector: str = Field(description="Likely attack vector or root cause")
    affected_assets: list[str] = Field(description="Asset names affected by tampering")
    recommendations: list[str] = Field(description="Actionable remediation recommendations")
    summary: str = Field(description="Brief summary of tamper analysis findings")


class VaultReportResult(BaseModel):
    """Structured output for the final vault health report."""

    title: str = Field(description="Report title")
    executive_summary: str = Field(description="1-2 sentence executive summary")
    vault_health_grade: str = Field(description="Grade: A, B, C, D, F")
    critical_findings: list[str] = Field(description="Critical findings requiring immediate action")
    compliance_status: str = Field(description="Compliance posture summary")


# --- Prompt templates ---

SYSTEM_ANALYZE_TAMPERING = """\
You are an expert data security analyst specializing in \
air-gapped vault integrity and AI asset protection.

You are given:
- Vault asset inventory (model weights, RAG indexes, training data, backups)
- Isolation verification results (network reachability, DNS, egress)
- Cryptographic integrity checks (SHA-256 hash chains)
- Tamper detection alerts (unauthorized access, modifications)
- Retention policy enforcement status

Your task is to:
1. Assess the overall risk level of detected tampering
2. Identify the likely attack vector (insider, supply chain, \
network breach, data poisoning)
3. List all affected assets by name
4. Provide actionable remediation recommendations

Pay special attention to AI-specific threats: model weight \
tampering, training data poisoning, RAG index manipulation, \
and embedding store corruption. These extend beyond traditional \
backup protection (Rubrik, Cohesity) into AI security territory."""

SYSTEM_GENERATE_REPORT = """\
You are an expert data security analyst generating a vault \
health report for an air-gapped data vault.

You are given the full vault verification context including \
asset inventory, isolation checks, integrity results, tamper \
alerts, and retention policy status.

Your task is to:
1. Write a concise report title
2. Provide an executive summary (1-2 sentences)
3. Assign a vault health grade (A=excellent, F=compromised)
4. List critical findings requiring immediate action
5. Summarize compliance posture across frameworks

Focus on AI asset protection gaps that traditional backup \
vendors miss: model integrity, training data provenance, \
and RAG index security."""
