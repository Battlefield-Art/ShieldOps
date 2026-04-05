"""AISurfaceScannerEngine — Scan AI attack surfaces including MCP, LLM, and RAG exposures."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AISurfaceScannerEngine = engine(
    "AISurfaceScannerEngine",
    description="Scan AI attack surfaces including MCP, LLM, and RAG exposures.",
    enums={
        "ai_surface": EnumDef(
            "AISurface",
            {
                "MCP_SERVER": "mcp_server",
                "LLM_ENDPOINT": "llm_endpoint",
                "RAG_PIPELINE": "rag_pipeline",
                "MODEL_REGISTRY": "model_registry",
                "AGENT_API": "agent_api",
            },
        ),
        "ai_exposure": EnumDef(
            "AIExposure",
            {
                "PUBLIC": "public",
                "AUTHENTICATED": "authenticated",
                "INTERNAL": "internal",
                "UNREACHABLE": "unreachable",
            },
        ),
        "ai_risk_level": EnumDef(
            "AIRiskLevel",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
    },
    record_fields=[
        FieldDef("endpoint_url", str, ""),
        FieldDef("auth_required", bool, True),
    ],
)

# Backward-compatible re-exports
AISurface = AISurfaceScannerEngine.AISurface
AIExposure = AISurfaceScannerEngine.AIExposure
AIRiskLevel = AISurfaceScannerEngine.AIRiskLevel
AISurfaceRecord = AISurfaceScannerEngine.Record
AISurfaceAnalysis = AISurfaceScannerEngine.Analysis
AISurfaceReport = AISurfaceScannerEngine.Report
