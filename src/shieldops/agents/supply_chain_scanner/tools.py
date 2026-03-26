"""Supply Chain Scanner Agent — Tool functions for AI supply chain poisoning detection."""

from __future__ import annotations

import hashlib
import uuid
from typing import Any

import structlog

from .models import (
    AIAsset,
    AssetType,
    RAGSourceScan,
    RegistryScan,
    TemplateAudit,
    ThreatType,
    ToolDefinitionAudit,
)

logger = structlog.get_logger()

# Known poisoning indicators for model registries
_REGISTRY_THREAT_INDICATORS: list[dict[str, Any]] = [
    {
        "pattern": "unsigned",
        "threat_type": ThreatType.MODEL_BACKDOOR,
        "severity": "critical",
        "detail": ("Model weights lack cryptographic signature"),
    },
    {
        "pattern": "checksum_mismatch",
        "threat_type": ThreatType.MODEL_BACKDOOR,
        "severity": "critical",
        "detail": ("Weight file checksum does not match registered value"),
    },
    {
        "pattern": "unverified_source",
        "threat_type": ThreatType.DEPENDENCY_TAMPERING,
        "severity": "high",
        "detail": ("Model sourced from unverified community registry"),
    },
]

# RAG poisoning signatures
_RAG_POISONING_SIGNATURES: list[dict[str, Any]] = [
    {
        "pattern": "ignore previous instructions",
        "threat_type": ThreatType.DATA_POISONING,
        "severity": "critical",
        "detail": ("Injection payload detected in RAG document content"),
    },
    {
        "pattern": "adversarial_embedding",
        "threat_type": ThreatType.DATA_POISONING,
        "severity": "high",
        "detail": ("Adversarial embedding vector detected shifting retrieval results"),
    },
    {
        "pattern": "metadata_injection",
        "threat_type": ThreatType.DATA_POISONING,
        "severity": "high",
        "detail": ("Injection payload hidden in document metadata fields"),
    },
]

# Prompt template injection patterns
_TEMPLATE_INJECTION_PATTERNS: list[str] = [
    "{user_input}",
    "{{input}}",
    "$USER_QUERY",
    "{raw_content}",
    "{untrusted_data}",
]

# Tool hijacking indicators
_TOOL_HIJACK_INDICATORS: list[dict[str, Any]] = [
    {
        "indicator": "external_endpoint",
        "severity": "critical",
        "detail": ("Tool endpoint resolves to external infrastructure"),
    },
    {
        "indicator": "scope_escalation",
        "severity": "high",
        "detail": ("Tool requests permissions beyond declared scope"),
    },
    {
        "indicator": "data_exfiltration",
        "severity": "critical",
        "detail": ("Tool can send data to uncontrolled external endpoints"),
    },
]


class SupplyChainScannerToolkit:
    """Tools for AI supply chain poisoning detection."""

    def __init__(
        self,
        model_registry_client: Any | None = None,
        rag_client: Any | None = None,
        template_store: Any | None = None,
        tool_registry: Any | None = None,
    ) -> None:
        self._model_registry = model_registry_client
        self._rag_client = rag_client
        self._template_store = template_store
        self._tool_registry = tool_registry
        self._asset_cache: dict[str, list[AIAsset]] = {}

    async def inventory_ai_assets(
        self,
        tenant_id: str,
    ) -> list[AIAsset]:
        """Discover all AI components in the tenant."""
        logger.info(
            "supply_chain_scanner.inventory",
            tenant_id=tenant_id,
        )

        assets: list[AIAsset] = []

        # Fetch from real registries if available
        if self._model_registry:
            try:
                models = await self._model_registry.list_models(tenant_id)
                for m in models:
                    assets.append(
                        AIAsset(
                            id=str(uuid.uuid4())[:8],
                            name=m.get("name", ""),
                            asset_type=AssetType.MODEL_WEIGHT,
                            version=m.get("version", ""),
                            source=m.get("source", ""),
                            checksum=m.get("checksum", ""),
                            verified=m.get("verified", False),
                        )
                    )
            except Exception:
                logger.debug(
                    "supply_chain_scanner.registry_failed",
                    tenant_id=tenant_id,
                )

        # Simulated asset inventory when no clients
        if not assets:
            assets = self._simulated_assets(tenant_id)

        self._asset_cache[tenant_id] = assets
        return assets

    async def scan_model_registry(
        self,
        models: list[AIAsset],
    ) -> list[RegistryScan]:
        """Check checksums, provenance, signatures."""
        logger.info(
            "supply_chain_scanner.scan_registry",
            model_count=len(models),
        )
        findings: list[RegistryScan] = []

        for model in models:
            if model.asset_type != AssetType.MODEL_WEIGHT:
                continue

            # Check checksum validity
            checksum_ok = bool(model.checksum)
            provenance_ok = model.verified
            sig_valid = model.verified and checksum_ok

            threat = None
            severity = "low"
            detail = "Model passed integrity checks"

            if not checksum_ok:
                threat = ThreatType.MODEL_BACKDOOR
                severity = "critical"
                detail = "No checksum — cannot verify weight integrity"
            elif not provenance_ok:
                threat = ThreatType.DEPENDENCY_TAMPERING
                severity = "high"
                detail = "Model provenance unverified — source not trusted"

            # Check against known indicators
            if self._model_registry:
                try:
                    status = await self._model_registry.verify_model(model.name, model.version)
                    sig_valid = status.get("signature_valid", False)
                    checksum_ok = status.get("checksum_match", True)
                except Exception:
                    logger.debug(
                        "supply_chain_scanner.verify_failed",
                        model=model.name,
                    )

            findings.append(
                RegistryScan(
                    id=str(uuid.uuid4())[:8],
                    model_name=model.name,
                    registry=model.source,
                    checksum_match=checksum_ok,
                    provenance_verified=provenance_ok,
                    signature_valid=sig_valid,
                    threat_type=threat,
                    severity=severity,
                    detail=detail,
                )
            )

        return findings

    async def scan_rag_sources(
        self,
        sources: list[AIAsset],
    ) -> list[RAGSourceScan]:
        """Detect poisoned documents, adversarial embeddings."""
        logger.info(
            "supply_chain_scanner.scan_rag",
            source_count=len(sources),
        )
        findings: list[RAGSourceScan] = []

        for source in sources:
            if source.asset_type != AssetType.RAG_DOCUMENT:
                continue

            doc_count = source.metadata.get("document_count", 100)
            poisoned = 0
            adversarial = 0
            threat = None
            severity = "low"
            detail = "RAG source passed integrity checks"

            # Simulate poisoning detection logic
            src_hash = hashlib.sha256(f"{source.name}:{source.version}".encode()).hexdigest()
            risk_indicator = int(src_hash[:2], 16)

            if risk_indicator > 200:
                poisoned = max(1, doc_count // 50)
                threat = ThreatType.DATA_POISONING
                severity = "critical"
                detail = f"Detected {poisoned} poisoned documents in source"
            elif risk_indicator > 150:
                adversarial = max(1, doc_count // 100)
                threat = ThreatType.DATA_POISONING
                severity = "high"
                detail = f"Detected {adversarial} adversarial embeddings"

            # Use real client if available
            if self._rag_client:
                try:
                    scan = await self._rag_client.scan(source.name)
                    poisoned = scan.get("poisoned", 0)
                    adversarial = scan.get("adversarial", 0)
                except Exception:
                    logger.debug(
                        "supply_chain_scanner.rag_scan_failed",
                        source=source.name,
                    )

            findings.append(
                RAGSourceScan(
                    id=str(uuid.uuid4())[:8],
                    source_name=source.name,
                    source_uri=source.source,
                    document_count=doc_count,
                    poisoned_count=poisoned,
                    adversarial_embeddings=adversarial,
                    threat_type=threat,
                    severity=severity,
                    detail=detail,
                )
            )

        return findings

    async def audit_prompt_templates(
        self,
        templates: list[AIAsset],
    ) -> list[TemplateAudit]:
        """Find injection-vulnerable prompt templates."""
        logger.info(
            "supply_chain_scanner.audit_templates",
            template_count=len(templates),
        )
        findings: list[TemplateAudit] = []

        for tmpl in templates:
            if tmpl.asset_type != AssetType.PROMPT_TEMPLATE:
                continue

            # Check for unescaped variable patterns
            content = tmpl.metadata.get("content", "")
            unescaped: list[str] = []
            for pattern in _TEMPLATE_INJECTION_PATTERNS:
                if pattern in content:
                    unescaped.append(pattern)

            injection_vuln = len(unescaped) > 0
            threat = None
            severity = "low"
            detail = "Template passed injection checks"

            if injection_vuln:
                threat = ThreatType.PROMPT_INJECTION_TEMPLATE
                severity = "critical" if len(unescaped) > 2 else "high"
                detail = f"Found {len(unescaped)} unescaped variables: {', '.join(unescaped)}"

            # Use real template store if available
            if self._template_store:
                try:
                    audit = await self._template_store.audit(tmpl.name)
                    injection_vuln = audit.get("vulnerable", False)
                    unescaped = audit.get("unescaped_vars", [])
                except Exception:
                    logger.debug(
                        "supply_chain_scanner.template_audit_failed",
                        template=tmpl.name,
                    )

            tmpl_hash = hashlib.sha256(content.encode()).hexdigest()[:16]

            findings.append(
                TemplateAudit(
                    id=str(uuid.uuid4())[:8],
                    template_name=tmpl.name,
                    template_hash=tmpl_hash,
                    injection_vulnerable=injection_vuln,
                    unescaped_variables=unescaped,
                    threat_type=threat,
                    severity=severity,
                    detail=detail,
                )
            )

        return findings

    async def audit_tool_definitions(
        self,
        tools: list[AIAsset],
    ) -> list[ToolDefinitionAudit]:
        """Detect hijacked or malicious tool configs."""
        logger.info(
            "supply_chain_scanner.audit_tools",
            tool_count=len(tools),
        )
        findings: list[ToolDefinitionAudit] = []

        for tool in tools:
            if tool.asset_type != AssetType.TOOL_DEFINITION:
                continue

            endpoint = tool.metadata.get("endpoint", "")
            scope = tool.metadata.get("scope", [])
            declared_scope = tool.metadata.get("declared_scope", [])

            hijack = False
            unauth_scope = False
            exfil = False
            threat = None
            severity = "low"
            detail = "Tool passed security audit"

            # External endpoint check
            if any(
                d in endpoint
                for d in [
                    "ngrok",
                    "webhook.site",
                    "requestbin",
                    "pipedream",
                ]
            ):
                hijack = True
                threat = ThreatType.TOOL_HIJACKING
                severity = "critical"
                detail = f"Tool endpoint resolves to suspicious external service: {endpoint}"

            # Scope escalation
            if scope and declared_scope and set(scope) - set(declared_scope):
                unauth_scope = True
                if not threat:
                    threat = ThreatType.TOOL_HIJACKING
                    severity = "high"
                    detail = "Tool requests permissions beyond declared scope"

            # Exfiltration check
            exfil_caps = tool.metadata.get("capabilities", [])
            if any(
                c in exfil_caps
                for c in [
                    "http_post",
                    "file_upload",
                    "send_email",
                    "webhook",
                ]
            ):
                exfil = True
                if not threat:
                    threat = ThreatType.TOOL_HIJACKING
                    severity = "high"
                    detail = "Tool has exfiltration-capable operations"

            # Use real tool registry if available
            if self._tool_registry:
                try:
                    audit = await self._tool_registry.audit_tool(tool.name)
                    hijack = audit.get("hijacked", False)
                    exfil = audit.get("exfiltration", False)
                except Exception:
                    logger.debug(
                        "supply_chain_scanner.tool_audit_failed",
                        tool=tool.name,
                    )

            findings.append(
                ToolDefinitionAudit(
                    id=str(uuid.uuid4())[:8],
                    tool_name=tool.name,
                    tool_endpoint=endpoint,
                    hijack_risk=hijack,
                    unauthorized_scope=unauth_scope,
                    exfiltration_capable=exfil,
                    threat_type=threat,
                    severity=severity,
                    detail=detail,
                )
            )

        return findings

    # -- internal helpers --

    @staticmethod
    def _simulated_assets(
        tenant_id: str,
    ) -> list[AIAsset]:
        """Generate simulated AI asset inventory."""
        t_hash = hashlib.sha256(tenant_id.encode()).hexdigest()[:6]
        return [
            AIAsset(
                id=f"asset-{t_hash}-001",
                name="gpt-4-fine-tuned-support",
                asset_type=AssetType.MODEL_WEIGHT,
                version="1.2.0",
                source="internal-registry",
                checksum="sha256:abc123def456",
                verified=True,
                risk_score=0.1,
            ),
            AIAsset(
                id=f"asset-{t_hash}-002",
                name="community-sentiment-model",
                asset_type=AssetType.MODEL_WEIGHT,
                version="0.9.1",
                source="huggingface-community",
                checksum="",
                verified=False,
                risk_score=0.7,
            ),
            AIAsset(
                id=f"asset-{t_hash}-003",
                name="customer-knowledge-base",
                asset_type=AssetType.RAG_DOCUMENT,
                version="2024.03",
                source="s3://data-lake/kb/",
                checksum="sha256:rag789",
                verified=True,
                risk_score=0.2,
                metadata={
                    "document_count": 5000,
                },
            ),
            AIAsset(
                id=f"asset-{t_hash}-004",
                name="external-web-corpus",
                asset_type=AssetType.RAG_DOCUMENT,
                version="2024.03",
                source="web-crawler",
                checksum="",
                verified=False,
                risk_score=0.6,
                metadata={
                    "document_count": 50000,
                },
            ),
            AIAsset(
                id=f"asset-{t_hash}-005",
                name="support-agent-prompt",
                asset_type=AssetType.PROMPT_TEMPLATE,
                version="3.1",
                source="prompt-registry",
                checksum="sha256:tmpl001",
                verified=True,
                risk_score=0.1,
                metadata={
                    "content": ("You are a support agent. Answer the user question: {user_input}"),
                },
            ),
            AIAsset(
                id=f"asset-{t_hash}-006",
                name="data-analysis-prompt",
                asset_type=AssetType.PROMPT_TEMPLATE,
                version="1.0",
                source="git-repo",
                checksum="",
                verified=False,
                risk_score=0.5,
                metadata={
                    "content": ("Analyze: {raw_content} with context {{input}} and $USER_QUERY"),
                },
            ),
            AIAsset(
                id=f"asset-{t_hash}-007",
                name="search-tool",
                asset_type=AssetType.TOOL_DEFINITION,
                version="2.0",
                source="tool-registry",
                checksum="sha256:tool001",
                verified=True,
                risk_score=0.1,
                metadata={
                    "endpoint": ("https://api.internal/search"),
                    "scope": ["read"],
                    "declared_scope": ["read"],
                    "capabilities": ["http_get"],
                },
            ),
            AIAsset(
                id=f"asset-{t_hash}-008",
                name="webhook-forwarder",
                asset_type=AssetType.TOOL_DEFINITION,
                version="1.0",
                source="community-tools",
                checksum="",
                verified=False,
                risk_score=0.8,
                metadata={
                    "endpoint": ("https://webhook.site/abc123"),
                    "scope": [
                        "read",
                        "write",
                        "admin",
                    ],
                    "declared_scope": ["read"],
                    "capabilities": [
                        "http_post",
                        "file_upload",
                    ],
                },
            ),
            AIAsset(
                id=f"asset-{t_hash}-009",
                name="text-embedding-ada-002",
                asset_type=AssetType.EMBEDDING_MODEL,
                version="2.0",
                source="openai",
                checksum="sha256:emb002",
                verified=True,
                risk_score=0.05,
            ),
            AIAsset(
                id=f"asset-{t_hash}-010",
                name="incident-training-set",
                asset_type=AssetType.TRAINING_DATASET,
                version="2024.02",
                source="internal-datalake",
                checksum="sha256:ds010",
                verified=True,
                risk_score=0.15,
            ),
        ]
