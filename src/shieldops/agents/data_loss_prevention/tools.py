"""Data Loss Prevention Agent — Tool functions for DLP operations."""

from __future__ import annotations

import re
import time
import uuid
from typing import Any

import structlog

from .models import (
    DataFlow,
    DataSensitivity,
    DLPPolicy,
    ExfiltrationAttempt,
    ExfiltrationChannel,
    IncidentResponse,
    SensitiveDataRecord,
)

logger = structlog.get_logger()

# -------------------------------------------------------------------
# Regex patterns for sensitive data detection in data flows
# -------------------------------------------------------------------

_PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "phone": re.compile(r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
}

_PHI_PATTERNS: dict[str, re.Pattern[str]] = {
    "mrn": re.compile(r"\bMRN[-:\s]?\d{6,10}\b", re.IGNORECASE),
    "diagnosis": re.compile(r"\b[A-Z]\d{2}(?:\.\d{1,4})?\b"),
}

_PCI_PATTERNS: dict[str, re.Pattern[str]] = {
    "card_number": re.compile(r"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13})\b"),
    "cvv": re.compile(r"\bCVV[-:\s]?\d{3,4}\b", re.IGNORECASE),
}

_SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "generic_secret": re.compile(r"(?i)(?:password|secret|token|api_key)\s*[=:]\s*\S+"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
}

_DATA_TYPE_PATTERNS: dict[str, dict[str, re.Pattern[str]]] = {
    "PII": _PII_PATTERNS,
    "PHI": _PHI_PATTERNS,
    "PCI": _PCI_PATTERNS,
    "secrets": _SECRET_PATTERNS,
}

_SENSITIVITY_MAP: dict[str, DataSensitivity] = {
    "PII": DataSensitivity.CONFIDENTIAL,
    "PHI": DataSensitivity.TOP_SECRET,
    "PCI": DataSensitivity.TOP_SECRET,
    "secrets": DataSensitivity.TOP_SECRET,
    "IP": DataSensitivity.RESTRICTED,
}

_REGULATION_MAP: dict[str, list[str]] = {
    "PII": ["GDPR", "CCPA"],
    "PHI": ["HIPAA"],
    "PCI": ["PCI_DSS"],
    "secrets": ["SOC2"],
    "IP": ["trade_secret"],
}

# AI-specific exfiltration indicators
_AI_EXFIL_INDICATORS: list[str] = [
    "prompt_injection_extract",
    "tool_call_data_dump",
    "agent_memory_export",
    "mcp_bulk_read",
    "llm_response_pii_leak",
    "rag_context_exfiltration",
    "fine_tune_data_poisoning",
]

# Channel risk weights for scoring
_CHANNEL_RISK_WEIGHT: dict[ExfiltrationChannel, float] = {
    ExfiltrationChannel.ENDPOINT: 0.7,
    ExfiltrationChannel.CLOUD_STORAGE: 0.8,
    ExfiltrationChannel.EMAIL: 0.6,
    ExfiltrationChannel.BROWSER: 0.75,
    ExfiltrationChannel.API: 0.8,
    ExfiltrationChannel.AI_PIPELINE: 0.95,
    ExfiltrationChannel.MCP_TOOL: 0.95,
}


def _uid() -> str:
    return str(uuid.uuid4())[:12]


class DataLossPreventionToolkit:
    """Tools for DLP across endpoints, cloud, browsers, and AI."""

    def __init__(
        self,
        endpoint_connector: Any | None = None,
        cloud_connector: Any | None = None,
        browser_connector: Any | None = None,
        ai_pipeline_connector: Any | None = None,
        mcp_connector: Any | None = None,
        policy_engine: Any | None = None,
    ) -> None:
        self._endpoint = endpoint_connector
        self._cloud = cloud_connector
        self._browser = browser_connector
        self._ai_pipeline = ai_pipeline_connector
        self._mcp = mcp_connector
        self._policy_engine = policy_engine
        self._flow_cache: dict[str, DataFlow] = {}

    async def discover_data_flows(
        self,
        tenant_id: str,
        channels: list[str] | None = None,
        time_window_hours: int = 24,
    ) -> list[DataFlow]:
        """Discover data flows across all monitored channels.

        In production this calls endpoint agents, cloud APIs,
        browser extension telemetry, and AI pipeline hooks.
        """
        logger.info(
            "dlp.discover_data_flows",
            tenant_id=tenant_id,
            channels=channels,
            window_hours=time_window_hours,
        )
        now = time.time()
        flows: list[DataFlow] = []

        # Default discovery set (simulates real telemetry)
        default_flows = [
            {
                "source": "endpoint/laptop-eng-042",
                "destination": "s3://analytics-exports",
                "channel": ExfiltrationChannel.CLOUD_STORAGE,
                "protocol": "HTTPS",
                "volume_mb": 245.0,
                "records_count": 18_000,
                "user_identity": "dev@corp.com",
                "is_encrypted": True,
                "geo_source": "US-West",
                "geo_destination": "US-East",
            },
            {
                "source": "crm-database/contacts",
                "destination": "personal-gdrive",
                "channel": ExfiltrationChannel.BROWSER,
                "protocol": "HTTPS",
                "volume_mb": 12.5,
                "records_count": 5_200,
                "user_identity": "sales-rep@corp.com",
                "is_encrypted": False,
                "geo_source": "US-East",
                "geo_destination": "US-East",
            },
            {
                "source": "patient-records/ehr",
                "destination": "llm-prompt/claude-3",
                "channel": ExfiltrationChannel.AI_PIPELINE,
                "protocol": "API",
                "volume_mb": 0.8,
                "records_count": 150,
                "user_identity": "ai-agent/triage-bot",
                "is_encrypted": True,
                "geo_source": "US-West",
                "geo_destination": "US-West",
            },
            {
                "source": "secrets-vault/prod-keys",
                "destination": "mcp-tool/file-writer",
                "channel": ExfiltrationChannel.MCP_TOOL,
                "protocol": "MCP",
                "volume_mb": 0.02,
                "records_count": 8,
                "user_identity": "ai-agent/deploy-bot",
                "is_encrypted": False,
                "geo_source": "US-East",
                "geo_destination": "US-East",
            },
            {
                "source": "hr-database/employees",
                "destination": "external-email",
                "channel": ExfiltrationChannel.EMAIL,
                "protocol": "SMTP",
                "volume_mb": 3.2,
                "records_count": 1_400,
                "user_identity": "hr-admin@corp.com",
                "is_encrypted": False,
                "geo_source": "EU-West",
                "geo_destination": "US-East",
            },
            {
                "source": "billing-api/transactions",
                "destination": "webhook/third-party",
                "channel": ExfiltrationChannel.API,
                "protocol": "HTTPS",
                "volume_mb": 8.7,
                "records_count": 3_500,
                "user_identity": "svc-billing-sync",
                "is_encrypted": True,
                "geo_source": "US-East",
                "geo_destination": "EU-Central",
            },
            {
                "source": "endpoint/laptop-exec-001",
                "destination": "usb-device",
                "channel": ExfiltrationChannel.ENDPOINT,
                "protocol": "USB",
                "volume_mb": 520.0,
                "records_count": 42_000,
                "user_identity": "exec@corp.com",
                "is_encrypted": False,
                "geo_source": "US-East",
                "geo_destination": "unknown",
            },
        ]

        active_channels = (
            [ExfiltrationChannel(c) for c in channels] if channels else list(ExfiltrationChannel)
        )

        for fd in default_flows:
            ch = fd["channel"]
            if ch not in active_channels:
                continue
            flow = DataFlow(
                id=_uid(),
                source=fd["source"],  # type: ignore[arg-type]
                destination=fd["destination"],  # type: ignore[arg-type]
                channel=ch,  # type: ignore[arg-type]
                protocol=fd["protocol"],  # type: ignore[arg-type]
                volume_mb=fd["volume_mb"],  # type: ignore[arg-type]
                records_count=fd["records_count"],  # type: ignore[arg-type]
                user_identity=fd["user_identity"],  # type: ignore[arg-type]
                timestamp=now,
                is_encrypted=fd["is_encrypted"],  # type: ignore[arg-type]
                geo_source=fd["geo_source"],  # type: ignore[arg-type]
                geo_destination=fd["geo_destination"],  # type: ignore[arg-type]
            )
            flows.append(flow)
            self._flow_cache[flow.id] = flow

        return flows

    async def classify_flow_data(
        self,
        flows: list[DataFlow],
        content_samples: dict[str, list[str]] | None = None,
    ) -> list[SensitiveDataRecord]:
        """Classify sensitive data found in data flows.

        Uses regex patterns for PII/PHI/PCI/secrets and heuristic
        detection based on flow source/destination names.
        """
        logger.info(
            "dlp.classify_flow_data",
            flow_count=len(flows),
        )
        records: list[SensitiveDataRecord] = []
        samples = content_samples or {}

        # Heuristic keywords for source-based classification
        _source_hints: dict[str, str] = {
            "patient": "PHI",
            "ehr": "PHI",
            "health": "PHI",
            "billing": "PCI",
            "payment": "PCI",
            "transaction": "PCI",
            "hr": "PII",
            "employee": "PII",
            "contact": "PII",
            "crm": "PII",
            "secret": "secrets",
            "vault": "secrets",
            "key": "secrets",
            "credential": "secrets",
        }

        for flow in flows:
            flow_samples = samples.get(flow.id, [])

            if flow_samples:
                # Regex detection on actual content samples
                for value in flow_samples:
                    for dtype, patterns in _DATA_TYPE_PATTERNS.items():
                        for pat_name, pat in patterns.items():
                            if pat.search(value):
                                records.append(
                                    SensitiveDataRecord(
                                        id=_uid(),
                                        flow_id=flow.id,
                                        data_type=dtype,
                                        sensitivity=(
                                            _SENSITIVITY_MAP.get(
                                                dtype,
                                                DataSensitivity.INTERNAL,
                                            )
                                        ),
                                        pattern_matched=pat_name,
                                        confidence=0.92,
                                        regulation=(_REGULATION_MAP.get(dtype, [""])[0]),
                                    )
                                )
            else:
                # Heuristic: infer from flow source name
                src_lower = flow.source.lower()
                for keyword, dtype in _source_hints.items():
                    if keyword in src_lower:
                        records.append(
                            SensitiveDataRecord(
                                id=_uid(),
                                flow_id=flow.id,
                                data_type=dtype,
                                sensitivity=(
                                    _SENSITIVITY_MAP.get(
                                        dtype,
                                        DataSensitivity.INTERNAL,
                                    )
                                ),
                                pattern_matched=(f"heuristic/{keyword}"),
                                confidence=0.72,
                                regulation=(_REGULATION_MAP.get(dtype, [""])[0]),
                            )
                        )

            # AI pipeline / MCP flows get elevated sensitivity
            if flow.channel in (
                ExfiltrationChannel.AI_PIPELINE,
                ExfiltrationChannel.MCP_TOOL,
            ) and not any(r.flow_id == flow.id for r in records):
                records.append(
                    SensitiveDataRecord(
                        id=_uid(),
                        flow_id=flow.id,
                        data_type="AI_data",
                        sensitivity=(DataSensitivity.RESTRICTED),
                        pattern_matched="ai_channel",
                        confidence=0.80,
                        regulation="SOC2",
                    )
                )

        return records

    async def detect_exfiltration(
        self,
        flows: list[DataFlow],
        sensitive_records: list[SensitiveDataRecord],
    ) -> list[ExfiltrationAttempt]:
        """Detect exfiltration attempts from data flows.

        Applies heuristics: volume anomalies, geo mismatch,
        unencrypted sensitive data, AI-specific indicators.
        """
        logger.info(
            "dlp.detect_exfiltration",
            flow_count=len(flows),
            record_count=len(sensitive_records),
        )
        attempts: list[ExfiltrationAttempt] = []
        flow_records: dict[str, list[SensitiveDataRecord]] = {}
        for r in sensitive_records:
            flow_records.setdefault(r.flow_id, []).append(r)

        for flow in flows:
            recs = flow_records.get(flow.id, [])
            if not recs:
                continue

            risk_score = 0.0
            technique = ""
            mitre = ""

            # Volume anomaly (> 100 MB)
            if flow.volume_mb > 100:
                risk_score += 0.3
                technique = "bulk_transfer"
                mitre = "T1041"

            # Unencrypted sensitive data
            if not flow.is_encrypted and any(
                r.sensitivity
                in (
                    DataSensitivity.CONFIDENTIAL,
                    DataSensitivity.RESTRICTED,
                    DataSensitivity.TOP_SECRET,
                )
                for r in recs
            ):
                risk_score += 0.35
                technique = technique or "unencrypted_exfil"
                mitre = mitre or "T1048"

            # Geo mismatch (cross-region sensitive data)
            if flow.geo_source != flow.geo_destination and flow.geo_destination != "unknown":
                risk_score += 0.15

            # AI-specific channel risk
            if flow.channel == ExfiltrationChannel.AI_PIPELINE:
                risk_score += 0.3
                technique = "llm_prompt_data_leak"
                mitre = "T1567.002"
            elif flow.channel == ExfiltrationChannel.MCP_TOOL:
                risk_score += 0.35
                technique = "mcp_tool_exfiltration"
                mitre = "T1567"

            # Browser exfil (personal storage)
            if flow.channel == ExfiltrationChannel.BROWSER:
                dst = flow.destination.lower()
                if any(
                    k in dst
                    for k in [
                        "personal",
                        "gdrive",
                        "dropbox",
                        "onedrive",
                    ]
                ):
                    risk_score += 0.25
                    technique = "browser_upload_personal"
                    mitre = "T1567.002"

            # USB endpoint exfil
            if flow.channel == ExfiltrationChannel.ENDPOINT and "usb" in flow.protocol.lower():
                risk_score += 0.3
                technique = "usb_exfiltration"
                mitre = "T1052"

            # Channel risk weighting
            risk_score *= _CHANNEL_RISK_WEIGHT.get(flow.channel, 0.5)

            # Severity mapping
            if risk_score >= 0.6:
                severity = "critical"
            elif risk_score >= 0.4:
                severity = "high"
            elif risk_score >= 0.2:
                severity = "medium"
            else:
                severity = "low"

            if risk_score >= 0.15:
                attempts.append(
                    ExfiltrationAttempt(
                        id=_uid(),
                        flow_id=flow.id,
                        channel=flow.channel,
                        severity=severity,
                        technique=technique,
                        data_types_involved=[r.data_type for r in recs],
                        volume_mb=flow.volume_mb,
                        user_identity=flow.user_identity,
                        blocked=False,
                        confidence=min(risk_score, 1.0),
                        mitre_tactic=mitre,
                    )
                )

        return attempts

    async def enforce_policies(
        self,
        attempts: list[ExfiltrationAttempt],
        custom_policies: list[dict[str, Any]] | None = None,
    ) -> list[DLPPolicy]:
        """Enforce DLP policies against detected exfiltration.

        In production calls OPA, firewall APIs, email gateways,
        browser extension controls, and AI pipeline interceptors.
        """
        logger.info(
            "dlp.enforce_policies",
            attempt_count=len(attempts),
        )
        policies: list[DLPPolicy] = []

        # Default channel policies
        _default_policies: dict[ExfiltrationChannel, dict[str, Any]] = {
            ExfiltrationChannel.ENDPOINT: {
                "policy_name": "endpoint_usb_block",
                "action": "block",
                "threshold": DataSensitivity.CONFIDENTIAL,
            },
            ExfiltrationChannel.CLOUD_STORAGE: {
                "policy_name": "cloud_egress_encrypt",
                "action": "encrypt",
                "threshold": DataSensitivity.INTERNAL,
            },
            ExfiltrationChannel.EMAIL: {
                "policy_name": "email_pii_block",
                "action": "quarantine",
                "threshold": DataSensitivity.CONFIDENTIAL,
            },
            ExfiltrationChannel.BROWSER: {
                "policy_name": "browser_upload_block",
                "action": "block",
                "threshold": DataSensitivity.CONFIDENTIAL,
            },
            ExfiltrationChannel.API: {
                "policy_name": "api_egress_monitor",
                "action": "alert",
                "threshold": DataSensitivity.RESTRICTED,
            },
            ExfiltrationChannel.AI_PIPELINE: {
                "policy_name": "ai_prompt_dlp",
                "action": "block",
                "threshold": DataSensitivity.INTERNAL,
            },
            ExfiltrationChannel.MCP_TOOL: {
                "policy_name": "mcp_tool_dlp",
                "action": "block",
                "threshold": DataSensitivity.INTERNAL,
            },
        }

        for attempt in attempts:
            pol_cfg = _default_policies.get(
                attempt.channel,
                {
                    "policy_name": "default_alert",
                    "action": "alert",
                    "threshold": DataSensitivity.RESTRICTED,
                },
            )

            applied = attempt.severity in ("high", "critical")
            fp = 0
            if attempt.confidence < 0.3:
                fp = 1
                applied = False

            if self._policy_engine:
                try:
                    result = await self._policy_engine.evaluate(attempt.model_dump())
                    applied = result.get("allow", applied)
                except Exception:
                    logger.warning(
                        "dlp.policy_engine_error",
                        attempt_id=attempt.id,
                    )

            policies.append(
                DLPPolicy(
                    id=_uid(),
                    policy_name=pol_cfg["policy_name"],
                    channel=attempt.channel,
                    action=pol_cfg["action"],
                    sensitivity_threshold=pol_cfg["threshold"],
                    applied=applied,
                    matches=1,
                    false_positives=fp,
                )
            )

        return policies

    async def respond_to_incidents(
        self,
        attempts: list[ExfiltrationAttempt],
        policies: list[DLPPolicy],
    ) -> list[IncidentResponse]:
        """Execute incident response for confirmed exfiltration.

        Actions: block the flow, revoke access, quarantine data,
        notify security team, escalate critical incidents.
        """
        logger.info(
            "dlp.respond_to_incidents",
            attempt_count=len(attempts),
        )
        responses: list[IncidentResponse] = []

        policy_map: dict[ExfiltrationChannel, DLPPolicy] = {}
        for p in policies:
            policy_map[p.channel] = p

        for attempt in attempts:
            pol = policy_map.get(attempt.channel)
            if not pol or not pol.applied:
                continue

            action = pol.action
            escalated = attempt.severity == "critical"

            # AI channel incidents always escalate
            if attempt.channel in (
                ExfiltrationChannel.AI_PIPELINE,
                ExfiltrationChannel.MCP_TOOL,
            ):
                escalated = True

            responses.append(
                IncidentResponse(
                    id=_uid(),
                    exfiltration_id=attempt.id,
                    action_taken=action,
                    success=True,
                    response_time_ms=85.0,
                    escalated=escalated,
                    containment_status=("contained" if action == "block" else "open"),
                )
            )

        return responses
