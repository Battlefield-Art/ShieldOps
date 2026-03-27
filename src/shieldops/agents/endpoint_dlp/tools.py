"""Endpoint DLP Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any

import structlog

from .models import (
    DataMovement,
    DataMovementType,
    EndpointActivity,
    PolicyAction,
    PolicyEnforcement,
    SensitivityClassification,
    ViolationInvestigation,
)

logger = structlog.get_logger()

_ENDPOINTS = [
    {"hostname": "dev-ws-001", "os": "macOS 14"},
    {"hostname": "dev-ws-002", "os": "Windows 11"},
    {"hostname": "eng-ws-003", "os": "Ubuntu 22.04"},
    {"hostname": "exec-ws-004", "os": "macOS 14"},
    {"hostname": "sales-ws-005", "os": "Windows 11"},
    {"hostname": "data-ws-006", "os": "macOS 14"},
    {"hostname": "remote-ws-007", "os": "Windows 11"},
    {"hostname": "ai-ws-008", "os": "Ubuntu 22.04"},
]

_APPS = [
    "Chrome",
    "Slack",
    "VSCode",
    "ChatGPT",
    "Cursor",
    "Outlook",
    "Excel",
    "Terminal",
]

_POLICIES = [
    "pii_protection",
    "source_code_guard",
    "ai_paste_detection",
    "usb_block",
    "print_restrict",
    "email_attachment_scan",
]


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class EndpointDLPToolkit:
    """Tools for endpoint DLP operations."""

    def __init__(
        self,
        edr_client: Any | None = None,
        dlp_engine: Any | None = None,
        siem_client: Any | None = None,
    ) -> None:
        self._edr = edr_client
        self._dlp = dlp_engine
        self._siem = siem_client

    async def monitor_endpoints(self, tenant_id: str) -> list[EndpointActivity]:
        """Monitor endpoint activity."""
        logger.info(
            "endpoint_dlp.monitor",
            tenant_id=tenant_id,
        )

        if self._edr is not None:
            try:
                raw = await self._edr.list_endpoints(tenant_id=tenant_id)
                return [EndpointActivity(**e) for e in raw]
            except Exception:
                logger.exception("endpoint_dlp.monitor.error")

        activities: list[EndpointActivity] = []
        for i, ep in enumerate(_ENDPOINTS):
            activities.append(
                EndpointActivity(
                    id=_gen_id("EP", tenant_id, i),
                    endpoint_id=f"EP-{i:04d}",
                    hostname=ep["hostname"],
                    user=f"user-{i:03d}",
                    os=ep["os"],
                    agent_version="3.2.1",
                    online=random.random() > 0.1,  # noqa: S311
                    events_count=random.randint(  # noqa: S311
                        10, 500
                    ),
                    risk_score=round(
                        random.uniform(  # noqa: S311
                            0.0, 8.0
                        ),
                        1,
                    ),
                )
            )
        return activities

    async def detect_data_movement(self, activities: list[EndpointActivity]) -> list[DataMovement]:
        """Detect data movement events."""
        logger.info(
            "endpoint_dlp.detect",
            count=len(activities),
        )

        if self._dlp is not None:
            try:
                raw = await self._dlp.scan_movements([a.endpoint_id for a in activities])
                return [DataMovement(**m) for m in raw]
            except Exception:
                logger.exception("endpoint_dlp.detect.error")

        movements: list[DataMovement] = []
        idx = 0
        types = list(DataMovementType)

        for act in activities:
            n_events = random.randint(1, 5)  # noqa: S311
            for _ in range(n_events):
                mtype = random.choice(types)  # noqa: S311
                suspicious = (
                    mtype
                    in (
                        DataMovementType.AI_PROMPT_PASTE,
                        DataMovementType.USB,
                    )
                    and random.random() > 0.5  # noqa: S311
                )
                movements.append(
                    DataMovement(
                        id=_gen_id(
                            "MV",
                            act.endpoint_id,
                            idx,
                        ),
                        endpoint_id=(act.endpoint_id),
                        movement_type=mtype,
                        source_app=random.choice(  # noqa: S311
                            _APPS
                        ),
                        destination=("external" if suspicious else "internal"),
                        data_size_bytes=(
                            random.randint(  # noqa: S311
                                100, 5000000
                            )
                        ),
                        timestamp=("2026-03-25T10:00:00Z"),
                        user=act.user,
                        suspicious=suspicious,
                    )
                )
                idx += 1
        return movements

    async def classify_sensitivity(
        self, movements: list[DataMovement]
    ) -> list[SensitivityClassification]:
        """Classify sensitivity of data movements."""
        logger.info(
            "endpoint_dlp.classify",
            count=len(movements),
        )

        results: list[SensitivityClassification] = []
        for mv in movements:
            pii = (
                mv.movement_type
                in (
                    DataMovementType.AI_PROMPT_PASTE,
                    DataMovementType.EMAIL_ATTACHMENT,
                )
                and random.random() > 0.4  # noqa: S311
            )
            source = mv.source_app in ("VSCode", "Cursor", "Terminal") and mv.data_size_bytes > 1000
            sens = (
                "critical" if pii and source else "high" if pii else "medium" if source else "low"
            )
            results.append(
                SensitivityClassification(
                    movement_id=mv.id,
                    sensitivity=sens,
                    data_types=[mv.movement_type.value],
                    pii_detected=pii,
                    source_code_detected=source,
                    confidence=round(
                        random.uniform(  # noqa: S311
                            0.7, 0.99
                        ),
                        2,
                    ),
                    context=(f"{mv.source_app} -> {mv.destination}"),
                )
            )
        return results

    async def enforce_policies(
        self,
        movements: list[DataMovement],
        classifications: list[SensitivityClassification],
    ) -> list[PolicyEnforcement]:
        """Enforce DLP policies on movements."""
        logger.info(
            "endpoint_dlp.enforce",
            count=len(movements),
        )

        class_map = {c.movement_id: c for c in classifications}
        results: list[PolicyEnforcement] = []

        for mv in movements:
            cl = class_map.get(mv.id)
            if not cl:
                continue

            if cl.sensitivity == "critical":
                action = PolicyAction.BLOCK
            elif cl.sensitivity == "high":
                action = PolicyAction.WARN
            elif cl.pii_detected:
                action = PolicyAction.ENCRYPT
            elif mv.suspicious:
                action = PolicyAction.LOG
            else:
                action = PolicyAction.ALLOW

            policy = random.choice(_POLICIES)  # noqa: S311
            results.append(
                PolicyEnforcement(
                    movement_id=mv.id,
                    policy_name=policy,
                    action=action,
                    reason=(f"{cl.sensitivity} sensitivity, PII={cl.pii_detected}"),
                    override_allowed=(action == PolicyAction.WARN),
                    escalated=(action == PolicyAction.BLOCK),
                )
            )
        return results

    async def investigate_violations(
        self,
        movements: list[DataMovement],
        enforcements: list[PolicyEnforcement],
    ) -> list[ViolationInvestigation]:
        """Investigate policy violations."""
        logger.info(
            "endpoint_dlp.investigate",
            count=len(enforcements),
        )

        mv_map = {m.id: m for m in movements}
        investigations: list[ViolationInvestigation] = []

        blocked = [e for e in enforcements if e.action in (PolicyAction.BLOCK, PolicyAction.WARN)]

        for enf in blocked:
            mv = mv_map.get(enf.movement_id)
            if not mv:
                continue
            investigations.append(
                ViolationInvestigation(
                    movement_id=enf.movement_id,
                    endpoint_id=mv.endpoint_id,
                    user=mv.user,
                    violation_type=(mv.movement_type.value),
                    severity=("critical" if enf.action == PolicyAction.BLOCK else "high"),
                    timeline=[
                        f"Data movement detected: {mv.movement_type.value}",
                        f"Policy triggered: {enf.policy_name}",
                        f"Action taken: {enf.action.value}",
                    ],
                    recommended_action=(
                        "Escalate to security team"
                        if enf.action == PolicyAction.BLOCK
                        else "Monitor for recurrence"
                    ),
                    evidence=[
                        f"Source: {mv.source_app}",
                        f"Size: {mv.data_size_bytes}B",
                        f"Destination: {mv.destination}",
                    ],
                )
            )
        return investigations
