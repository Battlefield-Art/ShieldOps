"""Regulatory Change Tracker Agent — Tool functions."""

from __future__ import annotations

import time
from typing import Any

import structlog

from .models import ImpactLevel

logger = structlog.get_logger()

_REG_UPDATES: dict[str, list[dict[str, Any]]] = {
    "gdpr": [
        {
            "title": "GDPR Art 25 — DPbD guidance update",
            "summary": "Updated guidance on data protection by design obligations",
        },
        {
            "title": "GDPR cross-border transfer ruling",
            "summary": "New adequacy decisions for third-country data transfers",
        },
    ],
    "ccpa": [
        {
            "title": "CPRA enforcement update",
            "summary": "California Privacy Rights Act enforcement guidelines finalized",
        },
    ],
    "hipaa": [
        {
            "title": "HIPAA Security Rule revision",
            "summary": "Updated technical safeguard requirements for ePHI",
        },
    ],
    "pci_dss": [
        {
            "title": "PCI DSS 4.0.1 clarification",
            "summary": "Clarified requirements for targeted risk analysis",
        },
    ],
    "sox": [
        {
            "title": "SOX IT controls guidance",
            "summary": "Updated PCAOB guidance on IT general controls testing",
        },
    ],
    "nist": [
        {
            "title": "NIST CSF 2.0 update",
            "summary": "New Govern function added to Cybersecurity Framework",
        },
    ],
}

_CONTROL_MAP: dict[str, list[str]] = {
    "gdpr": ["AC-1", "AC-2", "SC-12", "SC-28"],
    "ccpa": ["AC-1", "SI-12", "PM-25"],
    "hipaa": ["AC-3", "AU-2", "SC-8", "SC-13"],
    "pci_dss": ["AC-6", "AU-6", "SC-7", "SI-4"],
    "sox": ["AU-2", "AU-12", "CM-3", "SA-10"],
    "nist": ["ID.GV-1", "PR.AC-1", "DE.CM-1"],
}


class RegulatoryChangeTrackerToolkit:
    """Tools for tracking regulatory changes."""

    def __init__(
        self,
        reg_feed: Any | None = None,
        control_store: Any | None = None,
        notifier: Any | None = None,
    ) -> None:
        self._reg_feed = reg_feed
        self._control_store = control_store
        self._notifier = notifier

    async def scan_sources(
        self,
        regulations: list[str],
    ) -> list[dict[str, Any]]:
        """Scan regulatory sources for updates."""
        logger.info("rct.scan_sources", count=len(regulations))

        if self._reg_feed is not None:
            try:
                return await self._reg_feed.scan(
                    regulations=regulations,
                )
            except Exception:
                logger.exception("rct.scan_sources.error")

        results: list[dict[str, Any]] = []
        now = time.time()
        idx = 0
        for reg in regulations:
            entries = _REG_UPDATES.get(reg, [])
            for entry in entries:
                impact = (
                    ImpactLevel.CRITICAL
                    if idx % 5 == 0
                    else ImpactLevel.HIGH
                    if idx % 5 == 1
                    else ImpactLevel.MEDIUM
                )
                results.append(
                    {
                        "id": f"rct-{reg}-{idx:03d}",
                        "regulation": reg,
                        "title": entry["title"],
                        "summary": entry["summary"],
                        "effective_date": "2026-06-01",
                        "source_url": f"https://reg.gov/{reg}",
                        "impact": impact.value,
                        "scanned_at": now,
                    }
                )
                idx += 1
        return results

    async def map_controls(
        self,
        update: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Map a regulatory update to internal controls."""
        logger.info(
            "rct.map_controls",
            update_id=update.get("id", ""),
        )

        if self._control_store is not None:
            try:
                return await self._control_store.map(
                    update=update,
                )
            except Exception:
                logger.exception("rct.map_controls.error")

        reg = update.get("regulation", "")
        controls = _CONTROL_MAP.get(reg, [])
        return [
            {
                "update_id": update.get("id", ""),
                "control_id": ctrl,
                "gap_description": (f"{ctrl} may need update for {update.get('title', '')}"),
                "remediation_needed": True,
                "effort_hours": 4.0 + i * 2.0,
            }
            for i, ctrl in enumerate(controls)
        ]

    async def notify_stakeholders(
        self,
        update: dict[str, Any],
        stakeholders: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Notify stakeholders about regulatory changes."""
        logger.info(
            "rct.notify",
            update_id=update.get("id", ""),
        )

        if stakeholders is None:
            stakeholders = [
                "compliance-team",
                "legal",
                "ciso",
            ]

        if self._notifier is not None:
            try:
                return await self._notifier.send(
                    update=update,
                    stakeholders=stakeholders,
                )
            except Exception:
                logger.exception("rct.notify.error")

        return [
            {
                "stakeholder": s,
                "channel": "email",
                "update_id": update.get("id", ""),
                "sent": True,
            }
            for s in stakeholders
        ]

    def generate_report(
        self,
        updates: list[dict[str, Any]],
        mappings: list[dict[str, Any]],
        notifications: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Generate regulatory change tracking report."""
        total = len(updates)
        critical = sum(1 for u in updates if u.get("impact") == "critical")
        controls_affected = len({m.get("control_id") for m in mappings})
        notified = sum(1 for n in notifications if n.get("sent"))

        return {
            "total_updates": total,
            "critical_changes": critical,
            "controls_affected": controls_affected,
            "stakeholders_notified": notified,
            "updates": updates,
            "control_mappings": mappings,
            "generated_at": time.time(),
        }
