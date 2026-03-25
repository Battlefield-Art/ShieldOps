"""Vendor Normalizer Agent — Tool functions for OCSF schema normalization."""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import Any

import structlog

from .models import (
    NormalizedEvent,
    OCSFCategory,
    SchemaMapping,
    ValidationResult,
    VendorEvent,
    VendorType,
)

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Predefined OCSF field mappings per vendor
# ---------------------------------------------------------------------------
OCSF_FIELD_MAPPINGS: dict[VendorType, dict[str, str]] = {
    VendorType.CROWDSTRIKE: {
        "detection_id": "finding_info.uid",
        "detect_name": "finding_info.title",
        "detect_description": "finding_info.desc",
        "severity": "severity_id",
        "timestamp": "time",
        "device.hostname": "device.hostname",
        "device.external_ip": "device.ip",
        "technique": "attacks[].technique.uid",
        "tactic": "attacks[].tactic.uid",
        "sha256": "observables[].value",
        "user_name": "actor.user.name",
        "parent_process": "process.parent_process.name",
        "command_line": "process.cmd_line",
    },
    VendorType.MICROSOFT_DEFENDER: {
        "alertId": "finding_info.uid",
        "title": "finding_info.title",
        "description": "finding_info.desc",
        "severity": "severity_id",
        "createdDateTime": "time",
        "computerDnsName": "device.hostname",
        "machineId": "device.uid",
        "relatedUser.userName": "actor.user.name",
        "category": "finding_info.types[]",
        "mitreTechniques": "attacks[].technique.uid",
        "fileHash": "observables[].value",
        "url": "observables[].value",
    },
    VendorType.WIZ: {
        "id": "finding_info.uid",
        "name": "finding_info.title",
        "description": "finding_info.desc",
        "severity": "severity_id",
        "createdAt": "time",
        "resource.type": "resources[].type",
        "resource.name": "resources[].name",
        "resource.cloudPlatform": "cloud.provider",
        "resource.region": "cloud.region",
        "vulnerabilities": "vulnerabilities[]",
    },
    VendorType.SPLUNK: {
        "event_id": "finding_info.uid",
        "search_name": "finding_info.title",
        "description": "finding_info.desc",
        "urgency": "severity_id",
        "_time": "time",
        "src": "src_endpoint.ip",
        "dest": "dst_endpoint.ip",
        "user": "actor.user.name",
        "app": "app_name",
        "action": "activity_name",
        "signature": "finding_info.types[]",
    },
    VendorType.ELASTIC: {
        "event.id": "finding_info.uid",
        "rule.name": "finding_info.title",
        "rule.description": "finding_info.desc",
        "event.severity": "severity_id",
        "@timestamp": "time",
        "source.ip": "src_endpoint.ip",
        "destination.ip": "dst_endpoint.ip",
        "user.name": "actor.user.name",
        "host.name": "device.hostname",
        "process.name": "process.name",
        "threat.technique.id": "attacks[].technique.uid",
    },
    VendorType.DATADOG: {
        "id": "finding_info.uid",
        "name": "finding_info.title",
        "message": "finding_info.desc",
        "priority": "severity_id",
        "date_happened": "time",
        "host": "device.hostname",
        "tags": "metadata.tags",
        "source": "metadata.product.vendor_name",
        "alert_type": "finding_info.types[]",
    },
    VendorType.NEWRELIC: {
        "incident_id": "finding_info.uid",
        "condition_name": "finding_info.title",
        "details": "finding_info.desc",
        "priority": "severity_id",
        "opened_at": "time",
        "entity.name": "resources[].name",
        "entity.type": "resources[].type",
        "violation_chart_url": "metadata.references[]",
        "policy_name": "metadata.policy.name",
    },
    VendorType.PAGERDUTY: {
        "incident.id": "finding_info.uid",
        "incident.title": "finding_info.title",
        "incident.description": "finding_info.desc",
        "incident.urgency": "severity_id",
        "incident.created_at": "time",
        "incident.service.name": "resources[].name",
        "incident.assigned_to": "actor.user.name",
        "incident.escalation_policy": "metadata.policy.name",
    },
    VendorType.SERVICENOW: {
        "sys_id": "finding_info.uid",
        "short_description": "finding_info.title",
        "description": "finding_info.desc",
        "priority": "severity_id",
        "sys_created_on": "time",
        "cmdb_ci": "resources[].name",
        "assigned_to": "actor.user.name",
        "category": "finding_info.types[]",
        "state": "status_id",
    },
    VendorType.JIRA: {
        "key": "finding_info.uid",
        "fields.summary": "finding_info.title",
        "fields.description": "finding_info.desc",
        "fields.priority.name": "severity_id",
        "fields.created": "time",
        "fields.assignee.displayName": "actor.user.name",
        "fields.labels": "metadata.tags",
        "fields.status.name": "status_id",
    },
    VendorType.OPSGENIE: {
        "id": "finding_info.uid",
        "message": "finding_info.title",
        "description": "finding_info.desc",
        "priority": "severity_id",
        "createdAt": "time",
        "source": "metadata.product.vendor_name",
        "tags": "metadata.tags",
        "responders": "actor.user.name",
        "alias": "finding_info.analytic.uid",
    },
    VendorType.AWS: {
        "finding.id": "finding_info.uid",
        "finding.title": "finding_info.title",
        "finding.description": "finding_info.desc",
        "finding.severity.label": "severity_id",
        "finding.createdAt": "time",
        "resources[].type": "resources[].type",
        "resources[].id": "resources[].uid",
        "resources[].region": "cloud.region",
        "detail.accountId": "cloud.account.uid",
        "productArn": "metadata.product.uid",
    },
    VendorType.GCP: {
        "finding.name": "finding_info.uid",
        "finding.category": "finding_info.title",
        "finding.description": "finding_info.desc",
        "finding.severity": "severity_id",
        "finding.eventTime": "time",
        "finding.resourceName": "resources[].name",
        "finding.sourceProperties": "metadata.raw_data",
        "resource.project": "cloud.account.uid",
        "resource.type": "resources[].type",
    },
    VendorType.AZURE: {
        "properties.alertDisplayName": "finding_info.title",
        "properties.alertUri": "finding_info.uid",
        "properties.description": "finding_info.desc",
        "properties.severity": "severity_id",
        "properties.timeGeneratedUtc": "time",
        "properties.compromisedEntity": "resources[].name",
        "properties.remediationSteps": "remediation.desc",
        "properties.intent": "attacks[].tactic.name",
    },
    VendorType.KUBERNETES: {
        "involvedObject.uid": "finding_info.uid",
        "reason": "finding_info.title",
        "message": "finding_info.desc",
        "type": "severity_id",
        "metadata.creationTimestamp": "time",
        "involvedObject.name": "resources[].name",
        "involvedObject.kind": "resources[].type",
        "involvedObject.namespace": "resources[].labels.namespace",
        "source.component": "metadata.product.name",
    },
    VendorType.LINUX: {
        "audit_id": "finding_info.uid",
        "type": "finding_info.title",
        "msg": "finding_info.desc",
        "priority": "severity_id",
        "timestamp": "time",
        "hostname": "device.hostname",
        "uid": "actor.user.uid",
        "auid": "actor.user.name",
        "exe": "process.file.path",
        "comm": "process.name",
    },
    VendorType.WINDOWS: {
        "EventID": "finding_info.uid",
        "TaskDisplayName": "finding_info.title",
        "Message": "finding_info.desc",
        "Level": "severity_id",
        "TimeCreated": "time",
        "Computer": "device.hostname",
        "UserID": "actor.user.uid",
        "ProcessId": "process.pid",
        "ProviderName": "metadata.product.name",
        "Channel": "metadata.log_name",
    },
}

# Vendor -> default OCSF category heuristic
_VENDOR_CATEGORY_DEFAULTS: dict[VendorType, OCSFCategory] = {
    VendorType.CROWDSTRIKE: OCSFCategory.DETECTION_FINDING,
    VendorType.MICROSOFT_DEFENDER: OCSFCategory.DETECTION_FINDING,
    VendorType.WIZ: OCSFCategory.VULNERABILITY_FINDING,
    VendorType.SPLUNK: OCSFCategory.SECURITY_FINDING,
    VendorType.ELASTIC: OCSFCategory.DETECTION_FINDING,
    VendorType.DATADOG: OCSFCategory.APPLICATION_ACTIVITY,
    VendorType.NEWRELIC: OCSFCategory.APPLICATION_ACTIVITY,
    VendorType.PAGERDUTY: OCSFCategory.APPLICATION_ACTIVITY,
    VendorType.SERVICENOW: OCSFCategory.COMPLIANCE_FINDING,
    VendorType.JIRA: OCSFCategory.APPLICATION_ACTIVITY,
    VendorType.OPSGENIE: OCSFCategory.APPLICATION_ACTIVITY,
    VendorType.AWS: OCSFCategory.SECURITY_FINDING,
    VendorType.GCP: OCSFCategory.SECURITY_FINDING,
    VendorType.AZURE: OCSFCategory.SECURITY_FINDING,
    VendorType.KUBERNETES: OCSFCategory.SYSTEM_ACTIVITY,
    VendorType.LINUX: OCSFCategory.SYSTEM_ACTIVITY,
    VendorType.WINDOWS: OCSFCategory.SYSTEM_ACTIVITY,
}

# Severity normalization across vendors
_SEVERITY_MAP: dict[str, str] = {
    # CrowdStrike / generic
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "informational",
    "info": "informational",
    # Splunk urgency
    "urgent": "critical",
    # Datadog / PagerDuty
    "p1": "critical",
    "p2": "high",
    "p3": "medium",
    "p4": "low",
    "p5": "informational",
    # Kubernetes event types
    "warning": "medium",
    "normal": "informational",
    # Windows levels
    "1": "critical",
    "2": "high",
    "3": "medium",
    "4": "low",
    "5": "informational",
}

# Observable patterns for extraction
_OBSERVABLE_PATTERNS: dict[str, str] = {
    "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "ipv6": r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",
    "domain": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "sha1": r"\b[a-fA-F0-9]{40}\b",
    "md5": r"\b[a-fA-F0-9]{32}\b",
    "email": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
    "cve": r"CVE-\d{4}-\d{4,7}",
}


def _generate_id(prefix: str, *parts: str) -> str:
    """Generate a deterministic ID from parts."""
    raw = ":".join(parts)
    return f"{prefix}-{hashlib.sha256(raw.encode()).hexdigest()[:12].upper()}"


def _normalize_severity(raw: str) -> str:
    """Normalize vendor-specific severity to standard levels."""
    return _SEVERITY_MAP.get(raw.lower().strip(), "medium")


def _extract_observables(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract observable indicators from event data."""
    observables: list[dict[str, Any]] = []
    seen: set[str] = set()
    text = str(data)

    for obs_type, pattern in _OBSERVABLE_PATTERNS.items():
        for match in re.finditer(pattern, text):
            value = match.group()
            if value not in seen:
                seen.add(value)
                observables.append({"type": obs_type, "value": value})

    return observables


class VendorNormalizerToolkit:
    """Tools for normalizing vendor telemetry to OCSF format."""

    def __init__(
        self,
        schema_registry: Any | None = None,
        enrichment_service: Any | None = None,
    ) -> None:
        self._schema_registry = schema_registry
        self._enrichment_service = enrichment_service

    async def ingest_vendor_events(self, events: list[dict[str, Any]]) -> list[VendorEvent]:
        """Parse raw vendor events into structured VendorEvent models.

        Accepts a list of raw dicts and attempts to detect vendor type,
        extract timestamps, event types, and severity from each.
        """
        logger.info("vendor_normalizer.ingest_vendor_events", count=len(events))
        parsed: list[VendorEvent] = []

        for idx, raw in enumerate(events):
            vendor = self._detect_vendor(raw)
            event_id = _generate_id("EVT", str(idx), str(raw.get("id", "")))
            timestamp = self._extract_timestamp(raw, vendor)
            event_type = self._extract_event_type(raw, vendor)
            severity = raw.get("severity", raw.get("priority", "medium"))

            parsed.append(
                VendorEvent(
                    id=event_id,
                    vendor=vendor,
                    raw_data=raw,
                    timestamp=timestamp,
                    event_type=event_type,
                    severity=str(severity),
                )
            )

        return parsed

    async def detect_schema(self, events: list[VendorEvent]) -> list[SchemaMapping]:
        """Auto-detect vendor schema and generate field-level mappings.

        Uses predefined OCSF_FIELD_MAPPINGS as the base, and falls back
        to the schema_registry if available for custom mappings.
        """
        logger.info("vendor_normalizer.detect_schema", event_count=len(events))
        mappings: list[SchemaMapping] = []

        vendors_seen: set[VendorType] = set()
        for event in events:
            if event.vendor in vendors_seen:
                continue
            vendors_seen.add(event.vendor)

            vendor_mappings = OCSF_FIELD_MAPPINGS.get(event.vendor, {})

            # Try schema registry for additional / override mappings
            if self._schema_registry is not None:
                try:
                    extra = await self._schema_registry.get_mappings(vendor=event.vendor.value)
                    vendor_mappings = {**vendor_mappings, **extra}
                except Exception:
                    logger.exception("vendor_normalizer.detect_schema.registry_error")

            for vendor_field, ocsf_field in vendor_mappings.items():
                mapping_id = _generate_id("MAP", event.vendor.value, vendor_field, ocsf_field)
                mappings.append(
                    SchemaMapping(
                        id=mapping_id,
                        vendor=event.vendor,
                        vendor_field=vendor_field,
                        ocsf_field=ocsf_field,
                        transform_rule="direct" if "." not in ocsf_field else "nested",
                        confidence=0.9,
                    )
                )

        return mappings

    async def map_to_ocsf(
        self,
        events: list[VendorEvent],
        mappings: list[SchemaMapping],
    ) -> list[NormalizedEvent]:
        """Transform vendor events to OCSF format using schema mappings.

        Applies field mappings, normalizes severity, extracts observables,
        and sets the OCSF category and class.
        """
        logger.info(
            "vendor_normalizer.map_to_ocsf",
            event_count=len(events),
            mapping_count=len(mappings),
        )

        # Index mappings by vendor
        vendor_mappings: dict[VendorType, list[SchemaMapping]] = {}
        for m in mappings:
            vendor_mappings.setdefault(m.vendor, []).append(m)

        normalized: list[NormalizedEvent] = []

        for event in events:
            ocsf_category = _VENDOR_CATEGORY_DEFAULTS.get(
                event.vendor, OCSFCategory.SECURITY_FINDING
            )
            ocsf_class = f"{ocsf_category.value}:{event.event_type}"

            # Build metadata from mapped fields
            metadata: dict[str, Any] = {
                "vendor": event.vendor.value,
                "original_event_type": event.event_type,
                "product": {"vendor_name": event.vendor.value},
            }

            event_maps = vendor_mappings.get(event.vendor, [])
            for m in event_maps:
                value = self._resolve_field(event.raw_data, m.vendor_field)
                if value is not None:
                    metadata[m.ocsf_field] = value

            # Extract observables from raw data
            observables = _extract_observables(event.raw_data)

            norm_id = _generate_id("OCSF", event.id)
            normalized.append(
                NormalizedEvent(
                    id=norm_id,
                    ocsf_category=ocsf_category,
                    ocsf_class=ocsf_class,
                    vendor_source=event.vendor,
                    original_id=event.id,
                    severity=_normalize_severity(event.severity),
                    timestamp=event.timestamp,
                    metadata=metadata,
                    observables=observables,
                    enrichments=[],
                )
            )

        return normalized

    async def validate_normalization(self, events: list[NormalizedEvent]) -> list[ValidationResult]:
        """Validate normalized events against OCSF compliance requirements.

        Checks required fields, severity values, timestamp format,
        and calculates a completeness score.
        """
        logger.info(
            "vendor_normalizer.validate_normalization",
            event_count=len(events),
        )
        results: list[ValidationResult] = []

        required_fields = [
            "id",
            "ocsf_category",
            "ocsf_class",
            "vendor_source",
            "severity",
            "timestamp",
        ]
        valid_severities = {
            "critical",
            "high",
            "medium",
            "low",
            "informational",
        }

        for event in events:
            errors: list[str] = []
            warnings: list[str] = []
            event_data = event.model_dump()

            # Required field checks
            for field in required_fields:
                val = event_data.get(field)
                if not val:
                    errors.append(f"Missing required OCSF field: {field}")

            # Severity validation
            if event.severity not in valid_severities:
                errors.append(
                    f"Invalid severity '{event.severity}', expected one of {valid_severities}"
                )

            # Timestamp format check
            if event.timestamp:
                try:
                    datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
                except ValueError:
                    errors.append(f"Invalid timestamp format: {event.timestamp}, expected ISO 8601")

            # Completeness scoring
            optional_fields = [
                "metadata",
                "observables",
                "enrichments",
                "original_id",
            ]
            filled = sum(1 for f in optional_fields if event_data.get(f))
            completeness = filled / max(len(optional_fields), 1)

            if not event.observables:
                warnings.append("No observables extracted from event")
            if not event.metadata.get("product"):
                warnings.append("Missing product metadata in OCSF event")

            valid = len(errors) == 0
            result_id = _generate_id("VAL", event.id)
            results.append(
                ValidationResult(
                    id=result_id,
                    event_id=event.id,
                    valid=valid,
                    errors=errors,
                    warnings=warnings,
                    completeness_score=round(completeness, 2),
                )
            )

        return results

    async def enrich_context(self, events: list[NormalizedEvent]) -> list[NormalizedEvent]:
        """Add geo-IP, asset context, and threat intel enrichments.

        Uses the enrichment_service if available, otherwise applies
        basic observable-based enrichments.
        """
        logger.info(
            "vendor_normalizer.enrich_context",
            event_count=len(events),
        )
        enriched: list[NormalizedEvent] = []

        for event in events:
            new_enrichments: list[dict[str, Any]] = list(event.enrichments)

            # Try external enrichment service
            if self._enrichment_service is not None:
                try:
                    svc_result = await self._enrichment_service.enrich(
                        observables=event.observables,
                        vendor=event.vendor_source.value,
                    )
                    new_enrichments.extend(svc_result)
                except Exception:
                    logger.exception("vendor_normalizer.enrich_context.svc_error")

            # Basic enrichment: tag observable types
            for obs in event.observables:
                obs_type = obs.get("type", "unknown")
                if obs_type in ("ipv4", "ipv6"):
                    new_enrichments.append(
                        {
                            "type": "geo_ip",
                            "source": "internal",
                            "observable": obs.get("value", ""),
                            "status": "pending_lookup",
                        }
                    )
                elif obs_type in ("sha256", "sha1", "md5"):
                    new_enrichments.append(
                        {
                            "type": "threat_intel",
                            "source": "internal",
                            "observable": obs.get("value", ""),
                            "status": "pending_lookup",
                        }
                    )
                elif obs_type == "cve":
                    new_enrichments.append(
                        {
                            "type": "vulnerability",
                            "source": "internal",
                            "observable": obs.get("value", ""),
                            "status": "pending_lookup",
                        }
                    )

            enriched.append(event.model_copy(update={"enrichments": new_enrichments}))

        return enriched

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _detect_vendor(self, raw: dict[str, Any]) -> VendorType:
        """Detect vendor type from raw event structure."""
        # Explicit vendor field
        vendor_hint = str(raw.get("vendor", raw.get("source", raw.get("productArn", "")))).lower()

        vendor_keywords: dict[str, VendorType] = {
            "crowdstrike": VendorType.CROWDSTRIKE,
            "falcon": VendorType.CROWDSTRIKE,
            "defender": VendorType.MICROSOFT_DEFENDER,
            "microsoft": VendorType.MICROSOFT_DEFENDER,
            "wiz": VendorType.WIZ,
            "splunk": VendorType.SPLUNK,
            "elastic": VendorType.ELASTIC,
            "datadog": VendorType.DATADOG,
            "newrelic": VendorType.NEWRELIC,
            "new relic": VendorType.NEWRELIC,
            "pagerduty": VendorType.PAGERDUTY,
            "servicenow": VendorType.SERVICENOW,
            "jira": VendorType.JIRA,
            "opsgenie": VendorType.OPSGENIE,
            "aws": VendorType.AWS,
            "guardduty": VendorType.AWS,
            "securityhub": VendorType.AWS,
            "gcp": VendorType.GCP,
            "google": VendorType.GCP,
            "azure": VendorType.AZURE,
            "kubernetes": VendorType.KUBERNETES,
            "k8s": VendorType.KUBERNETES,
            "linux": VendorType.LINUX,
            "auditd": VendorType.LINUX,
            "windows": VendorType.WINDOWS,
            "eventlog": VendorType.WINDOWS,
        }

        for keyword, vendor in vendor_keywords.items():
            if keyword in vendor_hint:
                return vendor

        # Structural detection
        if "detection_id" in raw or "detect_name" in raw:
            return VendorType.CROWDSTRIKE
        if "alertId" in raw and "machineId" in raw:
            return VendorType.MICROSOFT_DEFENDER
        if "@timestamp" in raw and "rule" in raw:
            return VendorType.ELASTIC
        if "_time" in raw and "search_name" in raw:
            return VendorType.SPLUNK
        if "involvedObject" in raw:
            return VendorType.KUBERNETES
        if "EventID" in raw and "Channel" in raw:
            return VendorType.WINDOWS
        if "productArn" in raw:
            return VendorType.AWS

        return VendorType.AWS  # safe default

    def _extract_timestamp(self, raw: dict[str, Any], vendor: VendorType) -> str:
        """Extract and normalize timestamp from vendor event."""
        timestamp_fields = [
            "timestamp",
            "createdAt",
            "createdDateTime",
            "_time",
            "@timestamp",
            "time",
            "date_happened",
            "opened_at",
            "sys_created_on",
            "TimeCreated",
            "metadata.creationTimestamp",
            "finding.eventTime",
            "properties.timeGeneratedUtc",
            "incident.created_at",
            "fields.created",
        ]

        for field in timestamp_fields:
            value = self._resolve_field(raw, field)
            if value is not None:
                return str(value)

        return datetime.now(UTC).isoformat()

    def _extract_event_type(self, raw: dict[str, Any], vendor: VendorType) -> str:
        """Extract event type from vendor event."""
        type_fields = [
            "event_type",
            "type",
            "category",
            "detect_name",
            "title",
            "alert_type",
            "reason",
            "TaskDisplayName",
        ]
        for field in type_fields:
            value = raw.get(field)
            if value is not None:
                return str(value)
        return "unknown"

    @staticmethod
    def _resolve_field(data: dict[str, Any], field_path: str) -> Any:
        """Resolve a dot-notation field path in nested dict."""
        parts = field_path.split(".")
        current: Any = data
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
            if current is None:
                return None
        return current
