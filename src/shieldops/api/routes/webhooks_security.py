"""Webhook receivers for CrowdStrike, Microsoft Defender, and Wiz events."""

from __future__ import annotations

import hashlib
import hmac
import time
import uuid
from typing import Any

import structlog
from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, Field

logger = structlog.get_logger()
router = APIRouter(prefix="/webhooks/security", tags=["Security Webhooks"])

# ── Module-level state ───────────────────────────────────────────────────────

_dedup_cache: dict[str, float] = {}  # event_id -> timestamp
_dedup_window_seconds: int = 300  # 5 minutes
_event_buffer: list[dict[str, Any]] = []  # buffered events when Kafka unavailable
_producer: Any | None = None  # SecurityEventProducer instance


def set_producer(producer: Any) -> None:
    """Inject the Kafka producer for publishing security events."""
    global _producer
    _producer = producer


# ── Models ───────────────────────────────────────────────────────────────────


class NormalizedSecurityEvent(BaseModel):
    """Vendor-agnostic security event schema."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    vendor: str = ""
    event_type: str = ""
    severity: str = "medium"
    title: str = ""
    description: str = ""
    entities: list[dict[str, Any]] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)
    received_at: float = Field(default_factory=time.time)


class WebhookConfig(BaseModel):
    """Per-vendor webhook configuration."""

    vendor: str
    secret_key: str = ""
    enabled: bool = True
    dedup_window_seconds: int = 300


class WebhookReceiveResponse(BaseModel):
    """Standard response for webhook receipt."""

    received: bool = True
    event_id: str = ""
    message: str = "Event received and queued for processing"


# ── Vendor configs (secrets loaded from env at startup) ──────────────────────

_vendor_configs: dict[str, WebhookConfig] = {
    "crowdstrike": WebhookConfig(vendor="crowdstrike"),
    "defender": WebhookConfig(vendor="defender"),
    "wiz": WebhookConfig(vendor="wiz"),
}


def configure_vendor(vendor: str, secret_key: str, enabled: bool = True) -> None:
    """Configure a vendor webhook (called during app startup)."""
    _vendor_configs[vendor] = WebhookConfig(
        vendor=vendor,
        secret_key=secret_key,
        enabled=enabled,
    )


# ── Signature Verification ───────────────────────────────────────────────────


def _verify_signature(
    payload: bytes,
    signature: str,
    secret: str,
    algorithm: str = "sha256",
) -> bool:
    """Verify HMAC webhook signature.

    Supports sha256 and sha1 algorithms. Returns True if no secret is
    configured (verification disabled).
    """
    if not secret:
        return True
    if not signature:
        return False

    # Strip common prefixes (e.g., "sha256=...")
    clean_sig = signature
    for prefix in ("sha256=", "sha1=", "v0="):
        if clean_sig.startswith(prefix):
            clean_sig = clean_sig[len(prefix) :]
            break

    hash_func = hashlib.sha256 if algorithm == "sha256" else hashlib.sha1
    expected = hmac.new(secret.encode("utf-8"), payload, hash_func).hexdigest()
    return hmac.compare_digest(expected, clean_sig)


# ── Deduplication ────────────────────────────────────────────────────────────


def _is_duplicate(event_id: str) -> bool:
    """Check if event was already processed within the dedup window.

    Cleans expired entries on each call to prevent unbounded growth.
    """
    now = time.time()

    # Evict expired entries
    expired = [k for k, ts in _dedup_cache.items() if now - ts > _dedup_window_seconds]
    for k in expired:
        del _dedup_cache[k]

    if event_id in _dedup_cache:
        return True
    _dedup_cache[event_id] = now
    return False


# ── Normalization helpers ────────────────────────────────────────────────────

_cs_severity_map: dict[str, str] = {
    "1": "info",
    "2": "low",
    "3": "medium",
    "4": "high",
    "5": "critical",
}

_defender_severity_map: dict[str, str] = {
    "informational": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",  # noqa: ERA001
}

_wiz_severity_map: dict[str, str] = {
    "INFORMATIONAL": "info",
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high",
    "CRITICAL": "critical",
}


def _normalize_crowdstrike(payload: dict[str, Any]) -> NormalizedSecurityEvent:
    """Normalize a CrowdStrike Falcon detection event."""
    detection = payload.get("event", payload)
    detection_id = detection.get("DetectId", detection.get("detection_id", str(uuid.uuid4())))
    technique = detection.get("Technique", detection.get("technique", ""))
    tactic = detection.get("Tactic", detection.get("tactic", ""))
    severity_num = str(detection.get("Severity", detection.get("severity", "3")))
    device = detection.get("ComputerName", detection.get("device", {}).get("hostname", ""))
    filename = detection.get("FileName", detection.get("filename", ""))
    cmdline = detection.get("CommandLine", detection.get("command_line", ""))

    # Build MITRE techniques list
    mitre: list[str] = []
    if technique:
        mitre.append(technique)
    technique_id = detection.get("TechniqueId", detection.get("technique_id", ""))
    if technique_id:
        mitre.append(technique_id)

    entities: list[dict[str, Any]] = []
    if device:
        entities.append({"type": "host", "value": device})
    if filename:
        entities.append({"type": "file", "value": filename})
    user = detection.get("UserName", detection.get("user_name", ""))
    if user:
        entities.append({"type": "user", "value": user})

    return NormalizedSecurityEvent(
        event_id=detection_id,
        vendor="crowdstrike",
        event_type="detection",
        severity=_cs_severity_map.get(severity_num, "medium"),
        title=f"CrowdStrike Detection: {technique or tactic or 'Unknown'}",
        description=(
            f"Detection on {device}: {technique} (cmdline: {cmdline[:200]})"
            if cmdline
            else f"Detection on {device}: {technique}"
        ),
        entities=entities,
        mitre_techniques=mitre,
        raw_data=payload,
    )


def _normalize_defender(payload: dict[str, Any]) -> NormalizedSecurityEvent:
    """Normalize a Microsoft Defender alert event."""
    alert = payload.get("alert", payload)
    alert_id = alert.get("alertId", alert.get("id", str(uuid.uuid4())))
    category = alert.get("category", "")
    severity_raw = alert.get("severity", "medium").lower()
    title = alert.get("title", alert.get("alertDisplayName", "Defender Alert"))
    description = alert.get("description", "")
    devices = alert.get("devices", alert.get("relatedDevices", []))
    evidence = alert.get("evidence", alert.get("entities", []))

    # Build MITRE techniques
    mitre: list[str] = []
    mitre_techniques = alert.get("mitreTechniques", [])
    if mitre_techniques:
        mitre.extend(mitre_techniques)
    attack_techniques = alert.get("attackTechniques", [])
    if attack_techniques:
        mitre.extend(attack_techniques)

    # Build entities from devices and evidence
    entities: list[dict[str, Any]] = []
    for dev in devices[:10]:  # Cap to prevent oversized payloads
        hostname = dev.get("deviceDnsName", dev.get("hostname", ""))
        if hostname:
            entities.append({"type": "host", "value": hostname})
    for evi in evidence[:10]:
        evi_type = evi.get("entityType", evi.get("type", "unknown"))
        evi_value = evi.get("fileName", evi.get("ipAddress", evi.get("domainName", "")))
        if evi_value:
            entities.append({"type": evi_type, "value": evi_value})

    return NormalizedSecurityEvent(
        event_id=alert_id,
        vendor="defender",
        event_type=category or "alert",
        severity=_defender_severity_map.get(severity_raw, "medium"),
        title=title,
        description=description,
        entities=entities,
        mitre_techniques=mitre,
        raw_data=payload,
    )


def _normalize_wiz(payload: dict[str, Any]) -> NormalizedSecurityEvent:
    """Normalize a Wiz issue notification event."""
    issue = payload.get("issue", payload)
    issue_id = issue.get("id", issue.get("issueId", str(uuid.uuid4())))
    severity_raw = issue.get("severity", "MEDIUM").upper()
    source_rule = issue.get("sourceRule", {})
    rule_name = source_rule.get("name", "") if isinstance(source_rule, dict) else str(source_rule)
    resource = issue.get("resource", issue.get("entitySnapshot", {}))
    status = issue.get("status", "OPEN")

    # Extract resource details
    resource_name = ""
    resource_type = ""
    if isinstance(resource, dict):
        resource_name = resource.get("name", resource.get("id", ""))
        resource_type = resource.get("type", resource.get("nativeType", ""))
    cloud_account = ""
    if isinstance(resource, dict):
        cloud_account = resource.get("cloudAccount", {}).get("name", "")

    entities: list[dict[str, Any]] = []
    if resource_name:
        entities.append({"type": resource_type or "cloud_resource", "value": resource_name})
    if cloud_account:
        entities.append({"type": "cloud_account", "value": cloud_account})

    # Wiz sometimes includes MITRE mappings in securitySubCategories
    mitre: list[str] = []
    sub_cats = issue.get("securitySubCategories", [])
    for cat in sub_cats:
        cat_title = cat.get("title", "") if isinstance(cat, dict) else str(cat)
        if cat_title.startswith("T") and cat_title[1:5].isdigit():
            mitre.append(cat_title)

    return NormalizedSecurityEvent(
        event_id=issue_id,
        vendor="wiz",
        event_type=f"issue.{status.lower()}",
        severity=_wiz_severity_map.get(severity_raw, "medium"),
        title=f"Wiz Issue: {rule_name or 'Security Finding'}",
        description=(
            f"Issue on {resource_type} '{resource_name}' in {cloud_account}: {rule_name}"
            if resource_name
            else f"Wiz issue: {rule_name}"
        ),
        entities=entities,
        mitre_techniques=mitre,
        raw_data=payload,
    )


# ── Kafka Publishing ─────────────────────────────────────────────────────────


async def _publish_to_kafka(event: NormalizedSecurityEvent) -> None:
    """Publish normalized event to Kafka security-webhooks topic."""
    if _producer is not None:
        try:
            from shieldops.events.topics import SecurityTopic

            await _producer.publish_webhook_event(
                event_id=event.event_id,
                vendor=event.vendor,
                severity=event.severity,
                title=event.title,
                entities=event.entities,
                mitre_techniques=event.mitre_techniques,
            )
            logger.info(
                "security_webhook_published",
                event_id=event.event_id,
                vendor=event.vendor,
                topic=SecurityTopic.SECURITY_WEBHOOKS,
            )
            return
        except Exception as exc:
            logger.warning("security_webhook_publish_failed", error=str(exc))

    # Buffer locally if Kafka is unavailable
    _event_buffer.append(event.model_dump())
    if len(_event_buffer) > 10_000:
        _event_buffer.pop(0)  # Ring-buffer eviction
    logger.debug(
        "security_webhook_buffered", event_id=event.event_id, buffer_size=len(_event_buffer)
    )


# ── Routes ───────────────────────────────────────────────────────────────────


@router.post("/crowdstrike")
async def receive_crowdstrike(
    request: Request,
    x_cs_hmac_signature: str = Header("", alias="X-CS-Hmac-Signature"),
) -> WebhookReceiveResponse:
    """Receive CrowdStrike Falcon detection events.

    Verifies the ``X-CS-Hmac-Signature`` header, deduplicates within a 5-min
    window, normalizes the event, and publishes to the ``security-webhooks``
    Kafka topic.
    """
    config = _vendor_configs.get("crowdstrike")
    if config and not config.enabled:
        raise HTTPException(status_code=503, detail="CrowdStrike webhook receiver is disabled")

    body = await request.body()

    # Verify signature
    secret = config.secret_key if config else ""
    if secret and not _verify_signature(body, x_cs_hmac_signature, secret, algorithm="sha256"):
        logger.warning("crowdstrike_signature_invalid")
        raise HTTPException(status_code=401, detail="Invalid CrowdStrike webhook signature")

    # Parse payload
    try:
        payload = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON payload") from exc

    # Normalize
    event = _normalize_crowdstrike(payload)

    # Dedup
    if _is_duplicate(event.event_id):
        logger.debug("crowdstrike_event_duplicate", event_id=event.event_id)
        return WebhookReceiveResponse(
            received=True,
            event_id=event.event_id,
            message="Duplicate event — already processing",
        )

    # Publish
    await _publish_to_kafka(event)

    logger.info(
        "crowdstrike_webhook_received",
        event_id=event.event_id,
        severity=event.severity,
        title=event.title,
    )
    return WebhookReceiveResponse(received=True, event_id=event.event_id)


@router.post("/defender")
async def receive_defender(
    request: Request,
    x_ms_webhook_signature: str = Header("", alias="X-MS-Webhook-Signature"),
) -> WebhookReceiveResponse:
    """Receive Microsoft Defender alert events.

    Verifies the ``X-MS-Webhook-Signature`` header, normalizes the alert,
    and publishes to the ``security-webhooks`` Kafka topic.
    """
    config = _vendor_configs.get("defender")
    if config and not config.enabled:
        raise HTTPException(status_code=503, detail="Defender webhook receiver is disabled")

    body = await request.body()

    secret = config.secret_key if config else ""
    if secret and not _verify_signature(body, x_ms_webhook_signature, secret, algorithm="sha256"):
        logger.warning("defender_signature_invalid")
        raise HTTPException(status_code=401, detail="Invalid Defender webhook signature")

    try:
        payload = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON payload") from exc

    event = _normalize_defender(payload)

    if _is_duplicate(event.event_id):
        logger.debug("defender_event_duplicate", event_id=event.event_id)
        return WebhookReceiveResponse(
            received=True,
            event_id=event.event_id,
            message="Duplicate event — already processing",
        )

    await _publish_to_kafka(event)

    logger.info(
        "defender_webhook_received",
        event_id=event.event_id,
        severity=event.severity,
        title=event.title,
    )
    return WebhookReceiveResponse(received=True, event_id=event.event_id)


@router.post("/wiz")
async def receive_wiz(
    request: Request,
    x_wiz_signature: str = Header("", alias="X-Wiz-Signature"),
) -> WebhookReceiveResponse:
    """Receive Wiz issue notification events.

    Verifies the ``X-Wiz-Signature`` header (HMAC-SHA256), normalizes the
    issue, and publishes to the ``security-webhooks`` Kafka topic.
    """
    config = _vendor_configs.get("wiz")
    if config and not config.enabled:
        raise HTTPException(status_code=503, detail="Wiz webhook receiver is disabled")

    body = await request.body()

    secret = config.secret_key if config else ""
    if secret and not _verify_signature(body, x_wiz_signature, secret, algorithm="sha256"):
        logger.warning("wiz_signature_invalid")
        raise HTTPException(status_code=401, detail="Invalid Wiz webhook signature")

    try:
        payload = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON payload") from exc

    event = _normalize_wiz(payload)

    if _is_duplicate(event.event_id):
        logger.debug("wiz_event_duplicate", event_id=event.event_id)
        return WebhookReceiveResponse(
            received=True,
            event_id=event.event_id,
            message="Duplicate event — already processing",
        )

    await _publish_to_kafka(event)

    logger.info(
        "wiz_webhook_received",
        event_id=event.event_id,
        severity=event.severity,
        title=event.title,
    )
    return WebhookReceiveResponse(received=True, event_id=event.event_id)


@router.get("/health")
async def webhook_security_health() -> dict[str, Any]:
    """Health check for security webhook endpoints."""
    return {
        "status": "healthy",
        "vendors": {
            vendor: {
                "enabled": cfg.enabled,
                "secret_configured": bool(cfg.secret_key),
            }
            for vendor, cfg in _vendor_configs.items()
        },
        "dedup_window_seconds": _dedup_window_seconds,
        "dedup_cache_size": len(_dedup_cache),
        "event_buffer_size": len(_event_buffer),
        "kafka_producer_connected": _producer is not None,
    }
