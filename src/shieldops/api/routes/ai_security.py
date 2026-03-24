"""AI Runtime Defense API endpoints — prompt injection, LLM firewall, credential rotation."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from shieldops.api.auth.dependencies import get_current_user, require_role
from shieldops.api.auth.models import UserResponse, UserRole

logger = structlog.get_logger()
router = APIRouter(prefix="/ai-security", tags=["AI Security"])

_scanner: Any = None
_firewall: Any = None
_credential_store: Any = None


def set_scanner(scanner: Any) -> None:
    global _scanner
    _scanner = scanner


def set_firewall(firewall: Any) -> None:
    global _firewall
    _firewall = firewall


def set_credential_store(store: Any) -> None:
    global _credential_store
    _credential_store = store


# --- Request / Response Models ---


class ScanRequest(BaseModel):
    app_name: str
    app_type: str = "llm_application"
    scan_depth: str = "standard"
    include_prompt_injection: bool = True
    include_data_exfiltration: bool = True
    include_model_abuse: bool = True


class FirewallRuleRequest(BaseModel):
    name: str
    pattern: str
    action: str = "block"
    severity: str = "high"
    description: str = ""
    enabled: bool = True


# --- Scan Endpoints ---


@router.get("/scans")
async def list_scans(
    status: str | None = None,
    limit: int = 50,
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """List AI application security scans."""
    if _scanner is None:
        raise HTTPException(status_code=501, detail="AI security scanner not configured")
    scans: list[dict[str, Any]] = await _scanner.list_scans(status=status, limit=limit)
    return {"scans": scans, "total": len(scans)}


@router.post("/scan")
async def trigger_scan(
    body: ScanRequest,
    _user: UserResponse = Depends(require_role(UserRole.OPERATOR)),
) -> dict[str, Any]:
    """Trigger a new AI application security scan."""
    if _scanner is None:
        raise HTTPException(status_code=501, detail="AI security scanner not configured")
    scan_id = str(uuid.uuid4())
    result: dict[str, Any] = await _scanner.start_scan(
        scan_id=scan_id,
        app_name=body.app_name,
        app_type=body.app_type,
        scan_depth=body.scan_depth,
        checks={
            "prompt_injection": body.include_prompt_injection,
            "data_exfiltration": body.include_data_exfiltration,
            "model_abuse": body.include_model_abuse,
        },
    )
    logger.info("ai_security.scan_triggered", scan_id=scan_id, app_name=body.app_name)
    return {"scan_id": scan_id, **result}


@router.get("/scans/{scan_id}")
async def get_scan_results(
    scan_id: str,
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """Get results for a specific AI security scan."""
    if _scanner is None:
        raise HTTPException(status_code=501, detail="AI security scanner not configured")
    result: dict[str, Any] | None = await _scanner.get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result


# --- Firewall Endpoints ---


@router.get("/firewall/rules")
async def list_firewall_rules(
    enabled: bool | None = None,
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """List LLM firewall rules."""
    if _firewall is None:
        raise HTTPException(status_code=501, detail="LLM firewall not configured")
    rules: list[dict[str, Any]] = await _firewall.list_rules(enabled=enabled)
    return {"rules": rules, "total": len(rules)}


@router.post("/firewall/rules")
async def create_firewall_rule(
    body: FirewallRuleRequest,
    _user: UserResponse = Depends(require_role(UserRole.ADMIN)),
) -> dict[str, Any]:
    """Create a new LLM firewall rule."""
    if _firewall is None:
        raise HTTPException(status_code=501, detail="LLM firewall not configured")
    rule: dict[str, Any] = await _firewall.create_rule(
        name=body.name,
        pattern=body.pattern,
        action=body.action,
        severity=body.severity,
        description=body.description,
        enabled=body.enabled,
    )
    logger.info("ai_security.firewall_rule_created", name=body.name, action=body.action)
    return rule


# --- Credential Endpoints ---


@router.get("/credentials")
async def list_credentials(
    _user: UserResponse = Depends(require_role(UserRole.OPERATOR)),
) -> dict[str, Any]:
    """List AI service credentials (redacted)."""
    if _credential_store is None:
        raise HTTPException(status_code=501, detail="Credential store not configured")
    creds: list[dict[str, Any]] = await _credential_store.list_credentials()
    return {"credentials": creds, "total": len(creds)}


@router.post("/credentials/{credential_id}/rotate")
async def rotate_credential(
    credential_id: str,
    _user: UserResponse = Depends(require_role(UserRole.ADMIN)),
) -> dict[str, Any]:
    """Rotate an AI service credential."""
    if _credential_store is None:
        raise HTTPException(status_code=501, detail="Credential store not configured")
    result: dict[str, Any] | None = await _credential_store.rotate(credential_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Credential not found")
    logger.info("ai_security.credential_rotated", credential_id=credential_id)
    return result


# --- Metrics Endpoint ---


@router.get("/metrics")
async def ai_security_metrics(
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """Get AI security metrics (scan counts, blocked requests, detections)."""
    metrics: dict[str, Any] = {
        "timestamp": datetime.now(UTC).isoformat(),
        "scans": {},
        "firewall": {},
        "credentials": {},
    }
    if _scanner is not None:
        metrics["scans"] = await _scanner.get_metrics()
    if _firewall is not None:
        metrics["firewall"] = await _firewall.get_metrics()
    if _credential_store is not None:
        metrics["credentials"] = await _credential_store.get_metrics()
    return metrics
