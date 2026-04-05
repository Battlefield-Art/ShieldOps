"""Approval workflow API routes."""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from shieldops.policy.approval_gate import (
    ApprovalRequest,
    ApprovalStatus,
    approve_request,
    check_approval_status,
    create_approval_request,
    deny_request,
)

logger = structlog.get_logger()
router = APIRouter(
    prefix="/approvals",
    tags=["Approvals"],
)


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class CreateApprovalBody(BaseModel):
    agent_name: str
    action: str
    context: dict[str, Any] = {}

    model_config = {"extra": "forbid"}


class ApprovalActionBody(BaseModel):
    approver: str

    model_config = {"extra": "forbid"}


class ApprovalResponse(BaseModel):
    id: str
    agent_name: str
    action: str
    status: str
    created_at: str
    expires_at: str
    approver: str | None = None
    decided_at: str | None = None

    model_config = {"extra": "forbid"}


def _to_response(req: ApprovalRequest) -> ApprovalResponse:
    return ApprovalResponse(
        id=req.id,
        agent_name=req.agent_name,
        action=req.action,
        status=req.status.value,
        created_at=req.created_at.isoformat(),
        expires_at=req.expires_at.isoformat(),
        approver=req.approver,
        decided_at=req.decided_at.isoformat() if req.decided_at else None,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("", response_model=ApprovalResponse, status_code=201)
async def create_approval(body: CreateApprovalBody) -> ApprovalResponse:
    """Create a new approval request."""
    req = create_approval_request(
        agent_name=body.agent_name,
        action=body.action,
        context=body.context,
    )
    return _to_response(req)


@router.get("/{request_id}", response_model=ApprovalResponse)
async def get_approval(request_id: str) -> ApprovalResponse:
    """Get the current status of an approval request."""
    req = check_approval_status(request_id)
    if req is None:
        raise HTTPException(status_code=404, detail="Approval request not found.")
    return _to_response(req)


@router.post("/{request_id}/approve", response_model=ApprovalResponse)
async def approve(request_id: str, body: ApprovalActionBody) -> ApprovalResponse:
    """Approve a pending request."""
    # Check current status first to detect non-pending requests
    current = check_approval_status(request_id)
    if current is None:
        raise HTTPException(status_code=404, detail="Approval request not found.")
    if current.status != ApprovalStatus.PENDING:
        raise HTTPException(
            status_code=409,
            detail=f"Request is not pending (current status: {current.status.value}).",
        )
    req = approve_request(request_id, approver=body.approver)
    if req is None:
        raise HTTPException(status_code=404, detail="Approval request not found.")
    return _to_response(req)


@router.post("/{request_id}/deny", response_model=ApprovalResponse)
async def deny(request_id: str, body: ApprovalActionBody) -> ApprovalResponse:
    """Deny a pending request."""
    current = check_approval_status(request_id)
    if current is None:
        raise HTTPException(status_code=404, detail="Approval request not found.")
    if current.status != ApprovalStatus.PENDING:
        raise HTTPException(
            status_code=409,
            detail=f"Request is not pending (current status: {current.status.value}).",
        )
    req = deny_request(request_id, approver=body.approver)
    if req is None:
        raise HTTPException(status_code=404, detail="Approval request not found.")
    return _to_response(req)
