"""Node implementations for the Access Review Agent LangGraph workflow."""

import time
from typing import Any, cast
from uuid import uuid4

import structlog

from shieldops.agents.access_review.models import (
    AccessReviewState,
    AccessRisk,
    AccessViolation,
    CertificationResult,
    Entitlement,
    ReasoningStep,
    ReviewDecision,
    ReviewStage,
    ReviewTask,
)
from shieldops.agents.access_review.prompts import (
    SYSTEM_ACCESS_ANALYSIS,
    SYSTEM_CAMPAIGN_REPORT,
    SYSTEM_REVIEW_TASK_GENERATION,
    SYSTEM_VIOLATION_CLASSIFICATION,
    AccessAnalysisResult,
    CampaignReportResult,
    ReviewTaskRecommendationResult,
    ViolationClassificationResult,
)
from shieldops.agents.access_review.tools import AccessReviewToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: AccessReviewToolkit | None = None


def set_toolkit(toolkit: AccessReviewToolkit) -> None:
    """Configure the toolkit used by all nodes."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> AccessReviewToolkit:
    if _toolkit is None:
        return AccessReviewToolkit()
    return _toolkit


def _elapsed_ms(start: float) -> int:
    return int((time.time() - start) * 1000)


# ---------------------------------------------------------------------------
# Node 1: Collect Entitlements
# ---------------------------------------------------------------------------


async def collect_entitlements(state: AccessReviewState) -> dict[str, Any]:
    """Collect all entitlements from IAM providers for the tenant."""
    start = time.time()
    toolkit = _get_toolkit()

    logger.info(
        "access_review.collecting_entitlements",
        tenant_id=state.tenant_id,
        campaign=state.campaign_name,
    )

    raw_entitlements = await toolkit.collect_entitlements(
        tenant_id=state.tenant_id,
        identity_types=["human", "service_account", "ai_agent"],
    )

    # Enrich with last-usage data
    ent_ids = [e.get("id", "") for e in raw_entitlements]
    usage_map = await toolkit.check_last_usage(ent_ids)

    # Resolve identity statuses for orphan detection
    identity_ids = list({e.get("identity_id", "") for e in raw_entitlements})
    identity_statuses = await toolkit.resolve_identity_status(identity_ids)

    entitlements: list[Entitlement] = []
    for raw in raw_entitlements:
        eid = raw.get("id", f"ent-{uuid4().hex[:8]}")
        last_used = usage_map.get(eid, raw.get("last_used", 0.0))
        identity_id = raw.get("identity_id", "")
        identity_status = identity_statuses.get(identity_id, "active")

        # Preliminary risk scoring
        risk = AccessRisk.COMPLIANT
        age_days = (time.time() - raw.get("granted_at", time.time())) / 86400
        unused_days = (time.time() - last_used) / 86400 if last_used > 0 else 9999

        if identity_status == "terminated":
            risk = AccessRisk.CRITICAL
        elif unused_days > 180:
            risk = AccessRisk.HIGH
        elif unused_days > 90 or (age_days > 365 and not raw.get("justification")):
            risk = AccessRisk.MEDIUM

        entitlements.append(
            Entitlement(
                id=eid,
                identity_id=identity_id,
                identity_type=raw.get("identity_type", "human"),
                resource=raw.get("resource", ""),
                permission=raw.get("permission", ""),
                granted_at=raw.get("granted_at", 0.0),
                last_used=last_used,
                granted_by=raw.get("granted_by", ""),
                justification=raw.get("justification", ""),
                risk_level=risk,
            )
        )

    step = ReasoningStep(
        step=1,
        detail=(f"Collected {len(entitlements)} entitlements for tenant {state.tenant_id}"),
        confidence=0.95,
        metadata={
            "identity_count": len(identity_ids),
            "duration_ms": _elapsed_ms(start),
        },
    )

    return {
        "entitlements": entitlements,
        "stage": ReviewStage.COLLECT_ENTITLEMENTS,
        "reasoning_chain": [step],
        "current_step": "collect_entitlements",
        "session_start": start,
    }


# ---------------------------------------------------------------------------
# Node 2: Analyze Access
# ---------------------------------------------------------------------------


async def analyze_access(state: AccessReviewState) -> dict[str, Any]:
    """Analyze access patterns using LLM to find violations."""
    start = time.time()
    toolkit = _get_toolkit()

    logger.info(
        "access_review.analyzing_access",
        entitlement_count=len(state.entitlements),
    )

    # Fetch SoD policy for conflict detection
    sod_rules = await toolkit.get_sod_policy(state.tenant_id)

    # Build context for LLM
    context_lines = ["## Entitlements Under Review"]
    for ent in state.entitlements[:50]:
        unused_days = int((time.time() - ent.last_used) / 86400) if ent.last_used > 0 else "never"
        context_lines.append(
            f"- {ent.id}: identity={ent.identity_id} ({ent.identity_type}), "
            f"resource={ent.resource}, permission={ent.permission}, "
            f"unused_days={unused_days}, risk={ent.risk_level}, "
            f"justification={ent.justification!r}"
        )

    context_lines.append("\n## Separation-of-Duty Rules")
    for rule in sod_rules:
        context_lines.append(
            f"- {rule.get('rule_id')}: {rule.get('name')} — "
            f"conflicts={rule.get('conflicting_permissions')}"
        )

    user_prompt = "\n".join(context_lines)

    violations: list[AccessViolation] = []

    try:
        result = cast(
            AccessAnalysisResult,
            await llm_structured(
                system_prompt=SYSTEM_ACCESS_ANALYSIS,
                user_prompt=user_prompt,
                schema=AccessAnalysisResult,
            ),
        )

        # Map LLM findings to violation records
        for excess in result.excessive_access:
            violations.append(
                AccessViolation(
                    id=f"viol-{uuid4().hex[:8]}",
                    entitlement_id=excess.get("entitlement_id", ""),
                    violation_type="excessive",
                    description=excess.get("reason", "Excessive permissions"),
                    severity=excess.get("severity", "medium"),
                    auto_revocable=False,
                )
            )

        for unused_id in result.unused_access:
            violations.append(
                AccessViolation(
                    id=f"viol-{uuid4().hex[:8]}",
                    entitlement_id=unused_id,
                    violation_type="unused",
                    description="Entitlement not used in review period",
                    severity="medium",
                    auto_revocable=True,
                )
            )

        for conflict in result.sod_conflicts:
            violations.append(
                AccessViolation(
                    id=f"viol-{uuid4().hex[:8]}",
                    entitlement_id=conflict.get("entitlement_id", ""),
                    violation_type="separation_of_duties",
                    description=conflict.get("description", "SoD conflict detected"),
                    severity="high",
                    auto_revocable=False,
                )
            )

        for orphaned_id in result.orphaned_access:
            violations.append(
                AccessViolation(
                    id=f"viol-{uuid4().hex[:8]}",
                    entitlement_id=orphaned_id,
                    violation_type="orphaned",
                    description="Entitlement for non-existent identity",
                    severity="critical",
                    auto_revocable=True,
                )
            )

        output_detail = (
            f"LLM analysis: {result.risk_summary[:200]}. Found {len(violations)} violations."
        )
    except Exception as exc:
        logger.error("access_review.analysis_failed", error=str(exc))
        output_detail = f"LLM analysis failed, using heuristic fallback: {exc}"

        # Heuristic fallback
        for ent in state.entitlements:
            if ent.risk_level == AccessRisk.CRITICAL:
                violations.append(
                    AccessViolation(
                        id=f"viol-{uuid4().hex[:8]}",
                        entitlement_id=ent.id,
                        violation_type="orphaned",
                        description="Terminated identity with active access",
                        severity="critical",
                        auto_revocable=True,
                    )
                )
            elif ent.risk_level == AccessRisk.HIGH:
                violations.append(
                    AccessViolation(
                        id=f"viol-{uuid4().hex[:8]}",
                        entitlement_id=ent.id,
                        violation_type="unused",
                        description="Access unused for >180 days",
                        severity="high",
                        auto_revocable=True,
                    )
                )

        # Check SoD conflicts via rule matching
        identity_perms: dict[str, set[str]] = {}
        for ent in state.entitlements:
            identity_perms.setdefault(ent.identity_id, set()).add(ent.permission)

        for rule in sod_rules:
            conflicts = rule.get("conflicting_permissions", [])
            if len(conflicts) < 2:
                continue
            for iid, perms in identity_perms.items():
                if all(c in perms for c in conflicts):
                    violations.append(
                        AccessViolation(
                            id=f"viol-{uuid4().hex[:8]}",
                            entitlement_id=f"sod-{iid}",
                            violation_type="separation_of_duties",
                            description=(
                                f"Identity {iid} has conflicting permissions: {conflicts}"
                            ),
                            severity="high",
                            auto_revocable=False,
                        )
                    )

    step = ReasoningStep(
        step=len(state.reasoning_chain) + 1,
        detail=output_detail,
        confidence=0.85,
        metadata={
            "violations_found": len(violations),
            "duration_ms": _elapsed_ms(start),
        },
    )

    return {
        "violations": violations,
        "stage": ReviewStage.ANALYZE_ACCESS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_access",
    }


# ---------------------------------------------------------------------------
# Node 3: Identify Violations (classify severity)
# ---------------------------------------------------------------------------


async def identify_violations(state: AccessReviewState) -> dict[str, Any]:
    """Classify violations by severity and determine auto-revocability."""
    start = time.time()

    logger.info(
        "access_review.classifying_violations",
        violation_count=len(state.violations),
    )

    if not state.violations:
        step = ReasoningStep(
            step=len(state.reasoning_chain) + 1,
            detail="No violations to classify.",
            confidence=1.0,
            metadata={"duration_ms": _elapsed_ms(start)},
        )
        return {
            "stage": ReviewStage.IDENTIFY_VIOLATIONS,
            "reasoning_chain": [*state.reasoning_chain, step],
            "current_step": "identify_violations",
        }

    # Build entitlement lookup
    ent_map = {e.id: e for e in state.entitlements}

    context_lines = ["## Violations to Classify"]
    for v in state.violations[:50]:
        ent = ent_map.get(v.entitlement_id)
        ent_detail = ""
        if ent:
            ent_detail = (
                f" (identity={ent.identity_id}, type={ent.identity_type}, "
                f"resource={ent.resource}, permission={ent.permission})"
            )
        context_lines.append(
            f"- {v.id}: type={v.violation_type}, "
            f"entitlement={v.entitlement_id}{ent_detail}, "
            f"description={v.description!r}"
        )

    user_prompt = "\n".join(context_lines)
    updated_violations = list(state.violations)

    try:
        result = cast(
            ViolationClassificationResult,
            await llm_structured(
                system_prompt=SYSTEM_VIOLATION_CLASSIFICATION,
                user_prompt=user_prompt,
                schema=ViolationClassificationResult,
            ),
        )

        # Update violations with LLM classifications
        classified_map = {c.get("id", ""): c for c in result.classified_violations}
        for i, v in enumerate(updated_violations):
            if v.id in classified_map:
                cls = classified_map[v.id]
                updated_violations[i] = v.model_copy(
                    update={
                        "severity": cls.get("severity", v.severity),
                        "auto_revocable": cls.get("auto_revocable", v.auto_revocable),
                    }
                )

        output_detail = (
            f"Classified {len(result.classified_violations)} violations: "
            f"{result.critical_count} critical, {result.high_count} high. "
            f"Compliance gaps: {result.compliance_gaps}"
        )
    except Exception as exc:
        logger.error("access_review.classification_failed", error=str(exc))
        output_detail = f"Classification failed, using defaults: {exc}"

    step = ReasoningStep(
        step=len(state.reasoning_chain) + 1,
        detail=output_detail,
        confidence=0.80,
        metadata={"duration_ms": _elapsed_ms(start)},
    )

    return {
        "violations": updated_violations,
        "stage": ReviewStage.IDENTIFY_VIOLATIONS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "identify_violations",
    }


# ---------------------------------------------------------------------------
# Node 4: Generate Review Tasks
# ---------------------------------------------------------------------------


async def generate_tasks(state: AccessReviewState) -> dict[str, Any]:
    """Generate review tasks for violations requiring human certification."""
    start = time.time()

    logger.info(
        "access_review.generating_tasks",
        violation_count=len(state.violations),
    )

    ent_map = {e.id: e for e in state.entitlements}

    context_lines = ["## Violations Requiring Review Tasks"]
    for v in state.violations[:50]:
        ent = ent_map.get(v.entitlement_id)
        ent_detail = ""
        if ent:
            ent_detail = (
                f", identity={ent.identity_id}, resource={ent.resource}, "
                f"permission={ent.permission}"
            )
        context_lines.append(
            f"- {v.id}: type={v.violation_type}, "
            f"severity={v.severity}, auto_revocable={v.auto_revocable}"
            f"{ent_detail}"
        )

    user_prompt = "\n".join(context_lines)
    review_tasks: list[ReviewTask] = []

    try:
        result = cast(
            ReviewTaskRecommendationResult,
            await llm_structured(
                system_prompt=SYSTEM_REVIEW_TASK_GENERATION,
                user_prompt=user_prompt,
                schema=ReviewTaskRecommendationResult,
            ),
        )

        for task_data in result.tasks:
            ent_id = task_data.get("entitlement_id", "")
            ent = ent_map.get(ent_id)
            decision_str = task_data.get("recommended_decision", "escalate")
            try:
                decision = ReviewDecision(decision_str)
            except ValueError:
                decision = ReviewDecision.ESCALATE

            review_tasks.append(
                ReviewTask(
                    id=f"task-{uuid4().hex[:8]}",
                    reviewer=task_data.get("reviewer", "security-lead"),
                    entitlement_id=ent_id,
                    identity_name=(ent.identity_id if ent else task_data.get("identity_name", "")),
                    resource=(ent.resource if ent else task_data.get("resource", "")),
                    permission=(ent.permission if ent else task_data.get("permission", "")),
                    recommended_decision=decision,
                    reason=task_data.get("reason", ""),
                    due_date=time.time() + 86400 * 14,
                )
            )

        output_detail = (
            f"Generated {len(review_tasks)} tasks. "
            f"{result.auto_revoke_count} eligible for auto-revocation. "
            f"{result.summary[:150]}"
        )
    except Exception as exc:
        logger.error("access_review.task_generation_failed", error=str(exc))
        output_detail = f"Task generation failed, using defaults: {exc}"

        # Fallback: generate tasks from violations directly
        for v in state.violations:
            if v.auto_revocable:
                decision = ReviewDecision.REVOKE
            elif v.severity == "critical":
                decision = ReviewDecision.ESCALATE
            else:
                decision = ReviewDecision.MODIFY

            ent = ent_map.get(v.entitlement_id)
            review_tasks.append(
                ReviewTask(
                    id=f"task-{uuid4().hex[:8]}",
                    reviewer="security-lead",
                    entitlement_id=v.entitlement_id,
                    identity_name=ent.identity_id if ent else "",
                    resource=ent.resource if ent else "",
                    permission=ent.permission if ent else "",
                    recommended_decision=decision,
                    reason=v.description,
                    due_date=time.time() + 86400 * 14,
                )
            )

    step = ReasoningStep(
        step=len(state.reasoning_chain) + 1,
        detail=output_detail,
        confidence=0.85,
        metadata={
            "task_count": len(review_tasks),
            "duration_ms": _elapsed_ms(start),
        },
    )

    return {
        "review_tasks": review_tasks,
        "stage": ReviewStage.GENERATE_TASKS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "generate_tasks",
    }


# ---------------------------------------------------------------------------
# Node 5: Certify (process certifications / auto-revoke)
# ---------------------------------------------------------------------------


async def certify(state: AccessReviewState) -> dict[str, Any]:
    """Process certifications: auto-revoke eligible items, await others."""
    start = time.time()
    toolkit = _get_toolkit()

    logger.info(
        "access_review.certifying",
        task_count=len(state.review_tasks),
    )

    certifications: list[CertificationResult] = list(state.certifications)

    for task in state.review_tasks:
        # Find corresponding violation
        matching_violation = next(
            (v for v in state.violations if v.entitlement_id == task.entitlement_id),
            None,
        )

        # Auto-certify revocations for auto-revocable violations
        if (
            matching_violation
            and matching_violation.auto_revocable
            and task.recommended_decision == ReviewDecision.REVOKE
        ):
            record = await toolkit.submit_certification(
                task_id=task.id,
                decision=ReviewDecision.REVOKE,
                certified_by="system:auto-revoke",
                notes=(
                    f"Auto-revoked: {matching_violation.violation_type} "
                    f"violation — {matching_violation.description}"
                ),
            )
            certifications.append(
                CertificationResult(
                    id=record.get("id", f"cert-{uuid4().hex[:8]}"),
                    task_id=task.id,
                    decision=ReviewDecision.REVOKE,
                    certified_by="system:auto-revoke",
                    certified_at=record.get("certified_at", time.time()),
                    notes=record.get("notes", ""),
                )
            )
        else:
            # Pending human review — create a placeholder certification
            certifications.append(
                CertificationResult(
                    id=f"cert-{uuid4().hex[:8]}",
                    task_id=task.id,
                    decision=task.recommended_decision,
                    certified_by="pending:human-review",
                    certified_at=0.0,
                    notes=f"Awaiting reviewer: {task.reviewer}",
                )
            )

    auto_count = sum(1 for c in certifications if c.certified_by == "system:auto-revoke")
    pending_count = sum(1 for c in certifications if c.certified_by == "pending:human-review")

    step = ReasoningStep(
        step=len(state.reasoning_chain) + 1,
        detail=(
            f"Processed {len(certifications)} certifications: "
            f"{auto_count} auto-revoked, {pending_count} pending review"
        ),
        confidence=0.90,
        metadata={
            "auto_revoked": auto_count,
            "pending_review": pending_count,
            "duration_ms": _elapsed_ms(start),
        },
    )

    return {
        "certifications": certifications,
        "stage": ReviewStage.CERTIFY,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "certify",
    }


# ---------------------------------------------------------------------------
# Node 6: Report
# ---------------------------------------------------------------------------


async def report(state: AccessReviewState) -> dict[str, Any]:
    """Generate final campaign report with compliance findings."""
    start = time.time()

    logger.info(
        "access_review.generating_report",
        campaign=state.campaign_name,
        entitlements=len(state.entitlements),
        violations=len(state.violations),
        certifications=len(state.certifications),
    )

    auto_revoked = sum(1 for c in state.certifications if c.certified_by == "system:auto-revoke")
    pending = sum(1 for c in state.certifications if c.certified_by == "pending:human-review")
    critical_violations = sum(1 for v in state.violations if v.severity == "critical")
    high_violations = sum(1 for v in state.violations if v.severity == "high")

    # Build report context for LLM
    context_lines = [
        f"## Campaign: {state.campaign_name}",
        f"Tenant: {state.tenant_id}",
        f"Total entitlements reviewed: {len(state.entitlements)}",
        f"Violations found: {len(state.violations)}",
        f"  - Critical: {critical_violations}",
        f"  - High: {high_violations}",
        f"Certifications: {len(state.certifications)}",
        f"  - Auto-revoked: {auto_revoked}",
        f"  - Pending human review: {pending}",
        "",
        "## Violation Breakdown",
    ]
    violation_types: dict[str, int] = {}
    for v in state.violations:
        violation_types[v.violation_type] = violation_types.get(v.violation_type, 0) + 1
    for vtype, count in violation_types.items():
        context_lines.append(f"- {vtype}: {count}")

    user_prompt = "\n".join(context_lines)

    stats: dict[str, Any] = {
        "total_entitlements": len(state.entitlements),
        "total_violations": len(state.violations),
        "critical_violations": critical_violations,
        "high_violations": high_violations,
        "auto_revoked": auto_revoked,
        "pending_review": pending,
        "violation_types": violation_types,
    }

    try:
        result = cast(
            CampaignReportResult,
            await llm_structured(
                system_prompt=SYSTEM_CAMPAIGN_REPORT,
                user_prompt=user_prompt,
                schema=CampaignReportResult,
            ),
        )

        stats["executive_summary"] = result.executive_summary
        stats["compliance_status"] = result.compliance_status
        stats["soc2_findings"] = result.soc2_findings
        stats["hipaa_findings"] = result.hipaa_findings
        stats["risk_reduction_pct"] = result.risk_reduction_pct
        stats["open_items"] = result.open_items

        output_detail = (
            f"Report generated: {result.compliance_status}. "
            f"Risk reduction: {result.risk_reduction_pct}%. "
            f"{result.executive_summary[:150]}"
        )
    except Exception as exc:
        logger.error("access_review.report_failed", error=str(exc))
        output_detail = f"Report generation failed, using stats only: {exc}"

        stats["compliance_status"] = (
            "non_compliant" if critical_violations > 0 else "partially_compliant"
        )
        stats["executive_summary"] = (
            f"Access review campaign '{state.campaign_name}' found "
            f"{len(state.violations)} violations across "
            f"{len(state.entitlements)} entitlements. "
            f"{auto_revoked} auto-revoked, {pending} pending."
        )

    session_duration = int((time.time() - state.session_start) * 1000)

    step = ReasoningStep(
        step=len(state.reasoning_chain) + 1,
        detail=output_detail,
        confidence=0.90,
        metadata={
            "duration_ms": _elapsed_ms(start),
            "session_total_ms": session_duration,
        },
    )

    return {
        "stats": stats,
        "stage": ReviewStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
        "session_duration_ms": session_duration,
    }
