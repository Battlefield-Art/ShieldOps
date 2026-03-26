"""Security App Builder Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    AppRequirement,
    BuilderStage,
    DeploymentTarget,
    GeneratedCode,
    WorkflowDesign,
)
from .tools import SecurityAppBuilderToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def parse_requirements(
    state: dict[str, Any],
    toolkit: SecurityAppBuilderToolkit,
) -> dict[str, Any]:
    """Parse NL description into structured requirements."""
    logger.info("security_app_builder.node.parse_requirements")
    state = _to_dict(state)
    nl_description = state.get("nl_description", "")

    requirements = await toolkit.parse_nl_requirements(nl_description)
    req_dicts = [r.model_dump() for r in requirements]

    reasoning = (
        f"Parsed {len(requirements)} requirements from description ({len(nl_description)} chars)"
    )

    # LLM enhancement: intelligent requirement parsing
    try:
        from .prompts import (
            SYSTEM_PARSE_REQUIREMENTS,
            RequirementParseResult,
        )

        context = json.dumps(
            {
                "description": nl_description[:500],
                "detected_type": (requirements[0].app_type.value if requirements else "unknown"),
                "data_sources": (requirements[0].data_sources if requirements else []),
            },
            default=str,
        )
        llm_result = cast(
            RequirementParseResult,
            await llm_structured(
                system_prompt=SYSTEM_PARSE_REQUIREMENTS,
                user_prompt=(f"Parse these security app requirements:\n{context}"),
                schema=RequirementParseResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="security_app_builder",
            node="parse_requirements",
        )
        reasoning = f"{llm_result.summary} {reasoning}"

        # Enrich requirements with LLM insights
        if requirements and llm_result.data_sources:
            extra = [s for s in llm_result.data_sources if s not in requirements[0].data_sources]
            requirements[0].data_sources.extend(extra)
            req_dicts = [r.model_dump() for r in requirements]
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="security_app_builder",
            node="parse_requirements",
        )

    return {
        "stage": BuilderStage.DESIGN_WORKFLOW.value,
        "requirements": req_dicts,
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def design_workflow(
    state: dict[str, Any],
    toolkit: SecurityAppBuilderToolkit,
) -> dict[str, Any]:
    """Design a LangGraph workflow from requirements."""
    logger.info("security_app_builder.node.design_workflow")
    state = _to_dict(state)

    raw_reqs = state.get("requirements", [])
    reqs = [AppRequirement(**r) for r in raw_reqs]

    design = await toolkit.design_workflow(reqs)
    design_dict = design.model_dump()

    reasoning = (
        f"Designed {design.app_type.value} workflow "
        f"with {len(design.nodes)} nodes "
        f"and {len(design.edges)} edges"
    )

    # LLM enhancement: workflow design
    try:
        from .prompts import (
            SYSTEM_DESIGN_WORKFLOW,
            WorkflowDesignResult,
        )

        context = json.dumps(
            {
                "app_type": design.app_type.value,
                "nodes": [n.name for n in design.nodes],
                "requirements": (reqs[0].description[:300] if reqs else ""),
            },
            default=str,
        )
        llm_result = cast(
            WorkflowDesignResult,
            await llm_structured(
                system_prompt=SYSTEM_DESIGN_WORKFLOW,
                user_prompt=(f"Design this security workflow:\n{context}"),
                schema=WorkflowDesignResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="security_app_builder",
            node="design_workflow",
        )
        reasoning = f"{llm_result.summary} {reasoning}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="security_app_builder",
            node="design_workflow",
        )

    return {
        "stage": BuilderStage.GENERATE_CODE.value,
        "workflow_design": design_dict,
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def generate_code(
    state: dict[str, Any],
    toolkit: SecurityAppBuilderToolkit,
) -> dict[str, Any]:
    """Generate LangGraph code from workflow design."""
    logger.info("security_app_builder.node.generate_code")
    state = _to_dict(state)

    raw_design = state.get("workflow_design", {})
    design = WorkflowDesign(**raw_design)
    raw_reqs = state.get("requirements", [])
    reqs = [AppRequirement(**r) for r in raw_reqs]

    code_artifacts = await toolkit.generate_langgraph_code(design, reqs)
    code_dicts = [c.model_dump() for c in code_artifacts]

    total_lines = sum(c.line_count for c in code_artifacts)
    reasoning = f"Generated {len(code_artifacts)} code files ({total_lines} total lines)"

    # LLM enhancement: code generation
    try:
        from .prompts import (
            SYSTEM_GENERATE_CODE,
            CodeGenerationResult,
        )

        context = json.dumps(
            {
                "app_type": design.app_type.value,
                "nodes": [n.name for n in design.nodes],
                "requirements": (reqs[0].description[:300] if reqs else ""),
                "files_generated": [c.file_name for c in code_artifacts],
            },
            default=str,
        )
        llm_result = cast(
            CodeGenerationResult,
            await llm_structured(
                system_prompt=SYSTEM_GENERATE_CODE,
                user_prompt=(f"Generate LangGraph code for:\n{context}"),
                schema=CodeGenerationResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="security_app_builder",
            node="generate_code",
        )
        reasoning = f"{llm_result.summary} {reasoning}"

        # Replace template code with LLM-generated
        if llm_result.graph_code:
            for c in code_artifacts:
                if c.file_name == "graph.py":
                    c.content = llm_result.graph_code
                    c.line_count = c.content.count("\n") + 1
        if llm_result.models_code:
            for c in code_artifacts:
                if c.file_name == "models.py":
                    c.content = llm_result.models_code
                    c.line_count = c.content.count("\n") + 1
        if llm_result.nodes_code:
            for c in code_artifacts:
                if c.file_name == "nodes.py":
                    c.content = llm_result.nodes_code
                    c.line_count = c.content.count("\n") + 1
        if llm_result.tools_code:
            for c in code_artifacts:
                if c.file_name == "tools.py":
                    c.content = llm_result.tools_code
                    c.line_count = c.content.count("\n") + 1
        code_dicts = [c.model_dump() for c in code_artifacts]
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="security_app_builder",
            node="generate_code",
        )

    return {
        "stage": BuilderStage.VALIDATE_SECURITY.value,
        "generated_code": code_dicts,
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def validate_security(
    state: dict[str, Any],
    toolkit: SecurityAppBuilderToolkit,
) -> dict[str, Any]:
    """Validate generated code for security issues."""
    logger.info("security_app_builder.node.validate_security")
    state = _to_dict(state)

    raw_code = state.get("generated_code", [])
    code_artifacts = [GeneratedCode(**c) for c in raw_code]

    validations = await toolkit.validate_security(code_artifacts)
    val_dicts = [v.model_dump() for v in validations]

    passed_count = sum(1 for v in validations if v.passed)
    total = len(validations)
    score = round(passed_count / total, 4) if total > 0 else 0.0

    reasoning = f"Security validation: {passed_count}/{total} checks passed (score: {score})"

    # LLM enhancement: security validation
    try:
        from .prompts import (
            SYSTEM_VALIDATE_SECURITY,
            SecurityValidationResult,
        )

        context = json.dumps(
            {
                "checks_passed": passed_count,
                "checks_total": total,
                "failures": [
                    {
                        "check": v.check_name,
                        "details": v.details,
                    }
                    for v in validations
                    if not v.passed
                ],
                "code_files": [c.file_name for c in code_artifacts],
            },
            default=str,
        )
        llm_result = cast(
            SecurityValidationResult,
            await llm_structured(
                system_prompt=SYSTEM_VALIDATE_SECURITY,
                user_prompt=(f"Validate security of generated code:\n{context}"),
                schema=SecurityValidationResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="security_app_builder",
            node="validate_security",
        )
        reasoning = f"{llm_result.summary} {reasoning}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="security_app_builder",
            node="validate_security",
        )

    return {
        "stage": BuilderStage.DEPLOY_APP.value,
        "validations": val_dicts,
        "code_quality_score": score,
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def deploy_app(
    state: dict[str, Any],
    toolkit: SecurityAppBuilderToolkit,
) -> dict[str, Any]:
    """Deploy the generated application."""
    logger.info("security_app_builder.node.deploy_app")
    state = _to_dict(state)

    raw_code = state.get("generated_code", [])
    code_artifacts = [GeneratedCode(**c) for c in raw_code]

    target_str = state.get(
        "deployment_target",
        DeploymentTarget.DRY_RUN.value,
    )
    target = DeploymentTarget(target_str)
    tenant_id = state.get("tenant_id", "")

    result = await toolkit.deploy_app(code_artifacts, target, tenant_id)
    result_dict = result.model_dump()

    reasoning = f"Deployment to {target.value}: {'success' if result.success else 'failed'}"

    # LLM enhancement: deployment planning
    try:
        from .prompts import (
            SYSTEM_DEPLOY_APP,
            DeploymentPlanResult,
        )

        context = json.dumps(
            {
                "target": target.value,
                "success": result.success,
                "artifact_count": len(code_artifacts),
                "security_score": state.get("code_quality_score", 0.0),
            },
            default=str,
        )
        llm_result = cast(
            DeploymentPlanResult,
            await llm_structured(
                system_prompt=SYSTEM_DEPLOY_APP,
                user_prompt=(f"Plan deployment for security app:\n{context}"),
                schema=DeploymentPlanResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="security_app_builder",
            node="deploy_app",
        )
        reasoning = f"{llm_result.summary} {reasoning}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="security_app_builder",
            node="deploy_app",
        )

    return {
        "stage": BuilderStage.REPORT.value,
        "deployment": result_dict,
        "apps_built": state.get("apps_built", 0) + 1,
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def report(
    state: dict[str, Any],
    toolkit: SecurityAppBuilderToolkit,
) -> dict[str, Any]:
    """Generate final build report."""
    logger.info("security_app_builder.node.report")
    state = _to_dict(state)

    reqs = state.get("requirements", [])
    code = state.get("generated_code", [])
    vals = state.get("validations", [])
    deployment = state.get("deployment", {})
    score = state.get("code_quality_score", 0.0)

    passed = sum(1 for v in vals if (v.get("passed", False) if isinstance(v, dict) else v.passed))

    reasoning = (
        f"Build complete: {len(reqs)} requirements, "
        f"{len(code)} files generated, "
        f"{passed}/{len(vals)} security checks passed, "
        f"quality score {score}"
    )

    # LLM enhancement: report generation
    try:
        from .prompts import SYSTEM_REPORT

        context = json.dumps(
            {
                "requirements": len(reqs),
                "files_generated": len(code),
                "security_checks_passed": passed,
                "security_checks_total": len(vals),
                "quality_score": score,
                "deployed": deployment.get("success", False),
                "target": deployment.get("target", "dry_run"),
            },
            default=str,
        )

        from .prompts import SecurityValidationResult

        llm_result = cast(
            SecurityValidationResult,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=(f"Generate build report:\n{context}"),
                schema=SecurityValidationResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="security_app_builder",
            node="report",
        )
        reasoning = f"{llm_result.summary} {reasoning}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="security_app_builder",
            node="report",
        )

    return {
        "stage": BuilderStage.REPORT.value,
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }
