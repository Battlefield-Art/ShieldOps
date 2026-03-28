"""Node implementations for Custom Agent Factory."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.custom_agent_factory.models import (
    AgentCategory,
    CustomAgentFactoryState,
    FactoryStage,
    ValidationStatus,
)
from shieldops.agents.custom_agent_factory.prompts import (
    SYSTEM_AGENT_DESIGN,
    SYSTEM_CODE_GENERATION,
    SYSTEM_CODE_VALIDATION,
    SYSTEM_REQUIREMENT_PARSE,
    AgentDesignOutput,
    CodeGenerationOutput,
    RequirementParseOutput,
    ValidationOutput,
)
from shieldops.agents.custom_agent_factory.tools import (
    CustomAgentFactoryToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: CustomAgentFactoryToolkit | None = None


def set_toolkit(
    toolkit: CustomAgentFactoryToolkit,
) -> None:
    """Inject the toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> CustomAgentFactoryToolkit:
    if _toolkit is None:
        return CustomAgentFactoryToolkit()
    return _toolkit


def _elapsed_ms(start: datetime) -> int:
    return int((datetime.now(UTC) - start).total_seconds() * 1000)


# -------------------------------------------------------
# Node 1: parse_requirements
# -------------------------------------------------------
async def parse_requirements(
    state: CustomAgentFactoryState,
) -> dict[str, Any]:
    """Parse NL description into requirements."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "agent_factory.parse_requirements",
        tenant_id=state.tenant_id,
    )

    reqs = await toolkit.parse_requirements(state.requirements.description)

    # LLM-powered parsing
    try:
        result = cast(
            RequirementParseOutput,
            await llm_structured(
                system_prompt=(SYSTEM_REQUIREMENT_PARSE),
                user_prompt=(state.requirements.description),
                schema=RequirementParseOutput,
            ),
        )
        reqs.agent_name = result.agent_name
        if result.category in [c.value for c in AgentCategory]:
            reqs.category = AgentCategory(result.category)
        reqs.trigger = result.trigger
        reqs.data_sources = result.data_sources[:6]
        reqs.actions = result.actions[:8]
        reqs.schedule = result.schedule
    except Exception as exc:
        logger.debug(
            "llm_fallback",
            node="parse_requirements",
            error=str(exc),
        )

    chain_entry = f"Parsed: '{reqs.agent_name}' ({reqs.category.value})"

    return {
        "requirements": reqs,
        "stage": FactoryStage.DESIGN_AGENT,
        "reasoning_chain": [chain_entry],
        "current_step": "parse_requirements",
        "session_start": start,
    }


# -------------------------------------------------------
# Node 2: design_agent
# -------------------------------------------------------
async def design_agent(
    state: CustomAgentFactoryState,
) -> dict[str, Any]:
    """Design the agent blueprint."""
    toolkit = _get_toolkit()

    logger.info(
        "agent_factory.design_agent",
        name=state.requirements.agent_name,
    )

    design = await toolkit.design_agent(state.requirements)

    # LLM design enrichment
    user_prompt = (
        f"Agent: {state.requirements.agent_name}\n"
        f"Category: {state.requirements.category}\n"
        f"Actions: {state.requirements.actions}\n"
        f"Sources: {state.requirements.data_sources}"
    )
    try:
        result = cast(
            AgentDesignOutput,
            await llm_structured(
                system_prompt=SYSTEM_AGENT_DESIGN,
                user_prompt=user_prompt,
                schema=AgentDesignOutput,
            ),
        )
        design.nodes = result.nodes[:8]
        design.state_fields = result.state_fields[:15]
        design.tools_needed = result.tools_needed[:10]
        design.edge_flow = result.edge_flow[:10]
    except Exception as exc:
        logger.debug(
            "llm_fallback",
            node="design_agent",
            error=str(exc),
        )

    chain_entry = f"Designed: {len(design.nodes)} nodes, {len(design.tools_needed)} tools"

    return {
        "design": design,
        "stage": FactoryStage.GENERATE_CODE,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "design_agent",
    }


# -------------------------------------------------------
# Node 3: generate_code
# -------------------------------------------------------
async def generate_code(
    state: CustomAgentFactoryState,
) -> dict[str, Any]:
    """Generate agent code."""
    toolkit = _get_toolkit()

    logger.info(
        "agent_factory.generate_code",
        name=state.design.agent_name,
    )

    generated = await toolkit.generate_code(state.design)

    # LLM code generation
    user_prompt = (
        f"Agent: {state.design.agent_name}\n"
        f"Nodes: {state.design.nodes}\n"
        f"State: {state.design.state_fields}\n"
        f"Tools: {state.design.tools_needed}\n"
        f"Flow: {state.design.edge_flow}\n"
        f"Desc: {state.requirements.description}"
    )
    try:
        result = cast(
            CodeGenerationOutput,
            await llm_structured(
                system_prompt=(SYSTEM_CODE_GENERATION),
                user_prompt=user_prompt,
                schema=CodeGenerationOutput,
            ),
        )
        generated.files = {
            "__init__.py": result.init_py,
            "models.py": result.models_py,
            "tools.py": result.tools_py,
            "nodes.py": result.nodes_py,
            "graph.py": result.graph_py,
            "prompts.py": result.prompts_py,
            "runner.py": result.runner_py,
        }
        generated.file_count = len(generated.files)
        generated.total_lines = sum(c.count("\n") + 1 for c in generated.files.values())
    except Exception as exc:
        logger.debug(
            "llm_fallback",
            node="generate_code",
            error=str(exc),
        )

    chain_entry = f"Generated: {generated.file_count} files, {generated.total_lines} lines"

    return {
        "generated_code": generated,
        "stage": FactoryStage.VALIDATE_AGENT,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "generate_code",
    }


# -------------------------------------------------------
# Node 4: validate_agent
# -------------------------------------------------------
async def validate_agent(
    state: CustomAgentFactoryState,
) -> dict[str, Any]:
    """Validate generated agent code."""
    toolkit = _get_toolkit()

    logger.info(
        "agent_factory.validate_agent",
        name=state.generated_code.agent_name,
    )

    validation = await toolkit.validate_agent(state.generated_code)

    # LLM code review
    code_preview = ""
    for fname, content in state.generated_code.files.items():
        code_preview += f"\n### {fname}\n{content[:200]}\n"

    try:
        result = cast(
            ValidationOutput,
            await llm_structured(
                system_prompt=(SYSTEM_CODE_VALIDATION),
                user_prompt=code_preview[:2000],
                schema=ValidationOutput,
            ),
        )
        validation.syntax_valid = result.syntax_valid
        validation.pattern_compliant = result.pattern_compliant
        validation.warnings.extend(result.warnings[:5])
        validation.errors.extend(result.errors[:5])
        validation.quality_score = result.quality_score

        if validation.errors:
            validation.status = ValidationStatus.INVALID
        elif validation.warnings:
            validation.status = ValidationStatus.HAS_WARNINGS
        else:
            validation.status = ValidationStatus.VALID
    except Exception as exc:
        logger.debug(
            "llm_fallback",
            node="validate_agent",
            error=str(exc),
        )

    chain_entry = f"Validation: {validation.status.value}, quality={validation.quality_score}%"

    return {
        "validation": validation,
        "code_quality_score": (validation.quality_score),
        "stage": FactoryStage.REGISTER_AGENT,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "validate_agent",
    }


# -------------------------------------------------------
# Node 5: register_agent
# -------------------------------------------------------
async def register_agent(
    state: CustomAgentFactoryState,
) -> dict[str, Any]:
    """Register the agent in the fleet."""
    toolkit = _get_toolkit()

    logger.info(
        "agent_factory.register_agent",
        name=state.generated_code.agent_name,
    )

    reg = await toolkit.register_agent(state.generated_code, state.validation)

    chain_entry = f"Registration: {'success' if reg.registered else 'failed'} — {reg.notes}"

    return {
        "registration": reg,
        "agents_created": 1 if reg.registered else 0,
        "stage": FactoryStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "register_agent",
    }


# -------------------------------------------------------
# Node 6: report
# -------------------------------------------------------
async def report(
    state: CustomAgentFactoryState,
) -> dict[str, Any]:
    """Generate factory report."""
    logger.info(
        "agent_factory.report",
        name=state.requirements.agent_name,
        quality=state.code_quality_score,
    )

    duration = 0
    if state.session_start:
        duration = _elapsed_ms(state.session_start)

    stats = {
        "agent_name": state.requirements.agent_name,
        "category": state.requirements.category,
        "files_generated": (state.generated_code.file_count),
        "total_lines": (state.generated_code.total_lines),
        "validation_status": (state.validation.status),
        "quality_score": state.code_quality_score,
        "registered": (state.registration.registered),
        "registry_id": (state.registration.registry_id),
    }

    chain_entry = (
        f"Report: {state.requirements.agent_name} "
        f"quality={state.code_quality_score}% "
        f"registered={state.registration.registered}"
    )

    return {
        "stats": stats,
        "stage": FactoryStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "complete",
        "session_duration_ms": duration,
    }
