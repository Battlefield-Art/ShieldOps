"""Tool functions for Custom Agent Factory."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.custom_agent_factory.models import (
    AgentCategory,
    AgentDesign,
    AgentRequirement,
    AgentValidation,
    GeneratedAgent,
    RegistrationResult,
    ValidationStatus,
)

logger = structlog.get_logger()


class CustomAgentFactoryToolkit:
    """Tools for generating custom agents."""

    def __init__(
        self,
        registry_client: Any | None = None,
        template_store: Any | None = None,
        validator_client: Any | None = None,
    ) -> None:
        self._registry = registry_client
        self._templates = template_store
        self._validator = validator_client

    async def parse_requirements(
        self,
        description: str,
    ) -> AgentRequirement:
        """Parse NL description into requirements."""
        logger.info(
            "agent_factory.parsing_requirements",
            desc_len=len(description),
        )

        # Basic keyword extraction
        lower = description.lower()
        category = AgentCategory.DETECTION
        if "respond" in lower or "remediat" in lower:
            category = AgentCategory.RESPONSE
        elif "compliance" in lower or "audit" in lower:
            category = AgentCategory.COMPLIANCE
        elif "monitor" in lower:
            category = AgentCategory.MONITORING
        elif "test" in lower:
            category = AgentCategory.TESTING
        elif "report" in lower:
            category = AgentCategory.REPORTING

        # Generate snake_case name
        words = description.split()[:4]
        name = "_".join(w.lower() for w in words if w.isalnum())

        return AgentRequirement(
            id=f"req-{uuid4().hex[:8]}",
            description=description,
            category=category,
            agent_name=name or "custom_agent",
            trigger="event",
            data_sources=["agent_findings"],
            actions=["analyze", "report"],
            output_format="json",
            schedule="on_demand",
        )

    async def design_agent(
        self,
        requirements: AgentRequirement,
    ) -> AgentDesign:
        """Design the agent blueprint."""
        logger.info(
            "agent_factory.designing_agent",
            name=requirements.agent_name,
        )

        return AgentDesign(
            id=f"design-{uuid4().hex[:8]}",
            agent_name=requirements.agent_name,
            category=requirements.category,
            nodes=[
                "initialize",
                "collect_data",
                "analyze",
                "decide",
                "execute",
                "report",
            ],
            state_fields=[
                "request_id",
                "tenant_id",
                "stage",
                "data",
                "analysis",
                "decision",
                "result",
                "reasoning_chain",
                "error",
            ],
            tools_needed=[
                "collect_data",
                "analyze_data",
                "execute_action",
            ],
            edge_flow=[
                "initialize->collect_data",
                "collect_data->analyze",
                "analyze->decide",
                "decide->execute",
                "execute->report",
                "report->END",
            ],
        )

    async def generate_code(
        self,
        design: AgentDesign,
    ) -> GeneratedAgent:
        """Generate agent code from design."""
        logger.info(
            "agent_factory.generating_code",
            name=design.agent_name,
        )

        # Template-based code generation
        name = design.agent_name
        files: dict[str, str] = {}

        files["__init__.py"] = f'"""Custom agent: {name}."""\n'
        files["models.py"] = (
            f'"""Models for {name}."""\n'
            f"from __future__ import annotations\n"
            f"from pydantic import BaseModel, Field\n"
            f"from enum import StrEnum\n"
            f"from typing import Any\n\n"
            f"class {name.title().replace('_', '')}"
            f"State(BaseModel):\n"
            f'    request_id: str = ""\n'
            f'    tenant_id: str = ""\n'
            f'    error: str = ""\n'
        )
        files["tools.py"] = f'"""Tools for {name}."""\n'
        files["nodes.py"] = f'"""Nodes for {name}."""\n'
        files["graph.py"] = f'"""Graph for {name}."""\n'
        files["prompts.py"] = f'"""Prompts for {name}."""\n'
        files["runner.py"] = f'"""Runner for {name}."""\n'

        total_lines = sum(content.count("\n") + 1 for content in files.values())

        return GeneratedAgent(
            id=f"gen-{uuid4().hex[:8]}",
            agent_name=name,
            files=files,
            total_lines=total_lines,
            file_count=len(files),
        )

    async def validate_agent(
        self,
        generated: GeneratedAgent,
    ) -> AgentValidation:
        """Validate generated agent code."""
        logger.info(
            "agent_factory.validating_agent",
            name=generated.agent_name,
        )

        warnings: list[str] = []
        errors: list[str] = []

        # Basic validation
        required = [
            "__init__.py",
            "models.py",
            "tools.py",
            "nodes.py",
            "graph.py",
            "prompts.py",
            "runner.py",
        ]
        for f in required:
            if f not in generated.files:
                errors.append(f"Missing {f}")

        for fname, content in generated.files.items():
            lines = content.split("\n")
            for i, line in enumerate(lines):
                if len(line) > 100:
                    warnings.append(f"{fname}:{i + 1} — line too long ({len(line)} chars)")

        if errors:
            status = ValidationStatus.INVALID
        elif warnings:
            status = ValidationStatus.HAS_WARNINGS
        else:
            status = ValidationStatus.VALID

        score = 100.0
        score -= len(errors) * 20
        score -= len(warnings) * 5
        score = max(0.0, score)

        return AgentValidation(
            id=f"val-{uuid4().hex[:8]}",
            status=status,
            syntax_valid=len(errors) == 0,
            pattern_compliant=len(errors) == 0,
            warnings=warnings,
            errors=errors,
            quality_score=score,
        )

    async def register_agent(
        self,
        generated: GeneratedAgent,
        validation: AgentValidation,
    ) -> RegistrationResult:
        """Register the agent in the registry."""
        logger.info(
            "agent_factory.registering_agent",
            name=generated.agent_name,
            status=validation.status,
        )

        registered = validation.status in (
            ValidationStatus.VALID,
            ValidationStatus.HAS_WARNINGS,
        )

        return RegistrationResult(
            id=f"reg-{uuid4().hex[:8]}",
            agent_name=generated.agent_name,
            registered=registered,
            registry_id=(f"agent-{uuid4().hex[:8]}" if registered else ""),
            notes=(
                "Registered successfully" if registered else ("Not registered: validation failed")
            ),
        )
