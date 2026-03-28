"""LLM prompts and schemas for Custom Agent Factory."""

from __future__ import annotations

from pydantic import BaseModel, Field

# -----------------------------------------------------------
# Response schemas
# -----------------------------------------------------------


class RequirementParseOutput(BaseModel):
    """LLM output for requirement parsing."""

    agent_name: str = Field(description="Snake_case agent name")
    category: str = Field(description="Agent category")
    trigger: str = Field(description="What triggers this agent")
    data_sources: list[str] = Field(description="Data sources needed")
    actions: list[str] = Field(description="Actions the agent performs")
    schedule: str = Field(description="Schedule: on_demand/cron/event")


class AgentDesignOutput(BaseModel):
    """LLM output for agent design."""

    nodes: list[str] = Field(description="LangGraph node names")
    state_fields: list[str] = Field(description="State model fields")
    tools_needed: list[str] = Field(description="Toolkit methods needed")
    edge_flow: list[str] = Field(description="Edge flow: node1->node2")


class CodeGenerationOutput(BaseModel):
    """LLM output for code generation."""

    models_py: str = Field(description="models.py content")
    tools_py: str = Field(description="tools.py content")
    nodes_py: str = Field(description="nodes.py content")
    graph_py: str = Field(description="graph.py content")
    prompts_py: str = Field(description="prompts.py content")
    runner_py: str = Field(description="runner.py content")
    init_py: str = Field(description="__init__.py content")


class ValidationOutput(BaseModel):
    """LLM output for code validation."""

    syntax_valid: bool = Field(description="Syntax is valid Python")
    pattern_compliant: bool = Field(description="Follows ShieldOps patterns")
    warnings: list[str] = Field(description="Code warnings")
    errors: list[str] = Field(description="Code errors")
    quality_score: float = Field(description="Code quality 0-100")
    suggestions: list[str] = Field(description="Improvement suggestions")


# -----------------------------------------------------------
# Prompt templates
# -----------------------------------------------------------

SYSTEM_REQUIREMENT_PARSE = """\
You are an expert agent architect parsing natural \
language descriptions into structured agent \
requirements. Extract: agent name (snake_case), \
category (detection/response/compliance/monitoring/\
testing/reporting), trigger, data sources, actions, \
and schedule.

The agent will be a LangGraph StateGraph with the \
standard ShieldOps 7-file pattern."""

SYSTEM_AGENT_DESIGN = """\
You are a LangGraph agent architect designing the \
blueprint for a custom security agent. Given \
requirements, design: node names, state fields, \
toolkit methods, and edge flow.

Follow ShieldOps patterns:
- 5-7 nodes in a linear or conditional flow
- State model with request_id, tenant_id, stage, \
reasoning_chain, error
- Toolkit class with async methods
- Every node uses llm_structured with try/except"""

SYSTEM_CODE_GENERATION = """\
You are a Python code generator creating a complete \
LangGraph agent following the ShieldOps pattern. \
Generate all 7 files with correct imports, types, \
and structure.

Requirements:
- from __future__ import annotations
- import structlog
- from shieldops.utils.llm import llm_structured
- All lines under 100 characters
- 3 StrEnums, Pydantic models, full State
- Toolkit class with async methods
- Nodes with try/except LLM calls
- build_graph + create_X_graph factory
- Runner with tracer integration"""

SYSTEM_CODE_VALIDATION = """\
You are a senior Python code reviewer validating a \
generated LangGraph agent. Check:
1. Syntax validity (valid Python 3.12)
2. Pattern compliance (ShieldOps 7-file pattern)
3. Import correctness
4. Type hint completeness
5. Error handling (try/except on LLM calls)
6. Line length (<100 chars)

Score quality 0-100 and flag any issues."""
