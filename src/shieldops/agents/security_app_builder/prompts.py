"""Security App Builder Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class RequirementParseResult(BaseModel):
    """Structured output from NL requirement parsing."""

    summary: str = Field(description="Brief summary of parsed requirements")
    app_type: str = Field(description="Detected application type")
    inputs: list[str] = Field(description="Required data inputs")
    outputs: list[str] = Field(description="Expected outputs")
    data_sources: list[str] = Field(description="Data sources to integrate")
    security_constraints: list[str] = Field(description="Security constraints identified")


class WorkflowDesignResult(BaseModel):
    """Structured output from workflow design."""

    summary: str = Field(description="Workflow design summary")
    node_names: list[str] = Field(description="Names of workflow nodes")
    node_descriptions: list[str] = Field(description="Description of each node")
    edge_descriptions: list[str] = Field(description="Edge routing descriptions")
    entry_point: str = Field(description="Entry point node name")


class CodeGenerationResult(BaseModel):
    """Structured output from LangGraph code generation."""

    summary: str = Field(description="Code generation summary")
    graph_code: str = Field(description="LangGraph StateGraph code")
    models_code: str = Field(description="Pydantic models code")
    nodes_code: str = Field(description="Node function implementations")
    tools_code: str = Field(description="Tool function implementations")
    quality_notes: list[str] = Field(description="Code quality observations")


class SecurityValidationResult(BaseModel):
    """Structured output from security validation."""

    summary: str = Field(description="Security validation summary")
    passed: bool = Field(description="Whether all checks passed")
    findings: list[str] = Field(description="Security findings")
    recommendations: list[str] = Field(description="Security recommendations")


class DeploymentPlanResult(BaseModel):
    """Structured output from deployment planning."""

    summary: str = Field(description="Deployment plan summary")
    steps: list[str] = Field(description="Deployment steps")
    rollback_plan: str = Field(description="Rollback strategy")


SYSTEM_PARSE_REQUIREMENTS = (
    "You are a security application requirements analyst.\n"
    "Parse the natural language description into structured "
    "requirements for a LangGraph security application.\n"
    "For each requirement:\n"
    "1. Identify the application type (detection_rule, "
    "response_playbook, investigation_workflow, "
    "compliance_check, monitoring_dashboard)\n"
    "2. Extract required data inputs and expected outputs\n"
    "3. Identify data sources to integrate (SIEM, EDR, "
    "cloud logs, identity providers, etc.)\n"
    "4. Determine security constraints (auth, RBAC, "
    "audit logging, data sensitivity)\n"
    "5. Prioritize requirements by business impact"
)

SYSTEM_DESIGN_WORKFLOW = (
    "You are a LangGraph workflow architect.\n"
    "Design a composable workflow from parsed requirements.\n"
    "For each workflow:\n"
    "1. Define nodes as discrete processing steps\n"
    "2. Define edges with conditional routing logic\n"
    "3. Ensure proper error handling at each node\n"
    "4. Include validation and safety gates\n"
    "5. Design for testability and version control"
)

SYSTEM_GENERATE_CODE = (
    "You are a LangGraph code generator for ShieldOps.\n"
    "Generate production-quality Python code following the "
    "ShieldOps agent pattern:\n"
    "1. models.py — Pydantic v2 state and data models\n"
    "2. graph.py — StateGraph with nodes and edges\n"
    "3. nodes.py — Async node functions with structlog\n"
    "4. tools.py — Toolkit class with domain methods\n"
    "Rules:\n"
    "- All lines under 100 characters\n"
    "- Type hints on all public functions\n"
    "- Pydantic v2 models with Field defaults\n"
    "- async/await for all I/O operations\n"
    "- structlog for structured logging\n"
    "- No hardcoded credentials ever"
)

SYSTEM_VALIDATE_SECURITY = (
    "You are a security code reviewer for AI agents.\n"
    "Validate generated LangGraph code for security:\n"
    "1. No injection vulnerabilities (SQL, command, "
    "prompt injection)\n"
    "2. Proper authentication and authorization checks\n"
    "3. No hardcoded secrets or credentials\n"
    "4. Input validation on all external data\n"
    "5. Audit logging for security-relevant actions\n"
    "6. OPA policy integration for action gating\n"
    "7. Blast radius limits enforced"
)

SYSTEM_DEPLOY_APP = (
    "You are deploying a generated LangGraph security app.\n"
    "For each deployment:\n"
    "1. Validate all security checks passed\n"
    "2. Register the app in the ShieldOps agent registry\n"
    "3. Configure OPA policies for the new agent\n"
    "4. Set up monitoring and alerting\n"
    "5. Document the deployment with rollback plan"
)

SYSTEM_REPORT = (
    "You are summarizing a security app build process.\n"
    "Create a comprehensive report covering:\n"
    "1. Requirements parsed and fulfilled\n"
    "2. Workflow design decisions and rationale\n"
    "3. Code quality metrics and coverage\n"
    "4. Security validation results\n"
    "5. Deployment status and access details\n"
    "6. Recommendations for improvement"
)
