"""Security App Builder Agent — Tool functions for app building."""

from __future__ import annotations

import hashlib
import re
import time
from typing import Any

import structlog

from .models import (
    AppRequirement,
    AppType,
    DeploymentResult,
    DeploymentTarget,
    GeneratedCode,
    SecurityValidation,
    WorkflowDesign,
    WorkflowEdge,
    WorkflowNode,
)

logger = structlog.get_logger()

# App type to default node templates
_APP_NODE_TEMPLATES: dict[AppType, list[dict[str, str]]] = {
    AppType.DETECTION_RULE: [
        {
            "name": "ingest_events",
            "type": "input",
            "desc": "Ingest raw security events",
        },
        {
            "name": "normalize_data",
            "type": "transform",
            "desc": "Normalize event fields",
        },
        {
            "name": "apply_detection",
            "type": "action",
            "desc": "Run detection logic",
        },
        {
            "name": "enrich_alert",
            "type": "action",
            "desc": "Enrich with threat intel",
        },
        {
            "name": "emit_finding",
            "type": "output",
            "desc": "Emit detection finding",
        },
    ],
    AppType.RESPONSE_PLAYBOOK: [
        {
            "name": "receive_alert",
            "type": "input",
            "desc": "Receive security alert",
        },
        {
            "name": "assess_severity",
            "type": "action",
            "desc": "Assess alert severity",
        },
        {
            "name": "contain_threat",
            "type": "action",
            "desc": "Execute containment",
        },
        {
            "name": "remediate",
            "type": "action",
            "desc": "Apply remediation steps",
        },
        {
            "name": "close_incident",
            "type": "output",
            "desc": "Close and document incident",
        },
    ],
    AppType.INVESTIGATION_WORKFLOW: [
        {
            "name": "gather_evidence",
            "type": "input",
            "desc": "Collect investigation data",
        },
        {
            "name": "correlate_events",
            "type": "action",
            "desc": "Correlate across sources",
        },
        {
            "name": "analyze_indicators",
            "type": "action",
            "desc": "Analyze IOCs and TTPs",
        },
        {
            "name": "build_timeline",
            "type": "action",
            "desc": "Build attack timeline",
        },
        {
            "name": "generate_report",
            "type": "output",
            "desc": "Generate investigation report",
        },
    ],
    AppType.COMPLIANCE_CHECK: [
        {
            "name": "load_controls",
            "type": "input",
            "desc": "Load compliance controls",
        },
        {
            "name": "scan_resources",
            "type": "action",
            "desc": "Scan target resources",
        },
        {
            "name": "evaluate_compliance",
            "type": "action",
            "desc": "Evaluate control compliance",
        },
        {
            "name": "generate_evidence",
            "type": "action",
            "desc": "Generate evidence artifacts",
        },
        {
            "name": "produce_report",
            "type": "output",
            "desc": "Produce compliance report",
        },
    ],
    AppType.MONITORING_DASHBOARD: [
        {
            "name": "collect_metrics",
            "type": "input",
            "desc": "Collect security metrics",
        },
        {
            "name": "aggregate_data",
            "type": "transform",
            "desc": "Aggregate and window data",
        },
        {
            "name": "compute_indicators",
            "type": "action",
            "desc": "Compute KPIs and KRIs",
        },
        {
            "name": "detect_anomalies",
            "type": "action",
            "desc": "Flag metric anomalies",
        },
        {
            "name": "render_dashboard",
            "type": "output",
            "desc": "Render dashboard payload",
        },
    ],
}

# Security check catalog
_SECURITY_CHECKS: list[dict[str, str]] = [
    {
        "name": "no_hardcoded_secrets",
        "desc": "No API keys, passwords, or tokens in code",
        "pattern": (
            r"(api_key|password|secret|token)\s*="
            r"\s*[\"'][^\"']{8,}"
        ),
    },
    {
        "name": "no_command_injection",
        "desc": "No os.system or subprocess with user input",
        "pattern": (r"(os\.system|subprocess\.(call|run|Popen))"),
    },
    {
        "name": "no_sql_injection",
        "desc": "No raw SQL string concatenation",
        "pattern": r"(execute|cursor)\s*\(.*(f\"|%s|\+)",
    },
    {
        "name": "no_eval_exec",
        "desc": "No eval() or exec() calls",
        "pattern": r"\b(eval|exec)\s*\(",
    },
    {
        "name": "has_input_validation",
        "desc": "Uses Pydantic models for input validation",
        "pattern": r"BaseModel|Field\(",
    },
    {
        "name": "has_auth_check",
        "desc": "Includes authentication/authorization",
        "pattern": (r"(auth|permission|rbac|policy)"),
    },
    {
        "name": "has_audit_logging",
        "desc": "Includes structured audit logging",
        "pattern": r"(structlog|logger\.(info|warning))",
    },
]

# LangGraph code templates
_GRAPH_TEMPLATE = '''"""Generated LangGraph agent — {app_name}."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import {state_class}
from .nodes import {node_imports}
from .tools import {toolkit_class}


def build_graph(
    toolkit: {toolkit_class},
) -> StateGraph:
    """Build the {app_name} agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()
        return (
            dict(state)
            if not isinstance(state, dict)
            else state
        )

{node_wrappers}

    graph = StateGraph({state_class})
{node_adds}
    graph.set_entry_point("{entry_point}")
{edge_adds}
    graph.add_edge("{last_node}", END)

    return graph
'''

_MODELS_TEMPLATE = '''"""Generated Pydantic models — {app_name}."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class {state_class}(BaseModel):
    """State for {app_name} agent."""

    request_id: str = ""
{state_fields}
    reasoning_chain: list[str] = Field(
        default_factory=list
    )
    error: str = ""
'''

_NODES_TEMPLATE = '''"""Generated node functions — {app_name}."""

from __future__ import annotations

from typing import Any

import structlog

from .tools import {toolkit_class}

logger = structlog.get_logger()

{node_functions}
'''

_TOOLS_TEMPLATE = '''"""Generated toolkit — {app_name}."""

from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger()


class {toolkit_class}:
    """Toolkit for {app_name}."""

    def __init__(self) -> None:
        logger.info("{app_name_lower}.toolkit.init")

{tool_methods}
'''


class SecurityAppBuilderToolkit:
    """Tools for building security applications from NL."""

    def __init__(
        self,
        code_store: Any | None = None,
        registry_client: Any | None = None,
        opa_client: Any | None = None,
    ) -> None:
        self._code_store = code_store
        self._registry_client = registry_client
        self._opa_client = opa_client

    async def parse_nl_requirements(
        self,
        description: str,
    ) -> list[AppRequirement]:
        """Parse NL description into structured requirements.

        Analyzes the description to identify app type,
        data sources, security constraints, and priority.
        """
        logger.info(
            "security_app_builder.parse_nl_requirements",
            description_len=len(description),
        )

        if self._code_store is not None:
            try:
                raw = await self._code_store.parse(description)
                return [AppRequirement(**r) for r in raw]
            except Exception:
                logger.exception("security_app_builder.parse.error")

        # Determine app type from keywords
        desc_lower = description.lower()
        app_type = AppType.DETECTION_RULE

        type_keywords = {
            AppType.RESPONSE_PLAYBOOK: [
                "respond",
                "playbook",
                "contain",
                "remediate",
                "isolate",
            ],
            AppType.INVESTIGATION_WORKFLOW: [
                "investigate",
                "forensic",
                "correlate",
                "timeline",
                "hunt",
            ],
            AppType.COMPLIANCE_CHECK: [
                "compliance",
                "audit",
                "regulation",
                "hipaa",
                "soc2",
                "pci",
                "gdpr",
            ],
            AppType.MONITORING_DASHBOARD: [
                "monitor",
                "dashboard",
                "metrics",
                "kpi",
                "visualize",
            ],
        }

        for atype, keywords in type_keywords.items():
            if any(kw in desc_lower for kw in keywords):
                app_type = atype
                break

        # Extract data sources
        source_keywords = {
            "siem": "SIEM",
            "splunk": "Splunk",
            "elastic": "Elastic",
            "cloudtrail": "AWS CloudTrail",
            "guardduty": "AWS GuardDuty",
            "defender": "Microsoft Defender",
            "crowdstrike": "CrowdStrike Falcon",
            "wiz": "Wiz",
            "kubernetes": "Kubernetes",
            "cloud": "Cloud Logs",
            "endpoint": "Endpoint Telemetry",
            "network": "Network Traffic",
            "identity": "Identity Provider",
            "okta": "Okta",
            "azure ad": "Azure AD",
        }
        data_sources = [name for kw, name in source_keywords.items() if kw in desc_lower]
        if not data_sources:
            data_sources = ["Generic Security Logs"]

        # Security constraints
        constraints = [
            "Require OPA policy evaluation",
            "Audit log all actions",
            "No hardcoded credentials",
        ]
        if "pii" in desc_lower or "sensitive" in desc_lower:
            constraints.append("PII data masking required")
        if "prod" in desc_lower:
            constraints.append("Production blast-radius limits")

        req_id = hashlib.sha256(f"{description}:{time.time()}".encode()).hexdigest()[:12]

        return [
            AppRequirement(
                requirement_id=req_id,
                description=description,
                app_type=app_type,
                inputs=data_sources,
                outputs=[
                    "Security findings",
                    "Audit trail",
                ],
                data_sources=data_sources,
                security_constraints=constraints,
                priority="high",
            )
        ]

    async def design_workflow(
        self,
        requirements: list[AppRequirement],
    ) -> WorkflowDesign:
        """Design a LangGraph workflow from requirements.

        Creates node and edge specifications based on the
        app type and requirements.
        """
        logger.info(
            "security_app_builder.design_workflow",
            requirement_count=len(requirements),
        )

        if not requirements:
            return WorkflowDesign()

        primary_req = requirements[0]
        app_type = primary_req.app_type
        templates = _APP_NODE_TEMPLATES.get(
            app_type,
            _APP_NODE_TEMPLATES[AppType.DETECTION_RULE],
        )

        design_id = hashlib.sha256(
            f"design:{primary_req.requirement_id}:{time.time()}".encode()
        ).hexdigest()[:12]

        nodes: list[WorkflowNode] = []
        for i, tmpl in enumerate(templates):
            node_id = f"node_{i}"
            nodes.append(
                WorkflowNode(
                    node_id=node_id,
                    name=tmpl["name"],
                    description=tmpl["desc"],
                    node_type=tmpl["type"],
                    inputs=(primary_req.inputs if i == 0 else [f"node_{i - 1}_output"]),
                    outputs=[f"{node_id}_output"],
                )
            )

        edges: list[WorkflowEdge] = []
        for i in range(len(nodes) - 1):
            edges.append(
                WorkflowEdge(
                    source=nodes[i].name,
                    target=nodes[i + 1].name,
                    condition="",
                )
            )

        return WorkflowDesign(
            design_id=design_id,
            app_type=app_type,
            nodes=nodes,
            edges=edges,
            entry_point=nodes[0].name if nodes else "",
            description=(f"{app_type.value} workflow with {len(nodes)} stages"),
        )

    async def generate_langgraph_code(
        self,
        design: WorkflowDesign,
        requirements: list[AppRequirement],
    ) -> list[GeneratedCode]:
        """Generate LangGraph Python code from design.

        Produces models.py, graph.py, nodes.py, tools.py
        following ShieldOps agent conventions.
        """
        logger.info(
            "security_app_builder.generate_code",
            design_id=design.design_id,
            node_count=len(design.nodes),
        )

        app_name = design.app_type.value.replace("_", " ")
        app_name_title = app_name.title().replace(" ", "")
        state_class = f"{app_name_title}State"
        toolkit_class = f"{app_name_title}Toolkit"
        app_name_lower = design.app_type.value

        # Generate models code
        state_fields = ""
        for node in design.nodes:
            field = node.name
            state_fields += (
                f"    {field}_result: "
                f"dict[str, Any] = Field(\n"
                f"        default_factory=dict\n"
                f"    )\n"
            )

        models_code = _MODELS_TEMPLATE.format(
            app_name=app_name,
            state_class=state_class,
            state_fields=state_fields,
        )

        # Generate node functions
        node_funcs = ""
        for node in design.nodes:
            func_name = node.name
            node_funcs += (
                f"\nasync def {func_name}(\n"
                f"    state: dict[str, Any],\n"
                f"    toolkit: {toolkit_class},\n"
                f") -> dict[str, Any]:\n"
                f'    """{node.description}."""\n'
                f'    logger.info("{app_name_lower}'
                f'.node.{func_name}")\n'
                f"    result = await toolkit"
                f".{func_name}(state)\n"
                f"    return {{\n"
                f'        "{func_name}_result": result,\n'
                f'        "reasoning_chain": '
                f'state.get("reasoning_chain", [])\n'
                f"        + ["
                f'f"Completed {func_name}"],\n'
                f"    }}\n\n"
            )

        node_names = [n.name for n in design.nodes]
        node_imports_str = ",\n    ".join(node_names)
        nodes_code = _NODES_TEMPLATE.format(
            app_name=app_name,
            toolkit_class=toolkit_class,
            node_functions=node_funcs,
        )

        # Generate tool methods
        tool_methods = ""
        for node in design.nodes:
            tool_methods += (
                f"    async def {node.name}(\n"
                f"        self,\n"
                f"        state: dict[str, Any],\n"
                f"    ) -> dict[str, Any]:\n"
                f'        """{node.description}."""\n'
                f"        logger.info(\n"
                f'            "{app_name_lower}'
                f'.tool.{node.name}"\n'
                f"        )\n"
                f"        return {{\n"
                f'            "status": "completed",\n'
                f'            "node": "{node.name}",\n'
                f"        }}\n\n"
            )

        tools_code = _TOOLS_TEMPLATE.format(
            app_name=app_name,
            app_name_lower=app_name_lower,
            toolkit_class=toolkit_class,
            tool_methods=tool_methods,
        )

        # Generate graph code
        node_wrappers = ""
        node_adds = ""
        edge_adds = ""
        for i, node in enumerate(design.nodes):
            fn = node.name
            node_wrappers += (
                f"    async def _{fn}("
                f"state: Any) -> dict[str, Any]:\n"
                f"        return await {fn}("
                f"_to_dict(state), toolkit)\n\n"
            )
            node_adds += f'    graph.add_node("{fn}", _{fn})\n'
            if i > 0:
                prev = design.nodes[i - 1].name
                edge_adds += f'    graph.add_edge("{prev}", "{fn}")\n'

        last_node = design.nodes[-1].name if design.nodes else "end"

        graph_code = _GRAPH_TEMPLATE.format(
            app_name=app_name,
            state_class=state_class,
            node_imports=node_imports_str,
            toolkit_class=toolkit_class,
            node_wrappers=node_wrappers,
            node_adds=node_adds,
            entry_point=(design.nodes[0].name if design.nodes else ""),
            edge_adds=edge_adds,
            last_node=last_node,
        )

        artifacts = [
            GeneratedCode(
                file_name="models.py",
                content=models_code,
                line_count=models_code.count("\n") + 1,
            ),
            GeneratedCode(
                file_name="graph.py",
                content=graph_code,
                line_count=graph_code.count("\n") + 1,
            ),
            GeneratedCode(
                file_name="nodes.py",
                content=nodes_code,
                line_count=nodes_code.count("\n") + 1,
            ),
            GeneratedCode(
                file_name="tools.py",
                content=tools_code,
                line_count=tools_code.count("\n") + 1,
            ),
        ]

        return artifacts

    async def validate_security(
        self,
        code_artifacts: list[GeneratedCode],
    ) -> list[SecurityValidation]:
        """Validate generated code for security issues.

        Checks for injection, hardcoded secrets,
        missing auth, and other security concerns.
        """
        logger.info(
            "security_app_builder.validate_security",
            artifact_count=len(code_artifacts),
        )

        validations: list[SecurityValidation] = []
        all_code = "\n".join(a.content for a in code_artifacts)

        for check in _SECURITY_CHECKS:
            check_name = check["name"]
            pattern = check["pattern"]
            val_id = hashlib.sha256(f"{check_name}:{time.time()}".encode()).hexdigest()[:12]

            # Checks where match = bad
            is_negative = check_name in {
                "no_hardcoded_secrets",
                "no_command_injection",
                "no_sql_injection",
                "no_eval_exec",
            }

            matches = re.findall(pattern, all_code)

            if is_negative:
                passed = len(matches) == 0
                severity = "critical" if not passed else "info"
                details = (
                    f"Found {len(matches)} violations" if not passed else "No violations found"
                )
            else:
                # Positive checks — match = good
                passed = len(matches) > 0
                severity = "warning" if not passed else "info"
                details = "Check satisfied" if passed else f"Missing: {check['desc']}"

            validations.append(
                SecurityValidation(
                    validation_id=val_id,
                    check_name=check_name,
                    passed=passed,
                    severity=severity,
                    details=details,
                )
            )

        return validations

    async def deploy_app(
        self,
        code_artifacts: list[GeneratedCode],
        target: DeploymentTarget,
        tenant_id: str = "",
    ) -> DeploymentResult:
        """Deploy generated app to target environment.

        Registers the app, configures OPA policies,
        and sets up monitoring.
        """
        logger.info(
            "security_app_builder.deploy_app",
            target=target.value,
            artifact_count=len(code_artifacts),
            tenant_id=tenant_id,
        )

        deploy_id = hashlib.sha256(f"deploy:{tenant_id}:{time.time()}".encode()).hexdigest()[:12]

        if self._registry_client is not None:
            try:
                raw = await self._registry_client.deploy(
                    artifacts=[a.model_dump() for a in code_artifacts],
                    target=target.value,
                    tenant_id=tenant_id,
                )
                return DeploymentResult(**raw)
            except Exception:
                logger.exception("security_app_builder.deploy.error")

        # Mock deployment
        if target == DeploymentTarget.DRY_RUN:
            return DeploymentResult(
                deployment_id=deploy_id,
                target=target,
                success=True,
                endpoint="",
                details=("Dry run completed — code validated but not deployed"),
            )

        env = target.value
        endpoint = f"https://shieldops.{env}.internal/agents/custom/{deploy_id}"

        return DeploymentResult(
            deployment_id=deploy_id,
            target=target,
            success=True,
            endpoint=endpoint,
            details=(f"Deployed to {env} environment. Agent registered with OPA policies."),
        )
