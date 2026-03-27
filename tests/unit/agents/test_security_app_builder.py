"""Tests for shieldops.agents.security_app_builder."""

from __future__ import annotations

from shieldops.agents.security_app_builder.models import (
    AppType,
    BuilderStage,
    DeploymentTarget,
    SecurityAppBuilderState,
)


class TestEnums:
    def test_builderstage_parse_requirements(self):
        assert BuilderStage.PARSE_REQUIREMENTS == "parse_requirements"

    def test_builderstage_design_workflow(self):
        assert BuilderStage.DESIGN_WORKFLOW == "design_workflow"

    def test_builderstage_generate_code(self):
        assert BuilderStage.GENERATE_CODE == "generate_code"

    def test_builderstage_validate_security(self):
        assert BuilderStage.VALIDATE_SECURITY == "validate_security"

    def test_apptype_detection_rule(self):
        assert AppType.DETECTION_RULE == "detection_rule"

    def test_apptype_response_playbook(self):
        assert AppType.RESPONSE_PLAYBOOK == "response_playbook"

    def test_apptype_investigation_workflow(self):
        assert AppType.INVESTIGATION_WORKFLOW == "investigation_workflow"

    def test_apptype_compliance_check(self):
        assert AppType.COMPLIANCE_CHECK == "compliance_check"

    def test_deploymenttarget_staging(self):
        assert DeploymentTarget.STAGING == "staging"

    def test_deploymenttarget_production(self):
        assert DeploymentTarget.PRODUCTION == "production"

    def test_deploymenttarget_dry_run(self):
        assert DeploymentTarget.DRY_RUN == "dry_run"


class TestModels:
    def test_state_defaults(self):
        s = SecurityAppBuilderState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.security_app_builder.graph import (
            create_security_app_builder_graph,
        )

        sg = create_security_app_builder_graph()
        assert sg.compile() is not None
