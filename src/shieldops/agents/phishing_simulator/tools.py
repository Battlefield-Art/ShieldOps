"""Tool functions for the Phishing Simulator Agent.

SAFETY: ALL emails clearly marked as simulations.
Never uses real malware. Tracks who reports vs clicks.
"""

from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger()


class PhishingSimulatorToolkit:
    """Toolkit for safe phishing simulation campaigns.

    All simulations are clearly marked. No real malware
    or credential harvesting is ever performed.
    """

    def __init__(
        self,
        email_client: Any | None = None,
        hr_directory: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._email = email_client
        self._hr = hr_directory
        self._policy_engine = policy_engine
        self._repository = repository

    async def design_campaign(
        self,
        campaign_type: str,
        target_departments: list[str],
    ) -> list[dict[str, Any]]:
        """Design phishing campaign templates."""
        logger.info(
            "phishing_sim.design_campaign",
            type=campaign_type,
            departments=target_departments,
        )
        templates = {
            "credential_harvest": {
                "subject_line": ("[SIMULATION] Password Reset Required"),
                "sender_display": "IT Security Team",
                "template_name": "password_reset_v1",
                "landing_page_url": ("https://sim.internal/reset"),
            },
            "malware_link": {
                "subject_line": ("[SIMULATION] Invoice Attached"),
                "sender_display": "Accounts Payable",
                "template_name": "invoice_link_v1",
                "landing_page_url": ("https://sim.internal/invoice"),
            },
            "attachment": {
                "subject_line": ("[SIMULATION] Q4 Report"),
                "sender_display": "Finance Team",
                "template_name": "report_attachment_v1",
                "landing_page_url": "",
            },
        }
        tmpl = templates.get(
            campaign_type,
            templates["credential_harvest"],
        )
        return [
            {
                "campaign_id": f"camp-{campaign_type[:8]}",
                "campaign_type": campaign_type,
                "is_simulation": True,
                **tmpl,
            }
        ]

    async def select_targets(
        self,
        departments: list[str],
        roles: list[str],
    ) -> list[dict[str, Any]]:
        """Select simulation targets by dept/role."""
        logger.info(
            "phishing_sim.select_targets",
            departments=departments,
            roles=roles,
        )
        targets: list[dict[str, Any]] = []
        sample_depts = departments or ["engineering"]
        for dept in sample_depts:
            for i in range(3):
                targets.append(
                    {
                        "employee_id": f"emp-{dept[:3]}-{i}",
                        "email": (f"user{i}@{dept}.example.com"),
                        "department": dept,
                        "role": (roles[0] if roles else "individual_contributor"),
                        "previous_click_rate": 0.15 + i * 0.05,
                        "training_completed": i % 2 == 0,
                    }
                )
        return targets

    async def send_simulations(
        self,
        campaigns: list[dict[str, Any]],
        targets: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Send simulation emails (safely marked)."""
        logger.info(
            "phishing_sim.send_simulations",
            campaigns=len(campaigns),
            targets=len(targets),
        )
        deliveries: list[dict[str, Any]] = []
        for target in targets:
            deliveries.append(
                {
                    "employee_id": target.get("employee_id", ""),
                    "delivered": True,
                    "delivery_time": "2026-03-25T10:00:00Z",
                    "simulation_marked": True,
                }
            )
        return deliveries

    async def track_responses(
        self,
        deliveries: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Track employee responses to simulations."""
        logger.info(
            "phishing_sim.track_responses",
            count=len(deliveries),
        )
        responses: list[dict[str, Any]] = []
        for i, delivery in enumerate(deliveries):
            emp_id = delivery.get("employee_id", "")
            # Simulate varied responses
            clicked = i % 3 == 0
            reported = i % 4 == 0
            responses.append(
                {
                    "employee_id": emp_id,
                    "email_opened": True,
                    "link_clicked": clicked,
                    "credentials_submitted": (clicked and i % 5 == 0),
                    "reported_as_phishing": reported,
                    "response_time_seconds": 120 + i * 30,
                }
            )
        return responses

    async def analyze_results(
        self,
        targets: list[dict[str, Any]],
        responses: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Analyze results by department/role."""
        logger.info(
            "phishing_sim.analyze_results",
            targets=len(targets),
            responses=len(responses),
        )
        dept_map: dict[str, list[dict[str, Any]]] = {}
        target_dept = {t.get("employee_id"): t.get("department") for t in targets}
        for resp in responses:
            dept = target_dept.get(resp.get("employee_id"), "unknown")
            dept_map.setdefault(dept, []).append(resp)

        analyses: list[dict[str, Any]] = []
        for dept, resps in dept_map.items():
            total = len(resps)
            clicks = len([r for r in resps if r.get("link_clicked")])
            reports = len([r for r in resps if r.get("reported_as_phishing")])
            click_rate = clicks / total if total else 0
            report_rate = reports / total if total else 0

            if click_rate > 0.3:
                risk = "high_risk"
            elif click_rate > 0.15:
                risk = "moderate_risk"
            else:
                risk = "low_risk"

            analyses.append(
                {
                    "group_id": dept,
                    "group_type": "department",
                    "click_rate": round(click_rate, 3),
                    "report_rate": round(report_rate, 3),
                    "risk_level": risk,
                    "training_recommended": (click_rate > 0.15),
                }
            )
        return analyses
