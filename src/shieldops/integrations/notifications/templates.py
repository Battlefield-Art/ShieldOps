"""Pre-built notification templates for approval workflow dispatching."""

from __future__ import annotations

from typing import Any

_SEVERITY_COLORS: dict[str, str] = {
    "critical": "#FF0000",
    "high": "#FF6600",
    "medium": "#FFCC00",
    "low": "#00CC00",
    "info": "#0066FF",
}

_SEVERITY_EMOJI: dict[str, str] = {
    "critical": "\U0001f534",
    "high": "\U0001f7e0",
    "medium": "\U0001f7e1",
    "low": "\U0001f7e2",
    "info": "\U0001f535",
}


def _confidence_bar(confidence: float) -> str:
    """Render a text-based confidence bar."""
    filled = int(confidence * 10)
    return f"{'=' * filled}{'.' * (10 - filled)} {confidence:.0%}"


def approval_request_slack(
    title: str,
    description: str,
    severity: str,
    confidence: float,
    action_url: str,
) -> dict[str, Any]:
    """Slack Block Kit payload for an approval request with Approve/Reject buttons."""
    emoji = _SEVERITY_EMOJI.get(severity.lower(), "\U0001f535")
    color = _SEVERITY_COLORS.get(severity.lower(), "#0066FF")
    return {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} Approval Required: {title}"[:150],
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": description[:3000],
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:* {severity.upper()}"},
                    {
                        "type": "mrkdwn",
                        "text": f"*Confidence:* `{_confidence_bar(confidence)}`",
                    },
                ],
            },
            {"type": "divider"},
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Approve", "emoji": True},
                        "style": "primary",
                        "url": f"{action_url}/approve",
                        "action_id": "approval_approve",
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Reject", "emoji": True},
                        "style": "danger",
                        "url": f"{action_url}/reject",
                        "action_id": "approval_reject",
                    },
                ],
            },
        ],
        "attachments": [{"color": color, "blocks": []}],
    }


def approval_request_teams(
    title: str,
    description: str,
    severity: str,
    confidence: float,
    action_url: str,
) -> dict[str, Any]:
    """Microsoft Teams Adaptive Card payload for an approval request."""
    color = _SEVERITY_COLORS.get(severity.lower(), "#0066FF")
    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "msteams": {"width": "Full"},
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": f"Approval Required: {title}",
                            "weight": "Bolder",
                            "size": "Large",
                            "color": "Attention" if severity in ("critical", "high") else "Default",
                        },
                        {
                            "type": "TextBlock",
                            "text": description[:2000],
                            "wrap": True,
                        },
                        {
                            "type": "FactSet",
                            "facts": [
                                {"title": "Severity", "value": severity.upper()},
                                {"title": "Confidence", "value": f"{confidence:.0%}"},
                            ],
                        },
                    ],
                    "actions": [
                        {
                            "type": "Action.OpenUrl",
                            "title": "Approve",
                            "url": f"{action_url}/approve",
                            "style": "positive",
                        },
                        {
                            "type": "Action.OpenUrl",
                            "title": "Reject",
                            "url": f"{action_url}/reject",
                            "style": "destructive",
                        },
                    ],
                },
                "color": color,
            }
        ],
    }


def approval_escalation_slack(
    title: str,
    description: str,
    severity: str,
    confidence: float,
    action_url: str,
) -> dict[str, Any]:
    """Slack Block Kit payload for an escalation notification."""
    emoji = _SEVERITY_EMOJI.get(severity.lower(), "\U0001f535")
    return {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"\u26a0\ufe0f ESCALATION: {title}"[:150],
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"{emoji} *This approval request has been escalated.*\n\n"
                        f"{description[:2800]}"
                    ),
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:* {severity.upper()}"},
                    {
                        "type": "mrkdwn",
                        "text": f"*Confidence:* `{_confidence_bar(confidence)}`",
                    },
                ],
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Review Now"},
                        "style": "primary",
                        "url": action_url,
                        "action_id": "escalation_review",
                    },
                ],
            },
        ],
    }


def kill_switch_alert_slack(
    title: str,
    description: str,
    severity: str,
    confidence: float,
    action_url: str,
) -> dict[str, Any]:
    """Slack Block Kit payload for an emergency kill switch alert."""
    return {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"\U0001f6a8 KILL SWITCH ACTIVATED: {title}"[:150],
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"\U0001f534 *Emergency kill switch has been triggered.*\n\n"
                        f"{description[:2800]}\n\n"
                        f"*All autonomous actions are halted.*"
                    ),
                },
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Severity: *{severity.upper()}* | Confidence: *{confidence:.0%}*",
                    },
                ],
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "View Details"},
                        "url": action_url,
                        "action_id": "kill_switch_details",
                    },
                ],
            },
        ],
    }


def situation_created_slack(
    title: str,
    description: str,
    severity: str,
    confidence: float,
    action_url: str,
) -> dict[str, Any]:
    """Slack Block Kit payload for a new situation notification."""
    emoji = _SEVERITY_EMOJI.get(severity.lower(), "\U0001f535")
    return {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} New Situation: {title}"[:150],
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": description[:3000],
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:* {severity.upper()}"},
                    {
                        "type": "mrkdwn",
                        "text": f"*Confidence:* `{_confidence_bar(confidence)}`",
                    },
                ],
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "View Situation"},
                        "url": action_url,
                        "action_id": "situation_view",
                    },
                ],
            },
        ],
    }
