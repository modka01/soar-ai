"""Outbound notifications: Slack, PagerDuty and SMTP email.

Notification failures never abort the security workflow that triggered them —
a Slack outage must not stop a containment action from completing.
"""

from __future__ import annotations

import smtplib
from email.message import EmailMessage
from typing import Any

import httpx

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

_SEVERITY_COLOURS = {
    "critical": "#e53e3e",
    "high": "#d97706",
    "medium": "#2563eb",
    "low": "#059669",
}


class NotificationService:
    """Fans a security event out to the configured notification channels."""

    async def notify(
        self,
        *,
        title: str,
        message: str,
        severity: str = "medium",
        link: str | None = None,
        channels: list[str] | None = None,
        detail: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        """Send to every requested channel. Returns per-channel outcome."""
        channels = channels or ["slack", "pagerduty", "email"]
        outcomes: dict[str, str] = {}

        if "slack" in channels:
            outcomes["slack"] = await self._safe(
                "slack", self.send_slack(title, message, severity, link, detail)
            )
        if "pagerduty" in channels and severity == "critical":
            outcomes["pagerduty"] = await self._safe(
                "pagerduty", self.send_pagerduty(title, message, severity, detail)
            )
        if "email" in channels and severity in {"critical", "high"}:
            outcomes["email"] = await self._safe("email", self.send_email(title, message, severity))
        return outcomes

    @staticmethod
    async def _safe(channel: str, coroutine) -> str:
        try:
            await coroutine
        except Exception as exc:
            logger.warning("notification_failed", channel=channel, error=str(exc)[:200])
            return f"failed: {str(exc)[:120]}"
        return "sent"

    async def send_slack(
        self,
        title: str,
        message: str,
        severity: str,
        link: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        if not settings.slack_webhook_url:
            raise RuntimeError("Slack webhook is not configured.")

        blocks: list[dict[str, Any]] = [
            {"type": "header", "text": {"type": "plain_text", "text": title[:150]}},
            {"type": "section", "text": {"type": "mrkdwn", "text": message[:2900]}},
        ]
        if detail:
            fields = [
                {"type": "mrkdwn", "text": f"*{key}*\n{value}"}
                for key, value in list(detail.items())[:10]
            ]
            blocks.append({"type": "section", "fields": fields})
        if link:
            blocks.append(
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Open in SOAR"},
                            "url": link,
                            "style": "danger" if severity == "critical" else "primary",
                        }
                    ],
                }
            )

        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                settings.slack_webhook_url,
                json={
                    "text": f"[{severity.upper()}] {title}",
                    "blocks": blocks,
                    "attachments": [{"color": _SEVERITY_COLOURS.get(severity, "#6b7280")}],
                },
            )
        if response.status_code >= 400:
            raise RuntimeError(f"Slack returned HTTP {response.status_code}")

    async def send_pagerduty(
        self, title: str, message: str, severity: str, detail: dict[str, Any] | None = None
    ) -> None:
        if not settings.pagerduty_routing_key:
            raise RuntimeError("PagerDuty routing key is not configured.")

        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                "https://events.pagerduty.com/v2/enqueue",
                json={
                    "routing_key": settings.pagerduty_routing_key,
                    "event_action": "trigger",
                    "payload": {
                        "summary": title[:1024],
                        "source": "QuantNexa SOAR·AI",
                        "severity": "critical" if severity == "critical" else "warning",
                        "custom_details": {"message": message[:2000], **(detail or {})},
                    },
                },
            )
        if response.status_code >= 400:
            raise RuntimeError(f"PagerDuty returned HTTP {response.status_code}")

    async def send_email(self, title: str, message: str, severity: str) -> None:
        if not settings.smtp_host or not settings.critical_recipients:
            raise RuntimeError("SMTP host or recipient list is not configured.")

        email = EmailMessage()
        email["Subject"] = f"[SOAR {severity.upper()}] {title}"
        email["From"] = settings.smtp_from
        email["To"] = ", ".join(settings.critical_recipients)
        email.set_content(message)

        def _send() -> None:
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20) as server:
                server.starttls()
                if settings.smtp_user and settings.smtp_password:
                    server.login(settings.smtp_user, settings.smtp_password)
                server.send_message(email)

        import asyncio

        await asyncio.get_running_loop().run_in_executor(None, _send)


_service: NotificationService | None = None


def get_notification_service() -> NotificationService:
    global _service
    if _service is None:
        _service = NotificationService()
    return _service
