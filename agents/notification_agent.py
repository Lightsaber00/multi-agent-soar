"""
Multi-Agent SOAR - Notification Agent
Versendet Benachrichtigungen über verschiedene Kanäle
"""
from __future__ import annotations
from datetime import datetime
from typing import Dict, Any, List

from core.base_agent import BaseAgent
from core.models import Incident, Severity, AgentMessage


class NotificationAgent(BaseAgent):
    """
    Sendet Benachrichtigungen über:
    - Slack (simuliert)
    - E-Mail (simuliert)
    - Microsoft Teams (simuliert)
    - PagerDuty (simuliert)
    - Jira/ServiceNow (simuliert)
    """

    NAME = "notification_agent"

    def __init__(self):
        super().__init__(
            name=self.NAME,
            description="Multi-Channel Benachrichtigungen"
        )
        self.notification_log: List[Dict] = []

    def handle_message(self, message: AgentMessage):
        if message.message_type == "send_notification":
            incident_id = message.payload.get("incident_id")
            channels    = message.payload.get("channels", ["slack"])
            msg         = message.payload.get("message", "")
            incident    = self.store.get_incident(incident_id)
            if incident:
                self.notify(incident, channels, custom_message=msg)

    def notify(self, incident: Incident, channels: List[str] = None,
               custom_message: str = "") -> List[Dict]:
        if channels is None:
            channels = self._default_channels(incident.severity)

        results = []
        for channel in channels:
            result = self._send(channel, incident, custom_message)
            results.append(result)
            self.notification_log.append(result)

        incident.add_timeline_event(
            event_type="notifications_sent",
            actor=self.NAME,
            description=f"Benachrichtigungen über {len(channels)} Kanal(e) gesendet",
            data={"channels": channels, "results": results}
        )
        self.store.save_incident(incident)
        return results

    def _default_channels(self, severity: Severity) -> List[str]:
        if severity == Severity.CRITICAL:
            return ["slack", "email", "pagerduty"]
        elif severity == Severity.HIGH:
            return ["slack", "email"]
        else:
            return ["slack"]

    def _send(self, channel: str, incident: Incident,
               custom_message: str) -> Dict[str, Any]:
        emoji_map = {
            Severity.CRITICAL: "🚨", Severity.HIGH: "⚠️",
            Severity.MEDIUM: "⚡", Severity.LOW: "ℹ️"
        }
        emoji = emoji_map.get(incident.severity, "🔔")
        message = custom_message or self._format_message(incident, emoji)

        result = {
            "channel": channel,
            "timestamp": datetime.now().isoformat(),
            "incident_id": incident.id,
            "message_preview": message[:100] + "...",
            "success": True
        }

        if channel == "slack":
            result["webhook"] = "https://hooks.slack.com/sim/..."
            result["thread_ts"] = f"sim_{incident.id[:8]}"
        elif channel == "email":
            result["recipients"] = ["soc-team@example.com", "ciso@example.com"]
            result["subject"] = f"{emoji} [{incident.severity.value.upper()}] {incident.title}"
        elif channel == "pagerduty":
            result["alert_key"] = f"PD-{incident.id[:8].upper()}"
            result["dedup_key"] = incident.id
        elif channel == "teams":
            result["team_channel"] = "#security-alerts"
        elif channel == "jira":
            result["ticket"] = f"INC-{incident.id[:6].upper()}"
            result["url"] = f"https://jira.sim/browse/INC-{incident.id[:6].upper()}"

        self.log_action("NOTIFY", f"{channel.upper()} | Incident {incident.id[:8]}")
        return result

    def _format_message(self, incident: Incident, emoji: str) -> str:
        obs_count = len(incident.observables)
        mal_count = sum(1 for o in incident.observables if o.malicious)
        return (
            f"{emoji} *[{incident.severity.value.upper()}] Security Incident*\n"
            f"*Titel:* {incident.title}\n"
            f"*Status:* {incident.status.value}\n"
            f"*MITRE:* {', '.join(t.value.split(' - ')[1] for t in incident.mitre_tactics[:3])}\n"
            f"*IOCs:* {obs_count} ({mal_count} malicious)\n"
            f"*ID:* `{incident.id[:8]}`\n"
            f"*Link:* https://soar.example.com/incidents/{incident.id}"
        )

    def get_notification_log(self, limit: int = 50) -> List[Dict]:
        return self.notification_log[-limit:]
