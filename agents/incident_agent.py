"""
Multi-Agent SOAR - Incident Management Agent
Erstellt und verwaltet Incidents aus triaged Alerts
"""
from __future__ import annotations
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

from core.base_agent import BaseAgent
from core.models import (
    Alert, AlertStatus, Incident, IncidentStatus,
    Severity, ComplianceFramework, AgentMessage, MITRETactic
)


# Compliance-Framework-Mapping basierend auf Severity und Taktik
COMPLIANCE_MAPPING = {
    MITRETactic.EXFILTRATION:        [ComplianceFramework.GDPR, ComplianceFramework.ISO27001],
    MITRETactic.CREDENTIAL_ACCESS:   [ComplianceFramework.ISO27001, ComplianceFramework.SOC2],
    MITRETactic.IMPACT:              [ComplianceFramework.ISO27001, ComplianceFramework.SOC2,
                                      ComplianceFramework.NIST],
    MITRETactic.INITIAL_ACCESS:      [ComplianceFramework.ISO27001],
    MITRETactic.LATERAL_MOVEMENT:    [ComplianceFramework.ISO27001, ComplianceFramework.NIST],
    MITRETactic.PRIVILEGE_ESC:       [ComplianceFramework.SOC2, ComplianceFramework.ISO27001],
}

# SLA in Minuten (Standard – wird pro Tenant überschrieben)
DEFAULT_SLA = {
    Severity.CRITICAL: 60,
    Severity.HIGH:     240,
    Severity.MEDIUM:   1440,
    Severity.LOW:      4320,
}


class IncidentAgent(BaseAgent):
    """
    Verwaltet den gesamten Incident Lifecycle:
    - Automatische Incident-Erstellung aus Alerts
    - Alert-Korrelation (ähnliche Alerts → ein Incident)
    - SLA-Tracking
    - Status-Übergänge
    - Compliance-Framework-Zuordnung
    """

    NAME = "incident_agent"

    def __init__(self):
        super().__init__(
            name=self.NAME,
            description="Incident Lifecycle Management und Korrelation"
        )

    def handle_message(self, message: AgentMessage):
        if message.message_type == "evaluate_alert":
            alert_id = message.payload.get("alert_id")
            alert = self.store.get_alert(alert_id)
            if alert:
                incident = self.evaluate_and_create(alert)
                if incident:
                    # Playbook-Agenten benachrichtigen
                    self.send(
                        recipient="playbook_agent",
                        message_type="run_playbooks",
                        payload={"incident_id": incident.id},
                        correlation_id=message.correlation_id
                    )
        elif message.message_type == "update_incident_status":
            inc_id = message.payload.get("incident_id")
            new_status = message.payload.get("status")
            incident = self.store.get_incident(inc_id)
            if incident and new_status:
                self.update_status(incident, IncidentStatus(new_status),
                                   actor=message.sender)

    # ─────────────────────────────────────────────────────────
    #  Core Logic
    # ─────────────────────────────────────────────────────────

    def evaluate_and_create(self, alert: Alert) -> Optional[Incident]:
        """Entscheidet ob neuer Incident oder bestehender erweitert wird"""

        # False-Positive → kein Incident
        if alert.false_positive_score > 0.75:
            alert.status = AlertStatus.FALSE_POS
            self.store.save_alert(alert)
            self.store.update_kpi("alerts_false_positive", increment=True)
            self.log_action("FP_SKIP", f"Alert {alert.id[:8]} als False Positive übersprungen")
            return None

        # Niedrige Priorität → kein Incident
        if alert.triage_score < 20:
            alert.status = AlertStatus.RESOLVED
            self.store.save_alert(alert)
            self.store.update_kpi("alerts_auto_resolved", increment=True)
            return None

        # Korrelation: existierenden Incident suchen
        existing = self._find_correlating_incident(alert)
        if existing:
            self._add_alert_to_incident(existing, alert)
            return existing

        # Neuen Incident erstellen
        return self._create_incident(alert)

    def _find_correlating_incident(self, alert: Alert) -> Optional[Incident]:
        """Sucht nach offenen Incidents die zu diesem Alert passen"""
        open_statuses = {
            IncidentStatus.NEW, IncidentStatus.TRIAGING,
            IncidentStatus.ACTIVE, IncidentStatus.CONTAINED
        }
        for incident in self.store.get_incidents(
            tenant_id=alert.tenant_id, limit=50
        ):
            if incident.status not in open_statuses:
                continue
            # Taktik-Überschneidung
            tactic_overlap = set(incident.mitre_tactics) & set(alert.mitre_tactics)
            if tactic_overlap:
                return incident
            # Observable-Überschneidung
            inc_iocs = {o.value for o in incident.observables}
            alert_iocs = {o.value for o in alert.observables}
            if inc_iocs & alert_iocs:
                return incident
        return None

    def _add_alert_to_incident(self, incident: Incident, alert: Alert):
        """Fügt Alert zu bestehendem Incident hinzu"""
        incident.alert_ids.append(alert.id)

        # Severity upgraden wenn nötig
        sev_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM,
                     Severity.HIGH, Severity.CRITICAL]
        if sev_order.index(alert.severity) > sev_order.index(incident.severity):
            incident.severity = alert.severity

        # Neue Observables hinzufügen
        existing_vals = {o.value for o in incident.observables}
        for obs in alert.observables:
            if obs.value not in existing_vals:
                incident.observables.append(obs)

        # Neue Taktiken
        for t in alert.mitre_tactics:
            if t not in incident.mitre_tactics:
                incident.mitre_tactics.append(t)

        incident.add_timeline_event(
            event_type="alert_correlated",
            actor=self.NAME,
            description=f"Alert korreliert: {alert.title}",
            data={"alert_id": alert.id, "severity": alert.severity.value}
        )
        alert.assigned_incident_id = incident.id
        alert.status = AlertStatus.IN_PROGRESS

        self.store.save_incident(incident)
        self.store.save_alert(alert)
        self.log_action("CORRELATED", f"Alert {alert.id[:8]} → Incident {incident.id[:8]}")

    def _create_incident(self, alert: Alert) -> Incident:
        """Erstellt neuen Incident aus Alert"""
        tenant = self.store.tenants.get(alert.tenant_id)
        sla_config = tenant.sla_config if tenant else {}

        # SLA berechnen
        sla_minutes = sla_config.get(
            alert.severity.value,
            DEFAULT_SLA.get(alert.severity, 1440)
        )
        sla_deadline = datetime.now() + timedelta(minutes=sla_minutes)

        # Compliance-Frameworks
        frameworks = set()
        for tactic in alert.mitre_tactics:
            for fw in COMPLIANCE_MAPPING.get(tactic, []):
                frameworks.add(fw)
        if tenant:
            for fw in tenant.compliance_frameworks:
                frameworks.add(fw)

        incident = Incident(
            title=f"[{alert.severity.value.upper()}] {alert.title}",
            description=alert.description,
            severity=alert.severity,
            status=IncidentStatus.NEW,
            tenant_id=alert.tenant_id,
            alert_ids=[alert.id],
            observables=list(alert.observables),
            mitre_tactics=list(alert.mitre_tactics),
            mitre_techniques=list(alert.mitre_techniques),
            compliance_frameworks=list(frameworks),
            sla_deadline=sla_deadline,
        )

        incident.add_timeline_event(
            event_type="incident_created",
            actor=self.NAME,
            description=f"Incident automatisch erstellt aus Alert: {alert.title}",
            data={
                "alert_id": alert.id,
                "triage_score": alert.triage_score,
                "source": alert.source,
                "severity": alert.severity.value
            }
        )

        alert.assigned_incident_id = incident.id
        alert.status = AlertStatus.IN_PROGRESS

        self.store.save_incident(incident)
        self.store.save_alert(alert)

        self.log_action(
            "INCIDENT_CREATED", f"{incident.id[:8]}",
            {"severity": incident.severity.value, "sla": sla_minutes}
        )
        return incident

    # ─────────────────────────────────────────────────────────
    #  Status Management
    # ─────────────────────────────────────────────────────────

    def update_status(self, incident: Incident,
                      new_status: IncidentStatus, actor: str = "system") -> Incident:
        old_status = incident.status
        incident.status = new_status

        if new_status == IncidentStatus.CLOSED:
            incident.closed_at = datetime.now()
            self.store.update_kpi("incidents_closed", increment=True)
            # SLA-Prüfung
            if incident.sla_deadline and datetime.now() > incident.sla_deadline:
                incident.sla_breach = True
                self.store.update_kpi("sla_breaches", increment=True)
            # Alle Alerts als resolved markieren
            for aid in incident.alert_ids:
                a = self.store.get_alert(aid)
                if a:
                    a.status = AlertStatus.RESOLVED
                    self.store.save_alert(a)

        incident.add_timeline_event(
            event_type="status_change",
            actor=actor,
            description=f"Status geändert: {old_status.value} → {new_status.value}",
            data={"old": old_status.value, "new": new_status.value}
        )
        self.store.save_incident(incident)
        return incident

    def assign_incident(self, incident: Incident,
                        assignee: str, actor: str = "system") -> Incident:
        incident.assigned_to = assignee
        incident.status = IncidentStatus.TRIAGING
        incident.add_timeline_event(
            event_type="assigned",
            actor=actor,
            description=f"Incident zugewiesen an: {assignee}",
            data={"assignee": assignee}
        )
        self.store.save_incident(incident)
        return incident

    def add_note(self, incident: Incident, note: str, actor: str = "analyst") -> Incident:
        incident.notes += f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M')}] {actor}: {note}"
        incident.add_timeline_event(
            event_type="note_added",
            actor=actor,
            description="Notiz hinzugefügt",
            data={"note": note}
        )
        self.store.save_incident(incident)
        return incident

    def check_sla_breaches(self) -> List[Incident]:
        """Prüft alle offenen Incidents auf SLA-Verletzungen"""
        breached = []
        now = datetime.now()
        for incident in self.store.get_incidents():
            if (incident.sla_deadline and
                    not incident.sla_breach and
                    incident.status not in (IncidentStatus.CLOSED, IncidentStatus.REMEDIATED) and
                    now > incident.sla_deadline):
                incident.sla_breach = True
                incident.add_timeline_event(
                    event_type="sla_breach",
                    actor=self.NAME,
                    description="SLA verletzt!",
                    data={"deadline": incident.sla_deadline.isoformat()}
                )
                self.store.save_incident(incident)
                self.store.update_kpi("sla_breaches", increment=True)
                breached.append(incident)

        if breached:
            self.log_action("SLA_BREACH", f"{len(breached)} Incidents")
        return breached
