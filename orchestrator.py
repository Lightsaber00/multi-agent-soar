"""
Multi-Agent SOAR - Orchestrator
Verwaltet alle Agenten und koordiniert den Alert-to-Incident Workflow
"""
from __future__ import annotations
import logging
import sys
from typing import Dict, List, Optional

# Agent imports
sys.path.insert(0, '/home/claude/soar')
from core.base_agent import BaseAgent
from core.store import get_store
from core.models import Alert, Incident, AgentMessage

from agents.triage_agent import TriageAgent
from agents.enrichment_agent import EnrichmentAgent
from agents.incident_agent import IncidentAgent
from agents.playbook_agent import PlaybookAgent
from agents.containment_agent import ContainmentAgent
from agents.notification_agent import NotificationAgent
from agents.compliance_agent import ComplianceAgent


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)-30s | %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("soar.orchestrator")


class SOAROrchestrator:
    """
    Zentrale SOAR-Steuereinheit:
    - Initialisiert alle Agenten
    - Registriert Agenten-Registry
    - Steuert den vollständigen Alert → Incident → Response Workflow
    - Stellt API-ähnliche Methoden für die CLI bereit
    """

    def __init__(self):
        self.store = get_store()

        # Agenten instantiieren
        self.triage      = TriageAgent()
        self.enrichment  = EnrichmentAgent()
        self.incident    = IncidentAgent()
        self.playbook    = PlaybookAgent()
        self.containment = ContainmentAgent()
        self.notification = NotificationAgent()
        self.compliance  = ComplianceAgent()

        # Registry aufbauen
        self._registry: Dict[str, BaseAgent] = {
            TriageAgent.NAME:       self.triage,
            EnrichmentAgent.NAME:   self.enrichment,
            IncidentAgent.NAME:     self.incident,
            PlaybookAgent.NAME:     self.playbook,
            ContainmentAgent.NAME:  self.containment,
            NotificationAgent.NAME: self.notification,
            ComplianceAgent.NAME:   self.compliance,
        }

        # Registry in alle Agenten eintragen
        for agent in self._registry.values():
            agent.register_agents(self._registry)

        # Agenten starten (Background-Threads)
        for agent in self._registry.values():
            agent.start()

        logger.info(f"SOAR Orchestrator gestartet mit {len(self._registry)} Agenten.")

    # ─────────────────────────────────────────────────────────
    #  Main Ingestion Pipeline
    # ─────────────────────────────────────────────────────────

    def ingest_alert(self, alert: Alert) -> Dict:
        """
        Vollständige Pipeline: Alert → Triage → Enrichment → Incident → Playbooks
        (synchron für CLI/Demo)
        """
        logger.info(f"━━━ Neuer Alert: [{alert.severity.value.upper()}] {alert.title}")

        # 1. Speichern
        self.store.save_alert(alert)

        # 2. Triage
        alert = self.triage.triage_alert(alert)
        logger.info(f"    Triage Score: {alert.triage_score:.1f} | FP: {alert.false_positive_score:.2f}")

        # 3. Enrichment
        alert = self.enrichment.enrich_alert(alert)
        mal = sum(1 for o in alert.observables if o.malicious)
        logger.info(f"    Observables: {len(alert.observables)} ({mal} malicious)")

        # 4. Incident Management
        incident = self.incident.evaluate_and_create(alert)
        if not incident:
            logger.info(f"    ↳ Kein Incident erstellt (FP oder niedrige Priorität)")
            return {"alert": alert.to_dict(), "incident": None, "playbooks": []}

        logger.info(f"    Incident: {incident.id[:8]} [{incident.severity.value}] {incident.title[:50]}")

        # 5. Playbook Execution
        executions = self.playbook.run_matching_playbooks(incident)
        logger.info(f"    Playbooks: {len(executions)} ausgeführt")

        # 6. SLA prüfen
        self.incident.check_sla_breaches()

        # 7. Notifications (bei CRITICAL/HIGH)
        from core.models import Severity
        if incident.severity in (Severity.CRITICAL, Severity.HIGH):
            self.notification.notify(incident)

        logger.info(f"━━━ Verarbeitung abgeschlossen: Incident {incident.id[:8]}")

        return {
            "alert":     alert.to_dict(),
            "incident":  incident.to_dict(),
            "playbooks": [{"id": e.id, "playbook_id": e.playbook_id,
                            "status": e.status.value,
                            "steps": len(e.step_results)} for e in executions]
        }

    # ─────────────────────────────────────────────────────────
    #  Query Methods
    # ─────────────────────────────────────────────────────────

    def get_dashboard(self, tenant_id: str = None) -> Dict:
        return self.compliance.get_kpi_dashboard(tenant_id)

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        return self.store.get_incident(incident_id)

    def get_incidents(self, tenant_id: str = None, limit: int = 20) -> List[Incident]:
        return self.store.get_incidents(tenant_id=tenant_id, limit=limit)

    def get_alerts(self, tenant_id: str = None, limit: int = 50) -> List[Alert]:
        return self.store.get_alerts(tenant_id=tenant_id, limit=limit)

    def get_compliance_report(self, framework: str = "ISO27001",
                               tenant_id: str = "default") -> Dict:
        return self.compliance.generate_compliance_report(framework, tenant_id)

    def get_containment_status(self) -> Dict:
        return self.containment.get_containment_status()

    def get_playbooks(self) -> List:
        return self.store.get_playbooks()

    def update_incident_status(self, incident_id: str,
                                new_status: str, actor: str = "analyst") -> Optional[Incident]:
        from core.models import IncidentStatus
        incident = self.store.get_incident(incident_id)
        if incident:
            return self.incident.update_status(incident, IncidentStatus(new_status), actor)
        return None

    def add_incident_note(self, incident_id: str, note: str,
                           actor: str = "analyst") -> Optional[Incident]:
        incident = self.store.get_incident(incident_id)
        if incident:
            return self.incident.add_note(incident, note, actor)
        return None

    def execute_containment(self, incident_id: str) -> Dict:
        incident = self.store.get_incident(incident_id)
        if incident:
            return self.containment.execute_containment(incident)
        return {"error": "Incident nicht gefunden"}

    # ─────────────────────────────────────────────────────────
    #  Lifecycle
    # ─────────────────────────────────────────────────────────

    def shutdown(self):
        for agent in self._registry.values():
            agent.stop()
        logger.info("SOAR Orchestrator heruntergefahren.")
