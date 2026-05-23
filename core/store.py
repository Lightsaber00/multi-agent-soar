"""
Multi-Agent SOAR - In-Memory Data Store
Zentraler Speicher für alle SOAR-Objekte (produktiv: durch DB ersetzen)
"""
from __future__ import annotations
from collections import defaultdict
from datetime import datetime
from threading import Lock
from typing import Any, Dict, List, Optional

from .models import Alert, Incident, Playbook, PlaybookExecution, Tenant, Observable


class SOARStore:
    """Thread-sicherer In-Memory Store"""

    def __init__(self):
        self._lock = Lock()

        # Core collections
        self.alerts:      Dict[str, Alert]             = {}
        self.incidents:   Dict[str, Incident]          = {}
        self.playbooks:   Dict[str, Playbook]          = {}
        self.executions:  Dict[str, PlaybookExecution] = {}
        self.tenants:     Dict[str, Tenant]            = {}
        self.observables: Dict[str, Observable]        = {}

        # KPI counters
        self.kpi: Dict[str, Any] = {
            "alerts_ingested":        0,
            "alerts_auto_resolved":   0,
            "alerts_false_positive":  0,
            "incidents_created":      0,
            "incidents_closed":       0,
            "playbooks_executed":     0,
            "containments_executed":  0,
            "mean_ttr_minutes":       0.0,
            "mean_triage_seconds":    0.0,
            "sla_breaches":           0,
        }

        # Per-tenant indices
        self._tenant_alerts:    Dict[str, List[str]] = defaultdict(list)
        self._tenant_incidents: Dict[str, List[str]] = defaultdict(list)

        # Initialise default tenant
        self._init_defaults()

    # ─────────────────────────────────────────────────────────
    #  Bootstrap
    # ─────────────────────────────────────────────────────────

    def _init_defaults(self):
        from .models import Tenant, ComplianceFramework, Severity
        default = Tenant(
            id="default",
            name="Default Organization",
            description="Standard-Mandant",
            contact_email="soc@example.com",
            sla_config={
                Severity.CRITICAL.value: 60,
                Severity.HIGH.value:     240,
                Severity.MEDIUM.value:   1440,
                Severity.LOW.value:      4320,
            },
            compliance_frameworks=[ComplianceFramework.ISO27001, ComplianceFramework.SOC2]
        )
        self.tenants["default"] = default

    # ─────────────────────────────────────────────────────────
    #  Alerts
    # ─────────────────────────────────────────────────────────

    def save_alert(self, alert: Alert) -> Alert:
        with self._lock:
            self.alerts[alert.id] = alert
            if alert.id not in self._tenant_alerts[alert.tenant_id]:
                self._tenant_alerts[alert.tenant_id].append(alert.id)
            self.kpi["alerts_ingested"] += 1
        return alert

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        return self.alerts.get(alert_id)

    def get_alerts(self, tenant_id: str = None, status=None,
                   severity=None, limit: int = 500) -> List[Alert]:
        alerts = list(self.alerts.values())
        if tenant_id:
            alerts = [a for a in alerts if a.tenant_id == tenant_id]
        if status:
            alerts = [a for a in alerts if a.status == status]
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        alerts.sort(key=lambda a: a.created_at, reverse=True)
        return alerts[:limit]

    # ─────────────────────────────────────────────────────────
    #  Incidents
    # ─────────────────────────────────────────────────────────

    def save_incident(self, incident: Incident) -> Incident:
        with self._lock:
            is_new = incident.id not in self.incidents
            self.incidents[incident.id] = incident
            if is_new:
                self._tenant_incidents[incident.tenant_id].append(incident.id)
                self.kpi["incidents_created"] += 1
        return incident

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        return self.incidents.get(incident_id)

    def get_incidents(self, tenant_id: str = None, status=None,
                      severity=None, limit: int = 200) -> List[Incident]:
        incs = list(self.incidents.values())
        if tenant_id:
            incs = [i for i in incs if i.tenant_id == tenant_id]
        if status:
            incs = [i for i in incs if i.status == status]
        if severity:
            incs = [i for i in incs if i.severity == severity]
        incs.sort(key=lambda i: i.created_at, reverse=True)
        return incs[:limit]

    # ─────────────────────────────────────────────────────────
    #  Playbooks
    # ─────────────────────────────────────────────────────────

    def save_playbook(self, pb: Playbook) -> Playbook:
        with self._lock:
            self.playbooks[pb.id] = pb
        return pb

    def get_playbook(self, pb_id: str) -> Optional[Playbook]:
        return self.playbooks.get(pb_id)

    def get_playbooks(self, tenant_id: str = None,
                      enabled_only: bool = True) -> List[Playbook]:
        pbs = list(self.playbooks.values())
        if tenant_id and tenant_id != "default":
            pbs = [p for p in pbs
                   if p.tenant_id == tenant_id or p.tenant_id == "default"]
        if enabled_only:
            pbs = [p for p in pbs if p.enabled]
        return pbs

    # ─────────────────────────────────────────────────────────
    #  Playbook Executions
    # ─────────────────────────────────────────────────────────

    def save_execution(self, ex: PlaybookExecution) -> PlaybookExecution:
        with self._lock:
            self.executions[ex.id] = ex
            self.kpi["playbooks_executed"] += 1
        return ex

    def get_executions_for_incident(self, incident_id: str) -> List[PlaybookExecution]:
        return [e for e in self.executions.values()
                if e.incident_id == incident_id]

    # ─────────────────────────────────────────────────────────
    #  KPI Updates
    # ─────────────────────────────────────────────────────────

    def update_kpi(self, key: str, value: Any = None, increment: bool = False):
        with self._lock:
            if increment:
                self.kpi[key] = self.kpi.get(key, 0) + 1
            elif value is not None:
                self.kpi[key] = value

    def get_kpi_snapshot(self, tenant_id: str = None) -> Dict[str, Any]:
        """Berechnet KPI-Snapshot"""
        with self._lock:
            snap = dict(self.kpi)

        # Dynamische Metriken
        tenant_incidents = self.get_incidents(tenant_id=tenant_id)
        closed = [i for i in tenant_incidents
                  if i.closed_at and i.created_at]
        if closed:
            ttrs = [(i.closed_at - i.created_at).total_seconds() / 60
                    for i in closed]
            snap["mean_ttr_minutes"] = round(sum(ttrs) / len(ttrs), 1)

        snap["open_incidents"]   = len([i for i in tenant_incidents
                                        if i.status not in ("closed", "remediated")])
        snap["total_incidents"]  = len(tenant_incidents)
        snap["total_alerts"]     = len(self.get_alerts(tenant_id=tenant_id))
        snap["sla_breaches"]     = len([i for i in tenant_incidents if i.sla_breach])
        return snap


# Singleton
_store: Optional[SOARStore] = None

def get_store() -> SOARStore:
    global _store
    if _store is None:
        _store = SOARStore()
    return _store
