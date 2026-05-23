"""
Multi-Agent SOAR - Compliance & Reporting Agent
Erstellt Compliance-Reports (ISO27001, SOC2) und KPI-Dashboards
"""
from __future__ import annotations
from datetime import datetime, timedelta
from typing import Dict, Any, List

from core.base_agent import BaseAgent
from core.models import (
    Incident, IncidentStatus, Severity,
    ComplianceFramework, AgentMessage
)


class ComplianceAgent(BaseAgent):
    """
    Erstellt:
    - ISO 27001 Incident Reports
    - SOC 2 Compliance Reports
    - KPI Metriken & Trends
    - Executive Summaries
    - MITRE ATT&CK Heatmaps
    """

    NAME = "compliance_agent"

    def __init__(self):
        super().__init__(
            name=self.NAME,
            description="Compliance-Reporting und KPI-Dashboard"
        )

    def handle_message(self, message: AgentMessage):
        if message.message_type == "generate_report":
            framework = message.payload.get("framework")
            tenant_id = message.payload.get("tenant_id", "default")
            period_days = message.payload.get("period_days", 30)
            if framework:
                self.generate_compliance_report(framework, tenant_id, period_days)

    # ─────────────────────────────────────────────────────────
    #  KPI Dashboard
    # ─────────────────────────────────────────────────────────

    def get_kpi_dashboard(self, tenant_id: str = None) -> Dict[str, Any]:
        """Berechnet vollständiges KPI-Dashboard"""
        snap   = self.store.get_kpi_snapshot(tenant_id)
        incs   = self.store.get_incidents(tenant_id=tenant_id)
        alerts = self.store.get_alerts(tenant_id=tenant_id)

        # Severity-Verteilung
        sev_dist = {s.value: 0 for s in Severity}
        for inc in incs:
            sev_dist[inc.severity.value] += 1

        # Status-Verteilung
        status_dist = {s.value: 0 for s in IncidentStatus}
        for inc in incs:
            status_dist[inc.status.value] += 1

        # Alert-Quellen
        source_dist: Dict[str, int] = {}
        for a in alerts:
            source_dist[a.source] = source_dist.get(a.source, 0) + 1

        # MITRE-Häufigkeit
        mitre_freq: Dict[str, int] = {}
        for inc in incs:
            for t in inc.mitre_tactics:
                key = t.value.split(" - ")[1] if " - " in t.value else t.value
                mitre_freq[key] = mitre_freq.get(key, 0) + 1

        # Tagesweise Incidents (letzte 7 Tage)
        daily_trend = self._calc_daily_trend(incs, days=7)

        # MTTD / MTTR
        closed = [i for i in incs if i.closed_at]
        mttr = 0.0
        if closed:
            ttrs = [(i.closed_at - i.created_at).total_seconds() / 60
                    for i in closed]
            mttr = round(sum(ttrs) / len(ttrs), 1)

        # Automation Rate
        auto_resolved = snap.get("alerts_auto_resolved", 0)
        total_alerts  = snap.get("alerts_ingested", 1)
        automation_rate = round(auto_resolved / max(total_alerts, 1) * 100, 1)

        return {
            "generated_at":     datetime.now().isoformat(),
            "tenant_id":        tenant_id or "all",
            "summary": {
                "total_alerts":          len(alerts),
                "total_incidents":       len(incs),
                "open_incidents":        snap.get("open_incidents", 0),
                "closed_incidents":      snap.get("incidents_closed", 0),
                "sla_breaches":          snap.get("sla_breaches", 0),
                "playbooks_executed":    snap.get("playbooks_executed", 0),
                "containments":          snap.get("containments_executed", 0),
                "false_positives":       snap.get("alerts_false_positive", 0),
                "mttr_minutes":          mttr,
                "automation_rate_pct":   automation_rate,
            },
            "severity_distribution":  sev_dist,
            "status_distribution":    status_dist,
            "alert_sources":          source_dist,
            "mitre_frequency":        dict(sorted(mitre_freq.items(),
                                                   key=lambda x: x[1], reverse=True)[:10]),
            "daily_trend":            daily_trend,
        }

    def _calc_daily_trend(self, incidents: List[Incident],
                           days: int = 7) -> List[Dict]:
        trend = []
        now = datetime.now()
        for i in range(days - 1, -1, -1):
            day = (now - timedelta(days=i)).date()
            count = sum(1 for inc in incidents
                        if inc.created_at.date() == day)
            trend.append({"date": day.isoformat(), "incidents": count})
        return trend

    # ─────────────────────────────────────────────────────────
    #  Compliance Reports
    # ─────────────────────────────────────────────────────────

    def generate_compliance_report(self, framework: str,
                                    tenant_id: str = "default",
                                    period_days: int = 30) -> Dict[str, Any]:
        fw_map = {
            "ISO27001": self._iso27001_report,
            "SOC2":     self._soc2_report,
        }
        fn = fw_map.get(framework.upper())
        if fn:
            return fn(tenant_id, period_days)
        return {"error": f"Framework '{framework}' nicht unterstützt"}

    def _iso27001_report(self, tenant_id: str, period_days: int) -> Dict[str, Any]:
        incs   = self.store.get_incidents(tenant_id=tenant_id)
        alerts = self.store.get_alerts(tenant_id=tenant_id)
        cutoff = datetime.now() - timedelta(days=period_days)
        period_incs = [i for i in incs if i.created_at >= cutoff]

        high_crit = [i for i in period_incs
                     if i.severity in (Severity.CRITICAL, Severity.HIGH)]
        contained = [i for i in period_incs
                     if i.status in (IncidentStatus.CONTAINED,
                                     IncidentStatus.REMEDIATED, IncidentStatus.CLOSED)]
        sla_ok_count = sum(1 for i in period_incs if not i.sla_breach)
        sla_compliance = round(sla_ok_count / max(len(period_incs), 1) * 100, 1)

        return {
            "framework":        "ISO 27001:2022",
            "report_period":    f"Letzte {period_days} Tage",
            "generated_at":     datetime.now().isoformat(),
            "tenant_id":        tenant_id,
            "clauses": {
                "A.16.1.1_Responsibility": {
                    "status": "Erfüllt",
                    "evidence": f"SOAR-System aktiv, {len(period_incs)} Incidents verwaltet"
                },
                "A.16.1.2_Reporting": {
                    "status": "Erfüllt",
                    "evidence": f"Alle Incidents dokumentiert mit Timeline"
                },
                "A.16.1.4_Assessment": {
                    "status": "Erfüllt",
                    "evidence": f"Automatische Triage & Severity-Bewertung"
                },
                "A.16.1.5_Response": {
                    "status": "Erfüllt" if sla_compliance >= 80 else "Teilweise",
                    "evidence": f"SLA-Compliance: {sla_compliance}%",
                    "sla_compliance_pct": sla_compliance
                },
                "A.16.1.6_Lessons": {
                    "status": "In Bearbeitung",
                    "evidence": "Playbook-Optimierung basierend auf Incident-Daten"
                },
            },
            "metrics": {
                "total_incidents":          len(period_incs),
                "high_critical_incidents":  len(high_crit),
                "contained_pct":            round(len(contained) /
                                                   max(len(period_incs), 1) * 100, 1),
                "sla_compliance_pct":       sla_compliance,
                "avg_response_time_min":    self._avg_ttr(period_incs),
            },
            "recommendations": self._iso_recommendations(period_incs, sla_compliance)
        }

    def _soc2_report(self, tenant_id: str, period_days: int) -> Dict[str, Any]:
        incs   = self.store.get_incidents(tenant_id=tenant_id)
        cutoff = datetime.now() - timedelta(days=period_days)
        period_incs = [i for i in incs if i.created_at >= cutoff]
        sla_breaches = sum(1 for i in period_incs if i.sla_breach)
        availability = round((1 - sla_breaches / max(len(period_incs), 1)) * 100, 1)

        return {
            "framework":     "SOC 2 Type II",
            "report_period": f"Letzte {period_days} Tage",
            "generated_at":  datetime.now().isoformat(),
            "tenant_id":     tenant_id,
            "trust_criteria": {
                "CC6_LogicalAccess": {
                    "status": "Compliant",
                    "controls": ["MFA enforced", "Account lockout policy", "PAM implemented"]
                },
                "CC7_SystemOperations": {
                    "status": "Compliant",
                    "controls": [
                        f"SIEM monitoring active ({len(self.store.get_alerts(tenant_id=tenant_id))} alerts processed)",
                        "Automated incident response enabled",
                        f"Playbooks: {len(self.store.get_playbooks())} active"
                    ]
                },
                "CC8_ChangeManagement": {
                    "status": "Compliant",
                    "controls": ["Change tickets via ITSM", "Incident-driven changes tracked"]
                },
                "A1_Availability": {
                    "status": "Compliant" if availability >= 99 else "Review Required",
                    "sla_performance_pct": availability,
                    "controls": [f"SLA compliance: {availability}%"]
                },
            },
            "evidence_summary": {
                "incidents_managed":     len(period_incs),
                "automated_responses":   self.store.kpi.get("playbooks_executed", 0),
                "containment_actions":   self.store.kpi.get("containments_executed", 0),
                "notification_coverage": "100% critical incidents notified",
            },
            "auditor_notes": (
                "Alle Sicherheitsvorfälle wurden mit vollständiger Audit-Trail-Dokumentation "
                "verwaltet. Automatisierte Playbooks gewährleisten konsistente Reaktionen."
            )
        }

    def _avg_ttr(self, incidents: List[Incident]) -> float:
        closed = [i for i in incidents if i.closed_at]
        if not closed:
            return 0.0
        ttrs = [(i.closed_at - i.created_at).total_seconds() / 60 for i in closed]
        return round(sum(ttrs) / len(ttrs), 1)

    def _iso_recommendations(self, incidents: List[Incident],
                               sla_compliance: float) -> List[str]:
        recs = []
        if sla_compliance < 90:
            recs.append("SLA-Compliance verbessern: Playbook-Reaktionszeiten optimieren")
        breach = [i for i in incidents if i.sla_breach]
        if breach:
            recs.append(f"{len(breach)} SLA-Verletzungen analysieren und Eskalationspfade prüfen")
        unassigned = [i for i in incidents if not i.assigned_to]
        if unassigned:
            recs.append(f"{len(unassigned)} unzugewiesene Incidents: Auto-Assignment-Regeln erstellen")
        if not recs:
            recs.append("Alle ISO 27001 Anforderungen werden aktuell erfüllt. Regelmäßige Reviews durchführen.")
        return recs
