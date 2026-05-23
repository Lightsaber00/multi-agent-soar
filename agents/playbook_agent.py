"""
Multi-Agent SOAR - Playbook Automation Agent
Führt automatisierte Playbooks aus
"""
from __future__ import annotations
import time
from datetime import datetime
from typing import Dict, Any, List, Optional

from core.base_agent import BaseAgent
from core.models import (
    Incident, Playbook, PlaybookExecution, PlaybookStatus,
    PlaybookStep, Severity, MITRETactic, AgentMessage
)


class PlaybookAgent(BaseAgent):
    """
    Führt Playbooks automatisch aus:
    - Matching von Playbooks auf Incidents
    - Schrittweise Ausführung mit Bedingungen
    - Fehlerbehandlung und Retry-Logik
    - Integration mit Containment, Notification, Ticketing
    """

    NAME = "playbook_agent"

    def __init__(self):
        super().__init__(
            name=self.NAME,
            description="Automatisierte Playbook-Ausführung"
        )
        self._register_default_playbooks()

    def handle_message(self, message: AgentMessage):
        if message.message_type == "run_playbooks":
            incident_id = message.payload.get("incident_id")
            incident = self.store.get_incident(incident_id)
            if incident:
                self.run_matching_playbooks(incident)

    # ─────────────────────────────────────────────────────────
    #  Playbook Matching & Execution
    # ─────────────────────────────────────────────────────────

    def run_matching_playbooks(self, incident: Incident) -> List[PlaybookExecution]:
        matching = self._find_matching_playbooks(incident)
        executions = []
        for pb in matching:
            ex = self._execute_playbook(pb, incident)
            executions.append(ex)
        return executions

    def _find_matching_playbooks(self, incident: Incident) -> List[Playbook]:
        playbooks = self.store.get_playbooks(tenant_id=incident.tenant_id)
        matched = []
        for pb in playbooks:
            if self._matches(pb, incident):
                matched.append(pb)
        self.log_action("MATCH", f"Incident {incident.id[:8]}: {len(matched)} Playbooks")
        return matched

    def _matches(self, pb: Playbook, incident: Incident) -> bool:
        cond = pb.trigger_conditions

        # Severity-Filter
        if pb.applicable_severities:
            if incident.severity not in pb.applicable_severities:
                return False

        # Taktik-Filter
        if pb.mitre_tactics:
            overlap = set(pb.mitre_tactics) & set(incident.mitre_tactics)
            if not overlap:
                return False

        # Custom conditions
        if cond.get("min_triage_score"):
            alert_ids = incident.alert_ids
            if alert_ids:
                alert = self.store.get_alert(alert_ids[0])
                if alert and alert.triage_score < cond["min_triage_score"]:
                    return False

        # Tenant
        if pb.tenant_id not in ("default", incident.tenant_id):
            return False

        return True

    def _execute_playbook(self, pb: Playbook,
                          incident: Incident) -> PlaybookExecution:
        ex = PlaybookExecution(
            playbook_id=pb.id,
            incident_id=incident.id,
            status=PlaybookStatus.RUNNING,
            started_at=datetime.now()
        )
        self.store.save_execution(ex)
        self.log_action("PLAYBOOK_START", f"'{pb.name}' für Incident {incident.id[:8]}")

        incident.add_timeline_event(
            event_type="playbook_started",
            actor=self.NAME,
            description=f"Playbook gestartet: {pb.name}",
            data={"playbook_id": pb.id, "steps": len(pb.steps)}
        )

        step_map = {s.id: s for s in pb.steps}
        current_step = pb.steps[0] if pb.steps else None
        all_success = True

        while current_step:
            result = self._execute_step(current_step, incident, pb)
            ex.step_results.append(result)

            if result["success"]:
                next_id = current_step.on_success
            else:
                all_success = False
                next_id = current_step.on_failure

            current_step = step_map.get(next_id) if next_id else None

        ex.status = PlaybookStatus.COMPLETED if all_success else PlaybookStatus.FAILED
        ex.completed_at = datetime.now()

        incident.playbooks_executed.append(pb.id)
        incident.add_timeline_event(
            event_type="playbook_completed",
            actor=self.NAME,
            description=f"Playbook abgeschlossen: {pb.name} ({ex.status.value})",
            data={"execution_id": ex.id, "success": all_success,
                  "steps_executed": len(ex.step_results)}
        )

        self.store.save_execution(ex)
        self.store.save_incident(incident)
        self.log_action("PLAYBOOK_DONE", f"'{pb.name}': {ex.status.value}")

        # Containment- oder Notification-Agenten informieren
        if all_success:
            for result in ex.step_results:
                if result.get("action_type") == "contain" and result.get("success"):
                    self.send(
                        recipient="containment_agent",
                        message_type="execute_containment",
                        payload={
                            "incident_id": incident.id,
                            "actions": result.get("containment_actions", [])
                        }
                    )
                elif result.get("action_type") == "notify":
                    self.send(
                        recipient="notification_agent",
                        message_type="send_notification",
                        payload={
                            "incident_id": incident.id,
                            "channels": result.get("channels", []),
                            "message": result.get("message", "")
                        }
                    )
        return ex

    def _execute_step(self, step: PlaybookStep,
                       incident: Incident, pb: Playbook) -> Dict[str, Any]:
        result = {
            "step_id": step.id, "step_name": step.name,
            "action_type": step.action_type,
            "started_at": datetime.now().isoformat(),
            "success": False, "output": {}
        }

        try:
            # Bedingungen prüfen
            if not self._check_conditions(step.conditions, incident):
                result["success"]  = True
                result["skipped"]  = True
                result["output"]   = {"reason": "Condition not met, step skipped"}
                return result

            # Action ausführen
            output = self._dispatch_action(step, incident)
            result["success"] = True
            result["output"]  = output

        except Exception as e:
            result["success"] = False
            result["error"]   = str(e)
            self.logger.error(f"Step '{step.name}' fehlgeschlagen: {e}")

        result["completed_at"] = datetime.now().isoformat()
        return result

    def _check_conditions(self, conditions: Dict, incident: Incident) -> bool:
        if not conditions:
            return True
        for key, expected in conditions.items():
            if key == "severity" and incident.severity.value != expected:
                return False
            if key == "has_malicious_ioc":
                has_mal = any(o.malicious for o in incident.observables)
                if has_mal != expected:
                    return False
        return True

    def _dispatch_action(self, step: PlaybookStep,
                          incident: Incident) -> Dict[str, Any]:
        action = step.action_type
        params = step.parameters

        if action == "enrich":
            return {"enriched": True, "note": "Anreicherung ausgelöst"}
        elif action == "contain":
            actions = self._build_containment_actions(incident, params)
            step.parameters["_containment_actions"] = actions
            return {"containment_actions": actions, "action_type": "contain"}
        elif action == "query_siem":
            return self._simulate_siem_query(params, incident)
        elif action == "create_ticket":
            return self._simulate_create_ticket(incident, params)
        elif action == "notify":
            return self._simulate_notify(incident, params)
        elif action == "collect_forensics":
            return self._simulate_forensics(incident, params)
        elif action == "vulnerability_scan":
            return self._simulate_vuln_scan(incident, params)
        elif action == "update_status":
            new_status = params.get("status", "active")
            return {"status_updated_to": new_status}
        else:
            return {"note": f"Unbekannte Action: {action}"}

    # ─────────────────────────────────────────────────────────
    #  Simulated Action Handlers
    # ─────────────────────────────────────────────────────────

    def _build_containment_actions(self, incident: Incident,
                                    params: Dict) -> List[str]:
        actions = []
        for obs in incident.observables:
            if obs.malicious:
                if obs.type == "ip":
                    actions.append(f"block_ip:{obs.value}")
                elif obs.type == "domain":
                    actions.append(f"block_domain:{obs.value}")
                elif obs.type in ("md5", "sha256"):
                    actions.append(f"quarantine_hash:{obs.value}")
        if params.get("isolate_host"):
            actions.append("isolate_host:affected")
        return actions

    def _simulate_siem_query(self, params: Dict,
                              incident: Incident) -> Dict[str, Any]:
        return {
            "query": params.get("query", "index=* severity=high"),
            "results_count": 42,
            "events": [
                {"timestamp": "2024-01-15T10:23:45", "host": "WORKSTATION-01",
                 "event": "Suspicious process execution detected"},
                {"timestamp": "2024-01-15T10:24:01", "host": "WORKSTATION-01",
                 "event": "Network connection to known C2"}
            ],
            "source": "Splunk-Sim"
        }

    def _simulate_create_ticket(self, incident: Incident,
                                  params: Dict) -> Dict[str, Any]:
        ticket_id = f"INC-{incident.id[:6].upper()}"
        return {
            "ticket_id": ticket_id,
            "url": f"https://jira.example.com/browse/{ticket_id}",
            "priority": incident.severity.value,
            "system": params.get("system", "Jira"),
            "status": "Open"
        }

    def _simulate_notify(self, incident: Incident,
                          params: Dict) -> Dict[str, Any]:
        channels = params.get("channels", ["slack"])
        msg = (f"🚨 [{incident.severity.value.upper()}] Incident: {incident.title}\n"
               f"Status: {incident.status.value} | ID: {incident.id[:8]}")
        return {
            "action_type": "notify",
            "channels": channels,
            "message": msg,
            "sent": True,
            "timestamp": datetime.now().isoformat()
        }

    def _simulate_forensics(self, incident: Incident,
                              params: Dict) -> Dict[str, Any]:
        artifacts = [
            {"type": "process_list",   "host": "WORKSTATION-01",
             "collected_at": datetime.now().isoformat()},
            {"type": "network_connections", "host": "WORKSTATION-01",
             "collected_at": datetime.now().isoformat()},
            {"type": "registry_snapshot", "host": "WORKSTATION-01",
             "collected_at": datetime.now().isoformat()},
        ]
        incident.forensic_artifacts.extend(artifacts)
        self.store.save_incident(incident)
        return {"artifacts_collected": len(artifacts), "artifacts": artifacts}

    def _simulate_vuln_scan(self, incident: Incident,
                             params: Dict) -> Dict[str, Any]:
        cve_obs = [o for o in incident.observables if o.type == "cve"]
        vulns = []
        for obs in cve_obs:
            vulns.append({
                "cve": obs.value,
                "cvss": obs.metadata.get("cvss", "N/A"),
                "name": obs.metadata.get("name", "Unknown"),
                "patch": obs.metadata.get("patch", "See vendor advisory"),
                "affected_hosts": ["WORKSTATION-01", "SERVER-02"]
            })
        incident.vulnerabilities.extend(vulns)
        self.store.save_incident(incident)
        return {"vulnerabilities_found": len(vulns), "details": vulns}

    # ─────────────────────────────────────────────────────────
    #  Default Playbooks
    # ─────────────────────────────────────────────────────────

    def _register_default_playbooks(self):
        """Registriert vordefinierte Standard-Playbooks"""
        playbooks = [
            self._create_ransomware_playbook(),
            self._create_phishing_playbook(),
            self._create_generic_high_sev_playbook(),
            self._create_lateral_movement_playbook(),
        ]
        for pb in playbooks:
            self.store.save_playbook(pb)

    def _make_step(self, name: str, action_type: str, description: str = "",
                   params: Dict = None, conditions: Dict = None,
                   on_success: str = None, on_failure: str = None) -> PlaybookStep:
        s = PlaybookStep(
            name=name, action_type=action_type,
            description=description or name,
            parameters=params or {},
            conditions=conditions or {},
            on_success=on_success, on_failure=on_failure
        )
        return s

    def _create_ransomware_playbook(self) -> Playbook:
        s1 = self._make_step("SIEM Query",       "query_siem",
                              params={"query": "index=endpoint malware=ransomware"})
        s2 = self._make_step("Collect Forensics", "collect_forensics")
        s3 = self._make_step("Network Isolation", "contain",
                              params={"isolate_host": True},
                              conditions={"has_malicious_ioc": True})
        s4 = self._make_step("Create Ticket",    "create_ticket",
                              params={"system": "Jira", "priority": "P1"})
        s5 = self._make_step("Notify SOC",        "notify",
                              params={"channels": ["slack", "email"],
                                      "message": "CRITICAL: Ransomware detected!"})
        s1.on_success = s2.id; s2.on_success = s3.id
        s3.on_success = s4.id; s4.on_success = s5.id

        return Playbook(
            name="Ransomware Response",
            description="Automatisiertes Ransomware Response Playbook",
            trigger_conditions={"min_triage_score": 70},
            steps=[s1, s2, s3, s4, s5],
            applicable_severities=[Severity.CRITICAL, Severity.HIGH],
            mitre_tactics=[MITRETactic.IMPACT]
        )

    def _create_phishing_playbook(self) -> Playbook:
        s1 = self._make_step("Extract Observables", "enrich")
        s2 = self._make_step("Block Malicious URLs",  "contain",
                              conditions={"has_malicious_ioc": True})
        s3 = self._make_step("Create Ticket",        "create_ticket",
                              params={"system": "ServiceNow"})
        s4 = self._make_step("Notify User",           "notify",
                              params={"channels": ["email"],
                                      "message": "Phishing attempt blocked"})
        s1.on_success = s2.id; s2.on_success = s3.id; s3.on_success = s4.id

        return Playbook(
            name="Phishing Response",
            description="Phishing Alert Response Playbook",
            steps=[s1, s2, s3, s4],
            applicable_severities=[Severity.HIGH, Severity.MEDIUM, Severity.LOW],
            mitre_tactics=[MITRETactic.INITIAL_ACCESS]
        )

    def _create_generic_high_sev_playbook(self) -> Playbook:
        s1 = self._make_step("Triage & Enrich",  "enrich")
        s2 = self._make_step("SIEM Correlation",  "query_siem")
        s3 = self._make_step("Create Ticket",     "create_ticket",
                              params={"system": "Jira"})
        s4 = self._make_step("Notify Team",       "notify",
                              params={"channels": ["slack"]})
        s1.on_success = s2.id; s2.on_success = s3.id; s3.on_success = s4.id

        return Playbook(
            name="Generic High Severity",
            description="Standard-Playbook für HIGH/CRITICAL Alerts",
            trigger_conditions={"min_triage_score": 60},
            steps=[s1, s2, s3, s4],
            applicable_severities=[Severity.CRITICAL, Severity.HIGH],
        )

    def _create_lateral_movement_playbook(self) -> Playbook:
        s1 = self._make_step("Forensic Collection", "collect_forensics")
        s2 = self._make_step("Vulnerability Scan",  "vulnerability_scan")
        s3 = self._make_step("Containment",         "contain",
                              params={"isolate_host": True})
        s4 = self._make_step("Ticket & Escalate",   "create_ticket",
                              params={"system": "Jira", "escalate": True})
        s1.on_success = s2.id; s2.on_success = s3.id; s3.on_success = s4.id

        return Playbook(
            name="Lateral Movement Response",
            description="Response auf Lateral Movement Erkennung",
            steps=[s1, s2, s3, s4],
            applicable_severities=[Severity.CRITICAL, Severity.HIGH],
            mitre_tactics=[MITRETactic.LATERAL_MOVEMENT, MITRETactic.PRIVILEGE_ESC]
        )
