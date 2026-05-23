"""
Multi-Agent SOAR - Containment Agent
Führt automatische Containment-Maßnahmen aus
"""
from __future__ import annotations
from datetime import datetime
from typing import Dict, Any, List

from core.base_agent import BaseAgent
from core.models import Incident, IncidentStatus, AgentMessage


class ContainmentAgent(BaseAgent):
    """
    Führt Containment-Aktionen aus:
    - IP-Blockierung (Firewall-Simulation)
    - Domain-Blockierung (DNS-Sinkhole)
    - Host-Isolierung (EDR)
    - Hash-Quarantäne
    - Account-Sperrung
    """

    NAME = "containment_agent"

    # Simulierte Firewall-Blockliste
    _blocked_ips: List[str] = []
    _blocked_domains: List[str] = []
    _quarantined_hashes: List[str] = []
    _isolated_hosts: List[str] = []
    _locked_accounts: List[str] = []

    def __init__(self):
        super().__init__(
            name=self.NAME,
            description="Automatische Containment-Maßnahmen (IPs, Hosts, Hashes)"
        )

    def handle_message(self, message: AgentMessage):
        if message.message_type == "execute_containment":
            incident_id = message.payload.get("incident_id")
            actions     = message.payload.get("actions", [])
            incident    = self.store.get_incident(incident_id)
            if incident:
                self.execute_containment(incident, actions)

    # ─────────────────────────────────────────────────────────
    #  Main Containment
    # ─────────────────────────────────────────────────────────

    def execute_containment(self, incident: Incident,
                             actions: List[str] = None) -> Dict[str, Any]:
        """Führt alle Containment-Aktionen aus"""
        if actions is None:
            # Automatisch aus Observables ableiten
            actions = self._derive_actions(incident)

        results = []
        for action in actions:
            result = self._dispatch(action, incident)
            results.append(result)
            if result["success"]:
                incident.containment_actions.append(action)

        # Status auf CONTAINED setzen wenn Aktionen erfolgreich
        successful = [r for r in results if r["success"]]
        if successful:
            incident.status = IncidentStatus.CONTAINED
            incident.add_timeline_event(
                event_type="containment_executed",
                actor=self.NAME,
                description=f"{len(successful)}/{len(results)} Containment-Aktionen erfolgreich",
                data={"actions": results}
            )
            self.store.update_kpi("containments_executed", increment=True)

        self.store.save_incident(incident)
        self.log_action(
            "CONTAINMENT", f"Incident {incident.id[:8]}",
            {"total": len(results), "success": len(successful)}
        )
        return {"results": results, "successful": len(successful), "total": len(results)}

    def _derive_actions(self, incident: Incident) -> List[str]:
        actions = []
        for obs in incident.observables:
            if not obs.malicious:
                continue
            if obs.type == "ip":
                actions.append(f"block_ip:{obs.value}")
            elif obs.type == "domain":
                actions.append(f"block_domain:{obs.value}")
            elif obs.type in ("md5", "sha256"):
                actions.append(f"quarantine_hash:{obs.value}")
        return actions

    def _dispatch(self, action: str, incident: Incident) -> Dict[str, Any]:
        try:
            if action.startswith("block_ip:"):
                return self.block_ip(action.split(":", 1)[1], incident)
            elif action.startswith("block_domain:"):
                return self.block_domain(action.split(":", 1)[1], incident)
            elif action.startswith("quarantine_hash:"):
                return self.quarantine_hash(action.split(":", 1)[1], incident)
            elif action.startswith("isolate_host:"):
                return self.isolate_host(action.split(":", 1)[1], incident)
            elif action.startswith("lock_account:"):
                return self.lock_account(action.split(":", 1)[1], incident)
            else:
                return {"action": action, "success": False,
                        "error": "Unbekannte Action"}
        except Exception as e:
            return {"action": action, "success": False, "error": str(e)}

    # ─────────────────────────────────────────────────────────
    #  Individual Actions
    # ─────────────────────────────────────────────────────────

    def block_ip(self, ip: str, incident: Incident) -> Dict[str, Any]:
        if ip not in self._blocked_ips:
            self._blocked_ips.append(ip)
        result = {
            "action": f"block_ip:{ip}",
            "success": True,
            "method": "Firewall ACL (simulated)",
            "timestamp": datetime.now().isoformat(),
            "details": {
                "ip": ip,
                "rule_id": f"RULE-{abs(hash(ip)) % 99999:05d}",
                "applied_to": ["perimeter-fw-01", "internal-fw-02"]
            }
        }
        self.log_action("BLOCK_IP", ip)
        return result

    def block_domain(self, domain: str, incident: Incident) -> Dict[str, Any]:
        if domain not in self._blocked_domains:
            self._blocked_domains.append(domain)
        result = {
            "action": f"block_domain:{domain}",
            "success": True,
            "method": "DNS Sinkhole (simulated)",
            "timestamp": datetime.now().isoformat(),
            "details": {
                "domain": domain,
                "sinkhole_ip": "100.64.0.1",
                "applied_to": ["dns-resolver-01", "dns-resolver-02"]
            }
        }
        self.log_action("BLOCK_DOMAIN", domain)
        return result

    def quarantine_hash(self, file_hash: str, incident: Incident) -> Dict[str, Any]:
        if file_hash not in self._quarantined_hashes:
            self._quarantined_hashes.append(file_hash)
        result = {
            "action": f"quarantine_hash:{file_hash}",
            "success": True,
            "method": "EDR Hash Quarantine (simulated)",
            "timestamp": datetime.now().isoformat(),
            "details": {
                "hash": file_hash,
                "affected_endpoints": ["WORKSTATION-01"],
                "files_quarantined": 1
            }
        }
        self.log_action("QUARANTINE_HASH", file_hash[:16])
        return result

    def isolate_host(self, hostname: str, incident: Incident) -> Dict[str, Any]:
        if hostname not in self._isolated_hosts:
            self._isolated_hosts.append(hostname)
        result = {
            "action": f"isolate_host:{hostname}",
            "success": True,
            "method": "EDR Network Isolation (simulated)",
            "timestamp": datetime.now().isoformat(),
            "details": {
                "hostname": hostname,
                "isolation_type": "full_network",
                "management_channel": "preserved",
                "edr_agent": "CrowdStrike-Sim"
            }
        }
        self.log_action("ISOLATE_HOST", hostname)
        return result

    def lock_account(self, account: str, incident: Incident) -> Dict[str, Any]:
        if account not in self._locked_accounts:
            self._locked_accounts.append(account)
        result = {
            "action": f"lock_account:{account}",
            "success": True,
            "method": "Active Directory Account Disable (simulated)",
            "timestamp": datetime.now().isoformat(),
            "details": {
                "account": account,
                "sessions_terminated": True,
                "tokens_revoked": True
            }
        }
        self.log_action("LOCK_ACCOUNT", account)
        return result

    # ─────────────────────────────────────────────────────────
    #  Status
    # ─────────────────────────────────────────────────────────

    def get_containment_status(self) -> Dict[str, Any]:
        return {
            "blocked_ips":        list(self._blocked_ips),
            "blocked_domains":    list(self._blocked_domains),
            "quarantined_hashes": list(self._quarantined_hashes),
            "isolated_hosts":     list(self._isolated_hosts),
            "locked_accounts":    list(self._locked_accounts),
            "total_actions":      (len(self._blocked_ips) + len(self._blocked_domains) +
                                   len(self._quarantined_hashes) + len(self._isolated_hosts))
        }

    def unblock_ip(self, ip: str) -> bool:
        if ip in self._blocked_ips:
            self._blocked_ips.remove(ip)
            self.log_action("UNBLOCK_IP", ip)
            return True
        return False

    def deisolate_host(self, hostname: str) -> bool:
        if hostname in self._isolated_hosts:
            self._isolated_hosts.remove(hostname)
            self.log_action("DEISOLATE", hostname)
            return True
        return False
