"""
Multi-Agent SOAR - Alert Triage Agent
Bewertet und priorisiert eingehende Alerts automatisch
"""
from __future__ import annotations
import re
from datetime import datetime
from typing import Dict, Any

from core.base_agent import BaseAgent
from core.models import (
    Alert, AlertStatus, Severity, MITRETactic, AgentMessage
)


class TriageAgent(BaseAgent):
    """
    Analysiert Alerts und berechnet:
    - Triage Score (Priorität)
    - False-Positive-Wahrscheinlichkeit
    - MITRE ATT&CK Taktiken
    - Empfohlene Eskalation
    """

    NAME = "triage_agent"

    # Keyword → Score-Beitrag
    SEVERITY_KEYWORDS = {
        "ransomware":        95, "malware":           85, "exploit":          80,
        "lateral movement":  75, "privilege escalation": 75, "exfiltration":  70,
        "c2":                70, "command and control": 70, "backdoor":        80,
        "credential dump":   75, "brute force":        55, "phishing":        60,
        "suspicious":        30, "anomaly":            25, "policy violation": 20,
    }

    # Alert-Quelle → Vertrauensfaktor
    SOURCE_TRUST = {
        "edr":          1.0, "xdr":         1.0, "siem":        0.8,
        "firewall":     0.7, "ids":          0.75, "ips":        0.75,
        "email":        0.6, "cloud":        0.7, "manual":     0.9,
    }

    # MITRE-Mapping (vereinfacht)
    MITRE_KEYWORDS = {
        "phishing":            MITRETactic.INITIAL_ACCESS,
        "exploit":             MITRETactic.INITIAL_ACCESS,
        "powershell":          MITRETactic.EXECUTION,
        "wmi":                 MITRETactic.EXECUTION,
        "persistence":         MITRETactic.PERSISTENCE,
        "scheduled task":      MITRETactic.PERSISTENCE,
        "privilege":           MITRETactic.PRIVILEGE_ESC,
        "uac bypass":          MITRETactic.DEFENSE_EVASION,
        "credential":          MITRETactic.CREDENTIAL_ACCESS,
        "mimikatz":            MITRETactic.CREDENTIAL_ACCESS,
        "lateral":             MITRETactic.LATERAL_MOVEMENT,
        "pass the hash":       MITRETactic.LATERAL_MOVEMENT,
        "exfiltration":        MITRETactic.EXFILTRATION,
        "c2":                  MITRETactic.C2,
        "command and control": MITRETactic.C2,
        "ransomware":          MITRETactic.IMPACT,
        "wiper":               MITRETactic.IMPACT,
    }

    def __init__(self):
        super().__init__(
            name=self.NAME,
            description="Automatische Alert-Triage, Scoring und MITRE-Mapping"
        )

    def handle_message(self, message: AgentMessage):
        if message.message_type == "triage_alert":
            alert_id = message.payload.get("alert_id")
            alert = self.store.get_alert(alert_id)
            if alert:
                self._triage(alert)
                # Nächsten Agenten informieren
                self.send(
                    recipient="enrichment_agent",
                    message_type="enrich_alert",
                    payload={"alert_id": alert_id},
                    correlation_id=message.correlation_id
                )

    # ─────────────────────────────────────────────────────────
    #  Triage Logik
    # ─────────────────────────────────────────────────────────

    def triage_alert(self, alert: Alert) -> Alert:
        """Öffentliche Methode für synchronen Aufruf"""
        return self._triage(alert)

    def _triage(self, alert: Alert) -> Alert:
        text = f"{alert.title} {alert.description}".lower()

        # 1. Basis-Score aus Severity
        base_scores = {
            Severity.CRITICAL: 90, Severity.HIGH:   70,
            Severity.MEDIUM:   50, Severity.LOW:    25, Severity.INFO: 10
        }
        score = base_scores.get(alert.severity, 50)

        # 2. Keyword-Scoring
        keyword_bonus = 0
        for kw, bonus in self.SEVERITY_KEYWORDS.items():
            if kw in text:
                keyword_bonus = max(keyword_bonus, bonus)
        score = (score + keyword_bonus) / 2

        # 3. Quellen-Vertrauen
        source_lower = alert.source.lower()
        trust = 0.7
        for src, factor in self.SOURCE_TRUST.items():
            if src in source_lower:
                trust = factor
                break
        score = score * trust

        # 4. False-Positive-Score
        fp_score = self._calc_fp_score(alert, text)
        score = score * (1.0 - fp_score * 0.5)  # FP reduziert Score

        # 5. MITRE ATT&CK Mapping
        tactics = set()
        for kw, tactic in self.MITRE_KEYWORDS.items():
            if kw in text:
                tactics.add(tactic)
        alert.mitre_tactics = list(tactics)

        # 6. Schwellenwert-basierte Severity-Anpassung
        if score >= 85 and alert.severity not in (Severity.CRITICAL,):
            alert.severity = Severity.CRITICAL
        elif score >= 65 and alert.severity == Severity.LOW:
            alert.severity = Severity.MEDIUM

        alert.triage_score       = round(score, 2)
        alert.false_positive_score = round(fp_score, 2)
        alert.status             = AlertStatus.IN_PROGRESS
        alert.updated_at         = datetime.now()

        self.store.save_alert(alert)
        self.log_action(
            "TRIAGE", f"Alert {alert.id[:8]}",
            {"score": score, "fp": fp_score, "tactics": len(tactics)}
        )
        return alert

    def _calc_fp_score(self, alert: Alert, text: str) -> float:
        """Berechnet False-Positive-Wahrscheinlichkeit (0.0 - 1.0)"""
        score = 0.2  # Basis-FP-Rate

        fp_indicators = [
            "test", "scan", "scheduled", "backup", "maintenance",
            "allowed", "whitelist", "known good", "admin tool"
        ]
        for ind in fp_indicators:
            if ind in text:
                score += 0.1

        # Niedrige Severity → höhere FP-Wahrscheinlichkeit
        if alert.severity in (Severity.LOW, Severity.INFO):
            score += 0.2

        # Observable-Anreicherung vorhanden → niedrigere FP
        if alert.observables:
            score -= 0.1

        return min(max(score, 0.0), 1.0)

    def bulk_triage(self, alerts: list) -> list:
        """Triagiert eine Liste von Alerts"""
        results = []
        for alert in alerts:
            results.append(self._triage(alert))
        return sorted(results, key=lambda a: a.triage_score, reverse=True)
