"""
Multi-Agent SOAR - Enrichment Agent
Reichert Alerts mit Threat Intelligence an (simuliert VirusTotal, MISP, etc.)
"""
from __future__ import annotations
import hashlib
import ipaddress
import re
import time
from datetime import datetime
from typing import Dict, Any, List, Optional

from core.base_agent import BaseAgent
from core.models import Alert, Observable, AgentMessage


# ─────────────────────────────────────────────────────────────
#  Simulated Threat Intel Databases
# ─────────────────────────────────────────────────────────────

KNOWN_MALICIOUS_IPS = {
    "185.220.101.45": {"score": 95, "tags": ["tor-exit", "c2"], "country": "DE"},
    "91.241.19.47":   {"score": 88, "tags": ["ransomware", "c2"], "country": "RU"},
    "198.51.100.99":  {"score": 72, "tags": ["scanner", "brute-force"], "country": "CN"},
    "203.0.113.42":   {"score": 65, "tags": ["spam", "phishing"], "country": "NG"},
}

KNOWN_MALICIOUS_DOMAINS = {
    "evil-malware.ru":      {"score": 98, "tags": ["malware-distribution", "c2"]},
    "phish-bank.tk":        {"score": 90, "tags": ["phishing", "credential-theft"]},
    "ransomware-cdn.xyz":   {"score": 95, "tags": ["ransomware", "c2"]},
    "update-windows-now.com": {"score": 78, "tags": ["typosquat", "malware"]},
}

KNOWN_MALICIOUS_HASHES = {
    "d41d8cd98f00b204e9800998ecf8427e": {"score": 85, "tags": ["known-malware", "trojan"], "name": "TrojanSpy.Win32.Agent"},
    "5f4dcc3b5aa765d61d8327deb882cf99": {"score": 92, "tags": ["ransomware"], "name": "Ransomware.Ryuk"},
}

VULNERABILITY_DB = {
    "CVE-2021-44228": {"cvss": 10.0, "name": "Log4Shell", "vendor": "Apache", "patch": "2.15.0"},
    "CVE-2021-34527": {"cvss": 8.8, "name": "PrintNightmare", "vendor": "Microsoft", "patch": "KB5004945"},
    "CVE-2020-1472":  {"cvss": 10.0, "name": "ZeroLogon", "vendor": "Microsoft", "patch": "KB4565945"},
    "CVE-2023-23397": {"cvss": 9.8, "name": "Outlook NTLM Leak", "vendor": "Microsoft", "patch": "KB5023706"},
}


class EnrichmentAgent(BaseAgent):
    """
    Reichert Alerts an:
    - IP-Reputation (simuliert VirusTotal / AbuseIPDB)
    - Domain-Reputation (simuliert URLVoid / MISP)
    - Hash-Analyse (simuliert VirusTotal / MalwareBazaar)
    - CVE/Vulnerability Lookup
    - GeoIP-Informationen
    """

    NAME = "enrichment_agent"

    # Regex patterns für Observable-Extraktion
    IP_PATTERN     = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    DOMAIN_PATTERN = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|tk|xyz|info|biz|co)\b')
    MD5_PATTERN    = re.compile(r'\b[a-fA-F0-9]{32}\b')
    SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')
    CVE_PATTERN    = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
    URL_PATTERN    = re.compile(r'https?://[^\s]+')

    def __init__(self):
        super().__init__(
            name=self.NAME,
            description="IOC-Extraktion und Threat-Intelligence-Anreicherung"
        )

    def handle_message(self, message: AgentMessage):
        if message.message_type == "enrich_alert":
            alert_id = message.payload.get("alert_id")
            alert = self.store.get_alert(alert_id)
            if alert:
                self.enrich_alert(alert)
                # Nächsten Agenten informieren
                self.send(
                    recipient="incident_agent",
                    message_type="evaluate_alert",
                    payload={"alert_id": alert_id},
                    correlation_id=message.correlation_id
                )

    # ─────────────────────────────────────────────────────────
    #  Main Enrichment
    # ─────────────────────────────────────────────────────────

    def enrich_alert(self, alert: Alert) -> Alert:
        """Vollständige Anreicherung eines Alerts"""
        text = f"{alert.title} {alert.description} {str(alert.raw_data)}"

        # IOC-Extraktion
        observables = self._extract_observables(text)

        # Anreicherung jedes Observables
        for obs in observables:
            self._enrich_observable(obs)

        alert.observables = observables
        alert.enrichment_data = self._build_enrichment_summary(observables, text)
        alert.updated_at = datetime.now()

        self.store.save_alert(alert)
        self.log_action(
            "ENRICHMENT", f"Alert {alert.id[:8]}",
            {"observables": len(observables),
             "malicious": sum(1 for o in observables if o.malicious)}
        )
        return alert

    # ─────────────────────────────────────────────────────────
    #  Observable Extraction
    # ─────────────────────────────────────────────────────────

    def _extract_observables(self, text: str) -> List[Observable]:
        observables = []
        seen = set()

        # IPs
        for m in self.IP_PATTERN.finditer(text):
            val = m.group()
            if val not in seen and self._is_public_ip(val):
                seen.add(val)
                observables.append(Observable(type="ip", value=val))

        # Domains
        for m in self.DOMAIN_PATTERN.finditer(text):
            val = m.group().lower()
            if val not in seen and not val.endswith(".exe"):
                seen.add(val)
                observables.append(Observable(type="domain", value=val))

        # MD5 Hashes
        for m in self.MD5_PATTERN.finditer(text):
            val = m.group().lower()
            if val not in seen:
                seen.add(val)
                observables.append(Observable(type="md5", value=val))

        # SHA256 Hashes
        for m in self.SHA256_PATTERN.finditer(text):
            val = m.group().lower()
            if val not in seen:
                seen.add(val)
                observables.append(Observable(type="sha256", value=val))

        # CVEs
        for m in self.CVE_PATTERN.finditer(text):
            val = m.group().upper()
            if val not in seen:
                seen.add(val)
                observables.append(Observable(type="cve", value=val))

        # URLs
        for m in self.URL_PATTERN.finditer(text):
            val = m.group()
            if val not in seen:
                seen.add(val)
                observables.append(Observable(type="url", value=val))

        return observables

    def _is_public_ip(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            return not (ip.is_private or ip.is_loopback or ip.is_reserved)
        except ValueError:
            return False

    # ─────────────────────────────────────────────────────────
    #  Observable Enrichment (simulated TI)
    # ─────────────────────────────────────────────────────────

    def _enrich_observable(self, obs: Observable):
        if obs.type == "ip":
            self._enrich_ip(obs)
        elif obs.type == "domain":
            self._enrich_domain(obs)
        elif obs.type in ("md5", "sha256"):
            self._enrich_hash(obs)
        elif obs.type == "cve":
            self._enrich_cve(obs)
        elif obs.type == "url":
            self._enrich_url(obs)
        obs.enriched = True

    def _enrich_ip(self, obs: Observable):
        data = KNOWN_MALICIOUS_IPS.get(obs.value)
        if data:
            obs.threat_score = data["score"]
            obs.malicious    = True
            obs.tags         = data["tags"]
            obs.sources      = ["VirusTotal-Sim", "AbuseIPDB-Sim"]
            obs.metadata     = {"country": data.get("country", "Unknown"),
                                 "asn": "AS12345", "isp": "Simulated ISP"}
        else:
            obs.threat_score = 5.0
            obs.metadata     = {"country": "Unknown", "resolved": True}
            obs.sources      = ["GeoIP-Sim"]

    def _enrich_domain(self, obs: Observable):
        data = KNOWN_MALICIOUS_DOMAINS.get(obs.value)
        if data:
            obs.threat_score = data["score"]
            obs.malicious    = True
            obs.tags         = data["tags"]
            obs.sources      = ["URLVoid-Sim", "MISP-Sim"]
            obs.metadata     = {"registrar": "UNKNOWN", "age_days": 3,
                                 "mx_records": False, "whois": "hidden"}
        else:
            obs.threat_score = 10.0
            obs.sources      = ["URLVoid-Sim"]

    def _enrich_hash(self, obs: Observable):
        data = KNOWN_MALICIOUS_HASHES.get(obs.value)
        if data:
            obs.threat_score = data["score"]
            obs.malicious    = True
            obs.tags         = data["tags"]
            obs.sources      = ["VirusTotal-Sim", "MalwareBazaar-Sim"]
            obs.metadata     = {"malware_name": data.get("name", "Unknown"),
                                 "detection_ratio": "65/72", "first_seen": "2023-01-15"}
        else:
            obs.threat_score = 0.0
            obs.sources      = ["VirusTotal-Sim"]
            obs.metadata     = {"detection_ratio": "0/72", "clean": True}

    def _enrich_cve(self, obs: Observable):
        data = VULNERABILITY_DB.get(obs.value)
        if data:
            obs.threat_score = data["cvss"] * 10
            obs.malicious    = data["cvss"] >= 7.0
            obs.sources      = ["NVD", "MITRE"]
            obs.metadata     = data
            obs.tags         = ["vulnerability", f"cvss-{data['cvss']}"]
        else:
            obs.sources      = ["NVD"]
            obs.metadata     = {"note": "CVE not in local database"}

    def _enrich_url(self, obs: Observable):
        # Einfache Heuristik
        suspicious_tlds = [".ru", ".tk", ".xyz", ".pw", ".cc"]
        score = 10.0
        tags  = []
        if any(tld in obs.value.lower() for tld in suspicious_tlds):
            score += 30
            tags.append("suspicious-tld")
        if "login" in obs.value.lower() or "secure" in obs.value.lower():
            score += 20
            tags.append("credential-phishing-indicator")

        obs.threat_score = min(score, 100)
        obs.malicious    = score > 50
        obs.tags         = tags
        obs.sources      = ["URLScan-Sim"]

    # ─────────────────────────────────────────────────────────
    #  Summary
    # ─────────────────────────────────────────────────────────

    def _build_enrichment_summary(self, observables: List[Observable],
                                   text: str) -> Dict[str, Any]:
        malicious = [o for o in observables if o.malicious]
        return {
            "total_observables":    len(observables),
            "malicious_count":      len(malicious),
            "max_threat_score":     max((o.threat_score for o in observables), default=0),
            "malicious_ips":        [o.value for o in malicious if o.type == "ip"],
            "malicious_domains":    [o.value for o in malicious if o.type == "domain"],
            "malicious_hashes":     [o.value for o in malicious
                                     if o.type in ("md5", "sha256")],
            "vulnerabilities":      [o.value for o in observables if o.type == "cve"],
            "enrichment_sources":   list({s for o in observables for s in o.sources}),
            "enriched_at":          datetime.now().isoformat(),
        }
