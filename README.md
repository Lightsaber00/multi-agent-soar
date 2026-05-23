# 🛡️ Multi-Agent SOAR

> **Security Orchestration, Automation & Response** powered by a multi-agent architecture.  
> Autonomous threat triage, IOC enrichment, incident management, playbook execution, and compliance reporting — all in one CLI-driven system.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Framework](https://img.shields.io/badge/Framework-CrewAI-purple)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

---

## 🏗️ Architecture

```
Alert Input
    │
    ▼
[TriageAgent]          → Severity scoring, MITRE ATT&CK mapping, FP detection
    │
    ▼
[EnrichmentAgent]      → IOC extraction, OSINT, VirusTotal/EXA enrichment
    │
    ▼
[IncidentAgent]        → Incident creation, correlation, SLA monitoring
    │
    ▼
[PlaybookAgent]        → Automated playbook matching & execution
    │
    ▼
[ContainmentAgent]     → IP block, domain sinkhole, host isolation, hash quarantine
    │
    ▼
[NotificationAgent]    → Alerts for CRITICAL/HIGH incidents
    │
    ▼
[ComplianceAgent]      → ISO 27001 / SOC 2 reports, KPI dashboard
```

---

## ✨ Features

| Feature | Details |
|---|---|
| **7 Autonomous Agents** | Triage, Enrichment, Incident, Playbook, Containment, Notification, Compliance |
| **MITRE ATT&CK Mapping** | Automatic TTP tagging per incident |
| **Automated Containment** | Firewall ACL, DNS sinkhole, EDR isolation, AD account lockout |
| **Compliance Reports** | ISO 27001:2022 and SOC 2 Type II |
| **Interactive CLI** | Full menu-driven interface with real-time KPIs |
| **React Dashboard** | Network graph + live SOC dashboard (JSX) |
| **Multi-Tenant** | Per-tenant SLA configs and incident isolation |
| **In-Memory Store** | Thread-safe, replaceable with any DB |

---

## 🚀 Quick Start

```bash
# 1. Repo klonen
git clone https://github.com/<yourname>/multi-agent-soar.git
cd multi-agent-soar

# 2. Virtual Environment
python -m venv .venv && source .venv/bin/activate  # Linux/Mac
# oder: .venvScriptsactivate  # Windows

# 3. Dependencies installieren
pip install -r requirements.txt

# 4. CLI starten
python main.py
```

---

## 📋 Requirements

```
crewai>=0.28.0
langchain>=0.1.0
langchain-community>=0.0.20
langchain-core>=0.1.0
```

---

## 🎮 CLI Menu

```
 Demo starten          – Alle Sample-Alerts verarbeiten
[8] Einzelnen Alert       – Manuell auswählen
[9] Incidents anzeigen    – Mit Timeline & MITRE
[2] Dashboard / KPIs      – MTTR, Automation Rate, Severity
[3] Compliance Report     – ISO 27001 oder SOC 2
[4] Containment Status    – Geblockte IPs, Domains, Hashes
[5] Playbooks anzeigen    – Aktive Playbooks
[6] Incident bearbeiten   – Status, Notizen, Containment
```

---

## 🧩 Agent Overview

### `TriageAgent`
Bewertet eingehende Alerts mit einem Triage-Score (0–100) und filtert False Positives heraus. Mapped TTPs automatisch auf MITRE ATT&CK.

### `EnrichmentAgent`
Extrahiert Observables (IPs, Domains, Hashes) und reichert sie mit Threat-Intel-Quellen an.

### `IncidentAgent`
Erstellt und korreliert Incidents, überwacht SLA-Fristen und verwaltet den Lifecycle.

### `PlaybookAgent`
Matched Incidents auf passende Playbooks und führt diese automatisch aus.

### `ContainmentAgent`
Führt automatische Containment-Aktionen durch:
- `block_ip` → Firewall ACL
- `block_domain` → DNS Sinkhole
- `quarantine_hash` → EDR
- `isolate_host` → Netzwerk-Isolation
- `lock_account` → Active Directory

### `ComplianceAgent`
Generiert ISO 27001:2022 und SOC 2 Type II Reports mit SLA-Compliance-Metriken und MITRE Frequency-Analyse.

---

## 📊 Sample Alerts (built-in)

- Ransomware Activity (CrowdStrike EDR) — CRITICAL
- Phishing Email with Malicious Link — HIGH
- Lateral Movement via Pass-the-Hash (SIEM) — CRITICAL
- Suspicious PowerShell Execution (Defender) — HIGH
- Data Exfiltration via HTTPS (DLP/SIEM) — CRITICAL
- Brute Force on VPN Gateway (Firewall) — MEDIUM

---

## 🔐 Security Note

This project uses **simulated APIs** for containment actions (Firewall, EDR, AD).  
For production use, replace simulation stubs with real API integrations:
- Microsoft Defender XDR API
- CrowdStrike Falcon API
- Active Directory / Entra ID
- Jira / ServiceNow for ticketing

---

## 📄 License

MIT License — see [LICENSE](LICENSE)

---

## 🤝 Contributing

Pull Requests welcome! Please open an issue first for major changes.
