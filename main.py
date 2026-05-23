#!/usr/bin/env python3
"""
Multi-Agent SOAR - Interaktive CLI
Vollständige Kommandozeilen-Oberfläche für das SOAR System
"""
import json
import sys
import os
import time
import random
from datetime import datetime
from typing import Dict, Any, List, Optional

# Path setup
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from orchestrator import SOAROrchestrator
from core.models import (
    Alert, Severity, AlertStatus, IncidentStatus
)


# ─────────────────────────────────────────────────────────────
#  Terminal Colors
# ─────────────────────────────────────────────────────────────

class C:
    RED    = "\033[91m"; YELLOW = "\033[93m"; GREEN  = "\033[92m"
    BLUE   = "\033[94m"; CYAN   = "\033[96m"; PURPLE = "\033[95m"
    BOLD   = "\033[1m";  DIM    = "\033[2m";  RESET  = "\033[0m"
    WHITE  = "\033[97m"; ORANGE = "\033[33m"

def colored(text: str, *colors: str) -> str:
    return "".join(colors) + str(text) + C.RESET

def sev_color(sev: str) -> str:
    return {
        "critical": C.RED + C.BOLD, "high": C.RED,
        "medium": C.YELLOW, "low": C.CYAN, "info": C.DIM
    }.get(sev.lower(), C.WHITE)


# ─────────────────────────────────────────────────────────────
#  Sample Alert Generator
# ─────────────────────────────────────────────────────────────

SAMPLE_ALERTS = [
    {
        "title": "Ransomware Activity Detected on WORKSTATION-01",
        "description": "EDR detected ransomware behavior: mass file encryption, vssadmin delete shadows. "
                       "Source IP: 185.220.101.45. Hash: d41d8cd98f00b204e9800998ecf8427e. "
                       "CVE-2021-44228 exploitation attempt detected.",
        "source": "CrowdStrike EDR",
        "severity": Severity.CRITICAL
    },
    {
        "title": "Phishing Email with Malicious Link Detected",
        "description": "Phishing email received from attacker@phish-bank.tk with link to "
                       "http://update-windows-now.com/login. Multiple users targeted. "
                       "Credential theft indicators present.",
        "source": "Email Gateway",
        "severity": Severity.HIGH
    },
    {
        "title": "Lateral Movement via Pass-the-Hash Attack",
        "description": "SIEM detected lateral movement: mimikatz usage, pass-the-hash from "
                       "WORKSTATION-01 to SERVER-02. Privilege escalation via UAC bypass. "
                       "External C2 connection to 91.241.19.47:443 observed.",
        "source": "SIEM",
        "severity": Severity.CRITICAL
    },
    {
        "title": "Suspicious PowerShell Execution Detected",
        "description": "Encoded PowerShell command executed from Word macro. "
                       "Persistence via scheduled task created. "
                       "Downloads from 198.51.100.99/payload.exe detected.",
        "source": "Windows Defender",
        "severity": Severity.HIGH
    },
    {
        "title": "Data Exfiltration Attempt via HTTPS",
        "description": "Large data transfer (2.3GB) to ransomware-cdn.xyz detected. "
                       "DLP triggered on sensitive file access. Command and control "
                       "communication pattern identified. CVE-2023-23397 exploit used.",
        "source": "DLP / SIEM",
        "severity": Severity.CRITICAL
    },
    {
        "title": "Brute Force Attack on VPN Gateway",
        "description": "2000 failed authentication attempts from 203.0.113.42 in 10 minutes. "
                       "3 successful logins from suspicious location. Policy violation triggered.",
        "source": "Firewall",
        "severity": Severity.MEDIUM
    },
    {
        "title": "Scheduled Scan Result - Low Risk",
        "description": "Routine compliance scan completed. Some minor policy violations found. "
                       "Known good admin tool used. Whitelist validated.",
        "source": "Vulnerability Scanner",
        "severity": Severity.LOW
    },
]


# ─────────────────────────────────────────────────────────────
#  CLI Helpers
# ─────────────────────────────────────────────────────────────

def print_header():
    print(colored("""
╔══════════════════════════════════════════════════════════════════╗
║   ███████╗ ██████╗  █████╗ ██████╗                               ║
║   ██╔════╝██╔═══██╗██╔══██╗██╔══██╗                              ║
║   ███████╗██║   ██║███████║██████╔╝  Multi-Agent                 ║
║   ╚════██║██║   ██║██╔══██║██╔══██╗  Security Orchestration     ║
║   ███████║╚██████╔╝██║  ██║██║  ██║  Automation & Response      ║
║   ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝                             ║
╚══════════════════════════════════════════════════════════════════╝
""", C.CYAN, C.BOLD))
    print(colored("  Agenten: Triage | Enrichment | Incident | Playbook | Containment | Compliance\n",
                  C.DIM))

def print_menu():
    print(colored("\n══════════ HAUPTMENÜ ══════════", C.CYAN, C.BOLD))
    options = [
        ("1", "Demo starten",             "Alle Sample-Alerts verarbeiten"),
        ("2", "Einzelnen Alert einspelen", "Einen Alert manuell auswählen"),
        ("3", "Incidents anzeigen",        "Alle Incidents mit Details"),
        ("4", "Dashboard / KPIs",          "Metriken und Statistiken"),
        ("5", "Compliance Report",         "ISO 27001 oder SOC 2 Report"),
        ("6", "Containment Status",        "Geblockte IPs, Domains, Hashes"),
        ("7", "Playbooks anzeigen",        "Aktive Playbooks"),
        ("8", "Incident bearbeiten",       "Status, Notizen, Containment"),
        ("9", "Beenden",                   ""),
    ]
    for num, name, desc in options:
        desc_str = colored(f"  {desc}", C.DIM) if desc else ""
        print(f"  {colored(f'[{num}]', C.YELLOW, C.BOLD)} {colored(name, C.WHITE)}{desc_str}")

def separator(char="─", width=66, color=C.DIM):
    print(colored(char * width, color))

def print_alert_summary(alert: Dict):
    sev = alert.get("severity", "")
    col = sev_color(sev)
    print(f"\n  {colored('Alert:', C.BOLD)} {alert.get('title', '')[:60]}")
    print(f"  Severity:    {colored(sev.upper(), col)}")
    print(f"  Quelle:      {alert.get('source', '')}")
    triage_str = f"{alert.get('triage_score', 0):.1f}"
    print(f"  Triage:      {colored(triage_str, C.CYAN)}/100  "
          f"FP: {alert.get('false_positive_score', 0):.0%}")
    obs = alert.get("observables", [])
    mal = sum(1 for o in obs if o.get("malicious"))
    if obs:
        print(f"  IOCs:        {len(obs)} ({colored(str(mal) + ' malicious', C.RED if mal else C.GREEN)})")

def print_incident_summary(inc: Dict):
    sev = inc.get("severity", "")
    col = sev_color(sev)
    status = inc.get("status", "")
    print(f"\n  {colored('▶ Incident:', C.BOLD, C.YELLOW)} [{colored(sev.upper(), col)}] "
          f"{inc.get('title', '')[:55]}")
    print(f"  ID: {colored(inc.get('id', '')[:8], C.CYAN)}  "
          f"Status: {colored(status, C.GREEN if status == 'closed' else C.YELLOW)}  "
          f"Alerts: {len(inc.get('alert_ids', []))}")
    tactics = inc.get("mitre_tactics", [])
    if tactics:
        short_tactics = [t.split(" - ")[1] if " - " in t else t for t in tactics[:3]]
        print(f"  MITRE:  {colored(', '.join(short_tactics), C.PURPLE)}")
    pbs = inc.get("playbooks_executed", [])
    tl  = inc.get("timeline", [])
    print(f"  Playbooks: {len(pbs)}  |  Timeline: {len(tl)} Events")
    if inc.get("sla_breach"):
        print(f"  {colored('⚠ SLA VERLETZT!', C.RED, C.BOLD)}")

def progress_bar(label: str, duration: float = 0.8):
    steps = 20
    sys.stdout.write(f"  {label}: [")
    sys.stdout.flush()
    for i in range(steps):
        time.sleep(duration / steps)
        sys.stdout.write("█")
        sys.stdout.flush()
    sys.stdout.write("] ✓\n")
    sys.stdout.flush()


# ─────────────────────────────────────────────────────────────
#  CLI Screens
# ─────────────────────────────────────────────────────────────

def screen_demo(soar: SOAROrchestrator):
    print(colored("\n\n🚀 DEMO MODUS - Verarbeite alle Sample-Alerts\n", C.CYAN, C.BOLD))
    separator("═")

    results = []
    for i, sample in enumerate(SAMPLE_ALERTS, 1):
        alert = Alert(
            title=sample["title"],
            description=sample["description"],
            source=sample["source"],
            severity=sample["severity"],
            tenant_id="default",
            raw_data=sample
        )
        print(colored(f"\n[{i}/{len(SAMPLE_ALERTS)}] Verarbeite Alert...", C.YELLOW, C.BOLD))
        progress_bar("Pipeline", 0.3)
        result = soar.ingest_alert(alert)
        print_alert_summary(result["alert"])
        if result["incident"]:
            print_incident_summary(result["incident"])
        results.append(result)

    separator("═")
    print(colored(f"\n✅ Demo abgeschlossen: {len(SAMPLE_ALERTS)} Alerts verarbeitet", C.GREEN, C.BOLD))
    incidents = [r["incident"] for r in results if r["incident"]]
    print(f"   Incidents erstellt: {colored(str(len(incidents)), C.YELLOW)}")
    input(colored("\n  [Enter] zurück zum Menü...", C.DIM))

def screen_single_alert(soar: SOAROrchestrator):
    print(colored("\n\n📥 ALERT EINSPELEN\n", C.CYAN, C.BOLD))
    for i, s in enumerate(SAMPLE_ALERTS, 1):
        col = sev_color(s["severity"].value)
        sev_upper = s["severity"].value.upper()
        num_str = "[" + str(i) + "]"
        print("  " + colored(num_str, C.YELLOW) + " " + colored("[" + sev_upper + "]", col) + " " + s["title"][:55])
    print(colored("\n  [0] Eigenen Alert eingeben", C.DIM))
    choice = input(colored("\n  Auswahl: ", C.CYAN)).strip()

    if choice == "0":
        title  = input("  Titel: ").strip() or "Custom Alert"
        desc   = input("  Beschreibung: ").strip() or "Suspicious activity"
        source = input("  Quelle: ").strip() or "Custom"
        sev_in = input("  Severity (critical/high/medium/low): ").strip().lower()
        try:
            sev = Severity(sev_in)
        except ValueError:
            sev = Severity.MEDIUM
        sample = {"title": title, "description": desc, "source": source, "severity": sev}
    else:
        try:
            idx = int(choice) - 1
            s = SAMPLE_ALERTS[idx]
            sample = s
        except (ValueError, IndexError):
            print(colored("  Ungültige Auswahl.", C.RED))
            return

    alert = Alert(
        title=sample["title"],
        description=sample["description"],
        source=sample["source"],
        severity=sample["severity"],
        tenant_id="default",
        raw_data=sample
    )

    print(colored("\n  Verarbeite...", C.YELLOW))
    progress_bar("Triage", 0.4)
    progress_bar("Enrichment", 0.5)
    progress_bar("Incident Management", 0.3)
    progress_bar("Playbook Execution", 0.6)

    result = soar.ingest_alert(alert)
    separator()
    print_alert_summary(result["alert"])
    if result["incident"]:
        print_incident_summary(result["incident"])
        pbs = result.get("playbooks", [])
        if pbs:
            print(colored(f"\n  Playbooks ({len(pbs)}):", C.BOLD))
            for pb in pbs:
                status_col = C.GREEN if pb["status"] == "completed" else C.RED
                print(f"    • {colored(pb['status'].upper(), status_col)} "
                      f"- {pb['steps']} Steps ausgeführt")
    else:
        print(colored("\n  ℹ  Kein Incident erstellt (False Positive oder niedriger Score)", C.DIM))

    input(colored("\n  [Enter] zurück zum Menü...", C.DIM))

def screen_incidents(soar: SOAROrchestrator):
    print(colored("\n\n📋 INCIDENT ÜBERSICHT\n", C.CYAN, C.BOLD))
    incidents = soar.get_incidents(limit=20)
    if not incidents:
        print(colored("  Keine Incidents vorhanden. Bitte zuerst Demo starten.", C.DIM))
        input(colored("  [Enter] zurück...", C.DIM))
        return

    for i, inc in enumerate(incidents, 1):
        sev = inc.severity.value
        col = sev_color(sev)
        status_col = C.GREEN if inc.status == IncidentStatus.CLOSED else C.YELLOW
        print(f"\n  {colored(str(i), C.CYAN, C.BOLD)}. {colored(inc.title[:58], C.WHITE)}")
        print(f"     ID: {colored(inc.id[:8], C.DIM)}  "
              f"Sev: {colored(sev.upper(), col)}  "
              f"Status: {colored(inc.status.value, status_col)}")
        if inc.mitre_tactics:
            t = [t.value.split(" - ")[1] for t in inc.mitre_tactics[:2]]
            print(f"     MITRE: {colored(', '.join(t), C.PURPLE)}")

    # Detail-Ansicht
    print(colored("\n  Incident-Nr. für Details eingeben (oder Enter für Menü):", C.DIM))
    choice = input("  > ").strip()
    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(incidents):
            screen_incident_detail(incidents[idx])

def screen_incident_detail(incident):
    """Zeigt detaillierte Incident-Ansicht"""
    print(colored(f"\n\n{'═'*66}", C.CYAN))
    print(colored(f"  INCIDENT DETAIL: {incident.id[:8]}", C.CYAN, C.BOLD))
    print(colored(f"{'═'*66}", C.CYAN))

    sev_col = sev_color(incident.severity.value)
    print(f"\n  {colored('Titel:', C.BOLD)}    {incident.title}")
    print(f"  {colored('Severity:', C.BOLD)}  {colored(incident.severity.value.upper(), sev_col)}")
    print(f"  {colored('Status:', C.BOLD)}    {colored(incident.status.value, C.YELLOW)}")
    print(f"  {colored('Erstellt:', C.BOLD)}  {incident.created_at.strftime('%Y-%m-%d %H:%M')}")
    if incident.sla_deadline:
        breach = "⚠ VERLETZT" if incident.sla_breach else "✓ OK"
        print(f"  {colored('SLA:', C.BOLD)}       {incident.sla_deadline.strftime('%Y-%m-%d %H:%M')} "
              f"[{colored(breach, C.RED if incident.sla_breach else C.GREEN)}]")

    # MITRE
    if incident.mitre_tactics:
        print(colored("\n  MITRE ATT&CK:", C.BOLD))
        for t in incident.mitre_tactics:
            print(f"    {colored('▸', C.PURPLE)} {t.value}")

    # Observables
    if incident.observables:
        mal = [o for o in incident.observables if o.malicious]
        print(colored(f"\n  IOCs ({len(incident.observables)}, {len(mal)} malicious):", C.BOLD))
        for obs in incident.observables[:8]:
            col = C.RED if obs.malicious else C.DIM
            score_str = f"{obs.threat_score:.0f}" if obs.threat_score else "—"
            print(f"    {colored('✗' if obs.malicious else '·', col)} "
                  f"[{obs.type:8s}] {colored(obs.value[:40], col)}  "
                  f"Score: {score_str}")

    # Timeline
    if incident.timeline:
        print(colored(f"\n  Timeline ({len(incident.timeline)} Events):", C.BOLD))
        for event in incident.timeline[-6:]:
            ts = datetime.fromisoformat(event.timestamp.isoformat()).strftime("%H:%M:%S")
            print(f"    {colored(ts, C.DIM)} {colored(event.event_type, C.CYAN):25s} "
                  f"{colored(event.actor, C.YELLOW):20s} {event.description[:35]}")

    # Forensics
    if incident.forensic_artifacts:
        print(colored(f"\n  Forensic Artifacts: {len(incident.forensic_artifacts)}", C.BOLD))
        for a in incident.forensic_artifacts[:3]:
            print(f"    • {a.get('type', '')} @ {a.get('host', '')}")

    # Vulnerabilities
    if incident.vulnerabilities:
        print(colored(f"\n  Vulnerabilities:", C.BOLD))
        for v in incident.vulnerabilities[:3]:
            print(f"    • {colored(v.get('cve', ''), C.RED)} CVSS:{v.get('cvss', '?')} "
                  f"- {v.get('name', '')}")

    # Notes
    if incident.notes:
        print(colored("\n  Notizen:", C.BOLD))
        for line in incident.notes.strip().split("\n")[-3:]:
            print(f"    {colored(line, C.DIM)}")

    input(colored("\n  [Enter] zurück...", C.DIM))

def screen_dashboard(soar: SOAROrchestrator):
    print(colored("\n\n📊 DASHBOARD & KPI METRIKEN\n", C.CYAN, C.BOLD))
    dash = soar.get_dashboard()
    sep = dash.get("summary", {})

    print(colored("  ┌──────────────────────────────────────────────┐", C.CYAN))
    print(colored("  │              ZUSAMMENFASSUNG                  │", C.CYAN))
    print(colored("  └──────────────────────────────────────────────┘", C.CYAN))

    metrics = [
        ("Gesamt Alerts",      sep.get("total_alerts", 0),         C.WHITE),
        ("Gesamt Incidents",   sep.get("total_incidents", 0),       C.WHITE),
        ("Offene Incidents",   sep.get("open_incidents", 0),        C.YELLOW),
        ("Geschlossene",       sep.get("closed_incidents", 0),      C.GREEN),
        ("SLA Verletzungen",   sep.get("sla_breaches", 0),          C.RED),
        ("Playbooks",          sep.get("playbooks_executed", 0),    C.CYAN),
        ("Containments",       sep.get("containments", 0),          C.PURPLE),
        ("False Positives",    sep.get("false_positives", 0),       C.DIM),
        ("Ø MTTR (min)",       sep.get("mttr_minutes", 0),          C.CYAN),
        ("Automation Rate",    f"{sep.get('automation_rate_pct', 0)}%", C.GREEN),
    ]

    for label, value, col in metrics:
        bar = "█" * min(int(str(value).replace("%", "").replace(".", "")), 30) if isinstance(value, (int, float)) else ""
        print(f"  {label:<22} {colored(str(value), col, C.BOLD):>8}  {colored(bar[:25], col, C.DIM)}")

    # Severity Verteilung
    print(colored("\n  Incidents nach Severity:", C.BOLD))
    sev_dist = dash.get("severity_distribution", {})
    for sev, count in sev_dist.items():
        if count > 0:
            col = sev_color(sev)
            bar = "█" * count
            print(f"  {sev.upper():<12} {colored(f'{count:>3}', col)} {colored(bar[:30], col, C.DIM)}")

    # MITRE
    print(colored("\n  Top MITRE ATT&CK Taktiken:", C.BOLD))
    for tactic, count in list(dash.get("mitre_frequency", {}).items())[:6]:
        bar = "█" * count
        print(f"  {tactic[:25]:<28} {colored(str(count), C.PURPLE)} "
              f"{colored(bar[:20], C.PURPLE, C.DIM)}")

    # Trend
    print(colored("\n  Incident-Trend (letzte 7 Tage):", C.BOLD))
    for entry in dash.get("daily_trend", []):
        date = entry["date"]
        count = entry["incidents"]
        bar = "█" * count
        print(f"  {date}  {colored(f'{count:>3}', C.CYAN)}  {colored(bar[:30], C.CYAN, C.DIM)}")

    input(colored("\n  [Enter] zurück zum Menü...", C.DIM))

def screen_compliance(soar: SOAROrchestrator):
    print(colored("\n\n📜 COMPLIANCE REPORT\n", C.CYAN, C.BOLD))
    print(f"  {colored('[1]', C.YELLOW)} ISO 27001:2022")
    print(f"  {colored('[2]', C.YELLOW)} SOC 2 Type II")
    choice = input(colored("\n  Framework auswählen: ", C.CYAN)).strip()

    fw = "ISO27001" if choice == "1" else "SOC2"
    report = soar.get_compliance_report(fw)

    print(colored(f"\n  ════════ {report.get('framework', fw)} Report ════════\n", C.CYAN, C.BOLD))
    print(f"  Zeitraum: {report.get('report_period')}")
    print(f"  Erstellt: {colored(report.get('generated_at', '')[:19], C.DIM)}")

    if "clauses" in report:
        print(colored("\n  ISO 27001 Kontrollen:", C.BOLD))
        for clause, data in report["clauses"].items():
            status = data.get("status", "")
            col = C.GREEN if "Erfüllt" in status else C.YELLOW
            print(f"  {colored('✓' if 'Erfüllt' in status else '⚠', col)} "
                  f"{clause:<35} {colored(status, col)}")
            print(f"    {colored(data.get('evidence', '')[:60], C.DIM)}")

    if "trust_criteria" in report:
        print(colored("\n  SOC 2 Trust Service Criteria:", C.BOLD))
        for crit, data in report["trust_criteria"].items():
            status = data.get("status", "")
            col = C.GREEN if status == "Compliant" else C.YELLOW
            print(f"  {colored('✓' if status == 'Compliant' else '⚠', col)} "
                  f"{crit:<25} {colored(status, col)}")
            for ctrl in data.get("controls", [])[:2]:
                print(f"    {colored('·', C.DIM)} {ctrl[:65]}")

    if "metrics" in report:
        print(colored("\n  Metriken:", C.BOLD))
        for k, v in report["metrics"].items():
            print(f"  {k.replace('_', ' ').title():<35} {colored(str(v), C.CYAN)}")

    if "recommendations" in report:
        print(colored("\n  Empfehlungen:", C.BOLD))
        for rec in report["recommendations"]:
            print(f"  {colored('→', C.YELLOW)} {rec}")

    input(colored("\n  [Enter] zurück zum Menü...", C.DIM))

def screen_containment(soar: SOAROrchestrator):
    print(colored("\n\n🛡️  CONTAINMENT STATUS\n", C.CYAN, C.BOLD))
    status = soar.get_containment_status()

    sections = [
        ("Geblockte IPs",     status.get("blocked_ips", []),        C.RED),
        ("Geblockte Domains", status.get("blocked_domains", []),     C.RED),
        ("Quarantäne-Hashes", status.get("quarantined_hashes", []), C.YELLOW),
        ("Isolierte Hosts",   status.get("isolated_hosts", []),      C.ORANGE),
        ("Gesperrte Accounts", status.get("locked_accounts", []),   C.PURPLE),
    ]

    total = status.get("total_actions", 0)
    print(f"  {colored('Gesamt-Aktionen:', C.BOLD)} {colored(str(total), C.CYAN, C.BOLD)}\n")

    for section, items, col in sections:
        count = len(items)
        print(colored(f"  {section} ({count}):", C.BOLD))
        if items:
            for item in items[:5]:
                print(f"    {colored('✗', col)} {colored(item[:50], col)}")
        else:
            print(colored("    (keine)", C.DIM))
        print()

    input(colored("  [Enter] zurück zum Menü...", C.DIM))

def screen_playbooks(soar: SOAROrchestrator):
    print(colored("\n\n📖 AKTIVE PLAYBOOKS\n", C.CYAN, C.BOLD))
    playbooks = soar.get_playbooks()
    if not playbooks:
        print(colored("  Keine Playbooks gefunden.", C.DIM))
    for pb in playbooks:
        sev_strs = [s.value.upper() for s in pb.applicable_severities]
        tactic_strs = [t.value.split(" - ")[1] for t in pb.mitre_tactics[:2]]
        print(f"  {colored('▸', C.CYAN, C.BOLD)} {colored(pb.name, C.WHITE, C.BOLD)}")
        print(f"    {colored(pb.description[:60], C.DIM)}")
        print(f"    Steps: {colored(str(len(pb.steps)), C.YELLOW)}  "
              f"Version: {pb.version}  "
              f"Severities: {colored(', '.join(sev_strs) or 'alle', C.RED)}")
        if tactic_strs:
            print(f"    MITRE: {colored(', '.join(tactic_strs), C.PURPLE)}")
        print()
    input(colored("  [Enter] zurück zum Menü...", C.DIM))

def screen_edit_incident(soar: SOAROrchestrator):
    print(colored("\n\n✏️  INCIDENT BEARBEITEN\n", C.CYAN, C.BOLD))
    incidents = soar.get_incidents(limit=10)
    if not incidents:
        print(colored("  Keine Incidents vorhanden.", C.DIM))
        input(colored("  [Enter] zurück...", C.DIM))
        return

    for i, inc in enumerate(incidents, 1):
        print(f"  {colored(f'[{i}]', C.YELLOW)} {colored(inc.id[:8], C.DIM)} "
              f"{colored(inc.severity.value.upper(), sev_color(inc.severity.value))} "
              f"{inc.title[:45]}")

    choice = input(colored("\n  Incident-Nr.: ", C.CYAN)).strip()
    try:
        idx = int(choice) - 1
        incident = incidents[idx]
    except (ValueError, IndexError):
        return

    print(f"\n  Aktueller Status: {colored(incident.status.value, C.YELLOW)}")
    print(f"\n  {colored('[1]', C.YELLOW)} Status ändern")
    print(f"  {colored('[2]', C.YELLOW)} Notiz hinzufügen")
    print(f"  {colored('[3]', C.YELLOW)} Containment ausführen")
    print(f"  {colored('[4]', C.YELLOW)} Incident Details")

    action = input(colored("\n  Aktion: ", C.CYAN)).strip()

    if action == "1":
        print("  Status: new / triaging / active / contained / remediated / closed")
        new_status = input("  Neuer Status: ").strip()
        result = soar.update_incident_status(incident.id, new_status)
        if result:
            print(colored(f"  ✓ Status auf '{new_status}' gesetzt.", C.GREEN))
    elif action == "2":
        note = input("  Notiz: ").strip()
        if note:
            soar.add_incident_note(incident.id, note)
            print(colored("  ✓ Notiz hinzugefügt.", C.GREEN))
    elif action == "3":
        print(colored("  Führe Containment aus...", C.YELLOW))
        result = soar.execute_containment(incident.id)
        success = result.get("successful", 0)
        total   = result.get("total", 0)
        print(colored(f"  ✓ {success}/{total} Containment-Aktionen erfolgreich.", C.GREEN))
        for r in result.get("results", []):
            col = C.GREEN if r.get("success") else C.RED
            print(f"    {colored('✓' if r.get('success') else '✗', col)} {r.get('action', '')}")
    elif action == "4":
        screen_incident_detail(incident)

    input(colored("\n  [Enter] zurück zum Menü...", C.DIM))


# ─────────────────────────────────────────────────────────────
#  Main Loop
# ─────────────────────────────────────────────────────────────

def main():
    print_header()
    print(colored("  Initialisiere SOAR System...", C.DIM))
    soar = SOAROrchestrator()
    print(colored(f"  ✓ {len(soar._registry)} Agenten aktiv | "
                  f"{len(soar.get_playbooks())} Playbooks geladen\n", C.GREEN))

    screen_map = {
        "1": screen_demo,
        "2": screen_single_alert,
        "3": screen_incidents,
        "4": screen_dashboard,
        "5": screen_compliance,
        "6": screen_containment,
        "7": screen_playbooks,
        "8": screen_edit_incident,
    }

    while True:
        print_menu()
        choice = input(colored("\n  Auswahl: ", C.CYAN, C.BOLD)).strip()

        if choice == "9":
            soar.shutdown()
            print(colored("\n  SOAR System heruntergefahren. Auf Wiedersehen! 👋\n", C.CYAN))
            break
        elif choice in screen_map:
            screen_map[choice](soar)
        else:
            print(colored("  Ungültige Auswahl.", C.RED))


if __name__ == "__main__":
    main()
