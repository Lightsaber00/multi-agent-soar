"""
Multi-Agent SOAR - Core Data Models
Definiert alle Datenstrukturen für das SOAR System
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


# ─────────────────────────────────────────────────────────────
#  Enumerations
# ─────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"

class IncidentStatus(str, Enum):
    NEW         = "new"
    TRIAGING    = "triaging"
    ACTIVE      = "active"
    CONTAINED   = "contained"
    REMEDIATED  = "remediated"
    CLOSED      = "closed"

class AlertStatus(str, Enum):
    OPEN        = "open"
    IN_PROGRESS = "in_progress"
    ESCALATED   = "escalated"
    FALSE_POS   = "false_positive"
    RESOLVED    = "resolved"

class PlaybookStatus(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    SKIPPED   = "skipped"

class MITRETactic(str, Enum):
    INITIAL_ACCESS      = "TA0001 - Initial Access"
    EXECUTION           = "TA0002 - Execution"
    PERSISTENCE         = "TA0003 - Persistence"
    PRIVILEGE_ESC       = "TA0004 - Privilege Escalation"
    DEFENSE_EVASION     = "TA0005 - Defense Evasion"
    CREDENTIAL_ACCESS   = "TA0006 - Credential Access"
    DISCOVERY           = "TA0007 - Discovery"
    LATERAL_MOVEMENT    = "TA0008 - Lateral Movement"
    COLLECTION          = "TA0009 - Collection"
    C2                  = "TA0011 - Command and Control"
    EXFILTRATION        = "TA0010 - Exfiltration"
    IMPACT              = "TA0040 - Impact"

class ComplianceFramework(str, Enum):
    ISO27001 = "ISO 27001"
    SOC2     = "SOC 2"
    GDPR     = "GDPR"
    NIST     = "NIST CSF"
    PCI_DSS  = "PCI DSS"


# ─────────────────────────────────────────────────────────────
#  Observable / IOC
# ─────────────────────────────────────────────────────────────

@dataclass
class Observable:
    """Indicators of Compromise (IOC) / Observables"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: str = ""          # ip, domain, hash, url, email, ...
    value: str = ""
    threat_score: float = 0.0
    malicious: bool = False
    enriched: bool = False
    sources: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict:
        return {
            "id": self.id, "type": self.type, "value": self.value,
            "threat_score": self.threat_score, "malicious": self.malicious,
            "enriched": self.enriched, "sources": self.sources,
            "tags": self.tags, "metadata": self.metadata,
            "created_at": self.created_at.isoformat()
        }


# ─────────────────────────────────────────────────────────────
#  Alert
# ─────────────────────────────────────────────────────────────

@dataclass
class Alert:
    """Eingehender Security Alert"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    description: str = ""
    source: str = ""            # SIEM, EDR, Firewall, ...
    severity: Severity = Severity.MEDIUM
    status: AlertStatus = AlertStatus.OPEN
    tenant_id: str = "default"
    raw_data: Dict[str, Any] = field(default_factory=dict)
    observables: List[Observable] = field(default_factory=list)
    mitre_tactics: List[MITRETactic] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)  # z.B. T1059
    triage_score: float = 0.0
    false_positive_score: float = 0.0
    enrichment_data: Dict[str, Any] = field(default_factory=dict)
    assigned_incident_id: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "id": self.id, "title": self.title, "description": self.description,
            "source": self.source, "severity": self.severity.value,
            "status": self.status.value, "tenant_id": self.tenant_id,
            "observables": [o.to_dict() for o in self.observables],
            "mitre_tactics": [t.value for t in self.mitre_tactics],
            "mitre_techniques": self.mitre_techniques,
            "triage_score": self.triage_score,
            "false_positive_score": self.false_positive_score,
            "enrichment_data": self.enrichment_data,
            "assigned_incident_id": self.assigned_incident_id,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(), "tags": self.tags
        }


# ─────────────────────────────────────────────────────────────
#  Timeline Event
# ─────────────────────────────────────────────────────────────

@dataclass
class TimelineEvent:
    """Einzelnes Ereignis in der Incident-Timeline"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)
    event_type: str = ""    # alert, action, note, containment, ...
    actor: str = ""         # agent name oder user
    description: str = ""
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "id": self.id, "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type, "actor": self.actor,
            "description": self.description, "data": self.data
        }


# ─────────────────────────────────────────────────────────────
#  Incident
# ─────────────────────────────────────────────────────────────

@dataclass
class Incident:
    """Security Incident (aggregiert mehrere Alerts)"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    status: IncidentStatus = IncidentStatus.NEW
    tenant_id: str = "default"
    alert_ids: List[str] = field(default_factory=list)
    assigned_to: str = ""
    playbooks_executed: List[str] = field(default_factory=list)
    timeline: List[TimelineEvent] = field(default_factory=list)
    observables: List[Observable] = field(default_factory=list)
    mitre_tactics: List[MITRETactic] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    containment_actions: List[str] = field(default_factory=list)
    forensic_artifacts: List[Dict] = field(default_factory=list)
    vulnerabilities: List[Dict] = field(default_factory=list)
    compliance_frameworks: List[ComplianceFramework] = field(default_factory=list)
    sla_breach: bool = False
    sla_deadline: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    closed_at: Optional[datetime] = None
    tags: List[str] = field(default_factory=list)
    notes: str = ""

    def add_timeline_event(self, event_type: str, actor: str,
                           description: str, data: Dict = None):
        self.timeline.append(TimelineEvent(
            event_type=event_type, actor=actor,
            description=description, data=data or {}
        ))
        self.updated_at = datetime.now()

    def to_dict(self) -> Dict:
        return {
            "id": self.id, "title": self.title, "description": self.description,
            "severity": self.severity.value, "status": self.status.value,
            "tenant_id": self.tenant_id, "alert_ids": self.alert_ids,
            "assigned_to": self.assigned_to,
            "playbooks_executed": self.playbooks_executed,
            "timeline": [e.to_dict() for e in self.timeline],
            "observables": [o.to_dict() for o in self.observables],
            "mitre_tactics": [t.value for t in self.mitre_tactics],
            "mitre_techniques": self.mitre_techniques,
            "containment_actions": self.containment_actions,
            "forensic_artifacts": self.forensic_artifacts,
            "vulnerabilities": self.vulnerabilities,
            "compliance_frameworks": [c.value for c in self.compliance_frameworks],
            "sla_breach": self.sla_breach,
            "sla_deadline": self.sla_deadline.isoformat() if self.sla_deadline else None,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
            "tags": self.tags, "notes": self.notes
        }


# ─────────────────────────────────────────────────────────────
#  Playbook Step & Playbook
# ─────────────────────────────────────────────────────────────

@dataclass
class PlaybookStep:
    """Einzelner Schritt in einem Playbook"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    action_type: str = ""   # enrich, contain, notify, ticket, query_siem, ...
    parameters: Dict[str, Any] = field(default_factory=dict)
    conditions: Dict[str, Any] = field(default_factory=dict)  # Bedingungen für Ausführung
    on_success: Optional[str] = None   # next step id
    on_failure: Optional[str] = None   # fallback step id
    timeout_seconds: int = 60
    retry_count: int = 0

@dataclass
class Playbook:
    """Automatisiertes Playbook"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    trigger_conditions: Dict[str, Any] = field(default_factory=dict)
    steps: List[PlaybookStep] = field(default_factory=list)
    applicable_severities: List[Severity] = field(default_factory=list)
    mitre_tactics: List[MITRETactic] = field(default_factory=list)
    tenant_id: str = "default"
    enabled: bool = True
    version: str = "1.0"
    created_at: datetime = field(default_factory=datetime.now)

@dataclass
class PlaybookExecution:
    """Ausführungsprotokoll eines Playbooks"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    playbook_id: str = ""
    incident_id: str = ""
    status: PlaybookStatus = PlaybookStatus.PENDING
    step_results: List[Dict] = field(default_factory=list)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: str = ""


# ─────────────────────────────────────────────────────────────
#  Tenant (Multi-Tenancy)
# ─────────────────────────────────────────────────────────────

@dataclass
class Tenant:
    """Mandant / Organisation"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    contact_email: str = ""
    integrations: Dict[str, Dict] = field(default_factory=dict)
    sla_config: Dict[str, int] = field(default_factory=dict)  # severity -> minutes
    compliance_frameworks: List[ComplianceFramework] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    active: bool = True


# ─────────────────────────────────────────────────────────────
#  Agent Message (Inter-Agent Kommunikation)
# ─────────────────────────────────────────────────────────────

@dataclass
class AgentMessage:
    """Nachricht zwischen Agenten"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    sender: str = ""
    recipient: str = ""     # "broadcast" für alle
    message_type: str = ""  # task, result, error, event
    payload: Dict[str, Any] = field(default_factory=dict)
    correlation_id: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    processed: bool = False
