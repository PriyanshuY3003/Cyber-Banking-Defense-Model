"""Compliance logging and audit trail."""

from enum import Enum
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
import hashlib
import hmac


class AuditEventType(Enum):
    """Types of audit events."""
    CONFIG_CHANGE = "config_change"
    INCIDENT_RAISED = "incident_raised"
    CONTROL_DEPLOYED = "control_deployed"
    FINDING_REPORTED = "finding_reported"
    SIMULATION_START = "simulation_start"
    RISK_ASSESSED = "risk_assessed"
    ATTACK_DETECTED = "attack_detected"
    NODE_COMPROMISED = "node_compromised"
    SIMULATION_COMPLETE = "simulation_complete"


@dataclass
class AuditEvent:
    """Single audit trail event."""
    event_id: str = ""
    event_type: AuditEventType = AuditEventType.CONFIG_CHANGE
    timestamp: str = ""
    actor: str = "SYSTEM"
    node_id: Optional[str] = None
    threat_id: Optional[str] = None
    incident_id: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    severity: str = "INFO"
    pci_req: Optional[str] = None
    iso_control: Optional[str] = None
    nist_function: Optional[str] = None
    gdpr_article: Optional[str] = None
    event_hash: str = ""
    hmac_sig: str = ""
    prev_hash: str = ""
    
    def to_log_line(self) -> str:
        """Format event as log line."""
        return f"{self.event_id}|{self.event_type.value}|{self.timestamp}|{self.severity}"


class ComplianceLogger:
    """Logs security and compliance events."""
    
    HMAC_KEY = b"SECRET_KEY_FOR_HMAC"
    
    def __init__(self, log_file: Optional[str] = None):
        self.log_file = log_file
        self.log_path = "logs/audit.log" if log_file else None
        self.events: List[AuditEvent] = []
        self._prev_hash = "GENESIS"
        self._counter = 0
        
        # Mapping event types to compliance standards
        self.PCI_TAG_MAP = {AuditEventType.ATTACK_DETECTED: "6.5.1"}
        self.ISO_TAG_MAP = {AuditEventType.INCIDENT_RAISED: "A.16.1"}
        self.NIST_TAG_MAP = {
            AuditEventType.CONTROL_DEPLOYED: "PR",
            AuditEventType.ATTACK_DETECTED: "DE"
        }
        self.GDPR_TAG_MAP = {AuditEventType.FINDING_REPORTED: "Article 33"}
    
    def _make_event_hash(self, event: AuditEvent) -> str:
        """Create hash for event."""
        content = f"{event.event_id}{event.timestamp}{event.prev_hash}"
        return hashlib.sha256(content.encode()).hexdigest()
    
    def _make_hmac(self, event_hash: str) -> str:
        """Create HMAC-SHA256 signature."""
        return hmac.new(self.HMAC_KEY, event_hash.encode(), hashlib.sha256).hexdigest()
    
    def log_event(self, event_type: AuditEventType, message: str):
        pass
    
    def log(self, event_type: AuditEventType, component: str = "SYSTEM", 
            message: str = "", node_id: Optional[str] = None, 
            threat_id: Optional[str] = None, incident_id: Optional[str] = None,
            details: Optional[Dict] = None, severity: str = "INFO") -> AuditEvent:
        """Log an event with component info."""
        from datetime import datetime
        
        self._counter += 1
        ts = datetime.now().isoformat()
        event = AuditEvent(
            event_id=f"EVT-{self._counter:06d}",
            event_type=event_type,
            timestamp=ts,
            actor=component,
            node_id=node_id,
            threat_id=threat_id,
            incident_id=incident_id,
            details=details or {},
            severity=severity,
            pci_req=self.PCI_TAG_MAP.get(event_type),
            iso_control=self.ISO_TAG_MAP.get(event_type),
            nist_function=self.NIST_TAG_MAP.get(event_type),
            gdpr_article=self.GDPR_TAG_MAP.get(event_type),
            prev_hash=self._prev_hash,
        )
        event.event_hash = self._make_event_hash(event)
        event.hmac_sig = self._make_hmac(event.event_hash)
        self._prev_hash = event.event_hash
        
        self.events.append(event)
        return event
    
    def verify_chain(self) -> Dict[str, Any]:
        """Verify the audit chain integrity."""
        errors: List[str] = []
        if not self.events:
            return {"valid": True, "events_checked": 0, "errors": []}

        for i, event in enumerate(self.events):
            computed = self._make_event_hash(event)
            if computed != event.event_hash:
                errors.append(f"Hash mismatch at {event.event_id}")
            expected_hmac = self._make_hmac(event.event_hash)
            if expected_hmac != event.hmac_sig:
                errors.append(f"HMAC invalid at {event.event_id}")
            if i > 0 and event.prev_hash != self.events[i-1].event_hash:
                errors.append(f"Chain broken at {event.event_id}")

        return {
            "valid": len(errors) == 0,
            "events_checked": len(self.events),
            "errors": errors,
            "chain_tip": self._prev_hash[:16] + "..." if self._prev_hash else "GENESIS"
        }
    
    def generate_report(self, standards: Optional[List[str]] = None,
                       output_dir: str = "logs") -> Dict[str, Any]:
        """Generate an audit report."""
        standards = standards or ["PCI-DSS", "ISO-27001", "NIST-CSF", "GDPR"]
        reports: Dict[str, dict] = {}
        
        for std in standards:
            reports[std] = {
                "total_events": len(self.events),
                "critical_events": sum(1 for e in self.events if e.severity == "CRITICAL")
            }
        
        return reports


