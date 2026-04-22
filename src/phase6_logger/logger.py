
# PART 6 — Compliance & Audit Trail Generation
# logger.py: ComplianceLogger with SHA-256 hash-chain + HMAC-SHA256 signing.
# Layer 5 correct arch: legally admissible tamper-evident logs, evidence collection.
# Standards: PCI-DSS REQ-1 to 12 · ISO-27001 Annex A · NIST-CSF 2.0 · GDPR Art 25/32/33/35

from __future__ import annotations
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional
from enum import Enum


class AuditEventType(Enum):
    ATTACK_DETECTED      = "ATTACK_DETECTED"
    INCIDENT_RAISED      = "INCIDENT_RAISED"
    SOAR_ACTION          = "SOAR_ACTION"
    NODE_COMPROMISED     = "NODE_COMPROMISED"
    NODE_QUARANTINED     = "NODE_QUARANTINED"
    NODE_REMEDIATED      = "NODE_REMEDIATED"
    CONTROL_DEPLOYED     = "CONTROL_DEPLOYED"
    RISK_ASSESSED        = "RISK_ASSESSED"
    COMPLIANCE_CHECK     = "COMPLIANCE_CHECK"
    SLA_BREACH           = "SLA_BREACH"
    REPORT_GENERATED     = "REPORT_GENERATED"
    SIMULATION_START     = "SIMULATION_START"
    SIMULATION_COMPLETE  = "SIMULATION_COMPLETE"


@dataclass
class AuditEvent:
    """Single tamper-evident audit event."""
    event_id: str
    event_type: AuditEventType
    timestamp: str
    actor: str                   # System/user originating the event
    node_id: Optional[str]
    threat_id: Optional[str]
    incident_id: Optional[str]
    details: Dict
    severity: str                # CRITICAL / HIGH / MEDIUM / LOW / INFO
    # Compliance tagging
    pci_req: Optional[str] = None
    iso_control: Optional[str] = None
    nist_function: Optional[str] = None
    gdpr_article: Optional[str] = None
    # Hash chain fields
    event_hash: str = ""
    prev_hash: str = ""
    hmac_sig: str = ""

    def to_log_line(self) -> str:
        return json.dumps({
            "event_id": self.event_id,
            "type": self.event_type.value,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "node": self.node_id,
            "threat": self.threat_id,
            "incident": self.incident_id,
            "severity": self.severity,
            "details": self.details,
            "compliance": {
                "pci_req": self.pci_req,
                "iso_control": self.iso_control,
                "nist_function": self.nist_function,
                "gdpr_article": self.gdpr_article,
            },
            "chain": {
                "prev_hash": self.prev_hash,
                "event_hash": self.event_hash,
                "hmac": self.hmac_sig,
            }
        }, separators=(',', ':'))


class ComplianceLogger:
    """
    Tamper-evident, hash-chained audit logger.
    Layer 5 correct arch: HMAC-SHA256 signing for legally admissible logs.
    Each event's hash includes the previous event hash — any tampering breaks the chain.
    """
    HMAC_KEY = b"CyberBankingDefense_HMAC_Key_2025"  # In prod: HSM-stored key

    # Compliance mappings for auto-tagging
    PCI_TAG_MAP = {
        AuditEventType.ATTACK_DETECTED:     "REQ-10.3",
        AuditEventType.INCIDENT_RAISED:     "REQ-12.10",
        AuditEventType.NODE_COMPROMISED:    "REQ-12.10",
        AuditEventType.SOAR_ACTION:         "REQ-12.10",
        AuditEventType.CONTROL_DEPLOYED:    "REQ-6.3",
        AuditEventType.COMPLIANCE_CHECK:    "REQ-12.4",
        AuditEventType.REPORT_GENERATED:    "REQ-12.3",
    }
    ISO_TAG_MAP = {
        AuditEventType.ATTACK_DETECTED:     "A.16.1.2",
        AuditEventType.INCIDENT_RAISED:     "A.16.1.4",
        AuditEventType.SOAR_ACTION:         "A.16.1.5",
        AuditEventType.CONTROL_DEPLOYED:    "A.14.2.2",
        AuditEventType.COMPLIANCE_CHECK:    "A.18.2.3",
    }
    NIST_TAG_MAP = {
        AuditEventType.ATTACK_DETECTED:     "DE.AE-2",
        AuditEventType.INCIDENT_RAISED:     "RS.CO-2",
        AuditEventType.SOAR_ACTION:         "RS.MI-1",
        AuditEventType.NODE_QUARANTINED:    "RS.MI-2",
        AuditEventType.RISK_ASSESSED:       "ID.RA-1",
        AuditEventType.CONTROL_DEPLOYED:    "PR.IP-1",
    }
    GDPR_TAG_MAP = {
        AuditEventType.NODE_COMPROMISED:    "Art.33",
        AuditEventType.INCIDENT_RAISED:     "Art.33",
        AuditEventType.RISK_ASSESSED:       "Art.35",
        AuditEventType.CONTROL_DEPLOYED:    "Art.25",
    }

    def __init__(self, log_dir: str = "logs"):
        os.makedirs(log_dir, exist_ok=True)
        self.log_path     = os.path.join(log_dir, "compliance_audit.log")
        self.events: List[AuditEvent] = []
        self._counter     = 0
        self._prev_hash   = "GENESIS"
        # Load existing chain if log exists
        if os.path.exists(self.log_path):
            self._load_existing()

    def _load_existing(self):
        """Resume hash chain from last logged event."""
        try:
            with open(self.log_path) as f:
                lines = [l.strip() for l in f if l.strip()]
            if lines:
                last = json.loads(lines[-1])
                self._prev_hash = last["chain"]["event_hash"]
                self._counter   = len(lines)
        except Exception:
            pass

    def _make_event_hash(self, event: AuditEvent) -> str:
        """SHA-256 hash of event content + previous hash (chain link)."""
        content = (f"{event.event_id}|{event.event_type.value}|{event.timestamp}|"
                   f"{event.actor}|{event.node_id}|{event.threat_id}|"
                   f"{json.dumps(event.details, sort_keys=True)}|{event.prev_hash}")
        return hashlib.sha256(content.encode()).hexdigest()

    def _make_hmac(self, event_hash: str) -> str:
        """HMAC-SHA256 signature for legal admissibility."""
        return hmac.new(self.HMAC_KEY, event_hash.encode(), hashlib.sha256).hexdigest()

    def log(self, event_type: AuditEventType, actor: str = "SYSTEM",
            node_id: Optional[str] = None, threat_id: Optional[str] = None,
            incident_id: Optional[str] = None, details: Optional[dict] = None,
            severity: str = "INFO") -> AuditEvent:
        """Log a compliance event with hash chain + HMAC."""
        self._counter += 1
        ts = datetime.now(timezone.utc).isoformat()
        event = AuditEvent(
            event_id=f"EVT-{self._counter:06d}",
            event_type=event_type,
            timestamp=ts,
            actor=actor,
            node_id=node_id, threat_id=threat_id, incident_id=incident_id,
            details=details or {},
            severity=severity,
            pci_req=self.PCI_TAG_MAP.get(event_type),
            iso_control=self.ISO_TAG_MAP.get(event_type),
            nist_function=self.NIST_TAG_MAP.get(event_type),
            gdpr_article=self.GDPR_TAG_MAP.get(event_type),
            prev_hash=self._prev_hash,
        )
        event.event_hash = self._make_event_hash(event)
        event.hmac_sig   = self._make_hmac(event.event_hash)
        self._prev_hash  = event.event_hash

        self.events.append(event)
        with open(self.log_path, "a") as f:
            f.write(event.to_log_line() + "\n")
        return event

    def verify_chain(self) -> Dict:
        """Verify hash chain integrity of all logged events."""
        errors: List[str] = []
        if not self.events:
            return {"valid": True, "events_checked": 0, "errors": []}

        for i, event in enumerate(self.events):
            # Re-compute hash
            computed = self._make_event_hash(event)
            if computed != event.event_hash:
                errors.append(f"Hash mismatch at {event.event_id}")
            # Verify HMAC
            expected_hmac = self._make_hmac(event.event_hash)
            if expected_hmac != event.hmac_sig:
                errors.append(f"HMAC invalid at {event.event_id}")
            # Verify chain link
            if i > 0 and event.prev_hash != self.events[i-1].event_hash:
                errors.append(f"Chain broken between {self.events[i-1].event_id} → {event.event_id}")

        return {
            "valid": len(errors) == 0,
            "events_checked": len(self.events),
            "errors": errors,
            "chain_tip": self._prev_hash[:16] + "...",
        }

    def generate_report(self, standards: Optional[List[str]] = None,
                        output_dir: str = "logs") -> Dict:
        """
        Generate compliance reports per standard.
        Produces pci_dss_report.json, iso27001_report.json, etc.
        """
        standards = standards or ["PCI-DSS", "ISO-27001", "NIST-CSF", "GDPR"]
        reports: Dict[str, dict] = {}

        for std in standards:
            # Filter events relevant to this standard
            if std == "PCI-DSS":
                relevant = [e for e in self.events if e.pci_req]
            elif std == "ISO-27001":
                relevant = [e for e in self.events if e.iso_control]
            elif std == "NIST-CSF":
                relevant = [e for e in self.events if e.nist_function]
            elif std == "GDPR":
                relevant = [e for e in self.events if e.gdpr_article]
            else:
                relevant = self.events

            critical_count = sum(1 for e in relevant if e.severity == "CRITICAL")
            report = {
                "standard": std,
                "generated_at": datetime.utcnow().isoformat(),
                "total_events": len(relevant),
                "critical_events": critical_count,
                "chain_valid": self.verify_chain()["valid"],
                "events_by_type": {},
                "events": [json.loads(e.to_log_line()) for e in relevant[-20:]],  # last 20
            }
            for e in relevant:
                key = e.event_type.value
                report["events_by_type"][key] = report["events_by_type"].get(key, 0) + 1

            reports[std] = report
            # Write to disk
            fname = std.lower().replace("-","_").replace("/","_") + "_report.json"
            fpath = os.path.join(output_dir, fname)
            with open(fpath, "w") as f:
                json.dump(report, f, indent=2)

        return reports

    def evidence_package(self, incident_id: str) -> Dict:
        """
        Collect all evidence for a specific incident (for legal/forensic use).
        Returns all audit events referencing that incident.
        """
        evidence = [e for e in self.events if e.incident_id == incident_id]
        return {
            "incident_id": incident_id,
            "evidence_count": len(evidence),
            "chain_verified": self.verify_chain()["valid"],
            "events": [json.loads(e.to_log_line()) for e in evidence],
        }


if __name__ == "__main__":
    import os, sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
    os.makedirs("logs", exist_ok=True)

    logger = ComplianceLogger("logs")
    print("=" * 60)
    print("PART 6 — Compliance & Audit Trail")
    print("=" * 60)

    # Log sample events
    logger.log(AuditEventType.SIMULATION_START, "SYSTEM",
               details={"rounds": 10, "threats": 8}, severity="INFO")
    logger.log(AuditEventType.ATTACK_DETECTED, "SimulationEngine",
               node_id="N07", threat_id="T-008", severity="CRITICAL",
               details={"technique": "T1078", "stage": "exploit"})
    logger.log(AuditEventType.INCIDENT_RAISED, "SOAR",
               node_id="N07", threat_id="T-008", incident_id="INC-0001",
               severity="CRITICAL", details={"playbook": "PB-SWIFT"})
    logger.log(AuditEventType.NODE_QUARANTINED, "SOAR",
               node_id="N07", severity="HIGH",
               details={"reason": "SWIFT fraud detected"})

    # Verify chain
    chain_result = logger.verify_chain()
    print(f"\nChain integrity: {chain_result}")

    # Generate reports
    reports = logger.generate_report()
    for std, rpt in reports.items():
        print(f"\n[{std}] Events: {rpt['total_events']} | Critical: {rpt['critical_events']}")