"""Threat library and threat data models."""

from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from enum import Enum
import random


KILL_CHAIN_STAGES = [
    "RECONNAISSANCE", "WEAPONIZATION", "DELIVERY", "EXPLOITATION",
    "INSTALLATION", "COMMAND_CONTROL", "EXFILTRATION", "IMPACT"
]


class ThreatCategory(Enum):
    """Categories of threats."""
    EXTERNAL_ATTACK = "external_attack"
    INSIDER_THREAT = "insider_threat"
    SYSTEM_FAILURE = "system_failure"


class ThreatSeverity(Enum):
    """Severity levels."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class KillChainResult:
    """Result of kill chain simulation."""
    stages_completed: List[str] = field(default_factory=list)
    success: bool = False
    overall_prob: float = 0.0


@dataclass
class Threat:
    """Represents a threat."""
    threat_id: str
    name: str
    category: ThreatCategory
    severity: ThreatSeverity
    base_prob: float = 0.5
    min_impact_m: float = 5.0
    likely_impact_m: float = 20.0
    max_impact_m: float = 100.0
    mitre_techniques: List[str] = field(default_factory=list)
    target_node_types: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    
    def risk_score(self, vuln: float) -> float:
        """Calculate risk score given vulnerability."""
        if vuln <= 0:
            return 0.0
        return (vuln / 100.0) * self.base_prob * 100.0
    
    def simulate_kill_chain(self, vuln: float, round_num: int = 1) -> KillChainResult:
        """Simulate attack kill chain progression."""
        completed = []
        prob = 1.0
        
        for stage in KILL_CHAIN_STAGES:
            stage_prob = (vuln / 100.0) * self.base_prob
            if random.random() < stage_prob:
                completed.append(stage)
                prob *= stage_prob
            else:
                break
        
        return KillChainResult(
            stages_completed=completed,
            success=len(completed) >= 5,
            overall_prob=prob
        )
    
    def sample_impact(self) -> float:
        """Sample impact from PERT distribution."""
        # Simple triangular approximation
        return random.triangular(self.min_impact_m, self.max_impact_m, self.likely_impact_m)


class ThreatLibrary:
    """Library of known threats and vulnerabilities."""
    
    def __init__(self, threat_file: Optional[str] = None):
        self.threat_file = threat_file
        self.threats: Dict[str, Threat] = self._initialize_threats()
    
    def _initialize_threats(self) -> Dict[str, Threat]:
        """Initialize sample threats."""
        return {
            "T-001": Threat(
                "T-001", "SQL Injection", ThreatCategory.EXTERNAL_ATTACK,
                ThreatSeverity.HIGH, 0.6, 5.0, 30.0, 150.0,
                mitre_techniques=["T1190"],
                target_node_types=["core_banking"],
                mitigations=["Input validation", "WAF"]
            ),
            "T-002": Threat(
                "T-002", "Phishing Campaign", ThreatCategory.EXTERNAL_ATTACK,
                ThreatSeverity.MEDIUM, 0.4, 2.0, 10.0, 50.0,
                mitre_techniques=["T1566"],
                target_node_types=["core_banking"],
                mitigations=["Email filtering"]
            ),
            "T-003": Threat(
                "T-003", "Insider Data Theft", ThreatCategory.INSIDER_THREAT,
                ThreatSeverity.CRITICAL, 0.3, 10.0, 50.0, 200.0,
                mitre_techniques=["T1005"],
                target_node_types=["core_banking"],
                mitigations=["DLP", "Monitoring"]
            ),
            "T-004": Threat(
                "T-004", "Network Outage", ThreatCategory.SYSTEM_FAILURE,
                ThreatSeverity.HIGH, 0.5, 5.0, 25.0, 100.0,
                mitre_techniques=["T1498"],
                target_node_types=["core_banking", "swift_gateway"]
            ),
            "T-005": Threat(
                "T-005", "Ransomware Attack", ThreatCategory.EXTERNAL_ATTACK,
                ThreatSeverity.CRITICAL, 0.2, 20.0, 100.0, 500.0,
                mitre_techniques=["T1486"],
                target_node_types=["core_banking"],
                mitigations=["Backup", "EDR"]
            ),
            "T-006": Threat(
                "T-006", "API Abuse", ThreatCategory.EXTERNAL_ATTACK,
                ThreatSeverity.MEDIUM, 0.4, 1.0, 5.0, 20.0,
                mitre_techniques=["T1190"],
                target_node_types=["swift_gateway"],
                mitigations=["Rate limiting", "API key rotation"]
            ),
            "T-007": Threat(
                "T-007", "Privilege Escalation", ThreatCategory.INSIDER_THREAT,
                ThreatSeverity.HIGH, 0.35, 15.0, 60.0, 250.0,
                mitre_techniques=["T1548"],
                target_node_types=["core_banking"],
                mitigations=["PAM", "RBAC"]
            ),
            "T-008": Threat(
                "T-008", "Supply Chain Attack", ThreatCategory.EXTERNAL_ATTACK,
                ThreatSeverity.CRITICAL, 0.15, 30.0, 150.0, 500.0,
                mitre_techniques=["T1199"],
                target_node_types=["core_banking"],
                mitigations=["Vendor assessment", "Zero trust"]
            ),
        }
    
    def load_from_file(self):
        """Load threats from JSON file."""
        pass
    
    def get(self, threat_id: str) -> Optional[Threat]:
        """Get threat by ID."""
        return self.threats.get(threat_id)
    
    def for_node_type(self, node_type: str) -> List[Threat]:
        """Get threats applicable to a node type."""
        return [t for t in self.threats.values() if node_type in t.target_node_types]

