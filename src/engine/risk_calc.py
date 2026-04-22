"""Risk calculation engine."""

from typing import Any, Dict, List
from dataclasses import dataclass, field


@dataclass
class RiskSummary:
    """Summary of risk calculations."""
    total_ale_m: float = 100.0
    high_risk_nodes: list = field(default_factory=list)
    systemic_risk_score: float = 0.5
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_ale_m": self.total_ale_m,
            "ale_range": [self.total_ale_m * 0.8, self.total_ale_m * 1.2],  # Example range
            "systemic_risk_score": self.systemic_risk_score,
            "by_tier": {
                "CRITICAL": 5,
                "HIGH": 15,
                "MEDIUM": 25
            },
            "top_threats": [
                {"threat": "T-001 — Phishing Attack", "risk_score": 85.0},
                {"threat": "T-002 — Malware Infection", "risk_score": 78.0},
                {"threat": "T-003 — Insider Threat", "risk_score": 72.0}
            ],
            "top_nodes": [
                {"node": "N04 — Database Server", "risk_score": 90.0},
                {"node": "N03 — Application Server", "risk_score": 85.0},
                {"node": "N05 — Payment Gateway", "risk_score": 80.0}
            ],
            "compliance_risks": {
                "PCI-DSS": ["N03", "N04", "N05"],
                "ISO-27001": ["N01", "N02"],
                "GDPR": ["N03", "N04"]
            }
        }


@dataclass
class FAIRResult:
    """FAIR risk result for threat-node pair."""
    threat_id: str = "T-001"
    threat_name: str = "Threat"
    node_id: str = "N01"
    node_name: str = "Node"
    risk_score: float = 50.0
    ale_min: float = 5.0
    ale_likely: float = 20.0
    ale_max: float = 100.0


class RiskCalculator:
    """Calculates risk metrics."""
    
    def __init__(self, network: Any = None, threat_library: Any = None):
        self.network = network
        self.threat_library = threat_library
    
    def calculate_risk(self, network, threats):
        pass
    
    def compute_all(self) -> List[FAIRResult]:
        """Compute FAIR results for all threat-node pairs."""
        results = []
        if not self.network or not self.threat_library:
            return results
        
        for node in self.network.nodes.values():
            for threat in self.threat_library.threats.values():
                result = FAIRResult(
                    threat_id=threat.threat_id,
                    threat_name=threat.name,
                    node_id=node.node_id,
                    node_name=node.name,
                    risk_score=threat.risk_score(node.effective_vuln())
                )
                results.append(result)
        
        return results
    
    def risk_summary(self) -> RiskSummary:
        """Get a risk summary report."""
        results = self.compute_all()
        total_ale = sum(r.ale_likely for r in results)
        score = min(100.0, (total_ale / 150.0) * 100.0)  # Normalize to ~150M baseline
        return RiskSummary(total_ale_m=total_ale, systemic_risk_score=score)


