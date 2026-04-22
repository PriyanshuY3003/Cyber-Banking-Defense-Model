
# PART 5 — Systemic Cyber Risk Assessment Tools
# risk_calc.py: RiskCalculator with full FAIR model components.
# Layer 5 correct arch: FAIR with uncertainty, min/likely/max PERT distributions.
# Components: TEF · LEF · PLM · ALE · compute_all() · risk_summary()

from __future__ import annotations
import json
import math
import random
import statistics
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class FAIRResult:
    """Full FAIR analysis result for one threat–node pair."""
    threat_id: str
    threat_name: str
    node_id: str
    node_name: str
    node_vuln: float
    # FAIR components
    tef: float          # Threat Event Frequency (annualised)
    lef: float          # Loss Event Frequency
    plm: float          # Primary Loss Magnitude (USD M, mid-point)
    ale: float          # Annualised Loss Expectancy (USD M)
    # PERT uncertainty ranges
    ale_min: float
    ale_likely: float
    ale_max: float
    # Composite score 0–100
    risk_score: float
    # Classification
    risk_tier: str      # CRITICAL / HIGH / MEDIUM / LOW
    mitre_techniques: List[str] = field(default_factory=list)
    recommended_controls: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "threat": f"{self.threat_id} — {self.threat_name}",
            "node": f"{self.node_id} — {self.node_name}",
            "node_vuln": round(self.node_vuln, 1),
            "fair": {
                "tef_annual": round(self.tef, 3),
                "lef_annual": round(self.lef, 3),
                "plm_m": round(self.plm, 2),
                "ale_m": round(self.ale, 2),
            },
            "uncertainty": {
                "min_m": round(self.ale_min, 2),
                "likely_m": round(self.ale_likely, 2),
                "max_m": round(self.ale_max, 2),
            },
            "risk_score": round(self.risk_score, 1),
            "risk_tier": self.risk_tier,
            "mitre": self.mitre_techniques,
            "controls": self.recommended_controls,
        }


@dataclass
class RiskSummary:
    """Aggregated risk summary across entire bank estate."""
    total_ale_m: float
    total_ale_min_m: float
    total_ale_max_m: float
    risk_by_tier: Dict[str, int]
    top_threats: List[FAIRResult]
    top_nodes: List[FAIRResult]
    systemic_risk_score: float    # 0–100 estate-wide
    heat_map: Dict[str, Dict[str, float]]  # node_id → threat_id → risk_score
    compliance_risks: Dict[str, List[str]] # standard → at-risk nodes

    def to_dict(self) -> dict:
        return {
            "total_ale_m": round(self.total_ale_m, 2),
            "ale_range": [round(self.total_ale_min_m, 2), round(self.total_ale_max_m, 2)],
            "systemic_risk_score": round(self.systemic_risk_score, 1),
            "by_tier": self.risk_by_tier,
            "top_threats": [r.to_dict() for r in self.top_threats[:3]],
            "top_nodes": [r.to_dict() for r in self.top_nodes[:3]],
            "compliance_risks": self.compliance_risks,
        }


class RiskCalculator:
    """
    Full FAIR-model risk calculator.
    Computes TEF, LEF, PLM, ALE with PERT uncertainty for each threat–node pair.
    Layer 5 correct arch: min/likely/max ranges, not just point estimates.
    """

    # Control → risk reduction mapping for recommendations
    CONTROL_RECOMMENDATIONS = {
        "ransomware":     ["C04 (EDR)", "C11 (Backup/DR)", "C07 (Segmentation)"],
        "phishing":       ["C03 (MFA)", "C09 (Training)", "C05 (SIEM)"],
        "ddos":           ["C08 (DDoS Scrubbing)", "C01 (NGFW)"],
        "insider_threat": ["C06 (PAM)", "C10 (DLP)", "C05 (SIEM)"],
        "apt":            ["C05 (SIEM)", "C12 (ZTNA)", "C06 (PAM)"],
        "card_skimming":  ["C01 (NGFW)", "C05 (SIEM)"],
        "supply_chain":   ["C07 (Segmentation)", "C04 (EDR)", "C05 (SIEM)"],
        "swift_fraud":    ["C06 (PAM)", "C03 (MFA)", "C05 (SIEM)"],
    }

    def __init__(self, network, threat_library):
        self.network        = network
        self.threat_library = threat_library
        self._results: List[FAIRResult] = []

    # ── FAIR Component Calculators ────────────────────────────────────────────

    def _tef(self, threat, vuln: float) -> float:
        """Threat Event Frequency — annualised attack rate."""
        return threat.base_attack_prob * 365 * (threat.exploitability / 10.0)

    def _lef(self, tef: float, vuln: float) -> float:
        """Loss Event Frequency = TEF × probability of successful exploitation."""
        return tef * (vuln / 100.0)

    def _plm(self, threat) -> float:
        """Primary Loss Magnitude — mid-point of impact range."""
        return (threat.impact_range_m[0] + threat.impact_range_m[1]) / 2.0

    def _ale(self, lef: float, plm: float) -> float:
        """Annualised Loss Expectancy = LEF × PLM."""
        return lef * plm

    def _pert_uncertainty(self, threat, vuln: float) -> Tuple[float, float, float]:
        """
        PERT distribution for FAIR uncertainty (min/likely/max).
        Layer 5 correct arch: uncertainty ranges, not point estimates only.
        """
        lo, hi = threat.impact_range_m
        lef_lo      = self._lef(self._tef(threat, vuln * 0.7), vuln * 0.7)
        lef_likely  = self._lef(self._tef(threat, vuln), vuln)
        lef_hi      = self._lef(self._tef(threat, min(vuln * 1.3, 100)), min(vuln * 1.3, 100))
        ale_min    = lef_lo    * lo
        ale_likely = lef_likely * ((lo + hi) / 2.0)
        ale_max    = lef_hi    * hi
        return ale_min, ale_likely, ale_max

    def _risk_score(self, ale: float, severity_val: int) -> float:
        """Normalised risk score 0–100."""
        max_ale = 365 * 1000.0
        return min(100.0, (ale / max_ale) * (severity_val / 4.0) * 100)

    def _risk_tier(self, score: float) -> str:
        if score >= 75: return "CRITICAL"
        if score >= 50: return "HIGH"
        if score >= 25: return "MEDIUM"
        return "LOW"

    # ── Main computation ──────────────────────────────────────────────────────

    def compute_all(self) -> List[FAIRResult]:
        """Compute FAIR risk for every threat–node pair in the estate."""
        self._results = []
        for node in self.network.nodes.values():
            threats = self.threat_library.for_node_type(node.node_type.value)
            for threat in threats:
                vuln = node.effective_vuln()
                tef  = self._tef(threat, vuln)
                lef  = self._lef(tef, vuln)
                plm  = self._plm(threat)
                ale  = self._ale(lef, plm)
                ale_min, ale_likely, ale_max = self._pert_uncertainty(threat, vuln)
                score = self._risk_score(ale, threat.severity.value)
                result = FAIRResult(
                    threat_id=threat.threat_id, threat_name=threat.name,
                    node_id=node.node_id, node_name=node.name,
                    node_vuln=round(vuln, 1),
                    tef=tef, lef=lef, plm=plm, ale=ale,
                    ale_min=ale_min, ale_likely=ale_likely, ale_max=ale_max,
                    risk_score=round(score, 1), risk_tier=self._risk_tier(score),
                    mitre_techniques=[t.technique_id for t in threat.mitre_techniques],
                    recommended_controls=self.CONTROL_RECOMMENDATIONS.get(
                        threat.category.value, []),
                )
                self._results.append(result)
        return self._results

    def risk_summary(self) -> RiskSummary:
        """Aggregate all FAIR results into estate-wide risk summary."""
        if not self._results:
            self.compute_all()

        results = self._results
        total_ale       = sum(r.ale for r in results)
        total_ale_min   = sum(r.ale_min for r in results)
        total_ale_max   = sum(r.ale_max for r in results)

        # Risk tier distribution
        tier_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for r in results:
            tier_counts[r.risk_tier] += 1

        # Top threats (aggregated by threat_id)
        threat_ale: Dict[str, float] = {}
        for r in results:
            threat_ale[r.threat_id] = threat_ale.get(r.threat_id, 0.0) + r.ale
        top_threat_ids = sorted(threat_ale.keys(), key=lambda x: threat_ale[x], reverse=True)[:5]
        top_threats = [next(r for r in results if r.threat_id == tid)
                       for tid in top_threat_ids]

        # Top nodes (highest cumulative ALE)
        node_ale: Dict[str, float] = {}
        for r in results:
            node_ale[r.node_id] = node_ale.get(r.node_id, 0.0) + r.ale
        top_node_ids = sorted(node_ale.keys(), key=lambda x: node_ale[x], reverse=True)[:5]
        top_nodes = [next(r for r in results if r.node_id == nid)
                     for nid in top_node_ids]

        # Heat map: node → threat → risk_score
        heat_map: Dict[str, Dict[str,float]] = {}
        for r in results:
            if r.node_id not in heat_map:
                heat_map[r.node_id] = {}
            heat_map[r.node_id][r.threat_id] = r.risk_score

        # Systemic risk score
        systemic = min(100.0, sum(r.risk_score for r in results) / max(len(results), 1))

        # Compliance risks
        pci_nodes = [n.node_id for n in self.network.nodes.values() if n.pci_in_scope]
        compliance_risks = {
            "PCI-DSS": [r.node_id for r in results if r.node_id in pci_nodes
                        and r.risk_tier in ("CRITICAL","HIGH")],
            "GDPR":    [r.node_id for r in results if r.risk_score >= 50],
            "RBI":     [r.node_id for r in results if r.risk_tier == "CRITICAL"],
        }

        return RiskSummary(
            total_ale_m=round(total_ale, 2),
            total_ale_min_m=round(total_ale_min, 2),
            total_ale_max_m=round(total_ale_max, 2),
            risk_by_tier=tier_counts,
            top_threats=top_threats,
            top_nodes=top_nodes,
            systemic_risk_score=round(systemic, 1),
            heat_map=heat_map,
            compliance_risks=compliance_risks,
        )

    def get_node_risk_profile(self, node_id: str) -> List[FAIRResult]:
        """Get all FAIR results for a specific node."""
        if not self._results:
            self.compute_all()
        return sorted([r for r in self._results if r.node_id == node_id],
                      key=lambda r: r.risk_score, reverse=True)


if __name__ == "__main__":
    import os, sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
    from src.models.network import BankNetwork
    from src.models.threat import ThreatLibrary

    net = BankNetwork("config/settings.json")
    lib = ThreatLibrary("data/threat_intel.json")
    calc = RiskCalculator(net, lib)
    summary = calc.risk_summary()

    print("=" * 60)
    print("PART 5 — FAIR Risk Assessment Summary")
    print("=" * 60)
    print(json.dumps(summary.to_dict(), indent=2))

    print("\n── SWIFT Gateway Risk Profile ──────────────────────────────")
    for r in calc.get_node_risk_profile("N07")[:3]:
        print(f"  [{r.threat_id}] {r.threat_name}")
        print(f"    ALE=${r.ale:.1f}M  [{r.ale_min:.1f}–{r.ale_max:.1f}]  tier={r.risk_tier}")