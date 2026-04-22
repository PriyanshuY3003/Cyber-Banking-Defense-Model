
# PART 2 — Attack Vector Modelling & Threat Intelligence
# threat.py: 7-stage kill chain, FAIR components, MITRE ATT&CK v14.

from __future__ import annotations
import json, random
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum

class ThreatCategory(Enum):
    RANSOMWARE="ransomware"; PHISHING="phishing"; DDOS="ddos"
    INSIDER_THREAT="insider_threat"; APT="apt"; CARD_SKIMMING="card_skimming"
    SUPPLY_CHAIN="supply_chain"; SWIFT_FRAUD="swift_fraud"

class ThreatSeverity(Enum):
    LOW=1; MEDIUM=2; HIGH=3; CRITICAL=4

KILL_CHAIN_STAGES = ["recon","weaponize","deliver","exploit","install","c2","act"]
DEFAULT_STAGE_PROBS = {"recon":0.95,"weaponize":0.85,"deliver":0.70,
                       "exploit":0.60,"install":0.55,"c2":0.50,"act":0.45}

@dataclass
class MITRETechnique:
    technique_id: str; name: str; tactic: str; description: str = ""

@dataclass
class KillChainResult:
    threat_id: str; node_id: str
    stages_completed: List[str]; stages_failed: List[str]
    success: bool; stage_probs: Dict[str,float]; overall_prob: float

@dataclass
class Threat:
    threat_id: str; name: str; category: ThreatCategory; severity: ThreatSeverity
    mitre_techniques: List[MITRETechnique]; target_node_types: List[str]
    base_attack_prob: float; impact_range_m: Tuple[float,float]
    kill_chain_stages: List[str]; exploitability: float = 5.0
    iocs: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    description: str = ""

    def tef(self) -> float:
        return self.base_attack_prob * 365 * (self.exploitability / 10.0)

    def lef(self, node_vuln: float) -> float:
        return self.tef() * (node_vuln / 100.0)

    def plm(self) -> float:
        return (self.impact_range_m[0] + self.impact_range_m[1]) / 2.0

    def ale(self, node_vuln: float) -> float:
        return self.lef(node_vuln) * self.plm()

    def risk_score(self, node_vuln: float) -> float:
        max_ale = 365 * 1.0 * 1000.0
        normalized = min(self.ale(node_vuln) / max_ale, 1.0)
        return round(normalized * (self.severity.value / 4.0) * 100, 2)

    def simulate_kill_chain(self, node_vuln: float, round_num: int = 1) -> KillChainResult:
        vuln_factor = node_vuln / 100.0
        round_decay = max(0.6, 1.0 - (round_num - 1) * 0.04)
        stage_probs: Dict[str,float] = {}
        completed: List[str] = []; failed: List[str] = []; success = False
        for stage in self.kill_chain_stages:
            base = DEFAULT_STAGE_PROBS.get(stage, 0.5)
            if stage in ("exploit","install"):
                prob = base * vuln_factor * round_decay * (self.exploitability / 10.0)
            elif stage == "deliver":
                prob = base * round_decay * (self.exploitability / 10.0)
            else:
                prob = base * round_decay
            prob = min(1.0, max(0.01, prob))
            stage_probs[stage] = round(prob, 4)
            if random.random() < prob:
                completed.append(stage)
                if stage == "act": success = True
            else:
                failed.append(stage); break
        overall = 1.0
        for p in stage_probs.values(): overall *= p
        return KillChainResult(self.threat_id,"",completed,failed,success,stage_probs,round(overall,6))

    def will_attack(self, node_vuln: float, round_num: int = 1) -> bool:
        decay = max(0.5, 1.0 - (round_num - 1) * 0.05)
        return random.random() < self.base_attack_prob * (node_vuln / 100.0) * decay

    def sample_impact(self) -> float:
        lo, hi = self.impact_range_m; likely = (lo + hi) / 2.0
        alpha = 1 + 4 * (likely - lo) / (hi - lo) if hi > lo else 1
        beta  = 1 + 4 * (hi - likely) / (hi - lo) if hi > lo else 1
        return lo + random.betavariate(alpha, beta) * (hi - lo)

    def to_dict(self) -> dict:
        return {"threat_id": self.threat_id, "name": self.name,
                "category": self.category.value, "severity": self.severity.name,
                "mitre": [{"id":t.technique_id,"name":t.name,"tactic":t.tactic}
                          for t in self.mitre_techniques],
                "target_nodes": self.target_node_types,
                "base_prob": self.base_attack_prob, "exploitability": self.exploitability,
                "impact_m": list(self.impact_range_m),
                "kill_chain": self.kill_chain_stages, "iocs": self.iocs}


class ThreatLibrary:
    def __init__(self, intel_path: str = "data/threat_intel.json"):
        self.threats: Dict[str,Threat] = {}
        self._load(intel_path)

    def _load(self, path: str):
        severity_map = {"LOW":ThreatSeverity.LOW,"MEDIUM":ThreatSeverity.MEDIUM,
                        "HIGH":ThreatSeverity.HIGH,"CRITICAL":ThreatSeverity.CRITICAL}
        cat_map = {e.value:e for e in ThreatCategory}
        with open(path) as f: data = json.load(f)
        for td in data["threats"]:
            t = Threat(
                threat_id=td["id"], name=td["name"],
                category=cat_map[td["category"]],
                severity=severity_map[td["severity"]],
                mitre_techniques=[MITRETechnique(m["id"],m["name"],m["tactic"])
                                  for m in td["mitre"]],
                target_node_types=td["targets"],
                base_attack_prob=td["base_prob"],
                impact_range_m=(td["impact_min_m"],td["impact_max_m"]),
                kill_chain_stages=td.get("kill_chain", KILL_CHAIN_STAGES),
                exploitability=td["exploitability"],
                iocs=td.get("iocs",[]), mitigations=td.get("mitigations",[]),
            )
            self.threats[t.threat_id] = t

    def get(self, tid: str) -> Optional[Threat]: return self.threats.get(tid)

    def for_node_type(self, node_type: str) -> List[Threat]:
        return [t for t in self.threats.values() if node_type in t.target_node_types]

    def top_by_risk(self, vuln: float = 70.0, n: int = 5) -> List[Threat]:
        return sorted(self.threats.values(), key=lambda t: t.risk_score(vuln), reverse=True)[:n]

    def to_dict(self) -> dict:
        return {tid: t.to_dict() for tid,t in self.threats.items()}


if __name__ == "__main__":
    import os, sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
    lib = ThreatLibrary("data/threat_intel.json")
    print(f"Loaded {len(lib.threats)} threats\n")
    for t in lib.top_by_risk(75.0):
        r = t.simulate_kill_chain(75.0)
        print(f"[{t.threat_id}] {t.name}")
        print(f"  risk={t.risk_score(75.0):.1f} ALE=${t.ale(75.0):.1f}M/yr  chain_success={r.success}")