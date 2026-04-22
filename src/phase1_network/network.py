
# PART 1 — Simulation Architecture & Design Blueprint
# network.py — BankNetwork + NetworkNode
# Includes: BFS/DFS lateral movement, per-node attack surface scoring,
# SIEM-ready state, segmentation scoring.

from __future__ import annotations
import json
from collections import deque
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from enum import Enum


class NodeType(Enum):
    CORE_BANKING     = "core_banking"
    ATM_NETWORK      = "atm_network"
    INTERNET_BANKING = "internet_banking"
    PAYMENT_GATEWAY  = "payment_gateway"
    DATA_CENTER      = "data_center"
    INTERNAL_NETWORK = "internal_network"
    DMZ              = "dmz"
    SWIFT_GATEWAY    = "swift_gateway"


class DefenseLayer(Enum):
    NONE     = 0
    BASIC    = 1
    STANDARD = 2
    ADVANCED = 3
    FORTRESS = 4

    def reduction_factor(self) -> float:
        return {0: 0.0, 1: 0.20, 2: 0.40, 3: 0.65, 4: 0.85}[self.value]

    def upgrade(self) -> "DefenseLayer":
        levels = list(DefenseLayer)
        idx = levels.index(self)
        return levels[min(idx + 1, len(levels) - 1)]


@dataclass
class NetworkNode:
    node_id: str
    name: str
    node_type: NodeType
    vuln_score: float
    defense_layer: DefenseLayer
    connected_to: List[str] = field(default_factory=list)
    asset_value_m: float = 10.0
    pci_in_scope: bool = False
    is_compromised: bool = False
    is_quarantined: bool = False
    compromise_round: int = -1
    siem_alerts: List[dict] = field(default_factory=list)

    def effective_vuln(self) -> float:
        return max(0.0, self.vuln_score * (1 - self.defense_layer.reduction_factor()))

    def attack_surface_score(self) -> float:
        conn_penalty  = min(len(self.connected_to) * 5, 25)
        value_factor  = min(self.asset_value_m / 500.0, 1.0) * 15
        pci_penalty   = 10 if self.pci_in_scope else 0
        return min(100.0, self.effective_vuln() + conn_penalty + value_factor + pci_penalty)

    def compromise(self, round_num: int = 0):
        if not self.is_quarantined:
            self.is_compromised = True
            self.compromise_round = round_num

    def quarantine(self):
        self.is_quarantined = True
        self.is_compromised = False

    def remediate(self):
        self.is_compromised = False
        self.is_quarantined = False
        self.compromise_round = -1

    def upgrade_defense(self) -> bool:
        old = self.defense_layer
        self.defense_layer = self.defense_layer.upgrade()
        return self.defense_layer != old

    def add_siem_alert(self, threat_id: str, severity: str, details: str) -> None:
        self.siem_alerts.append({"node_id": self.node_id, "threat_id": threat_id,
                                  "severity": severity, "details": details})

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id, "name": self.name,
            "type": self.node_type.value,
            "raw_vuln": round(self.vuln_score, 1),
            "effective_vuln": round(self.effective_vuln(), 1),
            "attack_surface": round(self.attack_surface_score(), 1),
            "defense_layer": self.defense_layer.name,
            "connected_to": self.connected_to,
            "asset_value_m": self.asset_value_m,
            "pci_in_scope": self.pci_in_scope,
            "is_compromised": self.is_compromised,
            "is_quarantined": self.is_quarantined,
        }


class BankNetwork:
    """Full bank topology with BFS/DFS lateral movement (Layer 2 correct arch)."""

    def __init__(self, config_path: str = "config/settings.json"):
        with open(config_path) as f:
            cfg = json.load(f)
        self.bank_name = cfg["bank_name"]
        self.nodes: Dict[str, NetworkNode] = {}
        self._build(cfg["nodes"])

    def _build(self, node_configs: list):
        defense_map = {"NONE": DefenseLayer.NONE, "BASIC": DefenseLayer.BASIC,
                       "STANDARD": DefenseLayer.STANDARD, "ADVANCED": DefenseLayer.ADVANCED,
                       "FORTRESS": DefenseLayer.FORTRESS}
        type_map = {e.value: e for e in NodeType}
        for nc in node_configs:
            self.nodes[nc["id"]] = NetworkNode(
                node_id=nc["id"], name=nc["name"],
                node_type=type_map[nc["type"]],
                vuln_score=float(nc["vuln"]),
                defense_layer=defense_map[nc["defense"]],
                connected_to=nc["connects"],
                asset_value_m=nc["value_m"],
                pci_in_scope=nc["pci"],
            )

    def bfs_lateral_path(self, start: str, target: str) -> Optional[List[str]]:
        """Shortest lateral movement path via BFS."""
        if start not in self.nodes or target not in self.nodes:
            return None
        visited: Set[str] = {start}
        queue: deque = deque([[start]])
        while queue:
            path = queue.popleft()
            if path[-1] == target:
                return path
            for nb in self.nodes[path[-1]].connected_to:
                if nb not in visited:
                    visited.add(nb)
                    queue.append(path + [nb])
        return None

    def dfs_all_paths(self, start: str, target: str, max_depth: int = 6) -> List[List[str]]:
        """All kill-chain paths via DFS (bounded)."""
        results: List[List[str]] = []
        def _dfs(cur: str, path: List[str], vis: Set[str]):
            if len(path) > max_depth:
                return
            if cur == target:
                results.append(list(path))
                return
            for nb in self.nodes[cur].connected_to:
                if nb not in vis:
                    vis.add(nb); path.append(nb)
                    _dfs(nb, path, vis)
                    path.pop(); vis.discard(nb)
        _dfs(start, [start], {start})
        return results

    def pivot_probability(self, from_id: str, to_id: str, round_num: int = 1) -> float:
        """Per-node per-stage probability (not single dice roll — Layer 2 correct arch)."""
        src = self.nodes.get(from_id)
        dst = self.nodes.get(to_id)
        if not src or not dst:
            return 0.0
        base = dst.effective_vuln() / 100.0
        decay = max(0.5, 1.0 - (round_num - 1) * 0.05)
        return round(base * decay, 4)

    def high_risk_nodes(self, threshold: float = 50.0) -> List[NetworkNode]:
        return sorted([n for n in self.nodes.values() if n.effective_vuln() >= threshold],
                      key=lambda n: n.effective_vuln(), reverse=True)

    def compromised_nodes(self) -> List[NetworkNode]:
        return [n for n in self.nodes.values() if n.is_compromised]

    def total_asset_value(self) -> float:
        return sum(n.asset_value_m for n in self.nodes.values())

    def segmentation_score(self) -> float:
        path_ic = len(self.bfs_lateral_path("N01", "N04") or [])
        path_is = len(self.bfs_lateral_path("N01", "N07") or [])
        penalty = max(0, (8 - path_ic) * 4 + (8 - path_is) * 6)
        return max(0.0, min(100.0, 100.0 - penalty))

    def topology_summary(self) -> dict:
        return {
            "bank": self.bank_name,
            "total_nodes": len(self.nodes),
            "total_asset_m": round(self.total_asset_value(), 1),
            "avg_eff_vuln": round(sum(n.effective_vuln() for n in self.nodes.values()) / len(self.nodes), 1),
            "high_risk_nodes": [n.node_id for n in self.high_risk_nodes()],
            "pci_scope": [n.node_id for n in self.nodes.values() if n.pci_in_scope],
            "segmentation_score": round(self.segmentation_score(), 1),
            "internet_to_core_path": self.bfs_lateral_path("N01", "N04"),
            "internet_to_swift_path": self.bfs_lateral_path("N01", "N07"),
        }

    def to_dict(self) -> dict:
        return {"bank_name": self.bank_name,
                "nodes": {nid: n.to_dict() for nid, n in self.nodes.items()}}


if __name__ == "__main__":
    import os, sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
    net = BankNetwork("config/settings.json")
    print(json.dumps(net.topology_summary(), indent=2))
    paths = net.dfs_all_paths("N01", "N04")
    print(f"\nInternet → Core Banking: {len(paths)} kill-chain paths found")
    for p in paths[:3]:
        print(f"  {' → '.join(p)}")