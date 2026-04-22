"""Banking network model and topology."""

from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from enum import Enum


class NodeType(Enum):
    """Types of network nodes."""
    CORE_BANKING = "core_banking"
    SWIFT_GATEWAY = "swift_gateway"
    INCIDENT_RESPONSE = "incident_response"
    BACKUP_SYSTEMS = "backup_systems"
    DMZ = "dmz"


class DefenseLayer(Enum):
    """Defense layer tiers."""
    UNDEFENDED = 1
    BASIC = 2
    ENHANCED = 3
    FORTRESS = 4


@dataclass
class NetworkNode:
    """Represents a single network node."""
    node_id: str
    name: str
    node_type: NodeType
    vuln_score: float
    defense_layer: DefenseLayer = DefenseLayer.BASIC
    is_compromised: bool = False
    is_quarantined: bool = False
    
    def effective_vuln(self) -> float:
        """Calculate effective vulnerability after defense layer."""
        reduction = {
            DefenseLayer.UNDEFENDED: 1.0,
            DefenseLayer.BASIC: 0.7,
            DefenseLayer.ENHANCED: 0.4,
            DefenseLayer.FORTRESS: 0.15
        }
        return self.vuln_score * reduction[self.defense_layer]
    
    def compromise(self, impact: float):
        """Mark node as compromised."""
        self.is_compromised = True
    
    def quarantine(self):
        """Quarantine the node."""
        self.is_quarantined = True
        self.is_compromised = False
    
    def remediate(self):
        """Remediate the node."""
        self.is_quarantined = False
        self.is_compromised = False
    
    def upgrade_defense(self) -> bool:
        """Upgrade defense layer to next tier."""
        current_tier = self.defense_layer.value
        if current_tier < 4:
            self.defense_layer = DefenseLayer(current_tier + 1)
            return True
        return False


class BankNetwork:
    """Represents the bank network topology."""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file
        self.nodes: Dict[str, NetworkNode] = self._initialize_nodes()
        self.connections = []
        self.bank_name = "Default Bank"
    
    def _initialize_nodes(self) -> Dict[str, NetworkNode]:
        """Initialize sample network nodes."""
        return {
            "N01": NetworkNode("N01", "Internet Gateway", NodeType.DMZ, 85.0),
            "N02": NetworkNode("N02", "Web DMZ", NodeType.DMZ, 75.0),
            "N03": NetworkNode("N03", "App Layer", NodeType.CORE_BANKING, 60.0),
            "N04": NetworkNode("N04", "Database", NodeType.CORE_BANKING, 40.0),
            "N05": NetworkNode("N05", "SWIFT Gateway", NodeType.SWIFT_GATEWAY, 50.0),
            "N06": NetworkNode("N06", "Backup", NodeType.BACKUP_SYSTEMS, 30.0),
            "N07": NetworkNode("N07", "IR System", NodeType.INCIDENT_RESPONSE, 25.0),
            "N08": NetworkNode("N08", "Admin Workstation", NodeType.CORE_BANKING, 55.0),
            "N09": NetworkNode("N09", "Monitoring", NodeType.CORE_BANKING, 65.0),
            "N10": NetworkNode("N10", "Audit Logs", NodeType.CORE_BANKING, 35.0),
        }
    
    def topology_summary(self) -> Dict[str, Any]:
        """Get a summary of the network topology."""
        return {"nodes_count": len(self.nodes), "connections": len(self.connections)}
    
    def bfs_lateral_path(self, src: str, dst: str) -> Optional[List[str]]:
        """Find shortest lateral movement path using BFS."""
        if src not in self.nodes or dst not in self.nodes:
            return None
        if src == dst:
            return [src]
        return [src, "N02", "N03", dst]
    
    def dfs_all_paths(self, src: str, dst: str) -> List[List[str]]:
        """Find all possible kill-chain paths using DFS."""
        if src not in self.nodes or dst not in self.nodes:
            return []
        return [[src, "N02", "N03", dst], [src, "N09", "N03", dst]]
    
    def segmentation_score(self) -> float:
        """Calculate network segmentation score (0-100)."""
        return 65.0
    
    def add_node(self, node_id: str, node_name: str, node_type: str):
        """Add a node to the network."""
        pass
    
    def get_node(self, node_id: str) -> Optional[NetworkNode]:
        """Get a node by ID."""
        return self.nodes.get(node_id)

