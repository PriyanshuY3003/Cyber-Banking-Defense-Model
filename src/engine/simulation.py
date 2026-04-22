"""Monte Carlo simulation engine."""

from typing import Optional, Dict, Any
import random


class SimulationReport:
    """Report from a simulation run."""
    def __init__(self, total_attacks_attempted: int = 0, total_loss_m: float = 0.0, 
                 confidence_interval_95: Optional[tuple[float, float]] = None):
        self.data = {"rounds": 1000, "total_losses": 0.0}
        self.total_attacks_attempted = total_attacks_attempted
        self.total_loss_m = total_loss_m
        self.confidence_interval_95 = confidence_interval_95 or (0.0, 0.0)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "attacks_attempted": self.total_attacks_attempted,
            "attacks_successful": self.total_attacks_attempted,  # Assuming all attempted are successful in this simple model
            "success_rate_pct": 100.0 if self.total_attacks_attempted > 0 else 0.0,
            "total_loss_m": self.total_loss_m,
            "fair_uncertainty": {
                "likely_m": self.total_loss_m,
                "ci95": self.confidence_interval_95
            },
            "incidents_total": self.total_attacks_attempted,
            "incidents_p1": int(self.total_attacks_attempted * 0.1),  # 10% critical
            "sla_breaches": int(self.total_attacks_attempted * 0.05),  # 5% SLA breaches
            "top_mitre": ["T1059", "T1078", "T1566", "T1021", "T1548"]  # Sample MITRE techniques
        }


class SimulationEngine:
    """Runs multi-round Monte Carlo simulations."""
    def __init__(self, network, threat_library, rounds: int = 1000, 
                 mc_iterations: int = 1000, seed: Optional[int] = None):
        self.network = network
        self.threat_library = threat_library
        self.rounds = rounds
        self.mc_iterations = mc_iterations
        self.seed = seed
        if seed:
            random.seed(seed)
    
    def run(self):
        """Run the simulation."""
        losses = []
        total_attacks = 0
        
        for round_idx in range(self.rounds):
            round_loss = 0.0
            round_attacks = 0
            
            # Try each threat against each network node
            for node in self.network.nodes.values():
                for threat_id in ["T-001", "T-002", "T-003", "T-004", "T-005", "T-006", "T-007", "T-008"]:
                    threat = self.threat_library.get(threat_id)
                    if threat:
                        # Sample attack success
                        if random.random() < 0.3:  # 30% base success rate
                            impact = threat.sample_impact()
                            round_loss += impact
                            round_attacks += 1
            
            total_attacks += round_attacks
            losses.append(round_loss)
        
        # Compute statistics
        avg_loss = sum(losses) / len(losses) if losses else 0.0
        sorted_losses = sorted(losses)
        low_idx = int(len(sorted_losses) * 0.025)
        high_idx = int(len(sorted_losses) * 0.975)
        ci_95 = (sorted_losses[low_idx], sorted_losses[high_idx]) if len(sorted_losses) > 1 else (0.0, avg_loss)
        
        return SimulationReport(
            total_attacks_attempted=total_attacks,
            total_loss_m=avg_loss,
            confidence_interval_95=ci_95
        )
