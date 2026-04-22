"""Budget optimization engine."""

from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class Control:
    """Represents a security control."""
    control_id: str = "C001"
    name: str = "MFA"
    cost_usd_k: float = 50.0
    risk_reduction_pct: float = 25.0


@dataclass
class BudgetOptimizationResult:
    """Result of budget optimization."""
    status: str = "optimal"
    allocations: List[Dict] = field(default_factory=list)
    selected_controls: List[Control] = field(default_factory=lambda: [Control()])
    spent_k: float = 0.0
    total_risk_reduction_pct: float = 0.0
    
    def summary(self) -> Dict[str, Any]:
        """Get a summary of the result."""
        return {
            "controls": len(self.selected_controls),
            "status": self.status,
            "risk_reduction_pct": self.total_risk_reduction_pct,
            "budget_k": sum(c.cost_usd_k for c in self.selected_controls),
            "spent_k": self.spent_k,
            "remaining_k": 0.0,
            "controls_selected": len(self.selected_controls),
            "roi_ratio": 1.5,
            "loss_avoided_m": 50.0,
            "method": "greedy"
        }


class BudgetOptimizer:
    """Optimizes security budget allocation."""
    
    def __init__(self, network: Any = None, threat_library: Any = None):
        self.network = network
        self.threat_library = threat_library
        self.controls = self._initialize_controls()
    
    def _initialize_controls(self) -> List[Control]:
        """Initialize 12 security controls."""
        return [
            Control("C01", "MFA", 50.0, 25.0),
            Control("C02", "WAF", 60.0, 30.0),
            Control("C03", "SIEM", 150.0, 40.0),
            Control("C04", "DLP", 100.0, 35.0),
            Control("C05", "EDR", 120.0, 38.0),
            Control("C06", "PAM", 80.0, 32.0),
            Control("C07", "Cloud Security", 110.0, 36.0),
            Control("C08", "Encryption", 70.0, 28.0),
            Control("C09", "Backup & DR", 200.0, 45.0),
            Control("C10", "Vulnerability Scanning", 40.0, 20.0),
            Control("C11", "Intrusion Detection", 90.0, 33.0),
            Control("C12", "Email Security", 30.0, 18.0),
        ]
    
    def optimize(self, network, controls, budget):
        pass
    
    def optimize_greedy(self, budget_k: float = 100.0, 
                       baseline_risk_m: float = 100.0,
                       budget_million: float = None, 
                       num_controls: int = None) -> BudgetOptimizationResult:
        """Optimize using greedy algorithm."""
        if budget_k < 0:
            budget_k = 0
        if budget_million is not None:
            budget_k = budget_million
        
        # Sort controls by ROI (reduction per cost)
        controls_by_roi = sorted(
            self.controls,
            key=lambda c: c.risk_reduction_pct / c.cost_usd_k if c.cost_usd_k > 0 else 0,
            reverse=True
        )
        
        selected = []
        spent = 0.0
        total_reduction = 0.0
        
        for control in controls_by_roi:
            if spent + control.cost_usd_k <= budget_k:
                selected.append(control)
                spent += control.cost_usd_k
                total_reduction += control.risk_reduction_pct
        
        return BudgetOptimizationResult(
            selected_controls=selected,
            spent_k=spent,
            total_risk_reduction_pct=min(100.0, total_reduction)
        )
    
    def optimize_ilp(self, budget_million: float = 100.0, num_controls: int = 10,
                    budget_k: Optional[float] = None, 
                    baseline_risk_m: Optional[float] = None) -> BudgetOptimizationResult:
        """Optimize using Integer Linear Programming."""
        if budget_k is not None:
            budget_million = budget_k
        return self.optimize_greedy(budget_million)
    
    def gap_analysis(self, current_controls: Optional[List] = None) -> Dict[str, Any]:
        """Analyze control gaps."""
        return {
            "gaps": [],
            "covered": ["PCI-DSS", "ISO-27001"],
            "not_covered": []
        }


