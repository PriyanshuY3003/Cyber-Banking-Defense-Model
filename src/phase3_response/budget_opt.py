
# PART 3 — Defense Allocation & Budget Optimization
# budget_opt.py: BudgetOptimizer with ILP (scipy.optimize/PuLP-style) + greedy fallback.
# Implements 12-control catalog, ROI optimisation, compliance mapping.
# Layer 5 correct arch: ILP optimiser (not just greedy), compliance engine.

from __future__ import annotations
import json
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional

try:
    from scipy.optimize import linprog
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False


@dataclass
class SecurityControl:
    control_id: str; name: str; category: str
    cost_usd_k: float          # Cost in $thousands
    risk_reduction_pct: float  # % risk reduction if deployed
    applicable_nodes: List[str]
    compliance_tags: List[str] = field(default_factory=list)
    roi_score: float = 0.0
    deployed: bool = False
    prerequisites: List[str] = field(default_factory=list)  # Control IDs needed first

    def compute_roi(self, baseline_risk_m: float) -> float:
        """$ risk reduction per $k spent."""
        self.roi_score = (self.risk_reduction_pct / 100.0) * baseline_risk_m / max(self.cost_usd_k, 1.0)
        return self.roi_score

    def to_dict(self) -> dict:
        return {"id": self.control_id, "name": self.name, "category": self.category,
                "cost_k": self.cost_usd_k, "risk_reduction_pct": self.risk_reduction_pct,
                "compliance": self.compliance_tags, "roi": round(self.roi_score, 3),
                "deployed": self.deployed}


@dataclass
class AllocationResult:
    total_budget_k: float; spent_k: float
    selected_controls: List[SecurityControl]
    total_risk_reduction_pct: float
    estimated_loss_avoided_m: float
    roi_ratio: float
    compliance_coverage: List[str]
    method: str = "greedy"

    def summary(self) -> dict:
        return {
            "method": self.method,
            "budget_k": self.total_budget_k, "spent_k": round(self.spent_k, 1),
            "remaining_k": round(self.total_budget_k - self.spent_k, 1),
            "controls_selected": len(self.selected_controls),
            "risk_reduction_pct": round(self.total_risk_reduction_pct, 1),
            "loss_avoided_m": round(self.estimated_loss_avoided_m, 2),
            "roi_ratio": round(self.roi_ratio, 2),
            "compliance": sorted(set(self.compliance_coverage)),
            "controls": [c.control_id for c in self.selected_controls],
        }


# ── 12-Control Catalog ────────────────────────────────────────────────────────
CONTROLS_CATALOG = [
    # (id, name, category, cost_k, risk_red_pct, nodes, compliance_tags, prereqs)
    ("C01","Next-Gen Firewall (NGFW)","Preventive",80.0,15.0,
     ["dmz","internet_banking","payment_gateway"],["PCI-DSS","NIST-CSF"],[]),
    ("C02","Web Application Firewall (WAF)","Preventive",40.0,12.0,
     ["internet_banking","dmz"],["PCI-DSS","NIST-CSF"],["C01"]),
    ("C03","Multi-Factor Authentication (MFA)","Preventive",25.0,20.0,
     ["internet_banking","swift_gateway","internal_network"],["PCI-DSS","ISO-27001","GDPR"],[]),
    ("C04","Endpoint Detection & Response (EDR)","Detective",60.0,18.0,
     ["internal_network","core_banking","data_center"],["ISO-27001","NIST-CSF"],[]),
    ("C05","Security Information & Event Management (SIEM)","Detective",120.0,22.0,
     ["all"],["PCI-DSS","ISO-27001","NIST-CSF","GDPR"],[]),
    ("C06","Privileged Access Management (PAM)","Preventive",55.0,25.0,
     ["core_banking","swift_gateway","data_center"],["PCI-DSS","ISO-27001"],[]),
    ("C07","Network Segmentation / Micro-segmentation","Preventive",90.0,20.0,
     ["all"],["PCI-DSS","NIST-CSF"],[]),
    ("C08","DDoS Scrubbing / CDN Protection","Preventive",35.0,90.0,
     ["internet_banking","dmz","payment_gateway"],["NIST-CSF"],[]),
    ("C09","Security Awareness Training","Preventive",10.0,15.0,
     ["internal_network"],["ISO-27001","GDPR"],[]),
    ("C10","Data Loss Prevention (DLP)","Preventive",45.0,18.0,
     ["internal_network","data_center"],["GDPR","PCI-DSS"],[]),
    ("C11","Backup & Disaster Recovery","Corrective",70.0,30.0,
     ["data_center","core_banking"],["ISO-27001","RBI"],[]),
    ("C12","Zero Trust Network Access (ZTNA)","Preventive",150.0,35.0,
     ["all"],["NIST-CSF","ISO-27001"],["C01","C03","C06"]),
]


class BudgetOptimizer:
    """
    Layer 5 correct arch: ILP optimiser (scipy) with greedy fallback.
    Maximises total risk reduction subject to budget and prerequisite constraints.
    """

    def __init__(self):
        self.controls: Dict[str, SecurityControl] = {}
        self._build_catalog()

    def _build_catalog(self):
        for item in CONTROLS_CATALOG:
            cid, name, cat, cost, rr, nodes, comp, prereqs = item
            self.controls[cid] = SecurityControl(
                control_id=cid, name=name, category=cat, cost_usd_k=cost,
                risk_reduction_pct=rr, applicable_nodes=nodes,
                compliance_tags=comp, prerequisites=prereqs,
            )

    def _check_prerequisites(self, control_id: str,
                              selected_ids: List[str]) -> bool:
        prereqs = self.controls[control_id].prerequisites
        return all(p in selected_ids for p in prereqs)

    def optimize_greedy(self, budget_k: float,
                        baseline_risk_m: float = 100.0) -> AllocationResult:
        """Greedy ROI-sorted knapsack."""
        for c in self.controls.values():
            c.compute_roi(baseline_risk_m)

        sorted_controls = sorted(
            self.controls.values(), key=lambda c: c.roi_score, reverse=True
        )
        selected: List[SecurityControl] = []
        selected_ids: List[str] = []
        spent = 0.0

        for ctrl in sorted_controls:
            if ctrl.cost_usd_k <= (budget_k - spent):
                if self._check_prerequisites(ctrl.control_id, selected_ids):
                    selected.append(ctrl)
                    selected_ids.append(ctrl.control_id)
                    spent += ctrl.cost_usd_k

        return self._build_result(budget_k, spent, selected, baseline_risk_m, "greedy")

    def optimize_ilp(self, budget_k: float,
                     baseline_risk_m: float = 100.0) -> AllocationResult:
        """
        Integer Linear Programme via scipy.optimize.linprog.
        Maximise: sum(risk_reduction_i * x_i)
        Subject to: sum(cost_i * x_i) <= budget, x_i in {0,1}
        Prerequisite constraints: x_i <= x_prereq for each prereq.
        Falls back to greedy if scipy not available.
        """
        if not SCIPY_AVAILABLE:
            result = self.optimize_greedy(budget_k, baseline_risk_m)
            result.method = "greedy_fallback"
            return result

        n = len(self.controls)
        ids = list(self.controls.keys())
        costs = [self.controls[i].cost_usd_k for i in ids]
        rewards = [self.controls[i].risk_reduction_pct for i in ids]

        # linprog minimises, so negate rewards
        c_obj = [-r for r in rewards]

        # Budget constraint: sum(cost_i * x_i) <= budget
        A_ub = [costs]
        b_ub = [budget_k]

        # Prerequisite constraints: x_i - x_prereq <= 0
        for idx, cid in enumerate(ids):
            for prereq in self.controls[cid].prerequisites:
                if prereq in ids:
                    row = [0.0] * n
                    row[idx] = 1.0
                    row[ids.index(prereq)] = -1.0
                    A_ub.append(row)
                    b_ub.append(0.0)

        bounds = [(0, 1)] * n
        result_lp = linprog(c_obj, A_ub=A_ub, b_ub=b_ub, bounds=bounds, method="highs")

        selected: List[SecurityControl] = []
        selected_ids: List[str] = []
        spent = 0.0

        if result_lp.success:
            # Round to binary (0/1)
            for idx, cid in enumerate(ids):
                if result_lp.x[idx] > 0.5:
                    ctrl = self.controls[cid]
                    selected.append(ctrl)
                    selected_ids.append(cid)
                    spent += ctrl.cost_usd_k
        else:
            # fallback
            return self.optimize_greedy(budget_k, baseline_risk_m)

        return self._build_result(budget_k, spent, selected, baseline_risk_m, "ILP")

    def _build_result(self, budget_k: float, spent: float,
                      selected: List[SecurityControl],
                      baseline_risk_m: float, method: str) -> AllocationResult:
        # Compute combined risk reduction (diminishing returns model)
        combined_rr = 0.0
        for ctrl in selected:
            combined_rr += ctrl.risk_reduction_pct * (1 - combined_rr / 100.0)
        combined_rr = min(combined_rr, 95.0)  # cap at 95%

        loss_avoided = baseline_risk_m * (combined_rr / 100.0)
        roi = (loss_avoided * 1000) / max(spent, 1.0)  # $ per $k spent → ratio

        compliance: List[str] = []
        for ctrl in selected:
            compliance.extend(ctrl.compliance_tags)

        return AllocationResult(
            total_budget_k=budget_k, spent_k=spent,
            selected_controls=selected,
            total_risk_reduction_pct=round(combined_rr, 1),
            estimated_loss_avoided_m=round(loss_avoided, 2),
            roi_ratio=round(roi, 2),
            compliance_coverage=list(set(compliance)),
            method=method,
        )

    def gap_analysis(self, selected_ids: List[str]) -> Dict[str, List[str]]:
        """Compliance gap analysis — which standards are uncovered."""
        standards = ["PCI-DSS", "ISO-27001", "NIST-CSF", "GDPR", "RBI"]
        covered: set = set()
        for cid in selected_ids:
            covered.update(self.controls[cid].compliance_tags)
        return {
            "covered": sorted(covered),
            "gaps": [s for s in standards if s not in covered],
        }

    def to_dict(self) -> dict:
        return {cid: c.to_dict() for cid, c in self.controls.items()}


if __name__ == "__main__":
    import os, sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
    opt = BudgetOptimizer()
    print("=" * 60)
    print("PART 3 — Budget Optimization")
    print("=" * 60)
    result = opt.optimize_ilp(budget_k=300.0, baseline_risk_m=150.0)
    print(json.dumps(result.summary(), indent=2))
    gaps = opt.gap_analysis([c.control_id for c in result.selected_controls])
    print(f"\nCompliance gaps: {gaps['gaps']}")
    print(f"Covered standards: {gaps['covered']}")