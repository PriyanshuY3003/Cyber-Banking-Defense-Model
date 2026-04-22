
# PART 7 — Security Operations Dashboard & Platform Orchestrator          
# main.py — SOC Terminal Dashboard                                          
# Pipeline: load → simulate → assess → optimise → report → display        
# Integrates all 7 parts into unified platform                              

from __future__ import annotations
import json
import os
import sys
import time
from datetime import datetime
from typing import Optional

# ── Path setup
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from src.phase1_network.network    import BankNetwork
from src.models.threat     import ThreatLibrary
from src.engine.simulation import SimulationEngine
from src.engine.risk_calc  import RiskCalculator
from src.engine.budget_opt import BudgetOptimizer
from src.utils.logger      import ComplianceLogger, AuditEventType
from src.ml.ml_detection   import (AnomalyDetector, FraudClassifier,
                                    generate_network_events, generate_transactions)
from data.data_loader      import DataLoader

# ANSI Colors for terminal dashboard 
R  = "\033[91m"   # Red
G  = "\033[92m"   # Green
Y  = "\033[93m"   # Yellow
B  = "\033[94m"   # Blue
M  = "\033[95m"   # Magenta
C  = "\033[96m"   # Cyan
W  = "\033[97m"   # White (bright)
DIM = "\033[2m"
RESET = "\033[0m"
BOLD = "\033[1m"


def banner():
    print("""
================================================================================
   CYBER BANKING DEFENSE PLATFORM v2.0 | 7-Phase Architecture | MITRE ATT&CK v14
   PCI-DSS . ISO-27001 . NIST-CSF 2.0 . GDPR . RBI Compliant
================================================================================
""")


def section(title: str, color: str = B):
    print(f"\n{color}{'─'*76}{RESET}")
    print(f"{color}{BOLD}  {title}{RESET}")
    print(f"{color}{'─'*76}{RESET}")


def status(label: str, value, color: str = W, ok: bool = True):
    icon = f"{G}✓{RESET}" if ok else f"{R}✗{RESET}"
    print(f"  {icon} {DIM}{label:<35}{RESET} {color}{BOLD}{value}{RESET}")


def risk_color(score: float) -> str:
    if score >= 75: return R
    if score >= 50: return Y
    if score >= 25: return C
    return G


def severity_color(sev: str) -> str:
    return {
        "CRITICAL": R, "HIGH": Y, "MEDIUM": C, "LOW": G, "INFO": DIM
    }.get(sev, W)


def tier_bar(score: float, width: int = 20) -> str:
    filled = int(score / 100 * width)
    col    = risk_color(score)
    return f"{col}{'█' * filled}{'░' * (width - filled)}{RESET} {col}{score:.0f}{RESET}"


class CyberBankingPlatform:
    """
    Main orchestrator — wires all 7 parts together.
    Implements: load → simulate → assess → optimise → report → display
    """

    def __init__(self, config_path: str = "config/settings.json",
                 intel_path: str = "data/threat_intel.json"):
        self.config_path = config_path
        self.intel_path  = intel_path
        with open(config_path) as f:
            self.cfg = json.load(f)

        # Core components
        self.network    : Optional[BankNetwork]       = None
        self.lib        : Optional[ThreatLibrary]     = None
        self.engine     : Optional[SimulationEngine]  = None
        self.calc       : Optional[RiskCalculator]    = None
        self.optimizer  : Optional[BudgetOptimizer]   = None
        self.logger     : Optional[ComplianceLogger]  = None
        self.detector   : Optional[AnomalyDetector]   = None
        self.classifier : Optional[FraudClassifier]   = None

        # Results
        self.sim_report     = None
        self.risk_summary   = None
        self.budget_result  = None
        self.anomaly_results = []
        self.fraud_results   = []

    # ── Phase 1: Load ─────────────────────────────────────────────────────────

    def phase_load(self):
        section("PHASE 1 — Load: Network Architecture & Threat Intelligence")
        os.makedirs("logs", exist_ok=True)

        self.network = BankNetwork(self.config_path)
        self.lib     = ThreatLibrary(self.intel_path)
        self.logger  = ComplianceLogger("logs")

        topo = self.network.topology_summary()
        status("Bank name",             self.network.bank_name)
        status("Nodes loaded",          len(self.network.nodes))
        status("Total asset value",     f"${topo['total_asset_m']:.0f}M")
        status("Avg effective vuln",    f"{topo['avg_eff_vuln']:.1f}/100",
               color=risk_color(topo['avg_eff_vuln']))
        status("Segmentation score",    f"{topo['segmentation_score']:.1f}/100",
               color=G if topo['segmentation_score'] > 60 else R)
        status("Threats loaded",        len(self.lib.threats))
        status("PCI-DSS scope nodes",   len(topo['pci_scope']))
        status("Internet→Core path",    " → ".join(topo['internet_to_core_path'] or ["None"]),
               color=Y)
        status("Internet→SWIFT path",   " → ".join(topo['internet_to_swift_path'] or ["None"]),
               color=R)

        self.logger.log(AuditEventType.SIMULATION_START, "PLATFORM",
                        details={"nodes": len(self.network.nodes),
                                 "threats": len(self.lib.threats)}, severity="INFO")

    # ── Phase 2: Simulate ─────────────────────────────────────────────────────

    def phase_simulate(self):
        section("PHASE 2 — Simulate: Monte Carlo Attack Simulation (Parts 1+2+4)")
        sim_cfg = self.cfg["simulation"]

        self.engine = SimulationEngine(
            self.network, self.lib,
            rounds=sim_cfg["rounds"],
            mc_iterations=sim_cfg["monte_carlo_iterations"],
            seed=sim_cfg["seed"],
        )

        t0 = time.time()
        self.sim_report = self.engine.run()
        elapsed = time.time() - t0

        r = self.sim_report.to_dict()
        status("Simulation time",       f"{elapsed:.1f}s")
        status("Attacks attempted",     r["attacks_attempted"])
        status("Attacks successful",    r["attacks_successful"],
               color=R if r["attacks_successful"] > 0 else G)
        status("Success rate",          f"{r['success_rate_pct']}%",
               color=R if r['success_rate_pct'] > 20 else Y)
        status("Total simulated loss",  f"${r['total_loss_m']:.1f}M", color=R)
        status("FAIR ALE (likely)",     f"${r['fair_uncertainty']['likely_m']:.1f}M")
        status("FAIR CI-95",
               f"[${r['fair_uncertainty']['ci95'][0]:.1f}M – ${r['fair_uncertainty']['ci95'][1]:.1f}M]")
        status("Incidents raised",      r["incidents_total"])
        status("P1 Critical incidents", r["incidents_p1"], color=R if r["incidents_p1"] > 0 else G)
        status("SLA breaches",          r["sla_breaches"], color=R if r["sla_breaches"] > 0 else G,
               ok=r["sla_breaches"] == 0)

        if r.get("top_mitre"):
            print(f"\n  {DIM}Top MITRE Techniques:{RESET}")
            for tid in r["top_mitre"][:5]:
                print(f"    {Y}• {tid}{RESET}")

    # ── Phase 3: Assess ───────────────────────────────────────────────────────

    def phase_assess(self):
        section("PHASE 3 — Assess: FAIR Risk Assessment (Part 5)")
        self.calc = RiskCalculator(self.network, self.lib)
        self.risk_summary = self.calc.risk_summary()
        s = self.risk_summary.to_dict()

        status("Total Estate ALE",      f"${s['total_ale_m']:.1f}M/yr", color=R)
        status("ALE Range",             f"[${s['ale_range'][0]:.1f}M – ${s['ale_range'][1]:.1f}M]")
        status("Systemic Risk Score",   tier_bar(s['systemic_risk_score']))
        status("CRITICAL risk pairs",   s['by_tier']['CRITICAL'], color=R)
        status("HIGH risk pairs",       s['by_tier']['HIGH'],     color=Y)
        status("MEDIUM risk pairs",     s['by_tier']['MEDIUM'],   color=C)

        print(f"\n  {DIM}Top Risk Threats:{RESET}")
        for r in s['top_threats'][:3]:
            print(f"    {risk_color(r['risk_score'])}[{r['risk_score']:.0f}] "
                  f"{r['threat'].split('—')[1].strip()}{RESET}")

        print(f"\n  {DIM}Top Risk Nodes:{RESET}")
        for r in s['top_nodes'][:3]:
            assert self.network is not None, "Network not initialized"
            node = self.network.nodes.get(r['node'].split('—')[0].strip())
            name = node.name if node else r['node']
            print(f"    {risk_color(r['risk_score'])}[{r['risk_score']:.0f}] "
                  f"{name}{RESET}")

        print(f"\n  {DIM}Compliance Risk Nodes:{RESET}")
        for std, nodes in s['compliance_risks'].items():
            if nodes:
                print(f"    {R}{std}: {', '.join(nodes)}{RESET}")

        assert self.logger is not None, "Logger not initialized"
        self.logger.log(AuditEventType.RISK_ASSESSED, "RiskCalculator",
                        details={"ale_m": s['total_ale_m'],
                                 "systemic_score": s['systemic_risk_score']},
                        severity="HIGH")

    # ── Phase 4: Optimise ─────────────────────────────────────────────────────

    def phase_optimise(self):
        section("PHASE 4 — Optimise: Defense Allocation & Budget (Part 3)")
        self.optimizer = BudgetOptimizer()
        budget_k       = self.cfg["budget"]["total_usd_k"]
        baseline_m     = self.risk_summary.total_ale_m if self.risk_summary else 100.0

        self.budget_result = self.optimizer.optimize_ilp(
            budget_k=budget_k, baseline_risk_m=baseline_m
        )
        b = self.budget_result.summary()
        gaps = self.optimizer.gap_analysis(
            [c.control_id for c in self.budget_result.selected_controls]
        )

        status("Budget",                f"${b['budget_k']:.0f}k")
        status("Spent",                 f"${b['spent_k']:.0f}k")
        status("Remaining",             f"${b['remaining_k']:.0f}k")
        status("Controls selected",     b['controls_selected'])
        status("Risk reduction",        f"{b['risk_reduction_pct']}%", color=G)
        status("Loss avoided",          f"${b['loss_avoided_m']:.1f}M/yr", color=G)
        status("ROI",                   f"{b['roi_ratio']:.1f}x return", color=G)
        status("Method",                b['method'])

        print(f"\n  {DIM}Selected Controls:{RESET}")
        for c in self.budget_result.selected_controls:
            print(f"    {G}✓ [{c.control_id}] {c.name:<40}{RESET} "
                  f"{DIM}${c.cost_usd_k:.0f}k | {c.risk_reduction_pct:.0f}% reduction{RESET}")

        if gaps['gaps']:
            print(f"\n  {R}Compliance Gaps: {', '.join(gaps['gaps'])}{RESET}")
        else:
            print(f"\n  {G}All compliance standards covered!{RESET}")

        assert self.logger is not None, "Logger not initialized"
        self.logger.log(AuditEventType.CONTROL_DEPLOYED, "BudgetOptimizer",
                        details={"controls": b['controls'],
                                 "risk_reduction_pct": b['risk_reduction_pct']},
                        severity="INFO")

    # ── Phase 5: ML Detection ─────────────────────────────────────────────────

    def phase_ml(self):
        section("PHASE 5 — ML Detection: Anomaly + Fraud (Part 4 ML Layer)")
        ml_cfg = self.cfg["ml"]

        # Load real data
        loader = DataLoader()
        all_events = loader.load_network_events()
        all_txs = loader.load_transactions()

        # Split for training/testing (simple split)
        train_events = all_events[:int(0.8 * len(all_events))]
        test_events = all_events[int(0.8 * len(all_events)):]
        train_txs = all_txs[:int(0.8 * len(all_txs))]
        test_txs = all_txs[int(0.8 * len(all_txs)):]

        # Anomaly detection
        self.detector = AnomalyDetector(contamination=ml_cfg["anomaly_contamination"])
        self.detector.fit(train_events)
        self.anomaly_results = self.detector.predict(test_events)
        anomalies = [r for r in self.anomaly_results if r.is_anomaly]
        status("Network events tested", len(test_events))
        status("Anomalies detected",    len(anomalies),
               color=R if len(anomalies) > 5 else G)
        if anomalies:
            top = max(anomalies, key=lambda r: r.anomaly_score)
            print(f"  {DIM}Highest anomaly: node={top.node_id} "
                  f"score={top.anomaly_score:.4f} "
                  f"features={top.top_features}{RESET}")

        # Fraud classification
        self.classifier = FraudClassifier(threshold=ml_cfg["fraud_threshold"])
        self.classifier.fit(train_txs)
        self.fraud_results = self.classifier.predict(test_txs)
        fraud = [r for r in self.fraud_results if r.is_fraud]
        status("Transactions scored",   len(test_txs))
        status("Fraud flagged",         len(fraud),
               color=R if len(fraud) > 3 else G)
        if fraud:
            top_f = max(fraud, key=lambda r: r.fraud_probability)
            print(f"  {DIM}Highest risk tx: {top_f.tx_id} "
                  f"prob={top_f.fraud_probability:.3f} "
                  f"action={top_f.recommended_action}{RESET}")

    # ── Phase 6: Report ───────────────────────────────────────────────────────

    def phase_report(self):
        section("PHASE 6 — Compliance Reports & Audit Trail (Part 6)")
        assert self.logger is not None, "Logger not initialized"
        chain = self.logger.verify_chain()
        status("Chain integrity",
               "VALID ✓" if chain['valid'] else "COMPROMISED ✗",
               color=G if chain['valid'] else R, ok=chain['valid'])
        status("Events logged",         chain['events_checked'])
        status("Chain tip",             chain.get('chain_tip', 'N/A'))

        reports = self.logger.generate_report(
            standards=["PCI-DSS","ISO-27001","NIST-CSF","GDPR"],
            output_dir="logs"
        ) or {}
        for std, rpt in reports.items():
            status(f"{std} events",
                   f"{rpt['total_events']} ({rpt['critical_events']} critical)",
                   color=R if rpt['critical_events'] > 0 else G)
        print(f"\n  {G}Reports saved to logs/ directory{RESET}")

    # ── Phase 7: Dashboard Display ────────────────────────────────────────────

    def phase_dashboard(self):
        section("PHASE 7 — SOC Operations Dashboard")
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        r   = self.sim_report.to_dict() if self.sim_report else {}
        s   = self.risk_summary.to_dict() if self.risk_summary else {}
        b   = self.budget_result.summary() if self.budget_result else {}

        print(f"""
{B}╔{'═'*72}╗
║{W}{BOLD}  SOC OPERATIONS CENTRE — EXECUTIVE DASHBOARD                           {RESET}{B}  ║
║{DIM}  {now:<70}{RESET}{B}  ║
╠{'═'*72}╣{RESET}""")

        def box_row(label, value, color=W):
            line = f"  {DIM}{label:<28}{RESET} {color}{BOLD}{value}{RESET}"
            padding = 72 - len(label) - len(str(value)) - 6
            print(f"{B}║{RESET}{line}")

        # Threat status
        print(f"{B}║{RESET}  {C}{BOLD}THREAT STATUS{RESET}")
        box_row("Simulation Rounds", r.get('rounds', 'N/A'))
        box_row("Attacks Simulated", r.get('attacks_attempted', 'N/A'))
        box_row("Breach Events", r.get('attacks_successful', 'N/A'),
                color=R if r.get('attacks_successful',0) > 0 else G)
        box_row("Total Simulated Loss", f"${r.get('total_loss_m',0):.1f}M", color=R)
        box_row("FAIR ALE Estimate",
                f"${s.get('total_ale_m',0):.1f}M/yr", color=R)
        box_row("Systemic Risk Score",
                f"{s.get('systemic_risk_score',0):.1f}/100",
                color=risk_color(s.get('systemic_risk_score',50)))

        # Budget status
        print(f"{B}║{RESET}")
        print(f"{B}║{RESET}  {G}{BOLD}DEFENSE STATUS{RESET}")
        box_row("Budget Allocated", f"${b.get('budget_k',0):.0f}k")
        box_row("Controls Deployed", b.get('controls_selected', 0), color=G)
        box_row("Risk Reduction", f"{b.get('risk_reduction_pct',0):.1f}%", color=G)
        box_row("Loss Avoided (annual)", f"${b.get('loss_avoided_m',0):.1f}M", color=G)
        box_row("ROI", f"{b.get('roi_ratio',0):.1f}x", color=G)

        # Incident status
        print(f"{B}║{RESET}")
        print(f"{B}║{RESET}  {R}{BOLD}INCIDENT STATUS{RESET}")
        box_row("Total Incidents", r.get('incidents_total', 0))
        box_row("P1 Critical", r.get('incidents_p1', 0),
                color=R if r.get('incidents_p1',0) > 0 else G)
        box_row("SLA Breaches", r.get('sla_breaches', 0),
                color=R if r.get('sla_breaches',0) > 0 else G)
        box_row("Anomalies Detected", sum(1 for a in self.anomaly_results if a.is_anomaly))
        box_row("Fraud Transactions", sum(1 for f in self.fraud_results if f.is_fraud))

        print(f"{B}╠{'═'*72}╣{RESET}")

        # Recommendations
        print(f"{B}║{RESET}  {Y}{BOLD}RECOMMENDATIONS{RESET}")
        for i, rec in enumerate(r.get('recommendations', [])[:4], 1):
            rec_short = rec[:68] + "..." if len(rec) > 68 else rec
            print(f"{B}║{RESET}  {DIM}{i}. {rec_short}{RESET}")

        print(f"{B}╚{'═'*72}╝{RESET}")

        # Save dashboard JSON
        dashboard_data = {
            "generated_at": now,
            "simulation": r,
            "risk": s,
            "budget": b,
            "anomalies": sum(1 for a in self.anomaly_results if a.is_anomaly),
            "fraud_flagged": sum(1 for f in self.fraud_results if f.is_fraud),
        }
        with open("logs/dashboard_out.json", "w") as f:
            json.dump(dashboard_data, f, indent=2)
        print(f"\n  {G}Dashboard JSON saved to logs/dashboard_out.json{RESET}")

    # ── Full pipeline ─────────────────────────────────────────────────────────

    def run(self):
        banner()
        self.phase_load()
        self.phase_simulate()
        self.phase_assess()
        self.phase_optimise()
        self.phase_ml()
        self.phase_report()
        self.phase_dashboard()

        section("PLATFORM READY", color=G)
        print(f"""
  {G}{BOLD}All 7 phases completed successfully.{RESET}
  {DIM}Output files:{RESET}
    {DIM}• logs/compliance_audit.log         — tamper-evident SHA-256 hash chain{RESET}
    {DIM}• logs/pci_dss_report.json          — PCI-DSS REQ-1 to 12 compliance{RESET}
    {DIM}• logs/iso_27001_report.json        — ISO-27001 Annex A evidence{RESET}
    {DIM}• logs/nist_csf_report.json         — NIST CSF 2.0 function mapping{RESET}
    {DIM}• logs/gdpr_report.json             — GDPR Art 25/32/33/35 evidence{RESET}
    {DIM}• logs/dashboard_out.json           — SOC executive dashboard data{RESET}

  {DIM}To run tests: python tests/test_all.py{RESET}
  {DIM}To re-run:    python main.py{RESET}
{B}{'═'*76}{RESET}
""")


if __name__ == "__main__":
    platform = CyberBankingPlatform(
        config_path="config/settings.json",
        intel_path="data/threat_intel.json",
    )
    platform.run()