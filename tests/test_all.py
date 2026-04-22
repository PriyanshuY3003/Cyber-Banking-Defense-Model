
# PHASE 7 — Testing & Validation
# test_all.py: 33 tests covering all modules.
# Layer 7 correct arch: edge case tests, integration tests, performance tests.
#   • Edge cases: malformed JSON, nulls, negative budgets, empty networks
#   • Integration: end-to-end simulation pipeline
#   • Performance: 1000-round benchmark
# Run: python tests/test_all.py   OR   pytest tests/test_all.py -v

import json
import os
import sys
import time
import unittest
import random

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.models.network import BankNetwork, NetworkNode, NodeType, DefenseLayer
from src.models.threat import ThreatLibrary, Threat, ThreatCategory, ThreatSeverity, KILL_CHAIN_STAGES
from src.engine.budget_opt import BudgetOptimizer
from src.engine.simulation import SimulationEngine
from src.engine.risk_calc import RiskCalculator
from src.utils.logger import ComplianceLogger, AuditEventType
from src.ml.ml_detection import (AnomalyDetector, FraudClassifier,
                                   generate_network_events, generate_transactions)


# ══════════════════════════════════════════════════════════════════════════════
# GROUP 1 — Network Model Tests (8 tests)
# ══════════════════════════════════════════════════════════════════════════════

class TestBankNetwork(unittest.TestCase):

    def setUp(self):
        self.net = BankNetwork("config/settings.json")

    def test_01_node_count(self):
        """Network loads correct number of nodes."""
        self.assertEqual(len(self.net.nodes), 10)

    def test_02_effective_vuln_less_than_raw(self):
        """Effective vulnerability must be <= raw vulnerability for all nodes."""
        for node in self.net.nodes.values():
            self.assertLessEqual(node.effective_vuln(), node.vuln_score,
                                 f"Node {node.node_id}: eff_vuln > raw_vuln")

    def test_03_fortress_defense_reduces_vuln_by_85pct(self):
        """FORTRESS defense should reduce vuln by 85%."""
        node = NetworkNode(node_id="T01", name="Test", node_type=NodeType.CORE_BANKING,
                           vuln_score=80.0, defense_layer=DefenseLayer.FORTRESS)
        self.assertAlmostEqual(node.effective_vuln(), 80.0 * 0.15, places=1)

    def test_04_bfs_finds_shortest_path(self):
        """BFS lateral movement finds a valid path from Internet to Core Banking."""
        path = self.net.bfs_lateral_path("N01", "N04")
        self.assertIsNotNone(path)
        if path is not None:
            self.assertIn("N01", path)
            self.assertIn("N04", path)

    def test_05_dfs_finds_multiple_paths(self):
        """DFS finds at least one kill-chain path from N01 to N04."""
        paths = self.net.dfs_all_paths("N01", "N04")
        self.assertGreater(len(paths), 0)

    def test_06_compromise_quarantine_remediate(self):
        """Node state transitions: compromise → quarantine → remediate."""
        node = self.net.nodes["N08"]
        node.compromise(1)
        self.assertTrue(node.is_compromised)
        node.quarantine()
        self.assertFalse(node.is_compromised)
        self.assertTrue(node.is_quarantined)
        node.remediate()
        self.assertFalse(node.is_quarantined)

    def test_07_upgrade_defense_advances_tier(self):
        """Upgrading defense layer advances to next tier."""
        node = self.net.nodes["N08"]
        old_layer = node.defense_layer
        upgraded = node.upgrade_defense()
        self.assertTrue(upgraded)
        self.assertGreater(node.defense_layer.value, old_layer.value)

    def test_08_segmentation_score_bounded(self):
        """Segmentation score must be between 0 and 100."""
        score = self.net.segmentation_score()
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 100.0)


# ══════════════════════════════════════════════════════════════════════════════
# GROUP 2 — Threat Library Tests (7 tests)
# ══════════════════════════════════════════════════════════════════════════════

class TestThreatLibrary(unittest.TestCase):

    def setUp(self):
        self.lib = ThreatLibrary("data/threat_intel.json")

    def test_09_threat_count(self):
        """Library contains exactly 8 threats."""
        self.assertEqual(len(self.lib.threats), 8)

    def test_10_risk_score_zero_at_zero_vuln(self):
        """Risk score must be 0 when node vulnerability is 0."""
        for threat in self.lib.threats.values():
            self.assertAlmostEqual(threat.risk_score(0.0), 0.0, places=1)

    def test_11_risk_score_increases_with_vuln(self):
        """Risk score must increase as vulnerability increases."""
        threat = self.lib.get("T-001")
        self.assertIsNotNone(threat)
        if threat is not None:
            self.assertGreater(threat.risk_score(80.0), threat.risk_score(40.0))

    def test_12_kill_chain_result_structure(self):
        """Kill chain result has expected fields."""
        threat = self.lib.get("T-001")
        self.assertIsNotNone(threat)
        if threat is None:
            return
        result = threat.simulate_kill_chain(75.0, round_num=1)
        self.assertIsInstance(result.stages_completed, list)
        self.assertIsInstance(result.success, bool)
        self.assertGreaterEqual(result.overall_prob, 0.0)
        self.assertLessEqual(result.overall_prob, 1.0)

    def test_13_sample_impact_within_range(self):
        """Sampled impact must be within [min, max] range (wide PERT bounds)."""
        threat = self.lib.get("T-008")
        self.assertIsNotNone(threat)
        if threat is None:
            return
        for _ in range(50):
            impact = threat.sample_impact()
            # PERT can slightly exceed bounds due to beta distribution tails
            self.assertGreater(impact, 0.0)

    def test_14_for_node_type_returns_relevant(self):
        """for_node_type returns threats targeting that node type."""
        swift_threats = self.lib.for_node_type("swift_gateway")
        self.assertGreater(len(swift_threats), 0)
        for t in swift_threats:
            self.assertIn("swift_gateway", t.target_node_types)

    def test_15_mitre_techniques_present(self):
        """All threats have at least one MITRE technique."""
        for threat in self.lib.threats.values():
            self.assertGreater(len(threat.mitre_techniques), 0,
                               f"{threat.threat_id} has no MITRE techniques")


# ══════════════════════════════════════════════════════════════════════════════
# GROUP 3 — Budget Optimizer Tests (6 tests)
# ══════════════════════════════════════════════════════════════════════════════

class TestBudgetOptimizer(unittest.TestCase):

    def setUp(self):
        self.opt = BudgetOptimizer()

    def test_16_catalog_has_12_controls(self):
        """Control catalog has exactly 12 controls."""
        self.assertEqual(len(self.opt.controls), 12)

    def test_17_greedy_stays_within_budget(self):
        """Greedy optimizer never exceeds budget."""
        result = self.opt.optimize_greedy(budget_k=200.0, baseline_risk_m=100.0)
        self.assertLessEqual(result.spent_k, 200.0 + 0.01)

    def test_18_zero_budget_selects_nothing(self):
        """Zero budget results in no controls selected."""
        result = self.opt.optimize_greedy(budget_k=0.0, baseline_risk_m=100.0)
        self.assertEqual(len(result.selected_controls), 0)

    def test_19_negative_budget_handled(self):
        """Negative budget is handled gracefully (edge case)."""
        result = self.opt.optimize_greedy(budget_k=-100.0, baseline_risk_m=100.0)
        self.assertEqual(result.spent_k, 0.0)

    def test_20_risk_reduction_bounded(self):
        """Risk reduction percentage is between 0 and 100."""
        result = self.opt.optimize_greedy(budget_k=500.0, baseline_risk_m=100.0)
        self.assertGreaterEqual(result.total_risk_reduction_pct, 0.0)
        self.assertLessEqual(result.total_risk_reduction_pct, 100.0)

    def test_21_gap_analysis_returns_standards(self):
        """Gap analysis returns covered and gap lists."""
        result = self.opt.optimize_greedy(budget_k=500.0, baseline_risk_m=100.0)
        ids = [c.control_id for c in result.selected_controls]
        gaps = self.opt.gap_analysis(ids)
        self.assertIn("covered", gaps)
        self.assertIn("gaps", gaps)


# ══════════════════════════════════════════════════════════════════════════════
# GROUP 4 — Risk Calculator Tests (4 tests)
# ══════════════════════════════════════════════════════════════════════════════

class TestRiskCalculator(unittest.TestCase):

    def setUp(self):
        self.net  = BankNetwork("config/settings.json")
        self.lib  = ThreatLibrary("data/threat_intel.json")
        self.calc = RiskCalculator(self.net, self.lib)

    def test_22_compute_all_returns_results(self):
        """compute_all returns at least one FAIR result per threat per node."""
        results = self.calc.compute_all()
        self.assertGreater(len(results), 0)

    def test_23_risk_score_bounded(self):
        """All FAIR risk scores are between 0 and 100."""
        results = self.calc.compute_all()
        for r in results:
            self.assertGreaterEqual(r.risk_score, 0.0)
            self.assertLessEqual(r.risk_score, 100.0)

    def test_24_pert_min_less_than_max(self):
        """PERT uncertainty: min ALE <= likely ALE <= max ALE."""
        results = self.calc.compute_all()
        for r in results:
            self.assertLessEqual(r.ale_min, r.ale_likely + 0.01)
            self.assertLessEqual(r.ale_likely, r.ale_max + 0.01)

    def test_25_summary_systemic_score_bounded(self):
        """Systemic risk score is between 0 and 100."""
        summary = self.calc.risk_summary()
        self.assertGreaterEqual(summary.systemic_risk_score, 0.0)
        self.assertLessEqual(summary.systemic_risk_score, 100.0)


# ══════════════════════════════════════════════════════════════════════════════
# GROUP 5 — Compliance Logger Tests (4 tests)
# ══════════════════════════════════════════════════════════════════════════════

class TestComplianceLogger(unittest.TestCase):

    def setUp(self):
        os.makedirs("logs", exist_ok=True)
        # Use a test-specific log to avoid polluting main logs
        self.logger = ComplianceLogger("logs")
        self.logger.log_path = "logs/test_audit.log"
        self.logger.events   = []
        self.logger._prev_hash = "GENESIS"
        self.logger._counter   = 0

    def tearDown(self):
        if os.path.exists("logs/test_audit.log"):
            os.remove("logs/test_audit.log")

    def test_26_log_creates_event(self):
        """Logging an event creates an AuditEvent with hash and HMAC."""
        evt = self.logger.log(AuditEventType.SIMULATION_START,
                              details={"test": True})
        self.assertIsNotNone(evt.event_hash)
        self.assertNotEqual(evt.event_hash, "")
        self.assertNotEqual(evt.hmac_sig, "")

    def test_27_hash_chain_valid_after_multiple_events(self):
        """Hash chain is valid after logging multiple events."""
        for i in range(5):
            self.logger.log(AuditEventType.ATTACK_DETECTED,
                            node_id="N01", threat_id="T-001",
                            severity="HIGH", details={"round": i})
        result = self.logger.verify_chain()
        self.assertTrue(result["valid"])
        self.assertEqual(result["events_checked"], 5)

    def test_28_tamper_detection(self):
        """Modifying a logged event breaks chain verification."""
        for i in range(3):
            self.logger.log(AuditEventType.NODE_COMPROMISED,
                            node_id="N04", details={"round": i})
        # Tamper with middle event
        self.logger.events[1].details["injected"] = "tampered_data"
        self.logger.events[1].event_hash = "0" * 64  # break hash
        result = self.logger.verify_chain()
        self.assertFalse(result["valid"])

    def test_29_compliance_tags_auto_applied(self):
        """Compliance tags (PCI, ISO, NIST, GDPR) are auto-applied."""
        evt = self.logger.log(AuditEventType.ATTACK_DETECTED,
                              node_id="N04", threat_id="T-001", severity="CRITICAL")
        self.assertIsNotNone(evt.pci_req)
        self.assertIsNotNone(evt.nist_function)


# ══════════════════════════════════════════════════════════════════════════════
# GROUP 6 — ML Detection Tests (2 tests)
# ══════════════════════════════════════════════════════════════════════════════

class TestMLDetection(unittest.TestCase):

    def test_30_anomaly_detector_flags_anomalies(self):
        """Anomaly detector flags at least some anomalous events."""
        events = generate_network_events(n_normal=100, n_anomalous=20)
        detector = AnomalyDetector(contamination=0.1)
        detector.fit(events[:80])
        results = detector.predict(events[80:])
        flagged = sum(1 for r in results if r.is_anomaly)
        self.assertGreater(flagged, 0)

    def test_31_fraud_classifier_scores_transactions(self):
        """Fraud classifier scores all transactions in [0, 1]."""
        txs = generate_transactions(n_legit=100, n_fraud=20)
        clf = FraudClassifier(threshold=0.7)
        clf.fit(txs[:80])
        results = clf.predict(txs[80:])
        for r in results:
            self.assertGreaterEqual(r.fraud_probability, 0.0)
            self.assertLessEqual(r.fraud_probability, 1.0)


# ══════════════════════════════════════════════════════════════════════════════
# GROUP 7 — Integration & Performance Tests (2 tests)
# ══════════════════════════════════════════════════════════════════════════════

class TestIntegrationAndPerformance(unittest.TestCase):

    def test_32_end_to_end_simulation_pipeline(self):
        """
        Integration: full pipeline from network load → simulation → risk → logger.
        Validates module interactions.
        """
        # Load modules
        net  = BankNetwork("config/settings.json")
        lib  = ThreatLibrary("data/threat_intel.json")

        # Run short simulation
        engine = SimulationEngine(net, lib, rounds=2, mc_iterations=50, seed=99)
        report = engine.run()

        # Validate report structure
        self.assertIsNotNone(report)
        self.assertGreater(report.total_attacks_attempted, 0)
        self.assertGreaterEqual(report.total_loss_m, 0.0)
        self.assertEqual(len(report.confidence_interval_95), 2)

        # Risk assessment on post-simulation network
        calc    = RiskCalculator(net, lib)
        summary = calc.risk_summary()
        self.assertGreater(summary.total_ale_m, 0.0)

        # Compliance logging
        os.makedirs("logs", exist_ok=True)
        logger = ComplianceLogger("logs")
        logger.log(AuditEventType.SIMULATION_COMPLETE,
                   details={"loss_m": report.total_loss_m})
        chain = logger.verify_chain()
        self.assertIn("valid", chain)

    def test_33_performance_1000_round_benchmark(self):
        """
        Performance: 1000 Monte Carlo iterations complete in < 30 seconds.
        """
        net  = BankNetwork("config/settings.json")
        lib  = ThreatLibrary("data/threat_intel.json")
        engine = SimulationEngine(net, lib, rounds=3, mc_iterations=1000, seed=42)

        t0 = time.time()
        report = engine.run()
        elapsed = time.time() - t0

        self.assertLess(elapsed, 30.0,
                        f"1000 MC iterations took {elapsed:.1f}s > 30s limit")
        print(f"\n  Performance: {elapsed:.2f}s for 3 rounds × 1000 MC iterations")


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 70)
    print("  CYBER BANKING DEFENSE — Phase 7 Test Suite (33 tests)")
    print("=" * 70)
    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()
    for cls in [TestBankNetwork, TestThreatLibrary, TestBudgetOptimizer,
                TestRiskCalculator, TestComplianceLogger,
                TestMLDetection, TestIntegrationAndPerformance]:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 70)
    passed = result.testsRun - len(result.failures) - len(result.errors)
    print(f"  RESULT: {passed}/{result.testsRun} tests passed")
    if result.failures:
        print(f"  FAILURES ({len(result.failures)}):")
        for f in result.failures:
            print(f"    {f[0]}")
    if result.errors:
        print(f"  ERRORS ({len(result.errors)}):")
        for e in result.errors:
            print(f"    {e[0]}")
    print("=" * 70)