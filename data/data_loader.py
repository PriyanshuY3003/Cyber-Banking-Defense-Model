"""
data/processed/data_loader.py
─────────────────────────────
Bridges real-life data files → model-ready objects.

Usage
─────
  from data.processed.data_loader import DataLoader
  loader = DataLoader()
  network_events  = loader.load_network_events()   # → List[NetworkEvent]
  transactions    = loader.load_transactions()      # → List[Transaction]
  vuln_scores     = loader.load_vuln_scores()       # → Dict[node_id, float]

Replace the JSON paths below with live API calls when connecting
to Splunk, Nessus, or your CBS (Core Banking System).
"""

from __future__ import annotations
import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional

# ── Add project root to path ──────────────────────────────────────────────────
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from src.ml.ml_detection import NetworkEvent, Transaction


class DataLoader:
    """
    Loads real-life data from data/raw/*.json and converts to
    the dataclass types used by AnomalyDetector and FraudClassifier.

    To switch to live feeds, override the three load_* methods with
    API clients (Splunk SDK, Nessus REST, CBS JDBC, etc.).
    """

    RAW_DIR = os.path.join(os.path.dirname(__file__), ".")

    def __init__(self, raw_dir: Optional[str] = None):
        self.raw_dir = raw_dir or self.RAW_DIR

    # ── Network events ────────────────────────────────────────────────────────

    def load_network_events(self) -> List[NetworkEvent]:
        """
        Load SIEM network events from network_events_sample.json.
        Real-life replacement: Splunk SDK query or QRadar REST API.
        """
        path = os.path.join(self.raw_dir, "network_events_sample.json")
        with open(path) as f:
            raw = json.load(f)

        events: List[NetworkEvent] = []
        for r in raw:
            events.append(NetworkEvent(
                event_id          = r["event_id"],
                timestamp         = r["timestamp"],
                node_id           = r["node_id"],
                src_ip            = r["src_ip"],
                dst_ip            = r["dst_ip"],
                bytes_transferred = float(r.get("bytes_out", r.get("bytes_in", 0))),
                duration_sec      = float(r["duration_sec"]),
                port              = int(r["dst_port"]),
                protocol          = r["protocol"],
                hour_of_day       = int(r["hour_of_day"]),
                failed_logins     = int(r["failed_logins"]),
                is_privileged     = bool(r["is_privileged"]),
                label             = int(r["label"]),
            ))
        print(f"[DataLoader] Loaded {len(events)} network events "
              f"({sum(1 for e in events if e.label==1)} anomalous)")
        return events

    # ── Transactions ──────────────────────────────────────────────────────────

    def load_transactions(self) -> List[Transaction]:
        """
        Load banking transactions from transactions_sample.json.
        Real-life replacement: Core Banking System (Finacle / T24 / Temenos) API.
        """
        path = os.path.join(self.raw_dir, "transactions_sample.json")
        with open(path) as f:
            raw = json.load(f)

        txs: List[Transaction] = []
        for r in raw:
            txs.append(Transaction(
                tx_id                  = r["tx_id"],
                timestamp              = r["timestamp"],
                amount_usd             = float(r["amount_usd"]),
                sender_account         = r["sender_account"],
                receiver_account       = r["receiver_account"],
                channel                = r["channel"],
                country                = r["country"],
                is_international       = bool(r["is_international"]),
                hour_of_day            = int(r["hour_of_day"]),
                sender_avg_tx_amount   = float(r["sender_avg_tx_30d"]),
                sender_tx_count_24h    = int(r["sender_tx_count_24h"]),
                receiver_known         = bool(r["receiver_known"]),
                amount_rounded         = bool(r["amount_rounded"]),
                label                  = int(r["label"]),
            ))
        print(f"[DataLoader] Loaded {len(txs)} transactions "
              f"({sum(1 for t in txs if t.label==1)} fraud)")
        return txs

    # ── Vulnerability scores ──────────────────────────────────────────────────

    def load_vuln_scores(self) -> Dict[str, float]:
        """
        Load Nessus vulnerability scores from vulnerability_scores.json.
        Returns dict: node_id → normalised_vuln_score (0–100).
        Real-life replacement: Nessus REST API /scans/{id}/hosts
        """
        path = os.path.join(self.raw_dir, "vulnerability_scores.json")
        with open(path) as f:
            raw = json.load(f)

        scores: Dict[str, float] = {}
        for node in raw["nodes"]:
            scores[node["node_id"]] = float(node["vuln_score_normalised"])

        print(f"[DataLoader] Loaded vuln scores for {len(scores)} nodes")
        return scores

    def apply_vuln_scores_to_network(self, network) -> None:
        """
        Patch a live BankNetwork object with real Nessus scores.
        Call this after DataLoader().load_vuln_scores() to replace
        the static config/settings.json values with real scan results.
        """
        scores = self.load_vuln_scores()
        for node_id, score in scores.items():
            if node_id in network.nodes:
                old = network.nodes[node_id].vuln_score
                network.nodes[node_id].vuln_score = score
                print(f"  {node_id}: {old:.0f} → {score:.0f} (Nessus live)")


# ── Quick test ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    loader = DataLoader()
    print("\n── Network Events ──────────────────────────────────────────")
    evts = loader.load_network_events()
    for e in evts[:3]:
        print(f"  {e.event_id}  node={e.node_id}  "
              f"bytes={e.bytes_transferred:,.0f}  label={e.label}")

    print("\n── Transactions ────────────────────────────────────────────")
    txs = loader.load_transactions()
    for t in txs[:3]:
        print(f"  {t.tx_id}  ${t.amount_usd:,.2f}  "
              f"intl={t.is_international}  label={t.label}")

    print("\n── Vulnerability Scores ────────────────────────────────────")
    scores = loader.load_vuln_scores()
    for nid, score in sorted(scores.items()):
        bar = "█" * int(score // 10)
        print(f"  {nid}  [{bar:<10}]  {score:.0f}")
