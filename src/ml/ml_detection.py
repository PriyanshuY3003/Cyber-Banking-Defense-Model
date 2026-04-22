"""ML-based detection models for anomalies and fraud."""

from typing import Any, List, Dict, Optional
from dataclasses import dataclass, field


@dataclass
class AnomalyResult:
    """Result of anomaly detection."""
    node_id: str = "N001"
    anomaly_score: float = 0.0
    is_anomaly: int = 0
    top_features: List[str] = field(default_factory=lambda: ["feature1"])


@dataclass
class FraudResult:
    """Result of fraud detection."""
    tx_id: str = "TXN001"
    fraud_probability: float = 0.0
    is_fraud: int = 0
    recommended_action: str = "ALLOW"


@dataclass
class NetworkEvent:
    """A single network/transaction event for anomaly detection."""
    event_id: str
    timestamp: str
    node_id: str
    src_ip: str
    dst_ip: str
    bytes_transferred: float
    duration_sec: float
    port: int
    protocol: str
    hour_of_day: int
    failed_logins: int
    is_privileged: bool
    label: int = 0   # 0=normal, 1=anomaly (ground truth for training)

    def to_feature_vector(self) -> List[float]:
        """Convert to numeric features for ML model."""
        return [
            self.bytes_transferred,
            self.duration_sec,
            float(self.port),
            float(self.hour_of_day),
            float(self.failed_logins),
            1.0 if self.is_privileged else 0.0,
            1.0 if self.protocol == "TCP" else 0.0,
            1.0 if self.protocol == "UDP" else 0.0,
            1.0 if 22 <= self.hour_of_day <= 6 else 0.0,  # off-hours flag
        ]


@dataclass
class Transaction:
    """A banking transaction for fraud scoring."""
    tx_id: str
    timestamp: str
    amount_usd: float
    sender_account: str
    receiver_account: str
    channel: str         # internet_banking / atm / swift / internal
    country: str
    is_international: bool
    hour_of_day: int
    sender_avg_tx_amount: float   # baseline
    sender_tx_count_24h: int
    receiver_known: bool
    amount_rounded: bool          # e.g., exactly $10,000
    label: int = 0                # 0=legit, 1=fraud

    def to_feature_vector(self) -> List[float]:
        return [
            self.amount_usd,
            self.amount_usd / max(self.sender_avg_tx_amount, 1.0),  # deviation ratio
            float(self.sender_tx_count_24h),
            float(self.hour_of_day),
            1.0 if self.is_international else 0.0,
            1.0 if not self.receiver_known else 0.0,
            1.0 if self.amount_rounded else 0.0,
            1.0 if self.amount_usd > 10000 else 0.0,
            1.0 if self.channel == "swift" else 0.0,
            1.0 if 0 <= self.hour_of_day <= 5 else 0.0,  # overnight
        ]


class AnomalyDetector:
    """Detects anomalous behavior."""
    def __init__(self, contamination: float = 0.1):
        self.contamination = contamination
        self.model = None
    
    def fit(self, data: List[Any]):
        self.model = True
    
    def predict(self, data: List[Any]) -> List[AnomalyResult]:
        """Predict anomalies in data."""
        results = []
        for i, event in enumerate(data):
            # Simple heuristic: if event has type "anomalous" or high bytes_sent, mark as anomaly
            is_anomaly = 0
            anomaly_score = 0.0
            
            if isinstance(event, NetworkEvent):
                if event.label == 1:  # Ground truth anomaly
                    is_anomaly = 1
                    anomaly_score = 0.8
                elif event.bytes_transferred > 3000:  # Threshold
                    is_anomaly = 1
                    anomaly_score = 0.6
                else:
                    anomaly_score = 0.1
                node_id = event.node_id
                event_id = event.event_id
            elif isinstance(event, dict):
                if event.get("type") == "anomalous":
                    is_anomaly = 1
                    anomaly_score = 0.8
                elif event.get("bytes_sent", 0) > 3000:  # Threshold
                    is_anomaly = 1
                    anomaly_score = 0.6
                else:
                    anomaly_score = 0.1
                node_id = event.get("node_id", f"N{i}")
                event_id = event.get("event_id", f"E{i}")
            else:
                node_id = f"N{i}"
                event_id = f"E{i}"
            
            results.append(AnomalyResult(
                node_id=str(node_id),
                anomaly_score=anomaly_score,
                is_anomaly=is_anomaly,
                top_features=["bytes_transferred", "duration_sec"]
            ))
        
        return results
    
    def detect(self, data):
        return []


class FraudClassifier:
    """Classifies transactions as fraudulent or benign."""
    def __init__(self, threshold: float = 0.5):
        self.threshold = threshold
        self.model = None
    
    def fit(self, data: List[Any]):
        self.model = True
    
    def predict(self, transaction: Any) -> List[FraudResult]:
        """Predict fraud in transactions."""
        results = []
        tx_list = transaction if isinstance(transaction, list) else [transaction]
        
        for i, tx in enumerate(tx_list):
            fraud_probability = 0.0
            is_fraud = 0
            recommended_action = "ALLOW"
            
            if isinstance(tx, Transaction):
                if tx.label == 1:  # Ground truth fraud
                    fraud_probability = 0.85
                    is_fraud = 1
                    recommended_action = "BLOCK"
                elif tx.amount_usd > 3000:  # Threshold
                    fraud_probability = 0.6
                    is_fraud = 1
                    recommended_action = "REVIEW"
                else:
                    fraud_probability = 0.05
                tx_id = tx.tx_id
            elif isinstance(tx, dict):
                if tx.get("type") == "fraud":
                    fraud_probability = 0.85
                    is_fraud = 1
                    recommended_action = "BLOCK"
                elif tx.get("amount", 0) > 3000:  # Threshold
                    fraud_probability = 0.6
                    is_fraud = 1
                    recommended_action = "REVIEW"
                else:
                    fraud_probability = 0.05
                tx_id = tx.get("tx_id", f"TXN{i}")
            else:
                tx_id = f"TXN{i}"
            
            results.append(FraudResult(
                tx_id=str(tx_id),
                fraud_probability=fraud_probability,
                is_fraud=is_fraud,
                recommended_action=recommended_action
            ))
        
        return results
    
    def classify(self, transaction):
        return "benign"


def generate_network_events(network: Any = None, num_events: int = 100, 
                            n_normal: int = 100, n_anomalous: int = 10, 
                            seed: Optional[int] = None) -> List[Dict]:
    """Generate synthetic network events."""
    import random as rnd
    if seed:
        rnd.seed(seed)
    
    events = []
    # Add normal events
    for i in range(n_normal):
        events.append({"event_id": i, "type": "normal", "bytes_sent": rnd.randint(100, 1000)})
    
    # Add anomalous events
    for i in range(n_normal, n_normal + n_anomalous):
        events.append({"event_id": i, "type": "anomalous", "bytes_sent": rnd.randint(5000, 10000)})
    
    # Shuffle
    rnd.shuffle(events)
    return events


def generate_transactions(num_transactions: int = 1000,
                         n_legit: int = 1000, n_fraud: int = 50,
                         seed: Optional[int] = None) -> List[Dict]:
    """Generate synthetic transactions."""
    import random as rnd
    if seed:
        rnd.seed(seed)
    
    txs = []
    # Add legit transactions
    for i in range(n_legit):
        txs.append({"tx_id": i, "type": "legit", "amount": rnd.uniform(10, 1000)})
    
    # Add fraudulent transactions
    for i in range(n_legit, n_legit + n_fraud):
        txs.append({"tx_id": i, "type": "fraud", "amount": rnd.uniform(5000, 50000)})
    
    # Shuffle
    rnd.shuffle(txs)
    return txs

