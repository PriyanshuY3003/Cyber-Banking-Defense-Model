# How to Run the Cyber Banking Defense Model - Step by Step

### **Step 1: Open Terminal**

```powershell
# Open PowerShell in your project directory
cd "c:\Users\Dell\OneDrive\Desktop\ZeTheta Project\Cyber Banking Defense"
```

### **Step 2: Activate Virtual Environment**

```powershell
# Activate the Python virtual environment
python src/phase7_orchestrator/main.py
```

Your terminal prompt should now show `(venv)` at the beginning.

### **Step 3: Run the Main Orchestrator**

```powershell
# This runs ALL 7 phases
python src/phase7_orchestrator/main.py
```

**What happens:**

- Phase 1: Loads network topology (10 nodes, $880M assets)
- Phase 2: Runs Monte Carlo simulation (230 attacks simulated)
- Phase 3: FAIR risk assessment ($1600M ALE)
- Phase 4: Budget optimization (12 controls selected)
- Phase 5: **Loads your data & runs ML detection** (anomaly + fraud detection)
- Phase 6: Generates compliance reports
- Phase 7: Shows SOC dashboard

**Output files created:**

```
logs/
  ├── compliance_audit.log
  ├── pci_dss_report.json
  ├── dashboard_out.json
  └── ...other reports
```

---

## **OPTION 2: Train & Save ML Models Only**

### **Step 1: Open Terminal**

```powershell
cd "c:\Users\Dell\OneDrive\Desktop\ZeTheta Project\Cyber Banking Defense"
.\venv\Scripts\Activate.ps1
```

### **Step 2: Run Model Persistence Pipeline**

```powershell
# This trains and saves models as pickle files
python models/retrain_pipeline.py
```

**What happens:**

- Loads training data (16 network events, 12 transactions)
- Trains Anomaly Detector
- Trains Fraud Classifier
- Saves both as .pkl files
- Loads them back to verify

**Output files created:**

```
outputs/models/
  ├── anomaly_detector.pkl
  ├── anomaly_detector_metadata.json
  ├── fraud_classifier.pkl
  └── fraud_classifier_metadata.json
```

---

## **OPTION 3: Run Tests Only**

### **Step 1: Open Terminal**

```powershell
cd "c:\Users\Dell\OneDrive\Desktop\ZeTheta Project\Cyber Banking Defense"
.\venv\Scripts\Activate.ps1
```

### **Step 2: Run All Tests**

```powershell
# This runs all unit tests
python -m pytest tests/test_all.py -v
```

Or run a specific test:

```powershell
python -m pytest tests/test_all.py::TestBankNetwork::test_01_node_count -v
```

---

## **OPTION 4: Load & Use Saved Models**

### **Step 1: Open Python Interactive Shell**

```powershell
cd "c:\Users\Dell\OneDrive\Desktop\ZeTheta Project\Cyber Banking Defense"
.\venv\Scripts\Activate.ps1
python
```

### **Step 2: Load and Use Models**

```python
from models.retrain_pipeline import ModelPersistence
from data.data_loader import DataLoader

# Initialize persistence
persistence = ModelPersistence()

# Load saved models
detector, det_meta = persistence.load_model("anomaly_detector")
classifier, clf_meta = persistence.load_model("fraud_classifier")

# Load fresh data
loader = DataLoader()
events = loader.load_network_events()
transactions = loader.load_transactions()

# Split data
test_events = events[16:]
test_txs = transactions[12:]

# Make predictions
anomalies = detector.predict(test_events)
fraud_cases = classifier.predict(test_txs)

# View results
for result in anomalies:
    print(f"Event {result.node_id}: anomaly_score={result.anomaly_score:.2f}")

for result in fraud_cases:
    print(f"Transaction {result.tx_id}: fraud_prob={result.fraud_probability:.2f}")
```

## **DIRECTORY STRUCTURE**

```
Cyber Banking Defense/
├── src/
│   ├── phase7_orchestrator/main.py      ← RUN THIS for full pipeline
│   ├── phase1_network/network.py        ← Network topology
│   ├── ml/ml_detection.py               ← ML algorithms
│   └── engine/
│       ├── simulation.py                ← Threat simulation
│       ├── risk_calc.py                 ← Risk assessment
│       └── budget_opt.py                ← Budget optimization
├── models/
│   └── retrain_pipeline.py              ← RUN THIS to train & save models
├── data/
│   ├── data_loader.py                   ← Load your data
│   ├── network_events_sample.json       ← Your network data
│   └── transactions_sample.json         ← Your transaction data
├── outputs/
│   └── models/                          ← Saved .pkl files go here
├── logs/                                ← Reports generated here
└── dashboard/
    └── index.html                       ← Web dashboard
```

---

## **TROUBLESHOOTING**

### **Problem: Virtual environment not activated**

```powershell
# Fix: Run this
.\venv\Scripts\Activate.ps1
```

### **Problem: Module not found errors**

```powershell
# Fix: Make sure you're in the correct directory
cd "c:\Users\Dell\OneDrive\Desktop\ZeTheta Project\Cyber Banking Defense"
```

### **Problem: ModuleNotFoundError: No module named 'sklearn'**

```powershell
# Fix: Install missing dependencies
pip install scikit-learn numpy pandas
```

### **Problem: Port 8000 already in use**

```powershell
# Use different port for dashboard
python -m http.server 9000 --directory dashboard
# Then open: http://localhost:9000
```

---

## **NEXT STEPS**

1. ✅ **Run Phase 7 Orchestrator** (full model)

   ```powershell
   python src/phase7_orchestrator/main.py
   ```

2. ✅ **Train & Save Models as Pickle**

   ```powershell
   python models/retrain_pipeline.py
   ```

3. ✅ **View Dashboard**

   ```powershell
   python -m http.server 8000 --directory dashboard
   # Open: http://localhost:8000
   ```

4. ✅ **Run Tests**
   ```powershell
   python -m pytest tests/test_all.py -v
   ```

---

## **EXPECTED OUTPUT**

When you run `python src/phase7_orchestrator/main.py`, you should see:

```
================================================================================
   CYBER BANKING DEFENSE PLATFORM v2.0
================================================================================

PHASE 1 - Load: Network Architecture & Threat Intelligence
  ✓ Bank name: Default Bank
  ✓ Nodes loaded: 10
  ✓ Total asset value: $880M

PHASE 2 - Simulate: Monte Carlo Attack Simulation
  ✓ Attacks attempted: 230
  ✓ Total simulated loss: $2108.8M

PHASE 3 - Assess: FAIR Risk Assessment
  ✓ Total Estate ALE: $1600.0M/yr

PHASE 4 - Optimise: Defense Allocation & Budget
  ✓ Controls selected: 12
  ✓ Risk reduction: 100.0%

PHASE 5 - ML Detection: Anomaly + Fraud
  ✓ Network events tested: 4
  ✓ Anomalies detected: 4
  ✓ Fraud flagged: 3

PHASE 6 - Compliance Reports & Audit Trail
  ✓ Events logged: 3

PHASE 7 - SOC Operations Dashboard
  ✓ Dashboard ready

All 7 phases completed successfully!
```

---
