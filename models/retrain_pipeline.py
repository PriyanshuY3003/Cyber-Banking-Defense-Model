"""
Model Persistence Pipeline - Create Pickle Files
═════════════════════════════════════════════════════════════════════════════

WHAT IS A PICKLE FILE?
──────────────────────
• A .pkl file is a Python object serialized to binary format
• It preserves the complete state of a trained model (parameters, weights, etc.)
• Can be loaded later WITHOUT retraining the model
• Saves time and computational resources
• Only works with Python (not cross-language compatible)

WORKFLOW:
─────────
1. Train models on data
2. Save models to .pkl files using pickle.dump()
3. Load .pkl files when needed using pickle.load()
4. Use loaded models for predictions without retraining
"""

import pickle
import os
import json
import sys
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

# Add project root to path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.ml.ml_detection import AnomalyDetector, FraudClassifier
from data.data_loader import DataLoader


class ModelPersistence:
    """Handles saving and loading trained models as pickle files."""
    
    MODEL_DIR = os.path.join(ROOT, "outputs", "models")
    
    def __init__(self):
        """Initialize and ensure model directory exists."""
        os.makedirs(self.MODEL_DIR, exist_ok=True)
        print(f"✓ Model directory ready: {self.MODEL_DIR}")
    
    def save_model(self, model: Any, model_name: str, metadata: Optional[Dict] = None) -> str:
        """
        Save a trained model to pickle file.
        
        Args:
            model: The trained model object
            model_name: Name for the model
            metadata: Optional metadata (version, date, accuracy, etc.)
        
        Returns:
            Path to saved pickle file
        """
        filepath = os.path.join(self.MODEL_DIR, f"{model_name}.pkl")
        
        try:
            with open(filepath, 'wb') as f:
                pickle.dump(model, f)
            
            if metadata:
                meta_path = os.path.join(self.MODEL_DIR, f"{model_name}_metadata.json")
                metadata['saved_timestamp'] = datetime.now().isoformat()
                metadata['model_type'] = model.__class__.__name__
                with open(meta_path, 'w') as f:
                    json.dump(metadata, f, indent=2)
                print(f"  ✓ Model saved: {filepath}")
                print(f"  ✓ Metadata saved: {meta_path}")
            else:
                print(f"  ✓ Model saved: {filepath}")
            
            return filepath
            
        except Exception as e:
            print(f"  ✗ Error saving model: {e}")
            raise
    
    def load_model(self, model_name: str) -> Tuple[Any, Optional[Dict]]:
        """
        Load a trained model from pickle file.
        
        Args:
            model_name: Name of the model to load
        
        Returns:
            Tuple of (model, metadata)
        """
        filepath = os.path.join(self.MODEL_DIR, f"{model_name}.pkl")
        meta_path = os.path.join(self.MODEL_DIR, f"{model_name}_metadata.json")
        
        try:
            with open(filepath, 'rb') as f:
                model = pickle.load(f)
            
            metadata = None
            if os.path.exists(meta_path):
                with open(meta_path, 'r') as f:
                    metadata = json.load(f)
                print(f"  ✓ Model loaded: {filepath}")
            
            return model, metadata
            
        except FileNotFoundError:
            print(f"  ✗ Model not found: {filepath}")
            return None, None
        except Exception as e:
            print(f"  ✗ Error loading model: {e}")
            raise
    
    def list_models(self) -> Dict[str, Dict]:
        """List all saved models."""
        models = {}
        
        for file in os.listdir(self.MODEL_DIR):
            if file.endswith('.pkl'):
                model_name = file.replace('.pkl', '')
                meta_path = os.path.join(self.MODEL_DIR, f"{model_name}_metadata.json")
                
                file_path = os.path.join(self.MODEL_DIR, file)
                file_size = os.path.getsize(file_path) / 1024
                
                metadata = {}
                if os.path.exists(meta_path):
                    with open(meta_path, 'r') as f:
                        metadata = json.load(f)
                
                models[model_name] = {
                    "size_kb": round(file_size, 2),
                    "metadata": metadata
                }
        
        return models


if __name__ == "__main__":
    print("\n" + "="*80)
    print("MODEL PERSISTENCE PIPELINE - CREATING PICKLE FILES")
    print("="*80 + "\n")
    
    # Initialize persistence
    persistence = ModelPersistence()
    
    # Load training data
    print("[STEP 1] Loading training data...")
    loader = DataLoader()
    all_events = loader.load_network_events()
    all_txs = loader.load_transactions()
    
    train_events = all_events[:int(0.8 * len(all_events))]
    train_txs = all_txs[:int(0.8 * len(all_txs))]
    
    print(f"  • Loaded {len(train_events)} network events for training")
    print(f"  • Loaded {len(train_txs)} transactions for training")
    
    # Train Anomaly Detector
    print("\n[STEP 2] Training Anomaly Detection Model...")
    detector = AnomalyDetector(contamination=0.1)
    detector.fit(train_events)
    print("  ✓ Anomaly detector trained")
    
    # Save Anomaly Detector as pickle
    print("\n[STEP 3] Saving Anomaly Detector to pickle...")
    persistence.save_model(
        detector, 
        "anomaly_detector",
        metadata={
            "type": "Isolation Forest based",
            "contamination": 0.1,
            "training_samples": len(train_events),
            "description": "Detects anomalous network behavior"
        }
    )
    
    # Train Fraud Classifier
    print("\n[STEP 4] Training Fraud Detection Model...")
    classifier = FraudClassifier(threshold=0.5)
    classifier.fit(train_txs)
    print("  ✓ Fraud classifier trained")
    
    # Save Fraud Classifier as pickle
    print("\n[STEP 5] Saving Fraud Classifier to pickle...")
    persistence.save_model(
        classifier,
        "fraud_classifier",
        metadata={
            "type": "Decision Tree based",
            "threshold": 0.5,
            "training_samples": len(train_txs),
            "description": "Classifies fraudulent transactions"
        }
    )
    
    # List all saved models
    print("\n[STEP 6] Listing all saved models...")
    models = persistence.list_models()
    print(f"\n  Total saved models: {len(models)}")
    for name, info in models.items():
        print(f"\n  📦 {name}")
        print(f"     Size: {info['size_kb']} KB")
        if info['metadata']:
            print(f"     Description: {info['metadata'].get('description', 'N/A')}")
            print(f"     Saved: {info['metadata'].get('saved_timestamp', 'N/A')}")
    
    # Load models back
    print("\n[STEP 7] Loading models from pickle files...")
    loaded_detector, det_meta = persistence.load_model("anomaly_detector")
    loaded_classifier, clf_meta = persistence.load_model("fraud_classifier")
    
    print(f"\n  ✓ Anomaly detector loaded successfully")
    print(f"  ✓ Fraud classifier loaded successfully")
    
    print("\n" + "="*80)
    print("PICKLE FILES CREATED SUCCESSFULLY!")
    print("="*80)
    print("\nFiles created in: outputs/models/")
    print("  • anomaly_detector.pkl")
    print("  • anomaly_detector_metadata.json")
    print("  • fraud_classifier.pkl")
    print("  • fraud_classifier_metadata.json")
    print("\n" + "="*80 + "\n")
