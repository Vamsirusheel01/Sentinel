import pandas as pd
import numpy as np
import os
import sys
import joblib
from sklearn.ensemble import RandomForestClassifier

# Path setup to import shared models
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from shared.models import Severity, ActionType

class SentinelModel:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model_path = os.path.join(os.path.dirname(__file__), 'sentinel_brain.pkl')
        self.sources = ['process', 'network', 'registry', 'yara', 'system']
        self.source_map = {s: i for i, s in enumerate(self.sources)}
        self.action_rev_map = {
            0: ActionType.LOG_ONLY,
            1: ActionType.STRIP_PRIVILEGES,
            2: ActionType.KILL_PROCESS,
            3: ActionType.BLOCK_IP,
            4: ActionType.DISCONNECT_NETWORK,
            5: ActionType.LOCKOUT_USER,
            6: ActionType.REVERT_REGISTRY
        }

    def train(self, data_path):
        df = pd.read_csv(data_path)
        X = df[['source_id', 'severity_id', 'trust_score']]
        y = df['action_id']
        
        print(f"[AI] Training Aggressive Guardian model on {len(df)} samples...")
        self.model.fit(X, y)
        joblib.dump(self.model, self.model_path)
        print(f"[AI] Model saved to {self.model_path}")

    def predict_action(self, source, severity_value, trust_score) -> Tuple[ActionType, float]:
        if not os.path.exists(self.model_path):
            return ActionType.LOG_ONLY, 0.0
            
        mod = joblib.load(self.model_path)
        
        # Fuzzy source mapping
        src_id = 4 # Default to system
        for key, val in self.source_map.items():
            if key in source.lower():
                src_id = val
                break
        
        features = np.array([[src_id, severity_value, trust_score]])
        
        # Get probabilities
        probs = mod.predict_proba(features)[0]
        max_idx = np.argmax(probs)
        confidence = probs[max_idx]
        pred_id = mod.classes_[max_idx]
        
        return self.action_rev_map.get(pred_id, ActionType.LOG_ONLY), float(confidence)

if __name__ == "__main__":
    # If run directly, generate data and train
    from data_gen import generate_synthetic_data
    csv_path = os.path.join(os.path.dirname(__file__), 'threat_data.csv')
    generate_synthetic_data(3000)
    
    sm = SentinelModel()
    sm.train(csv_path)
