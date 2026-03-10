import pandas as pd
import numpy as np
import os
import sys

# Path setup to import shared models
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from shared.models import Severity, ActionType

def generate_synthetic_data(samples=5000):
    data = []
    
    sources = ['process', 'network', 'registry', 'yara', 'system']
    source_map = {s: i for i, s in enumerate(sources)}
    
    action_options = [
        ActionType.LOG_ONLY, ActionType.STRIP_PRIVILEGES, ActionType.KILL_PROCESS,
        ActionType.BLOCK_IP, ActionType.DISCONNECT_NETWORK, ActionType.LOCKOUT_USER,
        ActionType.REVERT_REGISTRY
    ]
    
    action_map = { a: i for i, a in enumerate(action_options) }
    
    for _ in range(samples):
        source = np.random.choice(sources)
        severity_value = np.random.choice([1, 2, 3, 4])
        trust_score = np.random.uniform(0, 100)
        
        # AGGRESSIVE GUARDIAN LOGIC
        action = ActionType.LOG_ONLY
        
        if severity_value == 4: # CRITICAL
            if source == 'registry': action = ActionType.REVERT_REGISTRY
            elif source == 'yara': action = ActionType.KILL_PROCESS
            elif source == 'network': action = ActionType.DISCONNECT_NETWORK
            else: action = ActionType.LOCKOUT_USER
            
        elif severity_value == 3: # HIGH
            if source == 'network': action = ActionType.BLOCK_IP
            elif source == 'process': action = ActionType.KILL_PROCESS
            else: action = ActionType.STRIP_PRIVILEGES
            
        elif severity_value == 2: # MEDIUM
            # Aggressive: even medium threats get penalized below 90% trust
            if trust_score < 90:
                action = ActionType.STRIP_PRIVILEGES
            else:
                action = ActionType.LOG_ONLY
        
        # Add very little noise for high precision
        if np.random.random() < 0.01:
            action = np.random.choice(action_options)
            
        data.append({
            'source_id': source_map[source],
            'severity_id': severity_value,
            'trust_score': trust_score,
            'action_id': action_map[action]
        })
        
    df = pd.DataFrame(data)
    output_path = os.path.join(os.path.dirname(__file__), 'threat_data.csv')
    df.to_csv(output_path, index=False)
    print(f"[AI] Dataset generated with 5,000 samples.")

if __name__ == "__main__":
    generate_synthetic_data()
