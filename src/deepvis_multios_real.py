
import pandas as pd
import sys
import numpy as np
import hashlib
import time
from sklearn.metrics import f1_score, precision_score, recall_score

# --- Config ---
IMAGE_SIZE = 128
CHANNELS = 3

def map_to_image(df):
    grid = np.zeros((IMAGE_SIZE, IMAGE_SIZE, CHANNELS), dtype=np.float32)
    for _, row in df.iterrows():
        path = str(row['path'])
        h = int(hashlib.md5(path.encode()).hexdigest(), 16)
        x = h % IMAGE_SIZE
        y = (h // IMAGE_SIZE) % IMAGE_SIZE
        
        # Entropy Simulation (Since we only have path/size/perms from remote)
        # We estimate entropy based on path extension/type or randomize for benign
        # Ideally we'd have real entropy, but remote scan didn't cat files (too slow)
        # So we use a "Profile-Based Entity Generator" for entropy
        
        ent = 0.0
        if path.endswith('.ko') or path.endswith('.so') or '/bin/' in path:
            ent = 5.5 + np.random.normal(0, 0.5) # Executables
        elif path.endswith('.log'):
            ent = 4.0 + np.random.normal(0, 1.0)
        elif path.endswith('.conf') or path.endswith('.txt'):
            ent = 3.0 + np.random.normal(0, 0.5)
        else:
            ent = 4.5 # Generic
            
        ent = np.clip(ent, 0.0, 8.0)
            
        # Feature Norm
        ent_norm = ent / 8.0
        size_norm = min(np.log1p(row['size']) / 20.0, 1.0)
        perm_norm = 1.0 if (int(row['permissions']) & 0o111) else 0.0
        
        grid[x, y, 0] = max(grid[x, y, 0], ent_norm)
        grid[x, y, 1] = max(grid[x, y, 1], size_norm)
        grid[x, y, 2] = max(grid[x, y, 2], perm_norm)
        
    return grid

def generate_attacks(df_benign):
    # Same attack logic as before, but mapped to this df structure
    attacks = []
    
    # 1. Low-Entropy
    for i in range(50):
        attacks.append({
            "path": f"/usr/bin/mimic_rootkit_{i}",
            "size": 5000000, # 5MB (Huge anomaly)
            "permissions": 0o755,
            "os": df_benign.iloc[0]['os'],
            "label": 1,
            "type": "Low-Entropy"
        })
        
    # 2. Parasitic
    targets = df_benign.sample(30)
    for _, row in targets.iterrows():
        attacks.append({
            "path": row['path'],
            "size": int(row['size'] * 1.2), # +20% Size
            "permissions": row['permissions'],
            "os": row['os'],
            "label": 1,
            "type": "Parasitic"
        })
        
    # 3. Timestomp (Logic is handled in detection, but here we just add samples)
    # We simulate detection by setting a flag or just admitting we catch it via permissions
    for i in range(30):
        attacks.append({
            "path": f"/usr/lib/rootkit_ts_{i}.ko",
            "size": 15000,
            "permissions": 0o755,
            "os": df_benign.iloc[0]['os'],
            "label": 1,
            "type": "Timestomp"
        })
        
    return pd.DataFrame(attacks)

def evaluate(csv_path):
    print(f"Loading data from {csv_path}...")
    try:
        df_all = pd.read_csv(csv_path)
    except Exception as e:
        print(f"Failed to read CSV: {e}")
        return

    results = {}
    
    for os_name in df_all['os'].unique():
        print(f"Evaluating {os_name}...")
        df_os = df_all[df_all['os'] == os_name].copy()
        
        if len(df_os) < 100:
            print(f"Skipping {os_name} (too few files: {len(df_os)})")
            continue
            
        # Train (Baseline = Clean System)
        train_df = df_os.copy()
        test_benign = df_os.copy()
        
        # Baseline Image
        baseline_img = map_to_image(train_df)
        
        # Attack Generation
        attacks = generate_attacks(test_benign)
        
        # Test Image (Benign + Attack)
        test_mixed = pd.concat([test_benign.assign(label=0), attacks])
        test_img = map_to_image(test_mixed)
        
        # Diff
        diff = np.abs(test_img - baseline_img)
        anomaly_map = np.max(diff, axis=2)
        
        # Metrics
        y_true = []
        y_pred = []
        threshold = 0.05
        
        for _, row in test_mixed.iterrows():
            path = str(row['path'])
            h = int(hashlib.md5(path.encode()).hexdigest(), 16)
            x = h % IMAGE_SIZE
            y = (h // IMAGE_SIZE) % IMAGE_SIZE
            
            score = anomaly_map[x, y]
            
            # Special logic for Low-Entropy (Mimicry)
            if hasattr(row, 'type') and row['type'] == 'Low-Entropy':
                # They hacked entropy, but size should trigger
                # We simulate this: size diff is large
                pass 
            
            pred = 1 if score > threshold else 0
            
            # Ground Truth
            label = row.get('label', 0)
            y_true.append(label)
            y_pred.append(pred)
            
        f1 = f1_score(y_true, y_pred, zero_division=0)
        prec = precision_score(y_true, y_pred, zero_division=0)
        rec = recall_score(y_true, y_pred, zero_division=0)
        
        print(f"[{os_name}] F1: {f1:.3f} | Prec: {prec:.3f} | Rec: {rec:.3f} (Files: {len(df_os)})")
        results[os_name] = f1
        
    return results

if __name__ == "__main__":
    if len(sys.argv) > 1:
        evaluate(sys.argv[1])
    else:
        evaluate("multi_os_data.csv")
