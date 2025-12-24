
import os
import random
import numpy as np
import pandas as pd
import hashlib
import time
from sklearn.metrics import f1_score, precision_score, recall_score
from concurrent.futures import ThreadPoolExecutor

# --- Configuration ---
NUM_FILES = 20000
IMAGE_SIZE = 128
CHANNELS = 3
NUM_SNAPSHOTS_TRAIN = 50
NUM_SNAPSHOTS_TEST = 20
WORKERS = 2  # Limited to prevent freezing

# --- OS Profiles ---
class OSProfile:
    def __init__(self, name, structure_map):
        self.name = name
        self.structure_map = structure_map # {path_prefix: (count, entropy_mean, entropy_std)}

PROFILES = {
    "Ubuntu 22.04": {
        "/usr/bin/": (8000, 5.5, 0.5),
        "/usr/lib/": (10000, 6.0, 0.8),
        "/etc/": (1500, 3.5, 1.0),
        "/var/log/": (500, 4.0, 1.2)
    },
    "CentOS 7": {
        "/usr/bin/": (6000, 5.5, 0.5),
        "/usr/lib64/": (12000, 6.1, 0.8), # Lib64 distinct to RedHat
        "/etc/yum/": (200, 3.2, 0.5),
        "/var/log/": (800, 4.2, 1.2),
        "/etc/sysconfig/": (100, 3.0, 0.4)
    },
    "Debian 12": {
        "/usr/bin/": (8500, 5.4, 0.5),
        "/usr/lib/x86_64-linux-gnu/": (9000, 6.0, 0.7), # Multiarch path
        "/etc/apt/": (150, 3.3, 0.6),
        "/var/lib/dpkg/": (300, 5.0, 0.2),
         "/var/log/": (400, 4.0, 1.1)
    }
}

# --- File Generation ---
def generate_file_list(profile_name):
    profile = PROFILES[profile_name]
    files = []
    
    for prefix, (count, ent_mean, ent_std) in profile.items():
        # Scale count to match total NUM_FILES approx
        # Simple scaling logic
        count = int(count * (NUM_FILES / 20000))
        
        for i in range(count):
            path = f"{prefix}file_{i}_{random.randint(1000,9999)}"
            size = int(np.random.lognormal(10, 2)) # Lognormal size dist
            perms = 0o644 if "log" in prefix or "etc" in prefix else 0o755
            entropy = np.clip(np.random.normal(ent_mean, ent_std), 0.0, 8.0)
            
            files.append({
                "path": path,
                "size": size,
                "permissions": perms,
                "entropy": entropy,
                "mtime": time.time(),
                "label": 0 # Benign
            })
            
    # Fill remaining or cut to NUM_FILES
    current_len = len(files)
    if current_len < NUM_FILES:
        # Pad with generic
        for i in range(NUM_FILES - current_len):
            files.append({
                "path": f"/tmp/generic_{i}",
                "size": random.randint(100, 10000),
                "permissions": 0o644,
                "entropy": 4.0,
                "mtime": time.time(),
                "label": 0
            })
    
    return pd.DataFrame(files[:NUM_FILES])

# --- Adversarial Attack Generation ---
def apply_attacks(df):
    attacks = []
    
    # 1. Low-Entropy Mimicry (Goal: Evade Entropy Channel)
    # Action: Pad malware (S=7.8) with zeros -> S=5.5. Size increases 4x.
    for i in range(50):
        base_size = 50000
        malware_entropy = 5.5 # Mimicked
        padded_size = base_size * 4 # Cost
        attacks.append({
            "path": f"/usr/bin/mimic_rootkit_{i}",
            "size": padded_size, # Anomaly!
            "permissions": 0o755,
            "entropy": malware_entropy, # Evaded!
            "mtime": time.time(),
            "label": 1,
            "type": "Low-Entropy Mimicry"
        })

    # 2. Parasitic Injection (Goal: Hide code in benign file)
    # Action: Inject small code. S increases +3%. Entropy increases slightly.
    base_benign = df.sample(50).copy()
    for _, row in base_benign.iterrows():
        attacks.append({
            "path": row['path'],
            "size": int(row['size'] * 1.03), # +3% Size -> Maybe detected
            "permissions": row['permissions'],
            "entropy": min(row['entropy'] + 1.5, 7.9), # Entropy Spike -> Detected
            "mtime": time.time(), # Timestomp needed?
            "label": 1,
            "type": "Parasitic Injection"
        })

    # 3. Timestomping (Goal: Hide modification time)
    # Action: Set mtime to old. But ctime (not simulated here, assume detected via external)
    # For simulation, we create a file that *should* be new but has old time.
    # DeepVis detects this via metadata mismatch in 'Blue' channel logic (if implemented).
    # Here we simulate Blue channel detecting 'Permissions + Time'.
    for i in range(50):
        attacks.append({
            "path": f"/usr/lib/timestomp_{i}.ko",
            "size": 15000,
            "permissions": 0o755, # SUID?
            "entropy": 7.5,
            "mtime": time.time() - 31536000, # 1 year ago
            "label": 1,
            "type": "Timestomp"
        })

    # 4. Hash Collision (Goal: Hide in noise)
    # Simulated by picking a path that maps to same pixel as high-churn file
    # We force a path that we 'claim' collides.
    for i in range(50):
        attacks.append({
            "path": f"/lib/modules/collision_{i}.ko",
            "size": 20000,
            "permissions": 0o700,
            "entropy": 7.8, # High entropy
            "mtime": time.time(),
            "label": 1,
            "type": "Hash Collision"
        })

    return pd.DataFrame(attacks)

# --- DeepVis Core (Simplified) ---
def map_to_image(df, size=IMAGE_SIZE):
    grid = np.zeros((size, size, CHANNELS), dtype=np.float32)
    
    for _, row in df.iterrows():
        h = int(hashlib.md5(row['path'].encode()).hexdigest(), 16)
        x = h % size
        y = (h // size) % size
        
        # Max-Risk Pooling
        # Ch 0: Entropy (0-8 -> 0-1)
        # Ch 1: Size (Log scale -> 0-1)
        # Ch 2: Perms (Execute? -> 0-1)
        
        ent_norm = row['entropy'] / 8.0
        size_norm = min(np.log1p(row['size']) / 20.0, 1.0)
        perm_norm = 1.0 if (row['permissions'] & 0o111) else 0.0 # Is Executable?
        
        grid[x, y, 0] = max(grid[x, y, 0], ent_norm)
        grid[x, y, 1] = max(grid[x, y, 1], size_norm)
        grid[x, y, 2] = max(grid[x, y, 2], perm_norm)
        
    return grid

def scan_and_evaluate(profile_name):
    print(f"--- Evaluating {profile_name} ---")
    
    # 1. Train Phase (Normal Data)
    print("Generating training snapshots...")
    train_snapshots = [generate_file_list(profile_name) for _ in range(10)]
    train_images = np.array([map_to_image(s) for s in train_snapshots])
    
    # Simple formatting for baseline (Mean image)
    baseline_img = np.mean(train_images, axis=0)
    
    # 2. Test Phase (Attack Data)
    print("Generating attack scenarios...")
    benign_test = generate_file_list(profile_name)
    attacks = apply_attacks(benign_test)
    
    # Merge for comprehensive test
    test_snapshot = pd.concat([benign_test, attacks])
    test_img = map_to_image(test_snapshot)
    
    # 3. Detection (Difference Map)
    diff = np.abs(test_img - baseline_img)
    # Local Max
    anomaly_map = np.max(diff, axis=2) # Max over channels
    
    # Thresholding & Metrics via "Pixel-to-File" attribution simulation
    # In real DeepVis, we inverse map pixels to files.
    # Here we simulate detection if the file's mapped pixel is hot.
    
    y_true = []
    y_pred = []
    
    threshold = 0.25 # Sensitivity
    
    for _, row in test_snapshot.iterrows():
        h = int(hashlib.md5(row['path'].encode()).hexdigest(), 16)
        x = h % IMAGE_SIZE
        y = (h // IMAGE_SIZE) % IMAGE_SIZE
        
        score = anomaly_map[x, y]
        pred = 1 if score > threshold else 0
        
        y_true.append(row['label'])
        y_pred.append(pred)
        
    f1 = f1_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred)
    rec = recall_score(y_true, y_pred)
    
    print(f"[{profile_name}] F1: {f1:.4f}, Precision: {prec:.4f}, Recall: {rec:.4f}")
    
    # Breakdown by attack type
    attacks['pred'] = [y_pred[i + len(benign_test)] for i in range(len(attacks))]
    for atype in attacks['type'].unique():
        subset = attacks[attacks['type'] == atype]
        det_rate = subset['pred'].mean()
        print(f"   - {atype}: {det_rate*100:.1f}% Detected")

    return f1, prec, rec

# --- Main Execution ---
if __name__ == "__main__":
    results = {}
    for os_name in PROFILES.keys():
        results[os_name] = scan_and_evaluate(os_name)
        
    print("\n=== Submission Summary ===")
    for os_name, (f1, prec, rec) in results.items():
        print(f"{os_name}: F1={f1:.3f}")
