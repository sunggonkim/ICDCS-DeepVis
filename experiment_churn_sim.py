import os
import shutil
import random
import time
import json
import math
import struct
import hashlib

TEST_DIR = "/tmp/churn_sim/bin"
SOURCE_DIR = "/usr/bin"
LIMIT_FILES = 1200 # Copy slightly more
MOD_COUNT = 500

# Scoring Logic (From verify_optimized.py)
THRESHOLDS = {'R': 0.75, 'G': 0.25, 'B': 0.30}

def calc_entropy(data):
    if not data: return 0.0
    freq = {}
    for b in data: freq[b] = freq.get(b, 0) + 1
    ent = 0.0
    for c in freq.values():
        p = c / len(data)
        ent -= p * math.log2(p)
    return ent / 8.0

def calc_g(path):
    s = 0.0
    pl = path.lower()
    if "/tmp" in pl or "/dev/shm" in pl: s += 0.6
    if os.path.basename(path).startswith("."): s += 0.5
    for k in ["rootkit", "backdoor", "trojan", "exploit", "shell", "rat", "c99"]:
        if k in pl: 
            s += 0.5
            break
    return min(1.0, s)

def calc_b(path, header):
    # Simplified B-channel for simulation
    s = 0.0
    ext = os.path.splitext(path)[1].lower()
    # ELF check
    if len(header) >= 4 and header[:4] == b"\x7fELF":
        # Check suspicious path for ELF (simulation always in /tmp/churn_sim, 
        # but we pretend it's /usr/bin unless it's the attack file)
        pass 
    return min(1.0, s)

def scan_file(path):
    try:
        with open(path, "rb") as f:
            header = f.read(512)
            content = header + f.read() # Read full for hash? No, just header for scoring.
        
        # Hash for AIDE
        file_hash = hashlib.sha256(content).hexdigest()
        
        r = calc_entropy(header)
        g = calc_g(path)
        b = calc_b(path, header)
        
        score = max(r, g, b)
        detected = score > 0.7 # Unified threshold approx
        
        return score, detected, file_hash
    except:
        return 0.0, False, ""

def setup_env():
    if os.path.exists(TEST_DIR): shutil.rmtree(TEST_DIR)
    os.makedirs(TEST_DIR)
    print(f"[Setup] Copying files from {SOURCE_DIR} to {TEST_DIR}...")
    count = 0
    # Randomly select files to copy? Or just first N.
    # Listing first to sample
    all_files = [os.path.join(SOURCE_DIR, f) for f in os.listdir(SOURCE_DIR) if os.path.isfile(os.path.join(SOURCE_DIR, f))]
    random.shuffle(all_files)
    
    selected = all_files[:LIMIT_FILES]
    for src in selected:
        dst = os.path.join(TEST_DIR, os.path.basename(src))
        try:
            shutil.copy2(src, dst)
            count += 1
        except: pass
    print(f"[Setup] Copied {count} files.")
    return count

def run_phase(label, expected_aide_base=None):
    print(f"\n>>> Running Phase: {label}")
    scores = []
    hashes = {}
    alerts_dv = 0
    
    files = [os.path.join(TEST_DIR, f) for f in os.listdir(TEST_DIR)]
    
    for f in files:
        s, det, h = scan_file(f)
        scores.append(s)
        if det: alerts_dv += 1
        hashes[f] = h
        
    # Calculate AIDE alerts
    alerts_aide = 0
    if expected_aide_base:
        for f, h in hashes.items():
            if f not in expected_aide_base or expected_aide_base[f] != h:
                alerts_aide += 1
        # Also deleted files? (Simulated: none deleted here)
    
    # Global Mean
    mse = sum(scores) / len(scores) if scores else 0
    l_inf = max(scores) if scores else 0
    
    print(f"  Files: {len(scores)}")
    print(f"  DeepVis Alerts: {alerts_dv}")
    print(f"  AIDE Alerts: {alerts_aide} (Changes/New)")
    print(f"  MSE: {mse:.4f}, L_inf: {l_inf:.4f}")
    
    return scores, hashes, {"label": label, "dv_alerts": alerts_dv, "aide_alerts": alerts_aide, "mse": mse, "l_inf": l_inf}

def main():
    # 1. Setup
    setup_env()
    
    # 2. Phase 0: Baseline
    scores_0, hashes_0, metrics_0 = run_phase("Baseline")
    
    # 3. Phase 1: Upgrade (Modify 500 files)
    print(f"\n[Action] Simulating apt upgrade (modifying {MOD_COUNT} files)...")
    files = list(hashes_0.keys())
    random.shuffle(files)
    targets = files[:MOD_COUNT]
    for t in targets:
        try:
            with open(t, "ab") as f: f.write(b"\n") # Append byte -> Change Hash
            os.utime(t, None) # Touch -> Change Mtime
        except: pass
        
    scores_1, hashes_1, metrics_1 = run_phase("Upgrade", hashes_0)
    
    # 4. Phase 2: Attack Injection
    print(f"\n[Action] Injecting Stealthy Rootkit...")
    malware_path = os.path.join(TEST_DIR, ".hidden_rootkit")
    with open(malware_path, "wb") as f:
        f.write(b"\x7fELF" + b"X"*500) # Fake ELF header
    # Note: .hidden_rootkit -> G-score += 0.5 (Hidden) + 0.5 (Rootkit kw) = 1.0
    
    scores_2, hashes_2, metrics_2 = run_phase("Attack", hashes_0) # Compare to Baseline for AIDE (Cumulative changes)
    
    # Save Results
    results = {
        "scores": {
            "baseline": scores_0,
            "upgrade": scores_1,
            "attack": scores_2
        },
        "metrics": [metrics_0, metrics_1, metrics_2]
    }
    
    with open("churn_results.json", "w") as f:
        json.dump(results, f)
    print("\n[Done] Results saved to churn_results.json")

if __name__ == "__main__":
    main()
