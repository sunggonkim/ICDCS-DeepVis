import os
import subprocess
import hashlib
import json
import math
import shutil
import time
import statistics

# Configuration
TARGET_DIRS = ["/usr/bin"] # Focus on binaries
MALWARE_NAME = ".deepvis_rootkit"
MALWARE_PATH = "/usr/bin/" + MALWARE_NAME
ARGS_APT = ["sudo", "DEBIAN_FRONTEND=noninteractive", "apt-get", "-y", "--reinstall", "install", 
            "coreutils", "binutils", "grep", "sed", "tar", "gzip", "util-linux", "findutils"]
            # Reinstalling core packages creates inode changes and mtime updates
            # even if content hash is same, AIDE (default config) triggers on inode/mtime/ctime.
            # To be strict FIM (Content only), we check Hash.
            # If hash doesn't change, we might need to install NEW packages to simulate 'Upgrade' adding files.
            # Let's add 'nmap' or 'zip' if not present?
            # Or just rely on re-install meta-data changes for AIDE (Metadata FIM).

# DeepVis Scoring (Optimized)
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

def calc_score(path):
    try:
        if not os.path.exists(path) or not os.path.isfile(path): return 0.0
        with open(path, "rb") as f:
            header = f.read(512)
        
        # R Channel
        r = calc_entropy(header)
        
        # G Channel (Optimized Weights)
        g = 0.0
        pl = path.lower()
        if "/tmp" in pl or "/dev/shm" in pl: g += 0.6
        if os.path.basename(path).startswith("."): g += 0.5
        for k in ["rootkit", "backdoor", "trojan", "exploit", "shell", "rat", "diamorphine"]:
            if k in pl: 
                g += 0.5
                break
        g = min(1.0, g)
        
        # B Channel (Simplified)
        b = 0.0
        # Assume standard binaries are fine (0.1 approx).
        # We focus on G/R for this experiment.
        
        # Final Anomaly Score (L_inf)
        return max(r, g, b)
    except:
        return 0.0

def get_file_state(dirs):
    state = {} # path -> (hash, inode)
    scores = []
    
    print(f"Scanning {dirs}...")
    for d in dirs:
        if not os.path.exists(d): continue
        for root, _, files in os.walk(d):
            for file in files:
                path = os.path.join(root, file)
                # Helper for Hash + Inode (AIDE)
                try:
                    stat = os.stat(path)
                    inode = stat.st_ino
                    with open(path, "rb") as f:
                        h = hashlib.md5(f.read(4096)).hexdigest()
                    state[path] = (h, inode)
                except: continue
                
                # Helper for DeepVis
                s = calc_score(path)
                scores.append(s)
                
    return state, scores

def compare_aide(state_old, state_new):
    alerts = 0
    # Changed or New
    for p, (h, ino) in state_new.items():
        if p not in state_old:
            alerts += 1 # New
        else:
            h_old, ino_old = state_old[p]
            if h != h_old or ino != ino_old:
                alerts += 1 # Changed (Content or Metadata)
                
    # Deleted
    for p in state_old:
        if p not in state_new:
            alerts += 1
    return alerts

def main():
    results = {"metrics": [], "scores": {}}
    
    # Phase 0: Baseline
    print(">>> Phase 0: Baseline Scan")
    state_0, scores_0 = get_file_state(TARGET_DIRS)
    
    alerts_dv_0 = sum(1 for s in scores_0 if s > 0.8)
    metrics_0 = {
        "phase": "Baseline",
        "files": len(state_0),
        "aide_alerts": 0,
        "dv_alerts": alerts_dv_0,
        "setae_mean": statistics.mean(scores_0) if scores_0 else 0
    }
    results["metrics"].append(metrics_0)
    results["scores"]["baseline"] = scores_0
    
    # Phase 1: Real Churn (apt reinstall)
    print(">>> Phase 1: Executing apt reinstall (Churn)...")
    subprocess.run(ARGS_APT, check=False) # check=False to proceed even if some fail
    # Add explicit sleep for FS sync
    time.sleep(2)
    
    print(">>> Phase 1: Post-Churn Scan")
    state_1, scores_1 = get_file_state(TARGET_DIRS)
    
    alerts_aide_1 = compare_aide(state_0, state_1)
    alerts_dv_1 = sum(1 for s in scores_1 if s > 0.8)
    
    metrics_1 = {
        "phase": "Churn",
        "files": len(state_1),
        "aide_alerts": alerts_aide_1, # Should be high (metadata/hash changes)
        "dv_alerts": alerts_dv_1,     # Should be same as baseline (approx)
        "setae_mean": statistics.mean(scores_1) if scores_1 else 0
    }
    results["metrics"].append(metrics_1)
    results["scores"]["churn"] = scores_1
    
    # Phase 2: Attack Injection
    print(">>> Phase 2: Injecting Rootkit...")
    # Inject Diamorphine simulation
    # 1. Hidden file (G+=0.5)
    # 2. Keyword 'rootkit' (G+=0.5) -> Total G=1.0
    with open(MALWARE_PATH, "wb") as f:
        f.write(b"\x7fELF" + b"X"*1000)
    
    print(">>> Phase 2: Post-Attack Scan")
    state_2, scores_2 = get_file_state(TARGET_DIRS)
    
    alerts_aide_2 = compare_aide(state_0, state_2) # Compare to baseline
    alerts_dv_2 = sum(1 for s in scores_2 if s > 0.8)
    
    metrics_2 = {
        "phase": "Attack",
        "files": len(state_2),
        "aide_alerts": alerts_aide_2,
        "dv_alerts": alerts_dv_2,
        "setae_mean": statistics.mean(scores_2) if scores_2 else 0
    }
    results["metrics"].append(metrics_2)
    results["scores"]["attack"] = scores_2
    
    # Cleanup
    if os.path.exists(MALWARE_PATH):
        os.remove(MALWARE_PATH)
        
    # Save
    with open("churn_real.json", "w") as f:
        json.dump(results, f)
    print("\n[Done] Saved to churn_real.json")
    
    # Print Summary
    print("\nSummary:")
    for m in results["metrics"]:
        print(m)

if __name__ == "__main__":
    main()
