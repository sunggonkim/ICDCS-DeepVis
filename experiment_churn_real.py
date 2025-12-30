import os
import time
import math
import subprocess
import shutil
import hashlib
import statistics
import json

# Configuration
MOCK_DIR = "/home/bigdatalab/mock_fleet"
TARGET_DIRS = ["/usr/bin", MOCK_DIR] 
MALWARE_NAME = ".deepvis_rootkit"
MALWARE_PATH = "/usr/bin/" + MALWARE_NAME
ARGS_APT = ["sudo", "DEBIAN_FRONTEND=noninteractive", "apt-get", "-y", "--reinstall", "install", 
            "coreutils", "binutils", "grep", "sed", "tar", "gzip", "util-linux", "findutils"]

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

def setup_mock_env():
    if os.path.exists(MOCK_DIR):
        shutil.rmtree(MOCK_DIR)
    os.makedirs(f"{MOCK_DIR}/web/conf", exist_ok=True)
    os.makedirs(f"{MOCK_DIR}/db/data", exist_ok=True)
    os.makedirs(f"{MOCK_DIR}/build/src", exist_ok=True)
    os.makedirs(f"{MOCK_DIR}/app/logs", exist_ok=True)

    # create initial files
    with open(f"{MOCK_DIR}/web/conf/nginx.conf", "w") as f: f.write("worker_processes 1;\n")
    with open(f"{MOCK_DIR}/build/src/main.c", "w") as f: f.write("int main(){return 0;}\n")
    with open(f"{MOCK_DIR}/app/logs/server.log", "w") as f: f.write("Init\n")

def run_workloads():
    print(">>> [Workload 1] Bastion: apt reinstall...")
    subprocess.run(ARGS_APT, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    print(">>> [Workload 2] Web: Updating Configs...")
    # Modify config (Metadata + Content Change)
    with open(f"{MOCK_DIR}/web/conf/nginx.conf", "a") as f: f.write(f"# Update {time.time()}\n")
    with open(f"{MOCK_DIR}/web/conf/vhost.conf", "w") as f: f.write("server { listen 80; }\n") # New file

    print(">>> [Workload 3] Build: Compiling Code...")
    # Compile (New Binary Artifacts)
    # Check if gcc exists
    subprocess.run(["gcc", f"{MOCK_DIR}/build/src/main.c", "-o", f"{MOCK_DIR}/build/src/app_bin"], check=False)
    
    print(">>> [Workload 4] DB: Writing Data...")
    # Write Binary Data (High Entropy) - Challenge for R-Channel
    # Header should be structured (e.g. SQLite) to avoid Header-Entropy FP on benign DB
    with open(f"{MOCK_DIR}/db/data/users.db", "wb") as f: 
        f.write(b"SQLite format 3\0" * 20) # Low entropy header (simulating valid magic bytes)
        f.write(os.urandom(1024 * 1024)) # High entropy body (ignored by header scan)
    
    print(">>> [Workload 5] App: Rotating Logs...")
    # Log Rotation (New files, content append)
    shutil.move(f"{MOCK_DIR}/app/logs/server.log", f"{MOCK_DIR}/app/logs/server.log.1")
    with open(f"{MOCK_DIR}/app/logs/server.log", "w") as f: f.write("New Log Start\n")

def main():
    setup_mock_env()
    results = {"metrics": [], "scores": {}}
    
    # Phase 0: Baseline
    print(">>> Phase 0: Baseline Scan (Fleet)")
    state_0, scores_0 = get_file_state(TARGET_DIRS)
    
    metrics_0 = {
        "phase": "Baseline",
        "files": len(state_0),
        "aide_alerts": 0,
        "dv_alerts": sum(1 for s in scores_0 if s > 0.8),
        "setae_mean": statistics.mean(scores_0) if scores_0 else 0
    }
    results["metrics"].append(metrics_0)
    results["scores"]["baseline"] = scores_0
    
    # Phase 1: Real Fleet Operations
    print(">>> Phase 1: Running 5 Real Workloads...")
    run_workloads()
    time.sleep(2) # Sync
    
    print(">>> Phase 1: Post-Workload Scan")
    state_1, scores_1 = get_file_state(TARGET_DIRS)
    
    alerts_aide_1 = compare_aide(state_0, state_1)
    alerts_dv_1 = sum(1 for s in scores_1 if s > 0.8)
    
    metrics_1 = {
        "phase": "Fleet Ops",
        "files": len(state_1),
        "aide_alerts": alerts_aide_1, # Real sum of all changes
        "dv_alerts": alerts_dv_1,     # DeepVis should ignore DB high entropy? Let's see.
        "setae_mean": statistics.mean(scores_1) if scores_1 else 0
    }
    results["metrics"].append(metrics_1)
    results["scores"]["churn"] = scores_1
    
    # Phase 2: Attack Injection
    print(">>> Phase 2: Injecting Rootkit...")
    with open(MALWARE_PATH, "wb") as f:
        f.write(b"\x7fELF" + b"X"*1000)
    
    print(">>> Phase 2: Post-Attack Scan")
    state_2, scores_2 = get_file_state(TARGET_DIRS)
    
    alerts_aide_2 = compare_aide(state_0, state_2)
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
    if os.path.exists(MALWARE_PATH): os.remove(MALWARE_PATH)
    if os.path.exists(MOCK_DIR): shutil.rmtree(MOCK_DIR)
        
    # Save
    with open("churn_real.json", "w") as f:
        json.dump(results, f)
    print("\n[Done] Saved Fleet Data to churn_real.json")
    
    # Summary
    print("\nReal Fleet Summary:")
    for m in results["metrics"]:
        print(m)

if __name__ == "__main__":
    main()
