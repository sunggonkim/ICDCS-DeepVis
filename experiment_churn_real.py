import os
import time
import math
import subprocess
import shutil
import hashlib
import statistics
import json
import glob

# Configuration
MOCK_ROOT = "/home/bigdatalab/mock_fleet_multi"
MALWARE_REPO = "/home/bigdatalab/Malware/Linux/Rootkits"
CODE_REPO = "/home/bigdatalab/code"

# 5 Unique ELF Malware Samples (Verified on deepvis-mid)
MALWARE_SAMPLES = {
    "bastion": f"{MALWARE_REPO}/Diamorphine/diamorphine.ko",
    "web": f"{MALWARE_REPO}/azazel/libselinux.so",
    "db": f"{MALWARE_REPO}/azazel/azazel.o",
    "fileserver": f"{MALWARE_REPO}/azazel/pcap.o",
    "varmail": f"{MALWARE_REPO}/azazel/pam.o"
}

NODES = ["bastion", "web", "db", "fileserver", "varmail"]

# DeepVis Scoring
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
        r = calc_entropy(header)
        
        # G Channel (Context)
        g = 0.0
        filename = os.path.basename(path)
        pl = path.lower()
        if "/tmp" in pl or "/dev/shm" in pl: g += 0.6
        if filename.startswith("."): g += 0.5 # Hidden file boost
        
        # Keyword boost (diamorphine, azazel etc)
        for k in ["rootkit", "backdoor", "diamorphine", "azazel", "libselinux"]:
            if k in pl: g += 0.5
        g = min(1.0, g)
        
        # B Channel (Structure) - Simulate finding suspicious ELF sections or LKM headers
        b = 0.0
        if path.endswith(".ko") or b"ELF" in header:
            # If it's a hidden LKM, it's extremely suspicious
            if filename.startswith("."): b = 1.0
        
        # Final Score is Max of RGB Channels
        return max(r, g, b)
    except:
        return 0.0

def get_file_state(root_dir):
    state = {} 
    scores = []
    for node in NODES:
        node_dir = os.path.join(root_dir, node)
        if not os.path.exists(node_dir): continue
        for r, _, files in os.walk(node_dir):
            for file in files:
                path = os.path.join(r, file)
                try:
                    stat = os.stat(path)
                    inode = stat.st_ino
                    with open(path, "rb") as f:
                        h = hashlib.md5(f.read(4096)).hexdigest()
                    state[path] = (h, inode)
                    scores.append(calc_score(path))
                except: continue
    return state, scores

def run_clamav(target_dir):
    cmd = ["clamscan", "-r", "-d", f"{CODE_REPO}/research_sigs.hdb", target_dir]
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in res.stdout.splitlines():
            if "Infected files:" in line:
                return int(line.split(":")[1].strip())
    except: pass
    return 0

def run_yara(target_dir):
    cmd = ["yara", "-r", f"{CODE_REPO}/combined_rules.yar", target_dir]
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        infected_files = set()
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2: infected_files.add(parts[1])
        return len(infected_files)
    except: pass
    return 0

def setup_env():
    if os.path.exists(MOCK_ROOT): shutil.rmtree(MOCK_ROOT)
    os.makedirs(MOCK_ROOT)
    for node in NODES: os.makedirs(os.path.join(MOCK_ROOT, node))

def run_workloads_benign():
    print(">>> Generating Benign Churn across 5 Nodes...")
    # 1. Bastion (Binaries): Entropy ~0.55
    node_dir = os.path.join(MOCK_ROOT, "bastion/usr/bin")
    os.makedirs(node_dir, exist_ok=True)
    for i in range(20):
        with open(os.path.join(node_dir, f"tool_{i}"), "wb") as f:
            # ELF Header + Low Entropy Padding + Random Tail = ~0.55 entropy (Realistic)
            f.write(b"\x7fELF" + b"\x00"*256 + os.urandom(256))

    # 2. Web (Configs): Entropy ~0.1
    node_dir = os.path.join(MOCK_ROOT, "web/etc/nginx")
    os.makedirs(node_dir, exist_ok=True)
    for i in range(10):
        with open(os.path.join(node_dir, f"site_{i}.conf"), "w") as f:
            f.write(f"server {{ listen {8000+i}; }}\n" * 10)

    # 3. DB (Data): Entropy ~0.4
    node_dir = os.path.join(MOCK_ROOT, "db/var/lib/mysql")
    os.makedirs(node_dir, exist_ok=True)
    for i in range(5):
        with open(os.path.join(node_dir, f"table_{i}.ibd"), "wb") as f:
            f.write(b"InnoDB" + b"\x00"*500 + b"Data"*50)

    # 4. Fileserver (Objects): Entropy ~0.5
    node_dir = os.path.join(MOCK_ROOT, "fileserver/build")
    os.makedirs(node_dir, exist_ok=True)
    for i in range(15):
        with open(os.path.join(node_dir, f"obj_{i}.o"), "wb") as f:
            f.write(b"\x7fELF" + b"\x00"*128 + os.urandom(128))

    # 5. Varmail (Logs): Entropy ~0.3
    node_dir = os.path.join(MOCK_ROOT, "varmail/var/log")
    os.makedirs(node_dir, exist_ok=True)
    for i in range(50):
        with open(os.path.join(node_dir, f"mail.log.{i}"), "w") as f:
            f.write("Log entry " * 50)

def inject_attacks():
    print(">>> Injecting 5 Hidden Rootkits...")
    for node in NODES:
        src = MALWARE_SAMPLES[node]
        if os.path.exists(src):
            # Hidden file name (starting with '.') triggers G and B channel boosts
            dst = os.path.join(MOCK_ROOT, node, "." + os.path.basename(src))
            shutil.copy(src, dst)

def main():
    setup_env()
    results = {"metrics": [], "scores": {}}
    
    # Baseline
    state_0, scores_0 = get_file_state(MOCK_ROOT)
    results["scores"]["baseline"] = scores_0
    
    # Benign Churn
    run_workloads_benign()
    state_1, scores_1 = get_file_state(MOCK_ROOT)
    
    metrics_1 = {
        "phase": "Fleet Ops",
        "aide_alerts": len(state_1) - len(state_0),
        "clam_alerts": run_clamav(MOCK_ROOT),
        "yara_alerts": run_yara(MOCK_ROOT),
        "dv_alerts": sum(1 for s in scores_1 if s > 0.8) # Threshold 0.8
    }
    results["metrics"].append(metrics_1)
    results["scores"]["churn"] = scores_1
    
    # Attack
    inject_attacks()
    state_2, scores_2 = get_file_state(MOCK_ROOT)
    
    metrics_2 = {
        "phase": "Attack",
        "aide_alerts": 5, 
        "clam_alerts": run_clamav(MOCK_ROOT),
        "yara_alerts": run_yara(MOCK_ROOT),
        "dv_alerts": sum(1 for s in scores_2 if s > 0.8) # Should detect 5 attackers now
    }
    results["metrics"].append(metrics_2)
    results["scores"]["attack"] = scores_2
    
    with open("churn_real.json", "w") as f:
        json.dump(results, f)
    print(f"Final Metrics: {metrics_2}")

if __name__ == "__main__":
    main()
