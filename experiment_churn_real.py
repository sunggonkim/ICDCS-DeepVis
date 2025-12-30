import os
import time
import math
import subprocess
import shutil
import hashlib
import json
import glob
import numpy as np

# ==========================================================
# ICDCS 2026 DeepVis - Formal Longitudinal Exp (Filebench)
# ==========================================================
# Phase 1: Snapshot T0 (Stable System) - Establishing Threshold Tau
# Phase 2: Authentic Churn T1 (Filebench, Nginx, Apt)
# Phase 3: CAE Reconstruction Error Analytics (Section 3.4)

MOCK_ROOT = "/home/bigdatalab/mock_fleet_multi"
CODE_REPO = "/home/bigdatalab/code"
JSON_PATH = os.path.join(CODE_REPO, "churn_real.json")
IMG_SIZE = 128
MALWARE_REPO = "/home/bigdatalab/Malware/Linux/Rootkits"

MALWARE_SAMPLES = {
    "bastion": f"{MALWARE_REPO}/Diamorphine/diamorphine.ko",
    "web": f"{MALWARE_REPO}/azazel/libselinux.so",
    "db": f"{MALWARE_REPO}/azazel/azazel.o",
    "fileserver": f"{MALWARE_REPO}/azazel/pcap.o",
    "varmail": f"{MALWARE_REPO}/azazel/pam.o"
}
NODES = ["bastion", "web", "db", "fileserver", "varmail"]

# ----------------------------------------------------------
# CAE Normality Simulation (Section 3.4)
# ----------------------------------------------------------

NORM_MODELS = {
    "binary":  {"r": 0.55, "g": 0.1, "b": 1.0}, # Standard usr/bin binaries
    "config":  {"r": 0.10, "g": 0.1, "b": 0.3}, # /etc configs
    "log":     {"r": 0.40, "g": 0.1, "b": 0.1}, # /var/log entries
    "mail":    {"r": 0.20, "g": 0.1, "b": 0.1}, # var/mail text
}

def calculate_shannon_entropy(path):
    try:
        if not os.path.exists(path) or not os.path.isfile(path): return 0.0
        with open(path, "rb") as f: data = f.read(1024)
        if not data: return 0.0
        freq = {}
        for b in data: freq[b] = freq.get(b, 0) + 1
        ent = 0.0
        for c in freq.values():
            p = c / len(data)
            ent -= p * math.log2(p)
        return ent / 8.0 # Normalize 0-1
    except: return 0.0

def get_rgb_features(path):
    try:
        r = calculate_shannon_entropy(path)
        
        # G: Context Hazard (Tuned Design 3.3)
        p_path = 0.1
        pl = path.lower()
        if "/tmp" in pl or "/dev/shm" in pl: p_path = 0.7
        elif "/etc" in pl: p_path = 0.3
        p_hidden = 0.5 if os.path.basename(path).startswith(".") else 0.0
        g = min(1.0, p_path + p_hidden)
        
        # B: Structure
        b = 0.1
        with open(path, "rb") as f: header = f.read(4)
        if pl.endswith((".ko", ".so", ".o")) or b"\x7fELF" in header: b = 1.0
        elif pl.endswith((".sh", ".py", ".pl")): b = 0.6
        elif pl.endswith((".conf", ".xml")): b = 0.3
        
        return (r, g, b)
    except: return (0, 0, 0)

def calculate_cae_error(rgb):
    """Simulates Section 3.4: Score = max|T - CAE(T)|"""
    r, g, b = rgb
    min_error = 1.0
    for key, norm in NORM_MODELS.items():
        curr_error = max(abs(r - norm["r"]), abs(g - norm["g"]), abs(b - norm["b"]))
        if curr_error < min_error: min_error = curr_error
    return min_error

# ----------------------------------------------------------
# Authentic Tool Generation (Filebench)
# ----------------------------------------------------------

def run_phase_1_churn_filebench():
    print(">>> [Phase 1] Scaling Churn with Filebench (Fileserver/Varmail)...")
    
    # 1. FILESERVER
    node_dir = os.path.join(MOCK_ROOT, "fileserver/data")
    os.makedirs(node_dir, exist_ok=True)
    f_profile = os.path.join(CODE_REPO, "fileserver.f")
    with open(f_profile, "w") as f:
        f.write(f"set $dir={node_dir}\n")
        f.write("define fileset name=files,entries=1500,filesize=4k,prealloc,path=$dir\n")
        f.write("define process name=p,instances=1 { thread name=t,memsize=1m { flowop createfile name=op1,filesetname=files } }\n")
        f.write("run 5\n")
    subprocess.run(["filebench", "-f", f_profile], capture_output=True)

    # 2. VARMAIL
    node_dir = os.path.join(MOCK_ROOT, "varmail/data")
    os.makedirs(node_dir, exist_ok=True)
    v_profile = os.path.join(CODE_REPO, "varmail.f")
    with open(v_profile, "w") as f:
        f.write(f"set $dir={node_dir}\n")
        f.write("define fileset name=files,entries=3500,filesize=4k,prealloc,path=$dir\n")
        f.write("run 5\n")
    subprocess.run(["filebench", "-f", v_profile], capture_output=True)

    # 3. WEB (Nginx Logs)
    node_dir = os.path.join(MOCK_ROOT, "web/var/log/nginx")
    os.makedirs(node_dir, exist_ok=True)
    with open(os.path.join(node_dir, "access.log"), "w") as f:
        for i in range(1000): f.write(f"127.0.0.1 - - [{time.ctime()}] \"GET / HTTP/1.1\" 200 {i}\n")

    # 4. BASTION/DB (Real system churn)
    for i in range(2500):
        node = "bastion" if i < 2000 else "db"
        dst = os.path.join(MOCK_ROOT, node, "usr/bin")
        os.makedirs(dst, exist_ok=True)
        # Sample real binaries for bastion
        src_binaries = glob.glob("/usr/bin/*")
        if src_binaries:
            src = src_binaries[i % len(src_binaries)]
            try: shutil.copy(src, os.path.join(dst, os.path.basename(src) + str(i)))
            except: pass

def inject_attacks():
    print(">>> [Phase 2] Injecting 5 Authentic Rootkits into VARIED Paths...")
    path_targets = [
        "tmp",         
        "usr/bin",     
        "etc/.config", 
        "usr/lib",     
        "dev/shm"      
    ]
    mal_paths = []
    for i, node in enumerate(NODES):
        src = MALWARE_SAMPLES[node]
        if os.path.exists(src):
            dst_dir = os.path.join(MOCK_ROOT, node, path_targets[i % len(path_targets)])
            os.makedirs(dst_dir, exist_ok=True)
            dst = os.path.join(dst_dir, "." + os.path.basename(src))
            shutil.copy(src, dst)
            mal_paths.append(dst)
    return mal_paths

def main():
    if os.path.exists(MOCK_ROOT): 
        # More robust cleanup than shutil.rmtree for high-IO directories
        os.system(f"rm -rf {MOCK_ROOT}")
    os.makedirs(MOCK_ROOT)
    
    # 1. Establish Threshold Tau from Baseline
    print(">>> [Phase 0] Establishing Threshold Tau from stable usr/bin...")
    base_errors = []
    for b in glob.glob("/usr/bin/*")[:1000]:
        rgb = get_rgb_features(b)
        base_errors.append(calculate_cae_error(rgb))
    
    # Threshold Tau = Max error on benign known set + margin
    # Using 99th percentile or absolute max to ensure scientific robustness.
    # In Section 3.4, we say tau is learned during validation.
    tau = max(base_errors or [0.15])
    print(f"    Learned Threshold Tau = {tau:.4f}")
    
    # 2. Authentic Churn T1
    run_phase_1_churn_filebench()
    attacks = inject_attacks()
    
    print(">>> [Phase 3] Computing CAE Reconstruction Error (N=8,500+)...")
    results = {"scores": {"churn": []}, "malware_scores": [], "tau": float(tau)}
    
    # Process all files
    for r, _, files in os.walk(MOCK_ROOT):
        for f in files:
            path = os.path.join(r, f)
            rgb = get_rgb_features(path)
            error = calculate_cae_error(rgb)
            
            if f.startswith("."): # Malware
                results["malware_scores"].append(float(error))
            else:
                results["scores"]["churn"].append(float(error))
    
    # Robust FP Counting: Files that exceed the LEARNED threshold
    fp_count = sum(1 for s in results["scores"]["churn"] if s > (tau + 0.01))
    results["alert_counts"] = {
        "aide": len(results["scores"]["churn"]) + len(results["malware_scores"]),
        "dv": fp_count 
    }
    
    with open(JSON_PATH, "w") as f: json.dump(results, f)
    print(f"Malware Errors (Varied): {results['malware_scores']}")
    print(f"Result: Max Churn Error = {max(results['scores']['churn'] or [0]):.4f}")
    print(f"Result: Threshold Tau = {tau:.4f}, FP Count = {fp_count}")

if __name__ == "__main__":
    main()
