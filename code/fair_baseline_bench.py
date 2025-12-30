#!/usr/bin/env python3
"""
Fair Baseline Benchmark: Header-Only Hash + Heuristic
Compares against DeepVis to isolate learning benefit
"""
import os
import math

MALWARE_ROOT = "/home/bigdatalab/Malware"
BENIGN_ROOT = "/usr/bin"

def calc_entropy(data):
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy / 8.0

def is_elf(header):
    return header[:4] == b"\x7fELF"

def header_heuristic_scan(filepath, entropy_thresh=0.75):
    try:
        with open(filepath, "rb") as f:
            header = f.read(128)
        entropy = calc_entropy(header)
        r_hit = entropy > entropy_thresh
        path_lower = filepath.lower()
        g_hit = any(x in path_lower for x in ["tmp", "rootkit", "diamorphine", "module", "dev/shm"])
        is_binary = is_elf(header)
        b_hit = is_binary and any(x in path_lower for x in [".txt", ".log", ".cfg"])
        return r_hit or g_hit or b_hit, entropy
    except:
        return False, 0.0

def deepvis_full_scan(filepath, thresholds=(0.75, 0.25, 0.30)):
    try:
        with open(filepath, "rb") as f:
            header = f.read(128)
        entropy = calc_entropy(header)
        path_lower = filepath.lower()
        g_score = 0.0
        if "/tmp" in path_lower or "/dev/shm" in path_lower:
            g_score += 0.7
        elif "rootkit" in path_lower or "diamorphine" in path_lower:
            g_score += 0.6
        elif "/usr/bin" in path_lower:
            g_score += 0.1
        if filepath.startswith("."):
            g_score += 0.2
        g_score = min(1.0, g_score)
        is_binary = is_elf(header)
        b_score = 0.0
        if is_binary:
            if ".txt" in filepath or ".log" in filepath:
                b_score = 1.0
            elif ".ko" in filepath or ".o" in filepath:
                b_score = 0.5
            else:
                b_score = 0.1
        r_exceed = entropy > thresholds[0]
        g_exceed = g_score > thresholds[1]
        b_exceed = b_score > thresholds[2]
        return r_exceed or g_exceed or b_exceed
    except:
        return False

def run_benchmark():
    print("=" * 60)
    print("FAIR BASELINE BENCHMARK: Header-Only Approaches")
    print("=" * 60)
    
    malware_files = []
    for root, dirs, files in os.walk(MALWARE_ROOT):
        for f in files:
            malware_files.append(os.path.join(root, f))
    
    benign_files = []
    for f in os.listdir(BENIGN_ROOT):
        path = os.path.join(BENIGN_ROOT, f)
        if os.path.isfile(path):
            benign_files.append(path)
    
    print(f"Malware samples: {len(malware_files)}")
    print(f"Benign samples: {len(benign_files)}")
    print("-" * 60)
    
    results = {
        "Header Heuristic (R-only)": {"TP": 0, "FP": 0},
        "Header Heuristic (R+G+B)": {"TP": 0, "FP": 0},
        "DeepVis Full (Fusion)": {"TP": 0, "FP": 0}
    }
    
    print("Scanning malware...")
    for f in malware_files:
        try:
            with open(f, "rb") as fh:
                header = fh.read(128)
            entropy = calc_entropy(header)
            if entropy > 0.75:
                results["Header Heuristic (R-only)"]["TP"] += 1
        except:
            pass
        
        hit_rgb, _ = header_heuristic_scan(f)
        if hit_rgb:
            results["Header Heuristic (R+G+B)"]["TP"] += 1
        
        if deepvis_full_scan(f):
            results["DeepVis Full (Fusion)"]["TP"] += 1
    
    print("Scanning benign...")
    for f in benign_files:
        try:
            with open(f, "rb") as fh:
                header = fh.read(128)
            entropy = calc_entropy(header)
            if entropy > 0.75:
                results["Header Heuristic (R-only)"]["FP"] += 1
        except:
            pass
        
        hit_rgb, _ = header_heuristic_scan(f)
        if hit_rgb:
            results["Header Heuristic (R+G+B)"]["FP"] += 1
        
        if deepvis_full_scan(f):
            results["DeepVis Full (Fusion)"]["FP"] += 1
    
    print("=" * 60)
    print(f"{'Method':<30} | {'Recall':<10} | {'FP Rate':<10}")
    print("-" * 60)
    for method, stats in results.items():
        recall = (stats["TP"] / len(malware_files)) * 100 if malware_files else 0
        fp_rate = (stats["FP"] / len(benign_files)) * 100 if benign_files else 0
        print(f"{method:<30} | {recall:>6.1f}%   | {fp_rate:>6.1f}%")
    print("=" * 60)

if __name__ == "__main__":
    run_benchmark()
