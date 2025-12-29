import os
import math
import subprocess
import random

MALWARE_ROOT = "/home/bigdatalab/Malware"
BENIGN_ROOT = "/usr/bin"
THRESHOLD = 0.75  # Entropy Threshold from DeepVis paper

def get_elf_files(root_dir, limit=None):
    elfs = []
    # Use find + file command to identify ELFs (faster than python loop for big dirs)
    cmd = f"find {root_dir} -type f -exec file {{}} + | grep 'ELF'"
    try:
        # Run command and capture output
        # NOTE: 'file' output format: "filename: ELF 64-bit..."
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        for line in p.stdout:
            path = line.split(":")[0].strip()
            elfs.append(path)
            if limit and len(elfs) >= limit: break
    except Exception as e:
        print(f"[!] Error scanning {root_dir}: {e}")
    return elfs

def calc_entropy(filepath):
    try:
        size = os.path.getsize(filepath)
        if size == 0: return 0.0
        with open(filepath, 'rb') as f:
            data = f.read()
        counts = [0]*256
        for b in data: counts[b] += 1
        ent = 0.0
        for c in counts:
            if c > 0:
                p = c / size
                ent -= p * math.log2(p)
        return ent / 8.0 # Normalize 0-1
    except: return 0.0

def run_bench():
    print("[-] Gathering Binary Dataset...")
    
    # 1. Malware ELFs
    print(f"[*] Scanning {MALWARE_ROOT} for ELFs...")
    malware_elfs = get_elf_files(MALWARE_ROOT) # Get ALL
    print(f"    -> Found {len(malware_elfs)} malware binaries.")
    
    # 2. Benign ELFs
    print(f"[*] Sampling {BENIGN_ROOT} for ELFs...")
    benign_elfs = get_elf_files(BENIGN_ROOT, limit=1000)
    print(f"    -> Found {len(benign_elfs)} benign binaries.")
    
    # 3. Experiment
    print(f"\n[-] Running DeepVis Logic (Entropy Threshold > {THRESHOLD})...")
    
    # Stats
    tp = 0; fn = 0
    fp = 0; tn = 0
    
    # Analyze Malware
    print("    Analyzing Malware...")
    missed_examples = []
    for f in malware_elfs:
        e = calc_entropy(f)
        if e > THRESHOLD:
            tp += 1
        else:
            fn += 1
            if len(missed_examples) < 5: missed_examples.append((f, e))
            
    # Analyze Benign
    print("    Analyzing Benign...")
    fp_examples = []
    for f in benign_elfs:
        e = calc_entropy(f)
        if e > THRESHOLD:
            fp += 1
            if len(fp_examples) < 5: fp_examples.append((f, e))
        else:
            tn += 1
            
    # 4. Report
    print("\n" + "="*60)
    print(f"{'Metric':<20} | {'Count':<10} | {'Rate (%)':<10}")
    print("-" * 60)
    
    malware_total = tp + fn
    benign_total = fp + tn
    
    recall = (tp / malware_total * 100) if malware_total else 0
    fp_rate = (fp / benign_total * 100) if benign_total else 0
    precision = (tp / (tp + fp) * 100) if (tp + fp) else 0
    
    print(f"{'Malware (Total)':<20} | {malware_total:<10} | -")
    print(f"{'  Detected (TP)':<20} | {tp:<10} | {recall:.1f}% (Recall)")
    print(f"{'  Missed (FN)':<20} | {fn:<10} | {100-recall:.1f}%")
    print("-" * 60)
    print(f"{'Benign (Total)':<20} | {benign_total:<10} | -")
    print(f"{'  False Pos (FP)':<20} | {fp:<10} | {fp_rate:.1f}% (FP Rate)")
    print(f"{'  Clean (TN)':<20} | {tn:<10} | {100-fp_rate:.1f}%")
    
    print("\n[!] Top 5 Missed Malware (Low Entropy):")
    for f, e in missed_examples:
        print(f"    - {os.path.basename(f)} (R={e:.3f})")
        
    print("\n[!] Top 5 False Positives (High Entropy Benign):")
    for f, e in fp_examples:
        print(f"    - {os.path.basename(f)} (R={e:.3f})")

if __name__ == "__main__":
    try:
        run_bench()
    except KeyboardInterrupt:
        pass
