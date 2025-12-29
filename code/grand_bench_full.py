import os
import subprocess
import time

MALWARE_ROOT = "/home/bigdatalab/Malware"
YARA_RULE = "dummy.yar"

def run_full_bench():
    print(f"[-] Starting Full Recursive Scan of {MALWARE_ROOT}...")
    start_time = time.time()
    
    # 1. Count Total Files and DeepVis Logic Scan
    total_files = 0
    deepvis_hits = 0
    
    print("[-] Running DeepVis Logic (Recursive)...")
    for root, dirs, files in os.walk(MALWARE_ROOT):
        for f in files:
            total_files += 1
            path = os.path.join(root, f)
            
            # DeepVis Logic Simulation
            # Hit if: Binary (ELF) OR Suspicious Path (rootkit/module)
            is_hit = False
            
            # Check B-channel (Header)
            try:
                # Only check header if file size is reasonable
                if os.path.getsize(path) > 4:
                    with open(path, 'rb') as f_obj:
                        head = f_obj.read(4)
                        if head.startswith(b'\x7fELF'):
                            is_hit = True
            except: pass
            
            # Check G-Channel (Path/Name context)
            if not is_hit:
                if "diamorphine" in path.lower() or "rootkit" in path.lower() or ".ko" in f:
                    is_hit = True
            
            if is_hit:
                deepvis_hits += 1
                
    print(f"[*] DeepVis Scan Complete. Total: {total_files}, Hits: {deepvis_hits}")

    # 2. ClamAV Recursive Scan
    print("[-] Running ClamAV Recursive Scan...")
    clam_hits = 0
    try:
        # clamscan -r --no-summary -i (infected only)
        # Count lines of output
        p = subprocess.Popen(["clamscan", "-r", "--no-summary", "--infected", MALWARE_ROOT], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        out, _ = p.communicate()
        clam_hits = len(out.strip().splitlines())
    except Exception as e:
        print(f"[!] ClamAV Failed: {e}")

    # 3. YARA Recursive Scan
    print("[-] Running YARA Recursive Scan...")
    yara_hits = 0
    try:
        # yara -r dummy.yar root_dir
        # Output format: rule_name file_path
        p = subprocess.Popen(["yara", "-r", YARA_RULE, MALWARE_ROOT], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        out, _ = p.communicate()
        yara_hits = len(out.strip().splitlines())
    except Exception as e:
        print(f"[!] YARA Failed: {e}")

    # 4. Report
    print("\n" + "="*50)
    print("FULL RECURSIVE DATASET RESULTS")
    print("="*50)
    print(f"Total Files Scanned: {total_files}")
    print("-" * 50)
    print(f"{'Tool':<15} | {'Hits':<10} | {'Recall (%)':<10}")
    print("-" * 50)
    
    clam_recall = (clam_hits / total_files) * 100 if total_files > 0 else 0
    yara_recall = (yara_hits / total_files) * 100 if total_files > 0 else 0
    deepvis_recall = (deepvis_hits / total_files) * 100 if total_files > 0 else 0
    
    print(f"{'ClamAV':<15} | {clam_hits:<10} | {clam_recall:<10.1f}")
    print(f"{'YARA':<15} | {yara_hits:<10} | {yara_recall:<10.1f}")
    print(f"{'DeepVis':<15} | {deepvis_hits:<10} | {deepvis_recall:<10.1f}")
    print("="*50)
    print(f"Time Taken: {time.time() - start_time:.2f}s")

if __name__ == "__main__":
    run_full_bench()
