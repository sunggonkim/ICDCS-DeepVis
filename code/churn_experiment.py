import deepvis_scanner
import subprocess
import os
import time

def run_deepvis():
    print("[DeepVis] Scanning...", flush=True)
    scanner = deepvis_scanner.DeepVisScanner()
    csv_path = os.path.expanduser("~/churn_deepvis.csv")
    # Scan
    result = scanner.scan_to_csv("/", csv_path, 500000)
    
    # Analyze False Positives (Entropy > 0.75)
    # Note: Normal binaries usually have entropy < 0.75. Packed/Encrypted > 0.75.
    # Updates replace binaries with other normal binaries, so entropy should stay low.
    fp_count = 0
    with open(csv_path, 'r') as f:
        next(f) # header
        for line in f:
            parts = line.split(',')
            try:
                entropy = float(parts[4])
                if entropy > 0.75:
                    # Optional: Print what triggered it
                    # print(f"FP: {parts[0]} (E={entropy})")
                    fp_count += 1
            except:
                pass
    return fp_count

def run_aide():
    print("[AIDE] Checking...", flush=True)
    # aide --check returns non-zero if changes found (exit code 1-7)
    # We use sudo
    proc = subprocess.run(['sudo', 'aide', '--check', '--config=/etc/aide/aide.conf'], 
                          capture_output=True, text=True)
    
    # Count changes from output
    output = proc.stdout
    # Fallback if stdout is empty (sometimes it goes to stderr or log)
    if not output:
        output = proc.stderr
        
    added = 0
    changed = 0
    removed = 0
    
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Added entries:"):
            added = int(line.split(':')[1].strip())
        elif line.startswith("Changed entries:"):
            changed = int(line.split(':')[1].strip())
        elif line.startswith("Removed entries:"):
            removed = int(line.split(':')[1].strip())
            
    total = added + changed + removed
    print(f"[AIDE] Output Summary: Added={added}, Changed={changed}, Removed={removed}")
    return total

if __name__ == "__main__":
    print("Starting Churn Tolerance Experiment...")
    
    start_dv = time.time()
    dv_fp = run_deepvis()
    print(f"DeepVis Time: {time.time() - start_dv:.2f}s")
    print(f"DeepVis False Positives: {dv_fp}")

    start_aide = time.time()
    aide_changes = run_aide()
    print(f"AIDE Time: {time.time() - start_aide:.2f}s")
    print(f"AIDE Alerts: {aide_changes}")
    
    print("-" * 30)
    print(f"Result: DeepVis FP={dv_fp} vs AIDE Alerts={aide_changes}")
