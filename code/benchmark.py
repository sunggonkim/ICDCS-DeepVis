#!/usr/bin/env python3
"""
DeepVis Benchmark - Real GCP Scalability Test
==============================================
Compares DeepVis (Rust, header-only) vs AIDE (full SHA-256)

Expected results: 7-8x speedup on Mid tier
"""

import os
import sys
import time
import hashlib
import subprocess
import csv
from datetime import datetime

# Try Rust scanner
try:
    sys.path.insert(0, os.path.expanduser('~'))
    import deepvis_scanner
    RUST_OK = True
    print("[OK] Rust scanner loaded")
except ImportError:
    RUST_OK = False
    print("[WARN] Rust scanner not available")

def sha256_full_file(filepath):
    """AIDE-style full file SHA-256"""
    sha = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                sha.update(chunk)
        return sha.hexdigest()
    except:
        return None

def run_benchmark():
    print("=" * 60)
    print("DeepVis vs AIDE Scalability Benchmark")
    print("=" * 60)
    print(f"Time: {datetime.now().isoformat()}")
    print()
    
    # Get file list
    print("Collecting files...")
    result = subprocess.run(
        "find /usr /etc /var -type f 2>/dev/null | head -n 100000",
        shell=True, capture_output=True, text=True
    )
    all_files = [f for f in result.stdout.strip().split('\n') if f and os.path.isfile(f)]
    print(f"Found {len(all_files)} files")
    
    results = []
    test_counts = [10000, 50000, 100000]
    
    for count in test_counts:
        files = all_files[:count]
        actual = len(files)
        print(f"\n=== Testing {actual} files ===")
        
        # DeepVis (Rust)
        if RUST_OK:
            scanner = deepvis_scanner.DeepVisScanner()
            start = time.time()
            result = scanner.scan_fast("/usr", actual)
            dv_time = time.time() - start
            dv_throughput = result.total_files / dv_time if dv_time > 0 else 0
            print(f"DeepVis: {dv_time:.2f}s ({dv_throughput:.0f} files/sec)")
        else:
            # Python fallback (header-only)
            start = time.time()
            for f in files:
                try:
                    with open(f, 'rb') as fp:
                        data = fp.read(64)
                except:
                    pass
            dv_time = time.time() - start
            dv_throughput = actual / dv_time if dv_time > 0 else 0
            print(f"DeepVis (Python): {dv_time:.2f}s ({dv_throughput:.0f} files/sec)")
        
        # AIDE-style (full SHA-256)
        start = time.time()
        for f in files:
            sha256_full_file(f)
        aide_time = time.time() - start
        aide_throughput = actual / aide_time if aide_time > 0 else 0
        print(f"AIDE: {aide_time:.2f}s ({aide_throughput:.0f} files/sec)")
        
        speedup = aide_time / dv_time if dv_time > 0 else 0
        print(f"Speedup: {speedup:.1f}x")
        
        results.append({
            'files': actual,
            'deepvis_time': dv_time,
            'deepvis_fps': dv_throughput,
            'aide_time': aide_time,
            'aide_fps': aide_throughput,
            'speedup': speedup
        })
    
    # Save
    with open('benchmark_results.csv', 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=results[0].keys())
        w.writeheader()
        w.writerows(results)
    
    print("\n" + "=" * 60)
    print("RESULTS SAVED: benchmark_results.csv")
    print("=" * 60)
    
    return results

if __name__ == "__main__":
    run_benchmark()
