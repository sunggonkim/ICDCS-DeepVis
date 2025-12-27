#!/usr/bin/env python3
"""
Real AIDE vs DeepVis Scalability Benchmark
================================================================================
This script runs REAL benchmarks on GCP:
  1. DeepVis: Header-only entropy calculation (our method)
  2. AIDE-style: Full file SHA-256 hashing (simulating AIDE baseline)

NO FAKE DATA - All measurements are actual file system operations.
================================================================================
"""

import os
import sys
import time
import hashlib
import subprocess
import csv
from datetime import datetime

def sha256_file(filepath):
    """Full file SHA-256 hash (AIDE-style)"""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except:
        return None

def deepvis_entropy(filepath):
    """Header-only entropy (DeepVis style)"""
    try:
        with open(filepath, 'rb') as f:
            data = f.read(4096)  # Header only
        if not data:
            return 0.0
        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        entropy = sum(-p/len(data) * (p/len(data) + 0.001).bit_length() 
                      for p in freq.values()) / 8.0
        return entropy
    except:
        return 0.0

def run_scalability_benchmark():
    """Run real AIDE vs DeepVis benchmark"""
    print("=" * 60)
    print("REAL AIDE vs DeepVis Scalability Benchmark")
    print("=" * 60)
    print(f"Started: {datetime.now().isoformat()}")
    print("WARNING: This runs REAL file system operations!")
    print()
    
    # Detect hardware
    try:
        with open('/proc/meminfo', 'r') as f:
            meminfo = f.read()
        mem_total_kb = int([l for l in meminfo.split('\n') if 'MemTotal' in l][0].split()[1])
        mem_gb = mem_total_kb / (1024 * 1024)
        print(f"Memory: {mem_gb:.1f} GB")
    except:
        mem_gb = 4
    
    file_counts = [1000, 5000, 10000, 20000]
    results = []
    
    for target_count in file_counts:
        print(f"\n[Benchmark] Target: {target_count} files")
        
        # Collect file list
        result = subprocess.run(
            f"find /usr /etc -type f 2>/dev/null | head -n {target_count}",
            shell=True, capture_output=True, text=True
        )
        files = [p for p in result.stdout.strip().split('\n') if p and os.path.isfile(p)]
        actual_count = len(files)
        print(f"  Actual files: {actual_count}")
        
        if actual_count < 100:
            print("  [SKIP] Not enough files")
            continue
        
        # ============================================================
        # DeepVis Benchmark (Header-only entropy)
        # ============================================================
        print("  Running DeepVis (header-only)...", end=" ", flush=True)
        start = time.time()
        dv_processed = 0
        for fpath in files:
            ent = deepvis_entropy(fpath)
            if ent is not None:
                dv_processed += 1
        dv_time = time.time() - start
        dv_throughput = dv_processed / dv_time if dv_time > 0 else 0
        print(f"{dv_time:.2f}s ({dv_throughput:.0f} files/sec)")
        
        # ============================================================
        # AIDE-style Benchmark (Full file SHA-256)
        # ============================================================
        print("  Running AIDE-style (SHA-256)...", end=" ", flush=True)
        start = time.time()
        aide_processed = 0
        for fpath in files:
            h = sha256_file(fpath)
            if h is not None:
                aide_processed += 1
        aide_time = time.time() - start
        aide_throughput = aide_processed / aide_time if aide_time > 0 else 0
        print(f"{aide_time:.2f}s ({aide_throughput:.0f} files/sec)")
        
        # Calculate speedup
        speedup = aide_time / dv_time if dv_time > 0 else 0
        
        print(f"  => Speedup: {speedup:.2f}x")
        
        results.append({
            'file_count': actual_count,
            'deepvis_time': dv_time,
            'deepvis_throughput': dv_throughput,
            'deepvis_processed': dv_processed,
            'aide_time': aide_time,
            'aide_throughput': aide_throughput,
            'aide_processed': aide_processed,
            'speedup': speedup
        })
    
    # Save results
    output_csv = 'real_scalability_data.csv'
    with open(output_csv, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    
    print(f"\n-> Saved: {output_csv}")
    
    # Summary
    print("\n" + "=" * 60)
    print("BENCHMARK SUMMARY (REAL DATA)")
    print("=" * 60)
    print(f"{'Files':<10} | {'DeepVis':<12} | {'AIDE':<12} | {'Speedup':<8}")
    print("-" * 50)
    for r in results:
        print(f"{r['file_count']:<10} | {r['deepvis_time']:.2f}s        | {r['aide_time']:.2f}s        | {r['speedup']:.2f}x")
    
    avg_speedup = sum(r['speedup'] for r in results) / len(results) if results else 0
    print("-" * 50)
    print(f"Average Speedup: {avg_speedup:.2f}x")
    
    print(f"\nCompleted: {datetime.now().isoformat()}")
    return results

if __name__ == "__main__":
    run_scalability_benchmark()
