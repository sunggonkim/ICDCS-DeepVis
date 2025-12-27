#!/usr/bin/env python3
"""
DeepVis v8 - Real Experiment with Rust Scanner
================================================================================
Uses high-performance Rust scanner (deepvis_scanner.so) for file collection
and entropy calculation, with Python handling orchestration and AIDE comparison.
================================================================================
"""

import os
import sys
import time
import subprocess
import threading
import json
from datetime import datetime

# Try to import Rust scanner
try:
    sys.path.insert(0, os.path.expanduser('~'))
    import deepvis_scanner
    RUST_AVAILABLE = True
    print("[OK] Rust scanner loaded successfully")
except ImportError:
    RUST_AVAILABLE = False
    print("[WARN] Rust scanner not available, using Python fallback")

#==============================================================================
# RESOURCE MONITORING
#==============================================================================
class ResourceMonitor:
    def __init__(self, interval=5.0, csv_file="resource_usage.csv"):
        self.interval = interval
        self.csv_file = csv_file
        self.running = False
        self.data = []
        self.thread = None
        self.start_time = None
    
    def start(self):
        self.running = True
        self.data = []
        self.start_time = time.time()
        with open(self.csv_file, 'w') as f:
            f.write("elapsed_sec,cpu_percent,mem_percent,mem_used_mb\n")
        self.thread = threading.Thread(target=self._monitor_loop)
        self.thread.start()
        print(f"[Monitor] Started (interval={self.interval}s)", flush=True)
    
    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join()
        print(f"[Monitor] Stopped. {len(self.data)} samples collected.", flush=True)
        return self.data
    
    def _monitor_loop(self):
        prev_idle, prev_total = 0, 0
        while self.running:
            try:
                elapsed = time.time() - self.start_time
                with open('/proc/stat', 'r') as f:
                    vals = list(map(int, f.readline().split()[1:8]))
                    idle, total = vals[3], sum(vals)
                d_idle, d_total = idle - prev_idle, total - prev_total
                cpu_pct = 100.0 * (1.0 - d_idle / d_total) if d_total > 0 else 0
                prev_idle, prev_total = idle, total
                
                with open('/proc/meminfo', 'r') as f:
                    lines = f.readlines()
                    mem_total = int(lines[0].split()[1])
                    mem_available = int(lines[2].split()[1])
                    mem_used = mem_total - mem_available
                    mem_pct = mem_used / mem_total * 100
                    mem_mb = mem_used / 1024
                
                self.data.append({'elapsed': elapsed, 'cpu': cpu_pct, 'mem_pct': mem_pct})
                with open(self.csv_file, 'a') as f:
                    f.write(f"{elapsed:.1f},{cpu_pct:.1f},{mem_pct:.1f},{mem_mb:.1f}\n")
            except Exception as e:
                print(f"[Monitor] Error: {e}", flush=True)
            time.sleep(self.interval)
    
    def get_summary(self):
        if not self.data: return {}
        cpu_vals = [d['cpu'] for d in self.data]
        mem_vals = [d['mem_pct'] for d in self.data]
        return {
            'cpu_avg': sum(cpu_vals)/len(cpu_vals),
            'cpu_max': max(cpu_vals),
            'mem_avg': sum(mem_vals)/len(mem_vals),
            'mem_max': max(mem_vals)
        }

#==============================================================================
# DEEPVIS SCAN (Rust or Python fallback)
#==============================================================================

def run_deepvis_scan():
    """Run DeepVis scan using Rust scanner"""
    print("\n" + "="*60, flush=True)
    print("DeepVis Scan (Rust Scanner)", flush=True)
    print("="*60, flush=True)
    
    csv_file = os.path.expanduser("~/deepvis_resources.csv")
    monitor = ResourceMonitor(interval=5.0, csv_file=csv_file)
    monitor.start()
    
    start = time.time()
    
    if RUST_AVAILABLE:
        # Use Rust scanner (Streaming Mode)
        print("[Rust] Scanning filesystem (Streaming to CSV)...", flush=True)
        scanner = deepvis_scanner.DeepVisScanner()
        
        # Stream directly to CSV to save memory
        csv_path = os.path.expanduser("~/deepvis_scan_results.csv")
        result = scanner.scan_to_csv("/", csv_path, 500000)
        
        # Result object now only contains timing stats
        files_count = int(result.files_per_sec * (result.total_time_ms / 1000.0))
        scan_time = result.total_time_ms / 1000.0
        files_per_sec = result.files_per_sec
        
        # Count high-entropy files from CSV (or trust Rust's internal counter if exposed)
        # For speed, we'll just estimate or read the last line if needed, 
        # but for now let's read the CSV line count quickly
        try:
            out = subprocess.check_output(['wc', '-l', csv_path]).decode()
            files_count = int(out.split()[0]) - 1 # header
        except:
            pass
            
        detected = 0 # TODO: Parse from CSV if needed, or update Rust to return count
        
        print(f"[Rust] Files: {files_count:,}", flush=True)
        print(f"[Rust] Time: {scan_time:.2f}s", flush=True)
        print(f"[Rust] Throughput: {files_per_sec:.0f} files/sec", flush=True)
    else:
        # Python fallback (much slower)
        print("[Python] Fallback mode - scanning...", flush=True)
        files_count = 0
        detected = 0
        # Simple recursive scan
        for root, dirs, files in os.walk('/'):
            dirs[:] = [d for d in dirs if d not in ['proc', 'sys', 'dev']]
            for f in files:
                files_count += 1
                if files_count >= 50000:
                    break
            if files_count >= 50000:
                break
        scan_time = time.time() - start
        files_per_sec = files_count / scan_time if scan_time > 0 else 0
    
    total_time = time.time() - start
    monitor.stop()
    resources = monitor.get_summary()
    
    print(f"\n[DeepVis] Total time: {total_time:.2f}s", flush=True)
    print(f"[DeepVis] CPU avg: {resources.get('cpu_avg', 0):.1f}%", flush=True)
    print(f"[DeepVis] Memory avg: {resources.get('mem_avg', 0):.1f}%", flush=True)
    
    return {
        'files': files_count,
        'detected': detected,
        'time': total_time,
        'throughput': files_per_sec,
        'resources': resources,
        'engine': 'rust' if RUST_AVAILABLE else 'python'
    }

#==============================================================================
# AIDE BASELINE
#==============================================================================

def run_aide_baseline():
    """Run AIDE for baseline comparison"""
    print("\n" + "="*60, flush=True)
    print("AIDE Baseline Scan", flush=True)
    print("="*60, flush=True)
    
    # Check if AIDE is installed
    if subprocess.call(["which", "aide"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
        print("[WARN] AIDE not found. Skipping baseline.", flush=True)
        return {
            'init_time': 0,
            'check_time': 0,
            'total_time': 0,
            'resources': {}
        }

    csv_file = os.path.expanduser("~/aide_resources.csv")
    monitor = ResourceMonitor(interval=5.0, csv_file=csv_file)
    monitor.start()
    
    # Init AIDE database
    print("[AIDE] Initializing database...", flush=True)
    init_start = time.time()
    # Force init to ensure it runs
    subprocess.run("sudo rm -f /var/lib/aide/aide.db.new.gz", shell=True)
    subprocess.run(['sudo', 'aide', '--init', '--config=/etc/aide/aide.conf'],
                   capture_output=True, timeout=1800)
    # Move new DB to current
    subprocess.run("sudo cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz", shell=True)
    init_time = time.time() - init_start
    print(f"[AIDE] Init: {init_time:.2f}s", flush=True)
    
    # Run check
    print("[AIDE] Running check...", flush=True)
    check_start = time.time()
    subprocess.run(['sudo', 'aide', '--check', '--config=/etc/aide/aide.conf'],
                   capture_output=True, timeout=1800)
    check_time = time.time() - check_start
    print(f"[AIDE] Check: {check_time:.2f}s", flush=True)
    
    total_time = init_time + check_time
    monitor.stop()
    resources = monitor.get_summary()
    
    print(f"\n[AIDE] Total time: {total_time:.2f}s", flush=True)
    print(f"[AIDE] CPU avg: {resources.get('cpu_avg', 0):.1f}%", flush=True)
    
    return {
        'init_time': init_time,
        'check_time': check_time,
        'total_time': total_time,
        'resources': resources
    }

#==============================================================================
# MAIN COMPARISON
#==============================================================================

def run_full_comparison():
    print("\n" + "#"*60, flush=True)
    print("# DeepVis vs AIDE: Real Comparative Experiment", flush=True)
    print("#"*60, flush=True)
    print(f"Started: {datetime.now().isoformat()}", flush=True)
    print(f"Rust Scanner: {'Available' if RUST_AVAILABLE else 'Not Available'}", flush=True)
    
    # Run DeepVis
    dv = run_deepvis_scan()
    
    # Run AIDE
    aide = run_aide_baseline()
    
    # Summary
    print("\n" + "="*60, flush=True)
    print("COMPARISON SUMMARY", flush=True)
    print("="*60, flush=True)
    print(f"{'Metric':<25} | {'DeepVis':<15} | {'AIDE':<15}", flush=True)
    print("-"*60, flush=True)
    print(f"{'Engine':<25} | {dv['engine']:<15} | {'aide':<15}", flush=True)
    print(f"{'Time (sec)':<25} | {dv['time']:<15.2f} | {aide['total_time']:<15.2f}", flush=True)
    print(f"{'Files Scanned':<25} | {dv['files']:<15,} | {'N/A':<15}", flush=True)
    print(f"{'Throughput (files/sec)':<25} | {dv['throughput']:<15.0f} | {'N/A':<15}", flush=True)
    print(f"{'CPU Avg %':<25} | {dv['resources'].get('cpu_avg',0):<15.1f} | {aide['resources'].get('cpu_avg',0):<15.1f}", flush=True)
    print(f"{'Memory Avg %':<25} | {dv['resources'].get('mem_avg',0):<15.1f} | {aide['resources'].get('mem_avg',0):<15.1f}", flush=True)
    
    # Save results
    json_path = os.path.expanduser('~/comparison_results.json')
    with open(json_path, 'w') as f:
        json.dump({'deepvis': dv, 'aide': aide, 'timestamp': datetime.now().isoformat()}, f, indent=2)
    
    csv_path = os.path.expanduser('~/comparison_results.csv')
    with open(csv_path, 'w') as f:
        f.write("Tool,Time_Sec,Files,Throughput,CPU_Avg,Mem_Avg\n")
        f.write(f"DeepVis,{dv['time']:.2f},{dv['files']},{dv['throughput']:.0f},{dv['resources'].get('cpu_avg',0):.1f},{dv['resources'].get('mem_avg',0):.1f}\n")
        f.write(f"AIDE,{aide['total_time']:.2f},N/A,N/A,{aide['resources'].get('cpu_avg',0):.1f},{aide['resources'].get('mem_avg',0):.1f}\n")
    
    print("\n-> Saved comparison_results.json", flush=True)
    print("-> Saved comparison_results.csv", flush=True)
    print(f"\nCompleted: {datetime.now().isoformat()}", flush=True)

if __name__ == "__main__":
    run_full_comparison()
