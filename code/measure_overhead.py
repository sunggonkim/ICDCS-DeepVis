import time
import psutil
import threading
import pandas as pd
import deepvis_scanner
import os

# Global flag to stop monitoring
keep_monitoring = True
data = []

def monitor_resources():
    process = psutil.Process(os.getpid())
    # Initialize CPU measurement
    process.cpu_percent(interval=None)
    
    print("Monitoring thread started...", flush=True)
    while keep_monitoring:
        # System-wide CPU (Host Overhead) - blocking call 0.1s
        sys_cpu = psutil.cpu_percent(interval=0.1)
        # Process CPU (DeepVis Contribution) - non-blocking (uses interval from sys_cpu delay?) 
        # Actually process.cpu_percent(interval=None) compares to last call.
        # Since sys_cpu blocked for 0.1s, enough time passed.
        proc_cpu = process.cpu_percent(interval=None)
        # Memory Usage (RSS)
        mem = process.memory_info().rss / (1024 * 1024) # MB
        
        data.append({
            'time': time.time(),
            'sys_cpu': sys_cpu,
            'proc_cpu': proc_cpu,
            'memory_mb': mem
        })

def run_scan():
    global keep_monitoring
    try:
        scanner = deepvis_scanner.DeepVisScanner()
        print("Starting full system scan (/usr)...", flush=True)
        scanner.scan_to_csv("/usr", "/tmp/overhead_test.csv", None)
        print("Scan complete.", flush=True)
    except Exception as e:
        print(f"Scan failed: {e}")
    finally:
        # Wait a bit to capture tail
        time.sleep(1.0)
        keep_monitoring = False

if __name__ == "__main__":
    # Start monitoring thread
    monitor_thread = threading.Thread(target=monitor_resources)
    monitor_thread.start()
    
    # Run scan
    start_time = time.time()
    run_scan()
    monitor_thread.join()
    
    # Save to CSV
    if data:
        df = pd.DataFrame(data)
        df['time'] = df['time'] - start_time # Relative time
        df.to_csv("/tmp/resource_usage.csv", index=False)
        print(f"Resource usage saved to /tmp/resource_usage.csv ({len(df)} samples)")
    else:
        print("No data collected!")
