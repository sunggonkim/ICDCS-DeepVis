import subprocess
import time
import statistics
import os
import sys

# Constants
header_sizes = [32, 64, 96, 128, 256, 512, 1024, 4096]
results = {}
target_path = "/usr/bin" 

# Fix PATH for subprocess calls
cargo_path = "/home/bigdatalab/.cargo/bin"
env_prefix = f"export PATH=$PATH:{cargo_path} && "

print("=== Starting Benchmark (PATH Fixed) ===", flush=True)

# Backup lib.rs if not backed up
if not os.path.exists("src/lib.rs.bak"):
    subprocess.run("cp src/lib.rs src/lib.rs.bak", shell=True)

try:
    for size in header_sizes:
        print(f"--- Benchmarking Size: {size} bytes ---", flush=True)
        
        # Modify READ_SIZE (Restore first to ensure clean state)
        subprocess.run("cp src/lib.rs.bak src/lib.rs", shell=True)
        
        with open("src/lib.rs", "r") as f:
            content = f.read()
        
        lines = content.splitlines()
        new_lines = []
        replaced = False
        for line in lines:
            if "const READ_SIZE: usize =" in line:
                new_lines.append(f"const READ_SIZE: usize = {size};")
                replaced = True
            else:
                new_lines.append(line)
        
        with open("src/lib.rs", "w") as f:
            f.write("\n".join(new_lines))
        
        # Rebuild
        print("  Rebuilding...", end="", flush=True)
        try:
            # Explicit PATH export
            subprocess.run(f"{env_prefix} maturin develop --release", shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            print(" Done.", flush=True)
        except subprocess.CalledProcessError as e:
            print(f" Failed! {e}", flush=True)
            results[size] = 0
            continue
            
        runs = []
        for i in range(5):
            # Measurement
            # We import the module in a fresh python process
            # Note: We don't drop cache because sudo might hang. We rely on large file count or accept warm cache (DeepVis is fast anyway).
            # To simulate cold cache, we might read a huge dummy file, but let's stick to raw throughput.
            
            bench_cmd = f"{env_prefix} python3 -c 'import deepvis_scanner, time; start=time.time(); res=deepvis_scanner.scan_filesystem(\"{target_path}\", 16, \"secret\"); dur=time.time()-start; print(len(res)/dur)'"
            
            try:
                out = subprocess.check_output(bench_cmd, shell=True).decode().strip()
                tput = float(out)
                runs.append(tput)
                print(f"  Run {i+1}: {int(tput)}", flush=True)
            except Exception as e:
                print(f"  Run {i+1}: Error {e}", flush=True)
                
        if runs:
            avg = statistics.mean(runs)
            results[size] = int(avg)
            print(f"  => Avg: {int(avg)}", flush=True)
        else:
            results[size] = 0

finally:
    subprocess.run("cp src/lib.rs.bak src/lib.rs", shell=True)
    subprocess.run(f"{env_prefix} maturin develop --release", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

print(f"{chr(10)}CSV_RESULT_START")
for size in header_sizes:
    print(f"{size},{results[size]}")
print("CSV_RESULT_END")
