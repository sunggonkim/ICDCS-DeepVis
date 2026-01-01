import os
import time
import subprocess
import sys

sys.stdout.reconfigure(line_buffering=True)

TARGET = "/usr/lib/python3.8"  # Use moderate size directory for speed (approx 5-10k files)
if not os.path.exists(TARGET):
    TARGET = "/usr/lib"

def run_bench(name, cmd_func):
    print(f"Benchmarking {name}...", flush=True)
    os.system("echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null")
    
    # Count files
    files = []
    for r, d, f in os.walk(TARGET):
        for file in f:
            files.append(os.path.join(r, file))
    n_files = len(files)
    print(f"Target: {n_files} files", flush=True)

    start = time.time()
    try:
        cmd_func(TARGET)
        dur = time.time() - start
        if dur < 0.1: dur = 0.1
        print(f"RESULT::{name}::{n_files / dur:.2f}", flush=True)
    except Exception as e:
        print(f"ERROR::{name}::{e}", flush=True)

# 1. ssdeep Full
def bench_ssdeep(path):
    subprocess.run(["ssdeep", "-r", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
run_bench("ssdeep-Full", bench_ssdeep)

# 2. ClamAV Full
def bench_clam(path):
    subprocess.run(["clamscan", "-r", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
run_bench("ClamAV-Full", bench_clam)

# 3. YARA Full
with open("/tmp/test.yar", "w") as f:
    f.write("rule t { condition: true }")

def bench_yara(path):
    subprocess.run(["yara", "-r", "/tmp/test.yar", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
run_bench("YARA-Full", bench_yara)

# 4. YARA Header (Python)
import yara
rule = yara.compile(source="rule t { condition: true }")

def bench_yara_header(path):
    for r, d, f in os.walk(path):
        for file in f:
            p = os.path.join(r, file)
            try:
                with open(p, "rb") as fd:
                    d = fd.read(128)
                    rule.match(data=d)
            except: pass
run_bench("YARA-Header", bench_yara_header)

