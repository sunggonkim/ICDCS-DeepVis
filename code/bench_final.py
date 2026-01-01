import os
import time
import subprocess
import sys

# Ensure unbuffered output
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', buffering=1)

TARGET_DIR = "/usr/lib/python3.8"
if not os.path.exists(TARGET_DIR):
    TARGET_DIR = "/usr/lib"

def drop_caches():
    os.system("sync; echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null")

def count_files(path):
    count = 0
    for r, d, f in os.walk(path):
        count += len(f)
    return count

def run_bench(name, cmd):
    print(f"--- Benchmarking {name} ---", flush=True)
    n_files = count_files(TARGET_DIR)
    drop_caches()
    start = time.time()
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        elapsed = time.time() - start
        tput = n_files / elapsed
        print(f"RESULT::{name}::{tput:.2f} files/s (Total: {n_files}, Time: {elapsed:.2f}s)", flush=True)
    except Exception as e:
        print(f"ERROR::{name}::{str(e)}", flush=True)

# 1. YARA Full
with open("audit_rule.yar", "w") as f:
    f.write("rule detect_all { condition: true }")

run_bench("YARA-Full", ["yara", "-r", "audit_rule.yar", TARGET_DIR])

# 2. YARA Header (Python)
import yara
def run_yara_header_bench(path):
    print("--- Benchmarking YARA-Header ---", flush=True)
    n_files = count_files(TARGET_DIR)
    rule = yara.compile(source="rule detect_all { condition: true }")
    drop_caches()
    start = time.time()
    processed = 0
    for r, d, f in os.walk(path):
        for file in f:
            full_path = os.path.join(r, file)
            try:
                with open(full_path, "rb") as fd:
                    data = fd.read(128)
                    rule.match(data=data)
                processed += 1
            except:
                continue
    elapsed = time.time() - start
    tput = processed / elapsed
    print(f"RESULT::YARA-Header::{tput:.2f} files/s (Total: {processed}, Time: {elapsed:.2f}s)", flush=True)

try:
    run_yara_header_bench(TARGET_DIR)
except Exception as e:
    print(f"ERROR::YARA-Header::{str(e)}", flush=True)

