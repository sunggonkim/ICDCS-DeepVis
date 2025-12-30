import os
import time
import subprocess
import hashlib

TARGET = "/usr/bin"
DUMMY_DB = "/tmp/test.ndb"

def drop_caches():
    print("Dropping caches...", end="", flush=True)
    os.system("sync; echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null")
    print(" Done.")

def setup_clam_db():
    print("Setting up dummy ClamAV database...")
    # Create a simple rule that matches 'ELF' header
    with open(DUMMY_DB, "w") as f:
        f.write("DeepVis_Test_Rule:0:*:7f454c46\n")

def count_files(path):
    count = 0
    for r, d, f in os.walk(path):
        count += len(f)
    return count

def run_bench(name, cmd_func):
    print(f"\n--- {name} ---", flush=True)
    drop_caches()
    n_files = count_files(TARGET)
    start = time.time()
    try:
        cmd_func(TARGET)
        dur = time.time() - start
        if dur < 0.1: dur = 0.1
        tput = n_files / dur
        print(f"RESULT::{name}::{tput:.2f} files/s (Total: {n_files}, Time: {dur:.2f}s)", flush=True)
    except Exception as e:
        print(f"ERROR::{name}::{e}", flush=True)

# 1. ssdeep
def bench_ssdeep(path):
    subprocess.run(["ssdeep", "-r", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# 2. ClamAV
def bench_clam(path):
    subprocess.run(["clamscan", "-d", DUMMY_DB, "-r", "--no-summary", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# 3. AIDE-Header Simulation (SHA256 Sync 128B)
def bench_aide_header(path):
    for r, d, f in os.walk(path):
        for file in f:
            p = os.path.join(r, file)
            try:
                with open(p, "rb") as fd:
                    data = fd.read(128)
                    hashlib.sha256(data).digest()
            except: pass

# 4. AIDE-Full Simulation (SHA256 Full File)
def bench_aide_full(path):
    for r, d, f in os.walk(path):
        for file in f:
            p = os.path.join(r, file)
            try:
                with open(p, "rb") as fd:
                    data = fd.read()
                    hashlib.sha256(data).digest()
            except: pass

# 5. YARA Full (Recursive Command)
def bench_yara_full(path):
    # Use a dummy rule that always matches or just runs
    rule_path = os.path.expanduser("~/test_yara.yar")
    with open(rule_path, "w") as f:
        f.write("rule detect_all { condition: true }")
    subprocess.run(["yara", "-r", rule_path, path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# 6. YARA Header (Python Sync 4KB)
import yara
def bench_yara_header_4k(path):
    rule = yara.compile(source="rule detect_all { condition: true }")
    for r, d, f in os.walk(path):
        for file in f:
            p = os.path.join(r, file)
            try:
                with open(p, "rb") as fd:
                    data = fd.read(4096)
                    rule.match(data=data)
            except: pass

if __name__ == "__main__":
    print(f"=== Competitor Benchmark Start (Target: {TARGET}) ===")
    setup_clam_db()
    run_bench("ssdeep-Full", bench_ssdeep)
    run_bench("ClamAV-Full", bench_clam)
    run_bench("AIDE-Header", bench_aide_header)
    run_bench("AIDE-Full", bench_aide_full)
    run_bench("YARA-Full", bench_yara_full)
    run_bench("YARA-Header-4K", bench_yara_header_4k)
    print("\n=== Benchmark Complete ===")

