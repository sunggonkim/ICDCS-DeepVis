import deepvis_scanner
import pandas as pd
import time
import os

def analyze_tradeoff():
    print("Starting Trade-off Analysis...", flush=True)
    
    # 1. Scan with Hash Export
    # Note: The modified Rust scanner now exports SHA-256 hash in the CSV
    scanner = deepvis_scanner.DeepVisScanner()
    csv_path = os.path.expanduser("~/tradeoff_results.csv")
    
    start = time.time()
    # Limit to 500k files (enough for full OS)
    try:
        result = scanner.scan_to_csv("/", csv_path, 500000)
        scan_time = time.time() - start
        # Estimate file count if not directly available
        files_count = int(result.files_per_sec * (result.total_time_ms / 1000.0))
        print(f"Scan completed in {scan_time:.2f}s. Estimated Files: {files_count}")
    except Exception as e:
        print(f"Scan failed: {e}")
        return

    # 2. Analyze Collisions
    print("Analyzing collisions...", flush=True)
    try:
        # Skip lines with parsing errors (e.g. commas in filenames)
        df = pd.read_csv(csv_path, on_bad_lines='skip')
        total_files = len(df)
        
        if 'hash' not in df.columns:
            print("Error: 'hash' column not found in CSV. Did you recompile the Rust scanner?")
            return

        # SHA-256 (Full 256-bit)
        collisions_256 = total_files - df['hash'].nunique()
        
        # 128-bit (First 32 hex chars)
        df['hash_128'] = df['hash'].str[:32]
        collisions_128 = total_files - df['hash_128'].nunique()
        
        # 64-bit (First 16 hex chars)
        df['hash_64'] = df['hash'].str[:16]
        collisions_64 = total_files - df['hash_64'].nunique()
        
        print("-" * 40)
        print(f"Total Files: {total_files}")
        print(f"Collision Rate (256-bit): {collisions_256/total_files*100:.6f}% ({collisions_256} collisions)")
        print(f"Collision Rate (128-bit): {collisions_128/total_files*100:.6f}% ({collisions_128} collisions)")
        print(f"Collision Rate (64-bit):  {collisions_64/total_files*100:.6f}% ({collisions_64} collisions)")
        print("-" * 40)
        
    except Exception as e:
        print(f"Analysis failed: {e}")

if __name__ == "__main__":
    analyze_tradeoff()
