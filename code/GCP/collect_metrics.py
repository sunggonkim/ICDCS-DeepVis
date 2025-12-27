import os
import math
import hashlib
from collections import Counter

def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    counter = Counter(data)
    for count in counter.values():
        p_x = count / len(data)
        entropy += - p_x * math.log2(p_x)
    return entropy / 8.0  # Normalize to [0, 1]

def collect_metrics(file_list_path):
    with open(file_list_path, 'r') as f:
        files = [line.strip() for line in f if line.strip()]
    
    results = []
    for fpath in files:
        if not os.path.exists(fpath):
            continue
        try:
            size = os.path.getsize(fpath)
            mode = os.stat(fpath).st_mode & 0o777
            # Only read first 8KB for speed
            with open(fpath, 'rb') as f:
                content = f.read(8192)
            entropy = calculate_entropy(content)
            
            # Simple API density proxy (search for common syscall strings/patterns)
            # This is a very rough proxy since we aren't doing full analysis
            api_density = 0 # Placeholder for now as it's complex
            
            results.append(f"{fpath}|{size}|{entropy}|{mode}|{api_density}")
        except Exception as e:
            continue
    
    with open('metrics.csv', 'w') as f:
        for r in results:
            f.write(r + "\n")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        collect_metrics(sys.argv[1])
