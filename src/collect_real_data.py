
import os
import pwd
from typing import List
from data_gen import FileEntry

# Directories to scan for our "Real Data" baseline
# Limiting to standard bin/config dirs to get a representative OS slice
SCAN_DIRS = ['/bin', '/usr/bin', '/etc']

import math
from collections import Counter

def calculate_entropy(filepath: str) -> float:
    """Calculates Shannon Entropy of a file (first 8KB)."""
    try:
        with open(filepath, 'rb') as f:
            data = f.read(8192) # Read header/first block is usually enough for type inference
            if not data:
                return 0.0
                
            counter = Counter(data)
            length = len(data)
            
            entropy = 0.0
            for count in counter.values():
                p = count / length
                entropy -= p * math.log2(p)
                
            return entropy
    except (PermissionError, FileNotFoundError, OSError):
        return 0.0

def collect_system_baseline(limit=10000) -> List[FileEntry]:
    """Scans the local filesystem to create a real FileEntry list."""
    files = []
    
    print(f"Scanning real system directories: {SCAN_DIRS}...")
    
    for d in SCAN_DIRS:
        if not os.path.exists(d):
            continue
            
        for root, _, filenames in os.walk(d):
            for name in filenames:
                if len(files) >= limit:
                    break
                    
                path = os.path.join(root, name)
                try:
                    stats = os.stat(path)
                    
                    # Owner resolution (might fail in some envs, fallback to str)
                    try:
                        owner = pwd.getpwuid(stats.st_uid).pw_name
                    except:
                        owner = str(stats.st_uid)
                    
                    # Calculate Real Entropy
                    ent = calculate_entropy(path)
                        
                    entry = FileEntry(
                        filename=path,
                        size=stats.st_size,
                        permissions=stats.st_mode,
                        owner=owner,
                        mtime=int(stats.st_mtime),
                        entropy=ent
                    )
                    files.append(entry)
                    
                except PermissionError:
                    continue # Skip unreadable files
                except FileNotFoundError:
                    continue # Race condition
                    
            if len(files) >= limit:
                break
    
    print(f"Collected {len(files)} real file entries from local system.")
    return files

if __name__ == "__main__":
    # Test run
    entries = collect_system_baseline()
    if entries:
        print(f"Sample: {entries[0]}")
