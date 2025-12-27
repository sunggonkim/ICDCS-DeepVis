#!/usr/bin/env python3
"""
DeepVis v2 Metrics Collector
RGB Encoding:
  R (Red)   = Entropy (0-1): High for packed/encrypted files
  G (Green) = Suspiciousness (0-1): Path anomaly + dangerous patterns + hidden files
  B (Blue)  = Anomaly (0-1): Type mismatch + recent modification
"""

import os
import sys
import math
import time
import re
from collections import Counter

# Suspicious paths (common malware drop zones)
SUSPICIOUS_PATHS = ['/tmp', '/var/tmp', '/dev/shm', '/var/www', '/home', '/root']
HIDDEN_WEIGHT = 0.2
EXEC_TEXT_WEIGHT = 0.15

# Dangerous function patterns (for scripts/webshells)
DANGEROUS_PATTERNS = [
    rb'eval\s*\(',
    rb'exec\s*\(',
    rb'system\s*\(',
    rb'passthru\s*\(',
    rb'shell_exec\s*\(',
    rb'popen\s*\(',
    rb'proc_open\s*\(',
    rb'base64_decode\s*\(',
    rb'\$_POST\[',
    rb'\$_GET\[',
    rb'\$_REQUEST\[',
    rb'chmod\s+777',
    rb'/bin/sh',
    rb'/bin/bash',
]

# Text file extensions
TEXT_EXTENSIONS = {'.txt', '.conf', '.cfg', '.ini', '.sh', '.py', '.php', '.js', '.html', '.xml', '.json', '.yml', '.yaml', '.log', '.md'}

# Binary magic bytes
ELF_MAGIC = b'\x7fELF'
SCRIPT_MAGIC = b'#!'


def calculate_entropy(data):
    """Calculate Shannon entropy normalized to 0-1"""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counter.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy / 8.0  # Normalize to [0, 1]


def calculate_suspiciousness(filepath, content, mode):
    """
    Calculate suspiciousness score (0-1)
    - Sensitive path location
    - Dangerous function patterns
    - Hidden files
    - Executable permission on text files
    """
    score = 0.0
    
    # 1. Sensitive path
    for spath in SUSPICIOUS_PATHS:
        if filepath.startswith(spath):
            score += 0.25
            break
    
    # 2. Dangerous patterns in content
    pattern_count = 0
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, content):
            pattern_count += 1
    score += min(0.4, pattern_count * 0.1)  # Cap at 0.4
    
    # 3. Hidden file
    basename = os.path.basename(filepath)
    if basename.startswith('.'):
        score += HIDDEN_WEIGHT
    
    # 4. Executable permission on text file
    ext = os.path.splitext(filepath)[1].lower()
    is_executable = (mode & 0o111) != 0
    if ext in TEXT_EXTENSIONS and is_executable:
        score += EXEC_TEXT_WEIGHT
    
    return min(1.0, score)


def calculate_anomaly(filepath, content, mtime):
    """
    Calculate anomaly score (0-1)
    - Extension vs content type mismatch
    - Recent modification in system directories
    """
    score = 0.0
    
    # 1. Extension vs content mismatch
    ext = os.path.splitext(filepath)[1].lower()
    
    is_elf = content[:4] == ELF_MAGIC
    is_script = content[:2] == SCRIPT_MAGIC
    
    # Text extension but binary content
    if ext in TEXT_EXTENSIONS and is_elf:
        score += 0.5
    
    # Binary extension but text content (less severe)
    if ext in {'.so', '.ko', '.bin', '.exe'} and not is_elf:
        score += 0.3
    
    # 2. Recent modification in system directories
    system_dirs = ['/usr', '/bin', '/sbin', '/lib', '/etc']
    for sdir in system_dirs:
        if filepath.startswith(sdir):
            # Modified in last 24 hours
            if time.time() - mtime < 86400:
                score += 0.3
            break
    
    return min(1.0, score)


def collect_metrics_v2(file_list_path, output_path='metrics_v2.csv'):
    """Collect RGB metrics for files"""
    with open(file_list_path, 'r') as f:
        files = [line.strip() for line in f if line.strip()]
    
    results = []
    for fpath in files:
        if not os.path.exists(fpath):
            continue
        if os.path.isdir(fpath):
            continue
        
        try:
            stat = os.stat(fpath)
            size = stat.st_size
            mode = stat.st_mode & 0o777
            mtime = stat.st_mtime
            
            # Read first 8KB for analysis
            with open(fpath, 'rb') as f:
                content = f.read(8192)
            
            # Calculate RGB channels
            r_entropy = calculate_entropy(content)
            g_suspiciousness = calculate_suspiciousness(fpath, content, mode)
            b_anomaly = calculate_anomaly(fpath, content, mtime)
            
            results.append(f"{fpath}|{size}|{r_entropy:.4f}|{g_suspiciousness:.4f}|{b_anomaly:.4f}|{mode}")
        except Exception as e:
            continue
    
    with open(output_path, 'w') as f:
        for r in results:
            f.write(r + "\n")
    
    print(f"Collected {len(results)} files -> {output_path}")


if __name__ == "__main__":
    if len(sys.argv) >= 2:
        output = sys.argv[2] if len(sys.argv) >= 3 else 'metrics_v2.csv'
        collect_metrics_v2(sys.argv[1], output)
    else:
        print("Usage: python3 collect_metrics_v2.py <file_list.txt> [output.csv]")
