#!/usr/bin/env python3
"""
DeepVis v3 Multi-Modal Feature Encoding
Based on the theoretical design:
  R (Red)   = Information Density (Entropy)
  G (Green) = Contextual Hazard (Path + Patterns + Hidden + Privilege)
  B (Blue)  = Structural Deviation (Type Mismatch + Temporal Freshness)
"""

import os
import sys
import math
import time
import re
from collections import Counter

#==============================================================================
# CHANNEL R: Information Density (Entropy)
#==============================================================================
def calculate_entropy(data):
    """Calculate Shannon entropy normalized to [0, 1]"""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counter.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy / 8.0  # Normalize to [0, 1] (max entropy = 8 bits)

#==============================================================================
# CHANNEL G: Contextual Hazard
#==============================================================================
# Path Sensitivity weights
VOLATILE_PATHS = {
    '/tmp': 0.30,
    '/var/tmp': 0.30,
    '/dev/shm': 0.35,
    '/var/www': 0.25,
    '/home': 0.15,
    '/root': 0.20,
}

# Dangerous patterns (webshells, backdoors)
DANGEROUS_PATTERNS = [
    (rb'eval\s*\(', 0.15),
    (rb'exec\s*\(', 0.15),
    (rb'system\s*\(', 0.15),
    (rb'passthru\s*\(', 0.15),
    (rb'shell_exec\s*\(', 0.15),
    (rb'base64_decode\s*\(', 0.10),
    (rb'\$_POST\[', 0.12),
    (rb'\$_GET\[', 0.12),
    (rb'\$_REQUEST\[', 0.12),
    (rb'/bin/sh', 0.10),
    (rb'/bin/bash', 0.08),
]

# Hidden file weight
HIDDEN_WEIGHT = 0.20

# Privilege anomaly weight (executable text file or world-writable)
EXEC_TEXT_WEIGHT = 0.15
WORLD_WRITABLE_WEIGHT = 0.10

TEXT_EXTENSIONS = {'.txt', '.conf', '.cfg', '.ini', '.sh', '.py', '.php', 
                   '.js', '.html', '.xml', '.json', '.yml', '.yaml', '.log', '.md'}

def calculate_contextual_hazard(filepath, content, mode):
    """
    G = Path Sensitivity + Pattern Density + Hidden Indicator + Privilege Anomaly
    """
    score = 0.0
    
    # 1. Path Sensitivity
    for path_prefix, weight in VOLATILE_PATHS.items():
        if filepath.startswith(path_prefix):
            score += weight
            break
    
    # 2. Dangerous Pattern Density
    for pattern, weight in DANGEROUS_PATTERNS:
        if re.search(pattern, content):
            score += weight
    
    # 3. Hidden File Indicator
    basename = os.path.basename(filepath)
    if basename.startswith('.'):
        score += HIDDEN_WEIGHT
    
    # 4. Privilege Anomaly
    ext = os.path.splitext(filepath)[1].lower()
    is_executable = (mode & 0o111) != 0
    is_world_writable = (mode & 0o002) != 0
    
    if ext in TEXT_EXTENSIONS and is_executable:
        score += EXEC_TEXT_WEIGHT
    
    if is_world_writable:
        score += WORLD_WRITABLE_WEIGHT
    
    return min(1.0, score)

#==============================================================================
# CHANNEL B: Structural Deviation
#==============================================================================
ELF_MAGIC = b'\x7fELF'
SCRIPT_MAGIC = b'#!'
PE_MAGIC = b'MZ'
ARCHIVE_MAGICS = [b'PK', b'\x1f\x8b', b'BZ']  # ZIP, GZIP, BZIP2

# Binary extensions
BINARY_EXTENSIONS = {'.so', '.ko', '.bin', '.exe', '.dll', '.o', '.a'}

# System directories (for temporal freshness check)
SYSTEM_DIRS = ['/usr', '/bin', '/sbin', '/lib', '/lib64', '/etc']

# Freshness window (24 hours)
FRESHNESS_WINDOW = 86400

def calculate_structural_deviation(filepath, content, mtime):
    """
    B = Type Mismatch + Temporal Freshness
    """
    score = 0.0
    
    ext = os.path.splitext(filepath)[1].lower()
    
    # Detect actual content type
    is_elf = len(content) >= 4 and content[:4] == ELF_MAGIC
    is_script = len(content) >= 2 and content[:2] == SCRIPT_MAGIC
    is_pe = len(content) >= 2 and content[:2] == PE_MAGIC
    is_archive = any(len(content) >= 2 and content[:2] == m for m in ARCHIVE_MAGICS)
    
    # 1. Type Mismatch Detection
    # Text extension but binary content
    if ext in TEXT_EXTENSIONS:
        if is_elf or is_pe:
            score += 0.50  # High deviation: ELF masquerading as text
        elif is_archive:
            score += 0.35  # Archive masquerading as text
    
    # Binary extension but text/script content
    if ext in BINARY_EXTENSIONS:
        if is_script:
            score += 0.40  # Script masquerading as binary
        elif not is_elf and not is_pe and len(content) > 0:
            # Check if mostly printable ASCII
            printable_ratio = sum(1 for b in content if 32 <= b <= 126) / len(content)
            if printable_ratio > 0.8:
                score += 0.30  # Text masquerading as binary
    
    # 2. Temporal Freshness (recent modification in system directories)
    current_time = time.time()
    for sdir in SYSTEM_DIRS:
        if filepath.startswith(sdir):
            if current_time - mtime < FRESHNESS_WINDOW:
                score += 0.30  # Recently modified system file
            break
    
    return min(1.0, score)

#==============================================================================
# Main Collector
#==============================================================================
def collect_metrics_v3(file_list_path, output_path='metrics_v3.csv'):
    """Collect RGB metrics using Multi-Modal Feature Encoding"""
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
            g_hazard = calculate_contextual_hazard(fpath, content, mode)
            b_deviation = calculate_structural_deviation(fpath, content, mtime)
            
            results.append(f"{fpath}|{size}|{r_entropy:.4f}|{g_hazard:.4f}|{b_deviation:.4f}|{mode}")
        except Exception as e:
            continue
    
    with open(output_path, 'w') as f:
        for r in results:
            f.write(r + "\n")
    
    print(f"Collected {len(results)} files -> {output_path}")

if __name__ == "__main__":
    if len(sys.argv) >= 2:
        output = sys.argv[2] if len(sys.argv) >= 3 else 'metrics_v3.csv'
        collect_metrics_v3(sys.argv[1], output)
    else:
        print("Usage: python3 collect_metrics_v3.py <file_list.txt> [output.csv]")
