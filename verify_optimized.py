#!/usr/bin/env python3
"""
Multi-Platform DeepVis Analyzer (Optimized Weights)
Supports: ELF (Linux), PE (Windows), DEX (Android), PHP/JS (Web)
Updated G-Channel Weights based on Grid Search (N=84k).
"""
import os
import math
import struct

THRESHOLDS = {'R': 0.75, 'G': 0.25, 'B': 0.30}

def calc_entropy(data):
    if not data or len(data) == 0:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy / 8.0

# ============================================================
# Platform Detection
# ============================================================
def is_elf(header):
    return len(header) >= 4 and header[:4] == b"\x7fELF"

def is_pe(header):
    if len(header) < 64 or header[:2] != b"MZ":
        return False
    try:
        pe_offset = struct.unpack("<I", header[0x3C:0x40])[0]
        return pe_offset < 0x1000  # Reasonable PE offset
    except:
        return False

def is_dex(header):
    return len(header) >= 8 and header[:4] == b"dex\n"

def is_php(header, filepath):
    return header.startswith(b"<?php") or header.startswith(b"<?=") or filepath.endswith(".php")

def is_js(header, filepath):
    return filepath.endswith(".js") or b"function" in header[:100] or b"var " in header[:100]

def get_platform(header, filepath):
    if is_elf(header):
        return "ELF"
    elif is_pe(header):
        return "PE"
    elif is_dex(header):
        return "DEX"
    elif is_php(header, filepath):
        return "PHP"
    elif is_js(header, filepath):
        return "JS"
    else:
        return "OTHER"

# ============================================================
# Platform-Specific B-Channel
# ============================================================
def calc_b_channel_elf(filepath, header):
    ext = os.path.splitext(filepath)[1].lower()
    score = 0.0
    if ext in [".txt", ".log", ".cfg", ".py", ".sh"]: score += 1.0
    if len(header) >= 18:
        e_type = struct.unpack("<H", header[16:18])[0]
        if e_type == 1:  # ET_REL
            if "/tmp" in filepath or "/dev/shm" in filepath: score += 0.5
    return min(1.0, score)

def calc_b_channel_pe(filepath, header):
    ext = os.path.splitext(filepath)[1].lower()
    score = 0.0
    if ext in [".txt", ".log", ".doc", ".pdf", ".jpg", ".png"]: score += 1.0
    path_lower = filepath.lower()
    if "temp" in path_lower or "tmp" in path_lower: score += 0.5
    if "download" in path_lower: score += 0.3
    if ext not in [".exe", ".dll", ".sys", ".scr", ".ocx"]: score += 0.4
    return min(1.0, score)

def calc_b_channel_dex(filepath, header):
    ext = os.path.splitext(filepath)[1].lower()
    score = 0.0
    if "classes" not in filepath.lower(): score += 0.3
    if ext not in [".dex", ".apk", ".jar"]: score += 0.6
    return min(1.0, score)

def calc_b_channel_php(filepath, header):
    score = 0.0
    content = header[:500]
    dangerous = [b"eval(", b"base64_decode", b"exec(", b"system(", b"passthru(", 
                 b"shell_exec", b"$_GET", b"$_POST", b"$_REQUEST"]
    for d in dangerous:
        if d in content: score += 0.15
    if b"\\x" in content or b"chr(" in content: score += 0.3
    return min(1.0, score)

def calc_b_channel_js(filepath, header):
    score = 0.0
    content = header[:500]
    suspicious = [b"eval(", b"document.write", b"unescape(", b"fromCharCode",
                  b"atob(", b"ActiveXObject", b"WScript.Shell"]
    for s in suspicious:
        if s in content: score += 0.15
    return min(1.0, score)

def calc_b_channel(filepath, header, platform):
    if platform == "ELF": return calc_b_channel_elf(filepath, header)
    elif platform == "PE": return calc_b_channel_pe(filepath, header)
    elif platform == "DEX": return calc_b_channel_dex(filepath, header)
    elif platform == "PHP": return calc_b_channel_php(filepath, header)
    elif platform == "JS": return calc_b_channel_js(filepath, header)
    else: return 0.0

# ============================================================
# G-Channel (Optimized via Grid Search)
# ============================================================
def calc_g_channel(filepath):
    """Context hazard"""
    path_lower = filepath.lower()
    score = 0.0
    
    # Suspicious paths (Linux)
    if "/tmp" in path_lower or "/dev/shm" in path_lower:
        score += 0.6 # Keep conservative
    
    # Suspicious paths (Windows)
    if "\\temp\\" in path_lower or "\\tmp\\" in path_lower:
        score += 0.6
    if "\\downloads\\" in path_lower:
        score += 0.3
    
    # Hidden files (UPDATED from Grid Search)
    if os.path.basename(filepath).startswith("."):
        score += 0.5 # 0.2 -> 0.5 (Grid Search Result)
    
    # Known malware keywords (UPDATED from Grid Search)
    keywords = ["rootkit", "backdoor", "trojan", "exploit", "shell", "rat", "c99"]
    for kw in keywords:
        if kw in path_lower:
            score += 0.5 # 0.4 -> 0.5 (Grid Search Result)
            break
    
    return min(1.0, score)

# ============================================================
# Analysis
# ============================================================
def analyze_file(filepath):
    try:
        with open(filepath, "rb") as f:
            header = f.read(512)
        platform = get_platform(header, filepath)
        r = calc_entropy(header)
        g = calc_g_channel(filepath)
        b = calc_b_channel(filepath, header, platform)
        
        detected = r > THRESHOLDS['R'] or g > THRESHOLDS['G'] or b > THRESHOLDS['B']
        return {"path": filepath, "platform": platform, "r": r, "g": g, "b": b, "detected": detected}
    except:
        return None

def scan_directory(root, limit=None):
    results = []
    count = 0
    for dirpath, _, filenames in os.walk(root):
        for fname in filenames:
            if limit and count >= limit: return results
            fpath = os.path.join(dirpath, fname)
            result = analyze_file(fpath)
            if result:
                results.append(result)
                count += 1
    return results

def run_experiment():
    ORGANIZED_ROOT = "/home/bigdatalab/Malware"
    platforms = {
        "Linux": f"{ORGANIZED_ROOT}/Linux",
        "Windows": f"{ORGANIZED_ROOT}/Windows",
        "Web": f"{ORGANIZED_ROOT}/Web",
        "Mobile": f"{ORGANIZED_ROOT}/Mobile",
    }
    
    print(f"{'Platform':<10} | {'Files':<6} | {'Recall':<6} | {'R (Ent)':<6} | {'G (Con)':<6} | {'B (Str)':<6}")
    print("-" * 65)
    
    for platform_name, path in platforms.items():
        if not os.path.exists(path): continue
        results = scan_directory(path)
        if not results: continue
        
        detected = sum(1 for r in results if r["detected"])
        recall = detected/len(results)*100
        r_mean = sum(r["r"] for r in results) / len(results)
        g_mean = sum(r["g"] for r in results) / len(results)
        b_mean = sum(r["b"] for r in results) / len(results)
        
        print(f"{platform_name:<10} | {len(results):<6} | {recall:<6.1f} | {r_mean:<6.3f}   | {g_mean:<6.3f}   | {b_mean:<6.3f}")

if __name__ == "__main__":
    run_experiment()
