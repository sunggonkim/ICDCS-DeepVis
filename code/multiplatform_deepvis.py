#!/usr/bin/env python3
"""
Multi-Platform DeepVis Analyzer
Supports: ELF (Linux), PE (Windows), DEX (Android), PHP/JS (Web)
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
    """Android DEX format"""
    return len(header) >= 8 and header[:4] == b"dex\n"

def is_php(header, filepath):
    """PHP file detection"""
    return header.startswith(b"<?php") or header.startswith(b"<?=") or filepath.endswith(".php")

def is_js(header, filepath):
    """JavaScript detection"""
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
    """ELF-specific structural analysis"""
    ext = os.path.splitext(filepath)[1].lower()
    score = 0.0
    
    # Extension mismatch
    if ext in [".txt", ".log", ".cfg", ".py", ".sh"]:
        score += 1.0
    
    # Kernel module in suspicious path
    if len(header) >= 18:
        e_type = struct.unpack("<H", header[16:18])[0]
        if e_type == 1:  # ET_REL
            if "/tmp" in filepath or "/dev/shm" in filepath:
                score += 0.5
    
    return min(1.0, score)

def calc_b_channel_pe(filepath, header):
    """Windows PE structural analysis"""
    ext = os.path.splitext(filepath)[1].lower()
    score = 0.0
    
    # PE in non-executable extension
    if ext in [".txt", ".log", ".doc", ".pdf", ".jpg", ".png"]:
        score += 1.0
    
    # DLL in suspicious path
    path_lower = filepath.lower()
    if "temp" in path_lower or "tmp" in path_lower:
        score += 0.5
    if "download" in path_lower:
        score += 0.3
    
    # Not standard PE extension
    if ext not in [".exe", ".dll", ".sys", ".scr", ".ocx"]:
        score += 0.4
    
    return min(1.0, score)

def calc_b_channel_dex(filepath, header):
    """Android DEX structural analysis"""
    ext = os.path.splitext(filepath)[1].lower()
    score = 0.0
    
    # DEX not in expected path
    if "classes" not in filepath.lower():
        score += 0.3
    
    # DEX with wrong extension
    if ext not in [".dex", ".apk", ".jar"]:
        score += 0.6
    
    return min(1.0, score)

def calc_b_channel_php(filepath, header):
    """PHP webshell detection"""
    score = 0.0
    content = header[:500]
    
    # Common webshell functions
    dangerous = [b"eval(", b"base64_decode", b"exec(", b"system(", b"passthru(", 
                 b"shell_exec", b"$_GET", b"$_POST", b"$_REQUEST"]
    for d in dangerous:
        if d in content:
            score += 0.15
    
    # Obfuscation patterns
    if b"\\x" in content or b"chr(" in content:
        score += 0.3
    
    return min(1.0, score)

def calc_b_channel_js(filepath, header):
    """Malicious JavaScript detection"""
    score = 0.0
    content = header[:500]
    
    # Suspicious patterns
    suspicious = [b"eval(", b"document.write", b"unescape(", b"fromCharCode",
                  b"atob(", b"ActiveXObject", b"WScript.Shell"]
    for s in suspicious:
        if s in content:
            score += 0.15
    
    return min(1.0, score)

def calc_b_channel(filepath, header, platform):
    """Universal B-channel dispatcher"""
    if platform == "ELF":
        return calc_b_channel_elf(filepath, header)
    elif platform == "PE":
        return calc_b_channel_pe(filepath, header)
    elif platform == "DEX":
        return calc_b_channel_dex(filepath, header)
    elif platform == "PHP":
        return calc_b_channel_php(filepath, header)
    elif platform == "JS":
        return calc_b_channel_js(filepath, header)
    else:
        return 0.0

# ============================================================
# G-Channel (Universal)
# ============================================================
def calc_g_channel(filepath):
    """Context hazard - universal"""
    path_lower = filepath.lower()
    score = 0.0
    
    # Suspicious paths (Linux)
    if "/tmp" in path_lower or "/dev/shm" in path_lower:
        score += 0.6
    
    # Suspicious paths (Windows)
    if "\\temp\\" in path_lower or "\\tmp\\" in path_lower:
        score += 0.6
    if "\\downloads\\" in path_lower:
        score += 0.3
    
    # Hidden files
    if os.path.basename(filepath).startswith("."):
        score += 0.2
    
    # Known malware keywords in path
    keywords = ["rootkit", "backdoor", "trojan", "exploit", "shell", "rat", "c99"]
    for kw in keywords:
        if kw in path_lower:
            score += 0.4
            break
    
    return min(1.0, score)

# ============================================================
# Main Analysis
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
        
        return {
            "path": filepath,
            "platform": platform,
            "r": r,
            "g": g, 
            "b": b,
            "detected": detected
        }
    except:
        return None

def scan_directory(root, limit=None):
    results = []
    count = 0
    for dirpath, _, filenames in os.walk(root):
        for fname in filenames:
            if limit and count >= limit:
                return results
            fpath = os.path.join(dirpath, fname)
            result = analyze_file(fpath)
            if result:
                results.append(result)
                count += 1
    return results

def run_multiplatform_experiment():
    ORGANIZED_ROOT = "/home/bigdatalab/Malware/Organized"
    
    print("=" * 70)
    print("Multi-Platform DeepVis Experiment")
    print("=" * 70)
    
    platforms = {
        "Linux": f"{ORGANIZED_ROOT}/Linux",
        "Windows": f"{ORGANIZED_ROOT}/Windows",
        "Web": f"{ORGANIZED_ROOT}/Web",
        "Mobile": f"{ORGANIZED_ROOT}/Mobile",
    }
    
    all_results = {}
    
    for platform_name, path in platforms.items():
        if not os.path.exists(path):
            print(f"[SKIP] {platform_name}: {path} not found")
            continue
        
        print(f"\n[Scanning] {platform_name}...")
        results = scan_directory(path, limit=1000)
        
        if not results:
            print(f"  No files found")
            continue
        
        # Statistics
        detected = sum(1 for r in results if r["detected"])
        platforms_found = {}
        for r in results:
            p = r["platform"]
            platforms_found[p] = platforms_found.get(p, 0) + 1
        
        r_mean = sum(r["r"] for r in results) / len(results)
        g_mean = sum(r["g"] for r in results) / len(results)
        b_mean = sum(r["b"] for r in results) / len(results)
        
        print(f"  Files: {len(results)}")
        print(f"  Detected: {detected} ({detected/len(results)*100:.1f}%)")
        print(f"  Platform breakdown: {platforms_found}")
        print(f"  Channels: R={r_mean:.3f}, G={g_mean:.3f}, B={b_mean:.3f}")
        
        all_results[platform_name] = {
            "total": len(results),
            "detected": detected,
            "recall": detected/len(results)*100,
            "r_mean": r_mean,
            "g_mean": g_mean,
            "b_mean": b_mean,
            "platforms": platforms_found
        }
    
    # Summary Table
    print("\n" + "=" * 70)
    print("SUMMARY: Multi-Platform Detection Results")
    print("=" * 70)
    print(f"{'Category':<12} | {'Files':<8} | {'Detected':<10} | {'Recall':<8} | {'R':<6} | {'G':<6} | {'B':<6}")
    print("-" * 70)
    for cat, data in all_results.items():
        print(f"{cat:<12} | {data['total']:<8} | {data['detected']:<10} | {data['recall']:<6.1f}% | {data['r_mean']:<6.3f} | {data['g_mean']:<6.3f} | {data['b_mean']:<6.3f}")
    print("=" * 70)

if __name__ == "__main__":
    run_multiplatform_experiment()
