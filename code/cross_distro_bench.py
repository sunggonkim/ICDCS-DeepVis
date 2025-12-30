#!/usr/bin/env python3
"""
Cross-Distro Generalization Experiment
Tests G-channel (Context) and B-channel (Structure) consistency across distros
"""
import os
import math
import platform

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

def is_elf(header):
    return len(header) >= 4 and header[:4] == b"\x7fELF"

def calc_g_channel(filepath, mode):
    """Context Hazard Score"""
    path_lower = filepath.lower()
    score = 0.0
    
    # Path sensitivity
    if "/dev/shm" in path_lower or "/tmp/.X11" in path_lower:
        score += 0.7
    elif "/tmp" in path_lower:
        score += 0.6
    elif "/usr/bin" in path_lower or "/usr/sbin" in path_lower:
        score += 0.1
    elif "/etc" in path_lower:
        score += 0.2
    
    # Hidden file
    if os.path.basename(filepath).startswith("."):
        score += 0.2
    
    # World-writable
    if mode & 0o002:
        score += 0.1
    
    return min(1.0, score)

def calc_b_channel(filepath, header):
    """Structural Deviation Score"""
    is_binary = is_elf(header)
    ext = os.path.splitext(filepath)[1].lower()
    
    score = 0.0
    
    # Extension mismatch
    if is_binary and ext in [".txt", ".log", ".cfg", ".conf", ".py", ".sh"]:
        score += 1.0
    elif not is_binary and ext in [".so", ".ko", ".bin"]:
        score += 0.8
    
    # Kernel module check
    if is_binary and len(header) >= 18:
        e_type = int.from_bytes(header[16:18], byteorder='little')
        if e_type == 1:  # ET_REL (relocatable - kernel module)
            if "/tmp" in filepath or "/dev/shm" in filepath:
                score += 0.5
    
    return min(1.0, score)

def scan_directory(root, limit=500):
    """Scan and compute RGB for files"""
    results = []
    count = 0
    
    for dirpath, _, filenames in os.walk(root):
        for fname in filenames:
            if count >= limit:
                return results
            
            fpath = os.path.join(dirpath, fname)
            try:
                stat = os.stat(fpath)
                with open(fpath, 'rb') as f:
                    header = f.read(128)
                
                r = calc_entropy(header)
                g = calc_g_channel(fpath, stat.st_mode)
                b = calc_b_channel(fpath, header)
                
                results.append({
                    'path': fpath,
                    'r': r,
                    'g': g,
                    'b': b,
                    'is_elf': is_elf(header)
                })
                count += 1
            except:
                pass
    
    return results

def main():
    # Get distro info
    try:
        with open("/etc/os-release") as f:
            os_info = f.read()
        distro = "Unknown"
        for line in os_info.split("\n"):
            if line.startswith("PRETTY_NAME="):
                distro = line.split("=")[1].strip('"')
                break
    except:
        distro = platform.system()
    
    print("=" * 60)
    print(f"Cross-Distro Experiment: {distro}")
    print("=" * 60)
    
    # Scan system directories
    dirs_to_scan = ["/usr/bin", "/usr/sbin", "/etc"]
    all_results = []
    
    for d in dirs_to_scan:
        if os.path.exists(d):
            results = scan_directory(d, limit=300)
            all_results.extend(results)
            print(f"Scanned {d}: {len(results)} files")
    
    print(f"\nTotal files: {len(all_results)}")
    
    # Compute statistics
    r_vals = [x['r'] for x in all_results]
    g_vals = [x['g'] for x in all_results]
    b_vals = [x['b'] for x in all_results]
    elf_count = sum(1 for x in all_results if x['is_elf'])
    
    print(f"\n[Channel Statistics]")
    print(f"  R (Entropy):  mean={sum(r_vals)/len(r_vals):.3f}, max={max(r_vals):.3f}")
    print(f"  G (Context):  mean={sum(g_vals)/len(g_vals):.3f}, max={max(g_vals):.3f}")
    print(f"  B (Structure): mean={sum(b_vals)/len(b_vals):.3f}, max={max(b_vals):.3f}")
    print(f"  ELF binaries: {elf_count}/{len(all_results)} ({elf_count/len(all_results)*100:.1f}%)")
    
    # Test detection thresholds
    thresholds = {'R': 0.75, 'G': 0.25, 'B': 0.30}
    r_exceed = sum(1 for x in all_results if x['r'] > thresholds['R'])
    g_exceed = sum(1 for x in all_results if x['g'] > thresholds['G'])
    b_exceed = sum(1 for x in all_results if x['b'] > thresholds['B'])
    any_exceed = sum(1 for x in all_results if x['r'] > thresholds['R'] or x['g'] > thresholds['G'] or x['b'] > thresholds['B'])
    
    print(f"\n[Threshold Exceedance (Baseline Alert Rate)]")
    print(f"  R > {thresholds['R']}: {r_exceed} ({r_exceed/len(all_results)*100:.2f}%)")
    print(f"  G > {thresholds['G']}: {g_exceed} ({g_exceed/len(all_results)*100:.2f}%)")
    print(f"  B > {thresholds['B']}: {b_exceed} ({b_exceed/len(all_results)*100:.2f}%)")
    print(f"  ANY exceed: {any_exceed} ({any_exceed/len(all_results)*100:.2f}%)")
    
    # Output CSV for comparison
    csv_file = f"/tmp/crossdistro_{distro.replace(' ', '_').replace('/', '_')[:20]}.csv"
    with open(csv_file, "w") as f:
        f.write("distro,files,elf_pct,r_mean,g_mean,b_mean,r_exceed_pct,g_exceed_pct,b_exceed_pct,any_exceed_pct\n")
        f.write(f"{distro},{len(all_results)},{elf_count/len(all_results)*100:.1f},{sum(r_vals)/len(r_vals):.3f},{sum(g_vals)/len(g_vals):.3f},{sum(b_vals)/len(b_vals):.3f},{r_exceed/len(all_results)*100:.2f},{g_exceed/len(all_results)*100:.2f},{b_exceed/len(all_results)*100:.2f},{any_exceed/len(all_results)*100:.2f}\n")
    
    print(f"\n[CSV saved to {csv_file}]")
    print("=" * 60)

if __name__ == "__main__":
    main()
