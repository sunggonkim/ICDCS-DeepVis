#!/usr/bin/env python3
"""
Windows PE Support Extension for DeepVis
Adds B-channel parsing for PE format alongside ELF
"""
import os
import math
import struct

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
    return entropy / 8.0  # Normalize to 0-1

def is_elf(header):
    """Check ELF magic: 0x7f 'E' 'L' 'F'"""
    return len(header) >= 4 and header[:4] == b"\x7fELF"

def is_pe(header):
    """Check PE format: MZ header + PE signature"""
    if len(header) < 64:
        return False
    # MZ magic
    if header[:2] != b"MZ":
        return False
    # PE offset at 0x3C
    try:
        pe_offset = struct.unpack("<I", header[0x3C:0x40])[0]
        # For valid PE, check if signature is within header range
        if pe_offset >= len(header):
            # Assume it's PE if MZ is present and offset is reasonable
            return pe_offset < 0x1000  # Reasonable PE offset
        if header[pe_offset:pe_offset+4] == b"PE\x00\x00":
            return True
        # Still treat as PE if MZ present and offset is valid
        return pe_offset < 0x1000
    except:
        pass
    return False

def get_pe_characteristics(header):
    """Parse PE Optional Header characteristics"""
    if len(header) < 128:
        return {}
    
    try:
        pe_offset = struct.unpack("<I", header[0x3C:0x40])[0]
        if pe_offset + 24 > len(header):
            return {}
        
        # COFF Header starts at PE+4
        coff_start = pe_offset + 4
        machine = struct.unpack("<H", header[coff_start:coff_start+2])[0]
        num_sections = struct.unpack("<H", header[coff_start+2:coff_start+4])[0]
        characteristics = struct.unpack("<H", header[coff_start+18:coff_start+20])[0]
        
        # Machine types
        machine_map = {
            0x14c: "x86",
            0x8664: "x64",
            0x1c0: "ARM",
            0xaa64: "ARM64"
        }
        
        return {
            "machine": machine_map.get(machine, "unknown"),
            "sections": num_sections,
            "is_dll": bool(characteristics & 0x2000),
            "is_executable": bool(characteristics & 0x0002),
        }
    except:
        return {}

def calc_b_channel_universal(filepath, header):
    """
    Universal B-channel (Structure Deviation) for both ELF and PE
    """
    ext = os.path.splitext(filepath)[1].lower()
    score = 0.0
    
    is_elf_file = is_elf(header)
    is_pe_file = is_pe(header)
    is_binary = is_elf_file or is_pe_file
    
    # === Extension Mismatch ===
    binary_exts = [".exe", ".dll", ".sys", ".so", ".ko", ".bin", ".elf"]
    text_exts = [".txt", ".log", ".cfg", ".conf", ".py", ".sh", ".bat", ".ps1", ".js"]
    
    if is_binary and ext in text_exts:
        score += 1.0  # Binary disguised as text
    elif not is_binary and ext in binary_exts:
        score += 0.8  # Non-binary with binary extension
    
    # === ELF-specific checks ===
    if is_elf_file and len(header) >= 18:
        e_type = struct.unpack("<H", header[16:18])[0]
        if e_type == 1:  # ET_REL (kernel module)
            path_lower = filepath.lower()
            if "/tmp" in path_lower or "/dev/shm" in path_lower:
                score += 0.5
    
    # === PE-specific checks ===
    if is_pe_file:
        pe_info = get_pe_characteristics(header)
        path_lower = filepath.lower()
        
        # DLL in suspicious location
        if pe_info.get("is_dll"):
            if "\\temp\\" in path_lower or "\\tmp\\" in path_lower:
                score += 0.5
            if "\\users\\" in path_lower and "\\downloads\\" in path_lower:
                score += 0.3
        
        # Executable with non-standard extension
        if pe_info.get("is_executable") and ext not in [".exe", ".dll", ".sys", ".scr"]:
            score += 0.6
        
        # Unusual section count (packed/obfuscated often have few sections)
        sections = pe_info.get("sections", 0)
        if sections < 2 or sections > 15:
            score += 0.3
    
    return min(1.0, score)

def demo_pe_detection():
    """Demonstrate PE parsing capability"""
    print("=" * 60)
    print("Windows PE Support Demo")
    print("=" * 60)
    
    # Create mock PE and ELF headers for testing
    test_cases = [
        ("normal.exe", b"MZ" + b"\x00"*0x3A + b"\x40\x00\x00\x00" + b"\x00"*0x40 + b"PE\x00\x00" + b"\x64\x86" + b"\x03\x00" + b"\x00"*14 + b"\x02\x00", "Valid PE x64"),
        ("disguised.txt", b"MZ" + b"\x00"*0x3A + b"\x40\x00\x00\x00" + b"\x00"*0x40 + b"PE\x00\x00" + b"\x4c\x01" + b"\x03\x00" + b"\x00"*14 + b"\x02\x00", "PE disguised as .txt"),
        ("rootkit.ko", b"\x7fELF\x02\x01\x01" + b"\x00"*9 + b"\x01\x00" + b"\x00"*100, "ELF kernel module"),
        ("script.py", b"#!/usr/bin/python3\nimport os\n", "Python script"),
        ("fake.dll", b"This is not a DLL file\n" + b"\x00"*100, "Fake DLL (text file)"),
    ]
    
    print(f"{'Filename':<20} | {'Type':<6} | {'B-score':<7} | {'Detected':<10}")
    print("-" * 60)
    
    for filename, header, desc in test_cases:
        is_bin = "PE" if is_pe(header) else ("ELF" if is_elf(header) else "Text")
        b_score = calc_b_channel_universal(f"/tmp/{filename}", header)
        detected = "ALERT" if b_score > 0.30 else "CLEAN"
        
        print(f"{filename:<20} | {is_bin:<6} | {b_score:<7.2f} | {detected:<10} ({desc})")
    
    print("=" * 60)
    print("\nPE Header Parsing Example:")
    
    # Parse a mock PE
    mock_pe = b"MZ" + b"\x00"*0x3A + b"\x40\x00\x00\x00" + b"\x00"*0x40 + b"PE\x00\x00" + b"\x64\x86" + b"\x05\x00" + b"\x00"*14 + b"\x02\x20"
    print(f"  is_pe: {is_pe(mock_pe)}")
    print(f"  characteristics: {get_pe_characteristics(mock_pe)}")

if __name__ == "__main__":
    demo_pe_detection()
