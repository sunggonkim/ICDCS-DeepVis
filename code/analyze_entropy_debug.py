import math
import collections
import os
import sys

def calculate_entropy(filepath, label):
    if not os.path.exists(filepath):
        print(f"[-] File not found: {filepath}")
        return
    
    with open(filepath, 'rb') as f:
        data = f.read()
    
    if len(data) == 0:
        print(f"[-] Empty file: {filepath}")
        return

    # Byte frequency
    c = collections.Counter(data)
    total = len(data)
    
    # Entropy calculation
    entropy = 0
    for count in c.values():
        p = count / total
        entropy -= p * math.log2(p)
        
    print(f"[*] {label}:")
    print(f"    File: {filepath}")
    print(f"    Size: {total} bytes")
    print(f"    Entropy: {entropy:.4f} bits/byte (Max 8.0)")
    print(f"    Normalized: {entropy/8.0:.4f} (0.0-1.0)")
    print(f"    Unique Bytes: {len(c)}/256")
    print(f"    Top 5 Bytes: {c.most_common(5)}")
    print("-" * 40)
    return entropy

print("=== Starting Entropy Analysis ===")
calculate_entropy('/etc/fstab', 'Text (Normal)')
calculate_entropy('/bin/bash', 'Binary (ELF)')
calculate_entropy('/home/bigdatalab/azazel_packed.so', 'Rootkit (Packed)')
print("=== Done ===")
