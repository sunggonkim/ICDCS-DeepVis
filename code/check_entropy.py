import sys
import math
import os

files = [
    "/home/bigdatalab/Malware/MalwareSourceCode-main/Libs/DDoS/VirTool.DDoS.TCP.a",
    "/home/bigdatalab/Malware/MalwareSourceCode-main/Libs/DDoS/VirTool.DDoS.WIZARD.a",
    "/home/bigdatalab/Malware/malware-master/Mazar/MazAr_Admin/uwsgi"
]

def calc_entropy(filepath):
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        if not data: return 0.0
        counts = [0]*256
        for b in data: counts[b] += 1
        ent = 0.0
        for c in counts:
            if c > 0:
                p = c / len(data)
                ent -= p * math.log2(p)
        return ent / 8.0 # Normalize to 0-1
    except: return 0.0

print(f"{'File':<40} | {'Entropy (R)':<10} | {'DeepVis Result'}")
print("-" * 70)
for f in files:
    e = calc_entropy(f)
    res = "HIT (High R)" if e > 0.75 else "MISS (Low R)"
    print(f"{os.path.basename(f):<40} | {e:<10.4f} | {res}")
