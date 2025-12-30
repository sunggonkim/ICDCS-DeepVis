#!/usr/bin/env python3
"""Real DeepVis Scanner - Fair Baseline Benchmark"""
import sys
sys.path.insert(0, "/home/bigdatahpclab")
import deepvis_scanner

MALWARE_ROOT = "/home/bigdatalab/Malware"
BENIGN_ROOT = "/usr/bin"

print("=" * 60)
print("REAL DeepVis Scanner - Fair Baseline Benchmark")
print("=" * 60)

scanner = deepvis_scanner.DeepVisScanner()
print("Scanner initialized!")

# Scan malware (limit for speed)
print("\n[1] Scanning Malware Directory (first 5000 files)...")
scan_result = scanner.scan(MALWARE_ROOT, limit=5000)
malware_result = scan_result.files
print(f"Total files: {len(malware_result)}")
print(f"Scan time: {scan_result.scan_time_ms:.0f}ms, Throughput: {scan_result.files_per_sec:.0f} files/s")

# Count by thresholds
r_only = 0  # Entropy only
rgb_heuristic = 0  # Simple OR
fusion = 0  # DeepVis full (with learned thresholds)

for e in malware_result:
    # R-only (Entropy > 0.75)
    if e.r > 0.75:
        r_only += 1
    
    # RGB Heuristic (simple OR)
    if e.r > 0.75 or e.g > 0.5 or e.b > 0.5:
        rgb_heuristic += 1
    
    # DeepVis Fusion (learned thresholds: R>0.75, G>0.25, B>0.30)
    if e.r > 0.75 or e.g > 0.25 or e.b > 0.30:
        fusion += 1

print(f"\n[2] Detection Results:")
print(f"  R-only (Entropy>0.75):    {r_only} ({r_only/len(malware_result)*100:.1f}%)")
print(f"  RGB Heuristic (OR 0.5):   {rgb_heuristic} ({rgb_heuristic/len(malware_result)*100:.1f}%)")
print(f"  DeepVis Fusion (Learned): {fusion} ({fusion/len(malware_result)*100:.1f}%)")

# Sample high-scoring entries
print("\n[3] Sample HIGH-RISK entries:")
count = 0
for e in malware_result:
    if e.r > 0.75 or e.g > 0.25 or e.b > 0.30:
        print(f"  {e.path[-60:]}")
        print(f"    R={e.r:.2f}, G={e.g:.2f}, B={e.b:.2f}")
        count += 1
        if count >= 10:
            break

# Scan benign for FP
print("\n[4] Scanning Benign Directory (/usr/bin)...")
benign_scan = scanner.scan(BENIGN_ROOT)
benign_result = benign_scan.files
print(f"Total benign files: {len(benign_result)}")

fp_r = fp_rgb = fp_fusion = 0
for e in benign_result:
    if e.r > 0.75:
        fp_r += 1
    if e.r > 0.75 or e.g > 0.5 or e.b > 0.5:
        fp_rgb += 1
    if e.r > 0.75 or e.g > 0.25 or e.b > 0.30:
        fp_fusion += 1

print(f"\n[5] False Positive Results:")
print(f"  R-only FP:    {fp_r} ({fp_r/len(benign_result)*100:.2f}%)")
print(f"  RGB Heur FP:  {fp_rgb} ({fp_rgb/len(benign_result)*100:.2f}%)")
print(f"  Fusion FP:    {fp_fusion} ({fp_fusion/len(benign_result)*100:.2f}%)")

print("=" * 60)
