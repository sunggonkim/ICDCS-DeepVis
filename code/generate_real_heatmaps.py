#!/usr/bin/env python3
"""
Generate REAL DeepVis heatmaps from GCP scans
1. Clean state - baseline filesystem scan
2. With malware - after injecting 10 rootkits
"""
import sys
import os
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

# Import Rust scanner (must be in current directory)
try:
    import deepvis_scanner
    RUST_OK = True
    print("[OK] Rust scanner loaded")
except ImportError as e:
    RUST_OK = False
    print(f"[ERROR] Rust scanner not available: {e}")
    sys.exit(1)

OUT_DIR = os.path.expanduser("~/heatmaps")
os.makedirs(OUT_DIR, exist_ok=True)

GRID_SIZE = 128
SECRET_KEY = "deepvis_icdcs_2026"

def scan_and_plot(title, filename, limit=50000):
    """Scan filesystem and generate heatmap"""
    print(f"\n=== Scanning: {title} ===")
    
    scanner = deepvis_scanner.DeepVisScanner()
    tensor_result, tensor = scanner.scan_to_tensor("/", limit)
    
    print(f"Files scanned: {tensor_result.total_files}")
    print(f"Unique pixels: {tensor_result.unique_pixels}")
    print(f"Max collisions: {tensor_result.max_collisions}")
    print(f"Anomaly pixels: {tensor_result.anomaly_pixels}")
    
    # Convert tensor to numpy array (RGB channels)
    r_channel = np.array([[tensor[y][x][0] for x in range(GRID_SIZE)] for y in range(GRID_SIZE)])
    g_channel = np.array([[tensor[y][x][1] for x in range(GRID_SIZE)] for y in range(GRID_SIZE)])
    b_channel = np.array([[tensor[y][x][2] for x in range(GRID_SIZE)] for y in range(GRID_SIZE)])
    
    # Combined visualization
    fig, axes = plt.subplots(1, 4, figsize=(16, 4))
    
    # R channel (Entropy)
    im0 = axes[0].imshow(r_channel, cmap='Reds', vmin=0, vmax=1, origin='lower')
    axes[0].set_title(f'R: Entropy', fontweight='bold')
    plt.colorbar(im0, ax=axes[0], fraction=0.046)
    
    # G channel (Context)
    im1 = axes[1].imshow(g_channel, cmap='Greens', vmin=0, vmax=1, origin='lower')
    axes[1].set_title(f'G: Context', fontweight='bold')
    plt.colorbar(im1, ax=axes[1], fraction=0.046)
    
    # B channel (Structure)
    im2 = axes[2].imshow(b_channel, cmap='Blues', vmin=0, vmax=1, origin='lower')
    axes[2].set_title(f'B: Structure', fontweight='bold')
    plt.colorbar(im2, ax=axes[2], fraction=0.046)
    
    # Combined RGB
    rgb_image = np.stack([r_channel, g_channel, b_channel], axis=-1)
    axes[3].imshow(rgb_image, origin='lower')
    axes[3].set_title(f'RGB Combined', fontweight='bold')
    
    plt.suptitle(title, fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig(os.path.join(OUT_DIR, filename), dpi=150, bbox_inches='tight')
    plt.close()
    print(f"-> Saved: {filename}")
    
    # Also save single combined heatmap
    fig2, ax2 = plt.subplots(figsize=(5, 5))
    # Use max of all channels for combined view
    combined = np.maximum(np.maximum(r_channel, g_channel), b_channel)
    im = ax2.imshow(combined, cmap='hot', vmin=0, vmax=1, origin='lower')
    ax2.set_title(title, fontsize=12, fontweight='bold')
    ax2.set_xlabel('X Coordinate')
    ax2.set_ylabel('Y Coordinate')
    plt.colorbar(im, ax=ax2, label='Max Feature Score')
    plt.tight_layout()
    single_name = filename.replace('.png', '_single.png')
    plt.savefig(os.path.join(OUT_DIR, single_name), dpi=150, bbox_inches='tight')
    plt.close()
    print(f"-> Saved: {single_name}")
    
    return tensor_result, r_channel, g_channel, b_channel

print("="*60)
print("DeepVis Real Heatmap Generation")
print("="*60)

# 1. Clean baseline scan
print("\n[1/2] Scanning CLEAN filesystem...")
clean_result, r_clean, g_clean, b_clean = scan_and_plot(
    "Clean Baseline (Before Attack)", 
    "heatmap_clean.png",
    limit=100000
)

# Note: Malware injection should be done separately
# The scan will pick up any malicious files already in /tmp, /dev/shm, etc.

print("\n" + "="*60)
print("HEATMAPS GENERATED!")
print(f"Output directory: {OUT_DIR}")
print("="*60)
