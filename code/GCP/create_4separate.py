#!/usr/bin/env python3
"""
Create 4 separate images for LaTeX subfloat:
(a) Clean baseline with zoom boxes
(b-d) Each with: Top=Original, Arrow, Bottom=+Attack
"""

import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as patches
import hashlib

IMG_SIZE = 256
ZOOM_SIZE = 40

def hash_filename_to_coords(filename):
    h = hashlib.sha256(filename.encode()).digest()
    row = (h[0] << 8 | h[1]) % IMG_SIZE
    col = (h[2] << 8 | h[3]) % IMG_SIZE
    return row, col

def normalize_entropy(e):
    return e

def normalize_size(s):
    if s <= 0: return 0
    import math
    return min(1.0, math.log10(s) / 7.0)

def normalize_permissions(p):
    return p / 511.0

def load_metrics(metrics_path):
    data = []
    with open(metrics_path, 'r') as f:
        for line in f:
            parts = line.strip().split('|')
            if len(parts) < 5: continue
            data.append({
                'path': parts[0],
                'size': float(parts[1]),
                'entropy': float(parts[2]),
                'mode': int(parts[3]),
                'api': float(parts[4])
            })
    return data

def create_fingerprint(data):
    img = np.zeros((IMG_SIZE, IMG_SIZE, 3), dtype=np.float32)
    for d in data:
        row, col = hash_filename_to_coords(d['path'])
        red = normalize_entropy(d['entropy'])
        green = max(normalize_size(d['size']), d['api'])
        blue = normalize_permissions(d['mode'])
        img[row, col, 0] = max(img[row, col, 0], red)
        img[row, col, 1] = max(img[row, col, 1], green)
        img[row, col, 2] = max(img[row, col, 2], blue)
    return img

def get_zoom_region(img, row, col, size=ZOOM_SIZE):
    half = size // 2
    r_start = max(0, row - half)
    r_end = min(IMG_SIZE, row + half)
    c_start = max(0, col - half)
    c_end = min(IMG_SIZE, col + half)
    return img[r_start:r_end, c_start:c_end], (r_start, r_end, c_start, c_end)

def create_clean_with_zoom_boxes(clean_path, mal_files, colors, output_path):
    """Create clean baseline image with zoom region boxes"""
    clean_data = load_metrics(clean_path)
    clean_img = create_fingerprint(clean_data)
    
    fig, ax = plt.subplots(figsize=(3.5, 3.5))
    ax.imshow(clean_img)
    
    for i, mal_file in enumerate(mal_files):
        row, col = hash_filename_to_coords(mal_file)
        rect = patches.Rectangle((col - ZOOM_SIZE//2, row - ZOOM_SIZE//2), 
                                  ZOOM_SIZE, ZOOM_SIZE,
                                  linewidth=2.5, edgecolor=colors[i], 
                                  facecolor='none', linestyle='-')
        ax.add_patch(rect)
    
    ax.axis('off')
    plt.tight_layout(pad=0)
    plt.savefig(output_path, dpi=200, bbox_inches='tight', pad_inches=0.02)
    plt.close()
    print(f"Saved: {output_path}")

def create_before_after_attack(clean_path, attack_path, mal_file, border_color, output_path):
    """Create vertical before/after image: Top=Clean, Arrow, Bottom=+Attack"""
    clean_data = load_metrics(clean_path)
    attack_data = load_metrics(attack_path)
    
    clean_img = create_fingerprint(clean_data)
    combined_data = clean_data + attack_data
    attack_img = create_fingerprint(combined_data)
    
    row, col = hash_filename_to_coords(mal_file)
    clean_zoom, (r1, r2, c1, c2) = get_zoom_region(clean_img, row, col)
    attack_zoom, _ = get_zoom_region(attack_img, row, col)
    
    # Create figure with 2 rows
    fig, axes = plt.subplots(2, 1, figsize=(3.5, 6))
    
    # Top: Clean (Original)
    axes[0].imshow(clean_zoom, interpolation='nearest')
    axes[0].set_title('Original', fontsize=10, fontweight='bold')
    for spine in axes[0].spines.values():
        spine.set_edgecolor(border_color)
        spine.set_linewidth(4)
    axes[0].set_xticks([])
    axes[0].set_yticks([])
    
    # Bottom: With Attack
    axes[1].imshow(attack_zoom, interpolation='nearest')
    # Mark the malicious pixel
    local_r = row - r1
    local_c = col - c1
    circle = patches.Circle((local_c, local_r), radius=3, linewidth=2,
                            edgecolor='white', facecolor='none')
    axes[1].add_patch(circle)
    axes[1].set_title('+ Attack', fontsize=10, fontweight='bold', color='red')
    for spine in axes[1].spines.values():
        spine.set_edgecolor(border_color)
        spine.set_linewidth(4)
    axes[1].set_xticks([])
    axes[1].set_yticks([])
    
    # Add arrow between them
    fig.text(0.5, 0.5, '↓', fontsize=30, ha='center', va='center', fontweight='bold')
    
    plt.tight_layout()
    plt.subplots_adjust(hspace=0.15)
    plt.savefig(output_path, dpi=200, bbox_inches='tight', pad_inches=0.02)
    plt.close()
    print(f"Saved: {output_path}")

if __name__ == "__main__":
    base = "/home/bigdatalab/skim/file system fingerprinting/code/GCP"
    out = "/home/bigdatalab/skim/file system fingerprinting/paper/figures"
    
    clean = f"{base}/clean_metrics.csv"
    colors = ['red', 'lime', 'orange']
    
    mal_files = [
        "/tmp/kmod_debug.ko",
        "/tmp/libsystem_core.so",
        "/tmp/syslog-daemon",
    ]
    
    attack_paths = [
        f"{base}/attack_diamorphine_full_metrics.csv",
        f"{base}/attack_azazel_full_metrics.csv",
        f"{base}/attack_miner_full_metrics.csv",
    ]
    
    # 1. Clean baseline with zoom boxes
    create_clean_with_zoom_boxes(clean, mal_files, colors, f"{out}/eval_clean.png")
    
    # 2-4. Before/After attacks
    create_before_after_attack(clean, attack_paths[0], mal_files[0], colors[0], f"{out}/eval_diamorphine.png")
    create_before_after_attack(clean, attack_paths[1], mal_files[1], colors[1], f"{out}/eval_azazel.png")
    create_before_after_attack(clean, attack_paths[2], mal_files[2], colors[2], f"{out}/eval_miner.png")
