#!/usr/bin/env python3
"""
Create a single figure with 4 subfigures:
(a) Clean baseline
(b) + Diamorphine (zoomed)
(c) + Azazel (zoomed)
(d) + XMRig (zoomed)
"""

import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as patches
import hashlib
import os

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
    """Load old format: path|size|entropy|mode|api"""
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

def create_4_subfigure(clean_path, attack_metrics_paths, malicious_filenames, titles, output_path):
    """
    Create 1x4 subfigure: Clean + 3 zoomed attacks with colored borders
    """
    clean_data = load_metrics(clean_path)
    clean_img = create_fingerprint(clean_data)
    
    fig, axes = plt.subplots(1, 4, figsize=(14, 3.5))
    
    # Colors for each attack (matching zoom boxes and borders)
    colors = ['red', 'lime', 'orange']
    
    # (a) Clean baseline - full image
    axes[0].imshow(clean_img)
    axes[0].set_title('(a) Clean Baseline', fontsize=10)
    axes[0].axis('off')
    
    # Mark zoom regions on clean image with colored boxes
    for i, mal_file in enumerate(malicious_filenames):
        row, col = hash_filename_to_coords(mal_file)
        rect = patches.Rectangle((col - ZOOM_SIZE//2, row - ZOOM_SIZE//2), 
                                  ZOOM_SIZE, ZOOM_SIZE,
                                  linewidth=2.5, edgecolor=colors[i], 
                                  facecolor='none', linestyle='-')
        axes[0].add_patch(rect)
    
    # (b), (c), (d) - Zoomed attack regions with colored borders
    for i, (attack_path, mal_file, title) in enumerate(zip(attack_metrics_paths, malicious_filenames, titles)):
        attack_data = load_metrics(attack_path)
        combined_data = clean_data + attack_data
        attack_img = create_fingerprint(combined_data)
        
        row, col = hash_filename_to_coords(mal_file)
        zoom_img, (r1, r2, c1, c2) = get_zoom_region(attack_img, row, col)
        
        ax = axes[i + 1]
        ax.imshow(zoom_img, interpolation='nearest')
        
        # Mark the malicious pixel with white circle (visible on any background)
        local_r = row - r1
        local_c = col - c1
        circle = patches.Circle((local_c, local_r), radius=3, linewidth=2,
                                edgecolor='white', facecolor='none')
        ax.add_patch(circle)
        
        # Add colored border around the entire subplot matching the zoom box color
        for spine in ax.spines.values():
            spine.set_edgecolor(colors[i])
            spine.set_linewidth(4)
        
        ax.set_title(f'({chr(98+i)}) + {title}', fontsize=10, color=colors[i], fontweight='bold')
        ax.set_xticks([])
        ax.set_yticks([])
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"Saved: {output_path}")

if __name__ == "__main__":
    base = "/home/bigdatalab/skim/file system fingerprinting/code/GCP"
    out = "/home/bigdatalab/skim/file system fingerprinting/paper/figures"
    
    clean = f"{base}/clean_metrics.csv"
    
    # Attack files and their malicious file paths (must match what's in the metrics)
    attack_paths = [
        f"{base}/attack_diamorphine_full_metrics.csv",
        f"{base}/attack_azazel_full_metrics.csv",
        f"{base}/attack_miner_full_metrics.csv",
    ]
    
    mal_files = [
        "/tmp/kmod_debug.ko",
        "/tmp/libsystem_core.so",
        "/tmp/syslog-daemon",
    ]
    
    titles = [
        "Diamorphine (.ko)",
        "Azazel (.so)", 
        "XMRig (packed)",
    ]
    
    create_4_subfigure(clean, attack_paths, mal_files, titles, f"{out}/eval_4subfig.png")
