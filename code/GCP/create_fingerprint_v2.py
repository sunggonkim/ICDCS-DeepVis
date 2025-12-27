#!/usr/bin/env python3
"""
DeepVis v2 Fingerprint Visualization
RGB: R=Entropy, G=Suspiciousness, B=Anomaly
"""

import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as patches
import hashlib
import os

IMG_SIZE = 256

def hash_filename_to_coords(filename):
    h = hashlib.sha256(filename.encode()).digest()
    row = (h[0] << 8 | h[1]) % IMG_SIZE
    col = (h[2] << 8 | h[3]) % IMG_SIZE
    return row, col

def load_metrics_v2(path):
    """Load v2 metrics: path|size|entropy|suspiciousness|anomaly|mode"""
    data = []
    with open(path, 'r') as f:
        for line in f:
            parts = line.strip().split('|')
            if len(parts) < 6:
                continue
            data.append({
                'path': parts[0],
                'size': float(parts[1]),
                'r': float(parts[2]),  # Entropy
                'g': float(parts[3]),  # Suspiciousness
                'b': float(parts[4]),  # Anomaly
                'mode': int(parts[5])
            })
    return data

def create_fingerprint(data):
    img = np.zeros((IMG_SIZE, IMG_SIZE, 3), dtype=np.float32)
    for d in data:
        row, col = hash_filename_to_coords(d['path'])
        img[row, col, 0] = max(img[row, col, 0], d['r'])
        img[row, col, 1] = max(img[row, col, 1], d['g'])
        img[row, col, 2] = max(img[row, col, 2], d['b'])
    return img

def create_comparison_figure(benign_path, attack_path, output_path):
    """Create side-by-side comparison of benign vs attack fingerprints"""
    
    benign_data = load_metrics_v2(benign_path)
    attack_data = load_metrics_v2(attack_path)
    
    benign_img = create_fingerprint(benign_data)
    
    # Attack = benign + attack files
    combined_data = benign_data + attack_data
    attack_img = create_fingerprint(combined_data)
    
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    
    # Benign
    axes[0].imshow(benign_img)
    axes[0].set_title('(a) Benign Software Only\n(R=Entropy, G=Suspiciousness, B=Anomaly)', fontsize=10)
    axes[0].axis('off')
    
    # Attack (with markers for attack files)
    axes[1].imshow(attack_img)
    
    # Mark each attack file
    for d in attack_data:
        row, col = hash_filename_to_coords(d['path'])
        # Color based on dominant channel
        if d['g'] > 0.5:
            color = 'lime'  # High suspiciousness (green dominant)
        elif d['r'] > 0.7:
            color = 'red'   # High entropy (red dominant)
        else:
            color = 'yellow'
        
        circle = patches.Circle((col, row), radius=8, linewidth=2,
                                edgecolor=color, facecolor='none')
        axes[1].add_patch(circle)
    
    axes[1].set_title('(b) + Realistic Attacks\n(Circles mark injected malicious files)', fontsize=10)
    axes[1].axis('off')
    
    # Add legend
    legend_elements = [
        patches.Patch(facecolor='none', edgecolor='lime', linewidth=2, label='High Suspiciousness (G>0.5)'),
        patches.Patch(facecolor='none', edgecolor='red', linewidth=2, label='High Entropy (R>0.7)'),
    ]
    fig.legend(handles=legend_elements, loc='lower center', ncol=2, fontsize=9)
    
    plt.tight_layout()
    plt.subplots_adjust(bottom=0.12)
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"Saved: {output_path}")

def create_rgb_channel_breakdown(attack_path, output_path):
    """Show RGB channels separately for attack files"""
    
    attack_data = load_metrics_v2(attack_path)
    
    fig, ax = plt.subplots(figsize=(10, 5))
    
    names = [os.path.basename(d['path']) for d in attack_data]
    r_vals = [d['r'] for d in attack_data]
    g_vals = [d['g'] for d in attack_data]
    b_vals = [d['b'] for d in attack_data]
    
    x = np.arange(len(names))
    width = 0.25
    
    ax.bar(x - width, r_vals, width, label='R (Entropy)', color='red', alpha=0.8)
    ax.bar(x, g_vals, width, label='G (Suspiciousness)', color='green', alpha=0.8)
    ax.bar(x + width, b_vals, width, label='B (Anomaly)', color='blue', alpha=0.8)
    
    ax.set_ylabel('Score (0-1)')
    ax.set_xlabel('Attack File')
    ax.set_title('DeepVis v2 RGB Channel Analysis of Realistic Attacks')
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=45, ha='right', fontsize=8)
    ax.legend()
    ax.axhline(y=0.5, color='gray', linestyle='--', alpha=0.5, label='Detection Threshold')
    ax.set_ylim(0, 1.1)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"Saved: {output_path}")

if __name__ == "__main__":
    base = "/home/bigdatalab/skim/file system fingerprinting/code/GCP"
    out = "/home/bigdatalab/skim/file system fingerprinting/paper/figures"
    
    create_comparison_figure(
        f"{base}/benign_v2.csv",
        f"{base}/realistic_attack_v2.csv",
        f"{out}/deepvis_v2_comparison.png"
    )
    
    create_rgb_channel_breakdown(
        f"{base}/realistic_attack_v2.csv",
        f"{out}/deepvis_v2_rgb_breakdown.png"
    )
