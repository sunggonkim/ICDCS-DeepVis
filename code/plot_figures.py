#!/usr/bin/env python3
"""
DeepVis v3 - Figure Generation for Paper
================================================================================
Generates all visualization figures for the paper:
  1. Fingerprint comparison (Clean vs Attack)
  2. RGB channel breakdown bar chart
  3. Before/After zoom comparison subfigures
  4. Detection results summary

Usage:
  python3 plot_figures.py --fingerprint-compare <clean.csv> <attack.csv> <output.png>
  python3 plot_figures.py --rgb-breakdown <metrics.csv> <output.png>
  python3 plot_figures.py --4subfig <clean.csv> <attack_metrics...> <output_dir>
================================================================================
"""

import os
import sys
import hashlib
import argparse
import json

IMG_SIZE = 256
ZOOM_SIZE = 40

def hash_to_coords(filepath):
    h = hashlib.sha256(filepath.encode()).digest()
    row = (h[0] << 8 | h[1]) % IMG_SIZE
    col = (h[2] << 8 | h[3]) % IMG_SIZE
    return row, col

def load_metrics(path):
    data = []
    with open(path, 'r') as f:
        for line in f:
            parts = line.strip().split('|')
            if len(parts) >= 6:
                data.append({
                    'path': parts[0],
                    'size': int(parts[1]),
                    'R': float(parts[2]),
                    'G': float(parts[3]),
                    'B': float(parts[4]),
                    'mode': int(parts[5])
                })
    return data

def create_fingerprint_image(data):
    import numpy as np
    img = np.zeros((IMG_SIZE, IMG_SIZE, 3), dtype=np.float32)
    for d in data:
        row, col = hash_to_coords(d['path'])
        img[row, col, 0] = max(img[row, col, 0], d['R'])
        img[row, col, 1] = max(img[row, col, 1], d['G'])
        img[row, col, 2] = max(img[row, col, 2], d['B'])
    return img

def plot_fingerprint_compare(clean_path, attack_path, output_path):
    """Side-by-side fingerprint comparison"""
    import numpy as np
    import matplotlib.pyplot as plt
    
    clean_data = load_metrics(clean_path)
    attack_data = load_metrics(attack_path)
    
    clean_img = create_fingerprint_image(clean_data)
    attack_img = create_fingerprint_image(clean_data + attack_data)
    
    fig, axes = plt.subplots(1, 2, figsize=(10, 5))
    axes[0].imshow(clean_img)
    axes[0].set_title('Clean Baseline', fontsize=12)
    axes[0].axis('off')
    
    axes[1].imshow(attack_img)
    axes[1].set_title('+ Attack Files', fontsize=12)
    axes[1].axis('off')
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"Saved: {output_path}")

def plot_rgb_breakdown(metrics_path, output_path, top_n=15):
    """Bar chart of RGB channels for files"""
    import numpy as np
    import matplotlib.pyplot as plt
    
    data = load_metrics(metrics_path)
    # Sort by max(R,G,B) to show most anomalous first
    data.sort(key=lambda x: max(x['R'], x['G'], x['B']), reverse=True)
    data = data[:top_n]
    
    names = [os.path.basename(d['path'])[:20] for d in data]
    r_vals = [d['R'] for d in data]
    g_vals = [d['G'] for d in data]
    b_vals = [d['B'] for d in data]
    
    x = np.arange(len(names))
    width = 0.25
    
    fig, ax = plt.subplots(figsize=(12, 5))
    ax.bar(x - width, r_vals, width, label='R (Entropy)', color='red', alpha=0.8)
    ax.bar(x, g_vals, width, label='G (Contextual Hazard)', color='green', alpha=0.8)
    ax.bar(x + width, b_vals, width, label='B (Structural Deviation)', color='blue', alpha=0.8)
    
    ax.set_ylabel('Score (0-1)')
    ax.set_xlabel('File')
    ax.set_title('DeepVis v3 Multi-Modal RGB Analysis')
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=45, ha='right', fontsize=8)
    ax.legend()
    ax.axhline(y=0.25, color='gray', linestyle='--', alpha=0.5, linewidth=1)
    ax.set_ylim(0, 1.1)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"Saved: {output_path}")

def plot_4subfig(clean_path, attack_paths, mal_files, titles, output_dir):
    """Generate 4 separate subfigure images for LaTeX"""
    import numpy as np
    import matplotlib.pyplot as plt
    import matplotlib.patches as patches
    
    clean_data = load_metrics(clean_path)
    clean_img = create_fingerprint_image(clean_data)
    colors = ['red', 'lime', 'orange']
    ZOOM_H, ZOOM_W = 40, 80 # Defined high level for shared use (Square stack)
    
    # (a) Clean with zoom boxes
    # (a) Clean with zoom boxes (Square, Full Map)
    fig, ax = plt.subplots(figsize=(3.5, 3.5))
    ax.imshow(clean_img)
    for i, mal_file in enumerate(mal_files):
        row, col = hash_to_coords(mal_file)
        c = colors[i % len(colors)]
        rect = patches.Rectangle((col - ZOOM_SIZE//2, row - ZOOM_SIZE//2),
                                  ZOOM_SIZE, ZOOM_SIZE,
                                  linewidth=2.5, edgecolor=c, facecolor='none')
        ax.add_patch(rect)
    ax.axis('off')
    plt.tight_layout(pad=0)
    plt.savefig(f"{output_dir}/eval_clean.png", dpi=200, bbox_inches='tight', pad_inches=0.02)
    plt.close()
    print(f"Saved: {output_dir}/eval_clean.png")
    
    # (b-d) Wide Stack (Square Result) with Centering & Padding
    def crop_centered(img, r, c, h, w):
        # Pad image if crop goes out of bounds to ensure result is always (h, w)
        # and pixel (r, c) is at center (h//2, w//2)
        pad_r = h // 2
        pad_c = w // 2
        # Pad with zeros (black)
        img_padded = np.pad(img, ((pad_r, pad_r), (pad_c, pad_c), (0, 0)), mode='constant')
        # New coordinates in padded image
        center_r = r + pad_r
        center_c = c + pad_c
        
        r_start = center_r - h // 2
        c_start = center_c - w // 2
        return img_padded[r_start:r_start+h, c_start:c_start+w]

    for i, (attack_path, mal_file, title) in enumerate(zip(attack_paths, mal_files, titles)):
        attack_data = load_metrics(attack_path)
        combined_img = create_fingerprint_image(clean_data + attack_data)
        
        row, col = hash_to_coords(mal_file)
        
        # Robust Crop
        clean_zoom = crop_centered(clean_img, row, col, ZOOM_H, ZOOM_W)
        attack_zoom = crop_centered(combined_img, row, col, ZOOM_H, ZOOM_W)
        
        # Figure size square (3.5 x 3.5) with BLACK background
        fig, axes = plt.subplots(2, 1, figsize=(3.5, 3.5), facecolor='black')
        
        # Top: Original
        axes[0].imshow(clean_zoom, interpolation='nearest', aspect='auto')
        # Label inside image
        axes[0].text(0.5, 0.90, 'Original', transform=axes[0].transAxes, 
                     color='white', ha='center', va='top', fontsize=10, fontweight='bold')
        c = colors[i % len(colors)]
        for spine in axes[0].spines.values():
            spine.set_edgecolor(c)
            spine.set_linewidth(3)
        axes[0].set_xticks([])
        axes[0].set_yticks([])
        
        # Bottom: Attack
        axes[1].imshow(attack_zoom, interpolation='nearest', aspect='auto')
        # Label inside image
        axes[1].text(0.5, 0.90, '+ Attack', transform=axes[1].transAxes, 
                     color='red', ha='center', va='top', fontsize=10, fontweight='bold')
        
        # Circle on attack pixel - ALWAYS CENTERED
        pixel_r = ZOOM_H // 2
        pixel_c = ZOOM_W // 2
        circle = patches.Circle((pixel_c, pixel_r), radius=3, linewidth=2, edgecolor='white', facecolor='none')
        axes[1].add_patch(circle)
        
        for spine in axes[1].spines.values():
            spine.set_edgecolor(c)
            spine.set_linewidth(3)
        axes[1].set_xticks([])
        axes[1].set_yticks([])
        
        # No Arrow needed in seamless dark mode
        
        plt.tight_layout(pad=0.5, h_pad=0.1)
        outname = title.lower().replace(' ', '_').replace('(', '').replace(')', '').replace('.', '')
        if 'packed' in outname: outname = 'packedrootkit'
        
        plt.savefig(f"{output_dir}/eval_{outname}.png", dpi=200, bbox_inches='tight', pad_inches=0.02, facecolor='black')
        plt.close()
        print(f"Saved: {output_dir}/eval_{outname}.png")

def main():
    parser = argparse.ArgumentParser(description='DeepVis v3 Figure Generation')
    parser.add_argument('--fingerprint-compare', nargs=3, metavar=('CLEAN', 'ATTACK', 'OUTPUT'))
    parser.add_argument('--rgb-breakdown', nargs=2, metavar=('METRICS', 'OUTPUT'))
    parser.add_argument('--4subfig', nargs='+', metavar='ARGS', dest='subfig')
    
    args = parser.parse_args()
    
    if args.fingerprint_compare:
        plot_fingerprint_compare(*args.fingerprint_compare)
    elif args.rgb_breakdown:
        plot_rgb_breakdown(*args.rgb_breakdown)
    elif args.subfig:
        # Usage: --4subfig clean.csv attack1.csv:file1:title1 attack2.csv:file2:title2 ... output_dir
        clean_path = args.subfig[0]
        output_dir = args.subfig[-1]
        attack_args = args.subfig[1:-1]
        
        attack_paths, mal_files, titles = [], [], []
        for arg in attack_args:
            parts = arg.split(':')
            attack_paths.append(parts[0])
            mal_files.append(parts[1])
            titles.append(parts[2] if len(parts) > 2 else os.path.basename(parts[0]))
        
        plot_4subfig(clean_path, attack_paths, mal_files, titles, output_dir)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
