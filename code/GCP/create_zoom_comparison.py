import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as patches
import hashlib
import os

IMG_SIZE = 256
ZOOM_SIZE = 32  # Size of zoom region

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
            fpath, size, entropy, mode, api_density = parts
            data.append({
                'path': fpath,
                'size': float(size),
                'entropy': float(entropy),
                'mode': int(mode),
                'api': float(api_density)
            })
    return data

def create_fingerprint_image(data):
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

def create_zoom_comparison(clean_path, attack_path, malicious_filename, title, output_path):
    """Create a figure with: Full clean fingerprint with zoom box, zoomed clean, zoomed attack"""
    
    clean_data = load_metrics(clean_path)
    attack_data = load_metrics(attack_path)
    
    clean_img = create_fingerprint_image(clean_data)
    attack_img = create_fingerprint_image(attack_data)
    
    # Find malicious file coordinates
    mal_row, mal_col = hash_filename_to_coords(malicious_filename)
    
    # Zoom region (centered on malicious file)
    half = ZOOM_SIZE // 2
    r_start = max(0, mal_row - half)
    r_end = min(IMG_SIZE, mal_row + half)
    c_start = max(0, mal_col - half)
    c_end = min(IMG_SIZE, mal_col + half)
    
    clean_zoom = clean_img[r_start:r_end, c_start:c_end]
    attack_zoom = attack_img[r_start:r_end, c_start:c_end]
    
    # Create figure
    fig, axes = plt.subplots(1, 3, figsize=(14, 4.5))
    
    # (a) Full Clean Fingerprint with zoom box
    axes[0].imshow(clean_img)
    rect = patches.Rectangle((c_start, r_start), c_end - c_start, r_end - r_start,
                              linewidth=2, edgecolor='yellow', facecolor='none')
    axes[0].add_patch(rect)
    axes[0].set_title('(a) Clean Fingerprint\n(Zoom region highlighted)', fontsize=10)
    axes[0].axis('off')
    
    # (b) Zoomed Clean
    axes[1].imshow(clean_zoom, interpolation='nearest')
    axes[1].set_title('(b) Clean (Zoomed)', fontsize=10)
    axes[1].axis('off')
    # Add crosshair at center
    axes[1].axhline(y=half, color='cyan', linewidth=0.5, linestyle='--')
    axes[1].axvline(x=half, color='cyan', linewidth=0.5, linestyle='--')
    
    # (c) Zoomed Attack - highlight the new pixel
    axes[2].imshow(attack_zoom, interpolation='nearest')
    # Mark the malicious file pixel
    local_r = mal_row - r_start
    local_c = mal_col - c_start
    circle = patches.Circle((local_c, local_r), radius=2, linewidth=2, 
                             edgecolor='red', facecolor='none')
    axes[2].add_patch(circle)
    axes[2].set_title(f'(c) + {title} (Zoomed)\n🔴 New malicious pixel', fontsize=10)
    axes[2].axis('off')
    axes[2].axhline(y=half, color='cyan', linewidth=0.5, linestyle='--')
    axes[2].axvline(x=half, color='cyan', linewidth=0.5, linestyle='--')
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"Saved: {output_path}")

if __name__ == "__main__":
    base = "/home/bigdatalab/skim/file system fingerprinting/code/GCP"
    out = "/home/bigdatalab/skim/file system fingerprinting/paper/figures"
    
    clean = f"{base}/clean_metrics.csv"
    
    # Diamorphine
    create_zoom_comparison(
        clean, 
        f"{base}/attack_diamorphine_full_metrics.csv",
        "/tmp/kmod_debug.ko",
        "Diamorphine (.ko)",
        f"{out}/zoom_diamorphine.png"
    )
    
    # Azazel
    create_zoom_comparison(
        clean,
        f"{base}/attack_azazel_full_metrics.csv", 
        "/tmp/libsystem_core.so",
        "Azazel (.so)",
        f"{out}/zoom_azazel.png"
    )
    
    # XMRig
    create_zoom_comparison(
        clean,
        f"{base}/attack_miner_full_metrics.csv",
        "/tmp/syslog-daemon", 
        "XMRig (packed)",
        f"{out}/zoom_miner.png"
    )
