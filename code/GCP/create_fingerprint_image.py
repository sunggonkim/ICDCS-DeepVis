import numpy as np
import matplotlib.pyplot as plt
import os
import math

IMG_SIZE = 256

def hash_filename_to_coords(filename):
    import hashlib
    h = hashlib.sha256(filename.encode()).digest()
    row = (h[0] << 8 | h[1]) % IMG_SIZE
    col = (h[2] << 8 | h[3]) % IMG_SIZE
    return row, col

def normalize_entropy(e):
    # Entropy is already normalized to [0, 1] in collect_metrics.py
    return e

def normalize_size(s):
    if s <= 0: return 0
    return min(1.0, math.log10(s) / 7.0) # Up to 10MB

def normalize_permissions(p):
    # 0o777 -> normalize
    return p / 511.0

def create_image(metrics_path, output_path):
    img = np.zeros((IMG_SIZE, IMG_SIZE, 3), dtype=np.float32)
    
    with open(metrics_path, 'r') as f:
        for line in f:
            parts = line.strip().split('|')
            if len(parts) < 4: continue
            
            fpath, size, entropy, mode, api_density = parts
            size = float(size)
            entropy = float(entropy)
            mode = int(mode)
            api_density = float(api_density)
            
            row, col = hash_filename_to_coords(fpath)
            
            red = normalize_entropy(entropy)
            green = max(normalize_size(size), api_density)
            blue = normalize_permissions(mode)
            
            # Max pooling as per DeepVis logic
            img[row, col, 0] = max(img[row, col, 0], red)
            img[row, col, 1] = max(img[row, col, 1], green)
            img[row, col, 2] = max(img[row, col, 2], blue)
            
    plt.figure(figsize=(8, 8))
    plt.imshow(img)
    plt.title("GCP Clean State Fingerprint")
    plt.axis('off')
    plt.savefig(output_path)
    plt.close()
    print(f"Image saved to {output_path}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) >= 3:
        create_image(sys.argv[1], sys.argv[2])
    else:
        create_image('clean_metrics.csv', 'gcp_clean_fingerprint.png')
