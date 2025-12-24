
import hashlib
import numpy as np
import math
from typing import List, Tuple
from data_gen import FileEntry, MAX_SIZE, CURRENT_TIME

IMG_SIZE = 128
NUM_PIXELS = IMG_SIZE * IMG_SIZE

def hash_filename_to_coords(filename: str) -> Tuple[int, int]:
    """Maps a filename to specific (x, y) coordinates using MD5 hash.
    
    This ensures that the same file ALWAYS maps to the same pixel, 
    solving the 'shift problem' inherent in sorting-based approaches.
    """
    digest = hashlib.md5(filename.encode('utf-8')).hexdigest()
    # Take first 8 chars (32 bits) is enough entropy for 128x128
    # 0xFFFFFFFF is 4294967295, plenty
    val = int(digest[:8], 16)
    
    # Map to linear index
    idx = val % NUM_PIXELS
    
    # Convert to (row, col)
    row = idx // IMG_SIZE
    col = idx % IMG_SIZE
    
    return row, col

def normalize_size(size: int) -> float:
    """Log-normalizes file size to 0-1 range."""
    # Add 1 to avoid log(0)
    # Using log10 to dampen large files
    log_val = math.log10(size + 1)
    max_log = math.log10(MAX_SIZE + 1)
    return min(log_val / max_log, 1.0)

def normalize_permissions(perms: int) -> float:
    """Maps permissions to 0-1 range.
    
    Focus on risk: 
    777 (world write) -> 1.0
    4755 (suid) -> 0.8
    755 (exec) -> 0.5
    644 (read) -> 0.2
    """
    # Simply normalizing the integer value usually works surprisingly well for visualization
    # But let's try a risk-based scoring.
    # Actually, the prompt says "Permissions (Mapped to 0-255)"
    # A simple way that preserves "weirdness" is just normalizing the octal value itself
    
    # SUID bit is 4000 octal = 2048 decimal
    # 0o777 = 511 decimal
    # 0o4777 = 2559 decimal
    
    # Max relevant perm value is probably around 0o7777 (4095)
    
    val = perms & 0o7777
    return min(val / 0o7777, 1.0)

def normalize_entropy(entropy: float) -> float:
    """Normalizes Shannon Entropy (0-8)."""
    # Max entropy for byte is 8.0
    return min(entropy / 8.0, 1.0)

def files_to_image(files: List[FileEntry]) -> np.ndarray:
    """Converts a list of FileEntries to a (3, 128, 128) numpy array."""
    # Initialize with zeros (Back of image is black)
    # Channel order: R, G, B
    img = np.zeros((3, IMG_SIZE, IMG_SIZE), dtype=np.float32)
    
    for f in files:
        r, c = hash_filename_to_coords(f.filename)
        
        # Calculate channels
        # R: Entropy (Malware/Packed indicator)
        red = normalize_entropy(f.entropy)
        
        # G: Size (Physical characteristic)
        green = normalize_size(f.size)
        
        # B: Permissions/Risk (Security characteristic)
        blue = normalize_permissions(f.permissions)
        
        # Collision Handling: MAX pooling
        img[0, r, c] = max(img[0, r, c], red)
        img[1, r, c] = max(img[1, r, c], green)
        img[2, r, c] = max(img[2, r, c], blue)
            
    return img

"""
DISCUSSION: Why Hash-based Mapping vs Sorting?

1. The Shift Problem:
   In a sorted list (e.g., alphabetical), inserting a single file "A_New_File" at the beginning 
   shifts every subsequent file by one position. In a 2D image representation, this causes a 
   massive "earthquake" where nearly every pixel changes color or position. 
   An autoencoder trained on the stable version will see the shifted version as MASSIVELY different 
   (high error everywhere), leading to a high False Positive rate for benign file additions.

2. Spatial Stability:
   Hash-based mapping ensures that 'file_X' ALWAYS maps to pixel (12, 34), regardless of 
   whether 'file_Y' exists or not. This Property is crucial. It means:
   - File additions only affect 1 pixel (or very few in collisions).
   - File deletions only affect 1 pixel.
   - File modifications only change the color of 1 pixel.
   
   This Locality property allows the CAE to learn the "normal state" of specific pixels 
   and ignore empty space, making it robust to normal system evolution (churn) while highlighting 
   specific, pinpoint anomalies.
"""
