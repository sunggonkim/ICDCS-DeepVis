import os
import json
import numpy as np
import math
import shutil

# Constants matching lib.rs
READ_SIZE = 64

def calculate_entropy(data):
    if not data:
        return 0.0
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    
    total = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy

def scan_directory(root):
    scores = []
    file_paths = []
    
    for r, d, f in os.walk(root):
        for file in f:
            path = os.path.join(r, file)
            try:
                with open(path, "rb") as fh:
                    # Read only 64 bytes as per Rust implementation (Phase 2 optimization)
                    header = fh.read(READ_SIZE)
                    ent = calculate_entropy(header)
                    scores.append(ent)
                    file_paths.append(path)
            except Exception as e:
                pass
                
    return scores, file_paths

def generate_data():
    DATA_DIR = "temp_bench_real"
    if os.path.exists(DATA_DIR):
        shutil.rmtree(DATA_DIR)
    os.makedirs(DATA_DIR)

    print("1. Generating 500 Benign Files (Low Entropy)...")
    # Benign: Repeated English text (low entropy)
    benign_content = b"This is a standard system configuration file. " * 10
    for i in range(500):
        with open(os.path.join(DATA_DIR, f"config_{i}.conf"), "wb") as f:
            f.write(benign_content)

    print("2. Generating 1 Malware File (High Entropy)...")
    # Malware: Random bytes (high entropy ~8.0)
    with open(os.path.join(DATA_DIR, "malware.bin"), "wb") as f:
        f.write(os.urandom(READ_SIZE * 2))

    print("3. Scanning...")
    scores, paths = scan_directory(DATA_DIR)
    
    scores = np.array(scores)
    
    # Identify Anomaly
    # DeepVis Logic: Max Pooling (Here we show the raw file scores)
    # The plot shows a "spike", which corresponds to the malware file's score using DeepVis scoring (Entropy).
    malware_idx = np.argmax(scores)
    max_score = scores[malware_idx]
    
    # Set-AE Logic: Global Average
    avg_score = np.mean(scores)
    
    print(f"Total Files: {len(scores)}")
    print(f"Max Entropy (DeepVis Anomaly): {max_score:.4f}")
    print(f"Avg Entropy (Set-AE Dilution): {avg_score:.4f}")
    
    # Prepare data for plotting
    # We want a trace around the malware index
    # Let's center the malware at index 250 for the plot consistency
    # Shift array to put argmax at 250
    display_len = 500
    if len(scores) < display_len:
        # Pad if necessary
        scores = np.pad(scores, (0, display_len - len(scores)), mode='constant')
    
    # Roll the array to center the spike
    shift = 250 - malware_idx
    scores_rolled = np.roll(scores, shift)
    
    # Save Data
    output = {
        "deepvis_trace": scores_rolled.tolist(),
        "set_ae_value": float(avg_score),
        "malware_value": float(max_score)
    }
    
    with open("data/real_dilution_data.json", "w") as f:
        json.dump(output, f)
    print("Saved data/real_dilution_data.json")
    
    # Cleanup
    shutil.rmtree(DATA_DIR)

if __name__ == "__main__":
    generate_data()
