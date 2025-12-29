import torch
import torch.nn as nn
import onnxruntime
import numpy as np
import sys

# Define thresholds
L_INF_THRESH = 0.50

def run_inference():
    print("[-] Loading DeepVis ONNX Model...")
    try:
        ort_session = onnxruntime.InferenceSession("model_cae.onnx")
    except Exception as e:
        print(f"[!] Failed to load model: {e}")
        return

    scenarios = [
        {
            "name": "Script Trojan (Bash)",
            "desc": "Malicious script in /usr/share. Header is '#!/bin/bash'.",
            "R": 0.55, "G": 0.00, "B": 0.00, 
            "expected": "MISS"
        },
        {
            "name": "Reconstructed Header",
            "desc": "Packed ELF with first 128 bytes reconstructed to match benign glibc.",
            "R": 0.61, "G": 0.00, "B": 0.00,
            "expected": "MISS"
        },
        {
            "name": "Safe-Path Implant",
            "desc": "Benign-looking ET_DYN object moved to /usr/bin.",
            "R": 0.60, "G": 0.00, "B": 0.00,
            "expected": "MISS"
        }
    ]

    print(f"\n{'Scenario':<25} | {'R':<5} {'G':<5} {'B':<5} | {'L_inf':<8} | {'Result':<10}")
    print("-" * 75)

    # Model Expects [1, 3, 128, 128]
    # We will test simply by filling the WHOLE grid with the feature vector
    # This simulates a "Worst Case" where ALL files are this type, but since it's 1x1 conv, 
    # the error per pixel is independent. 
    
    for s in scenarios:
        # Create full grid input [1, 3, 128, 128]
        input_tensor = np.zeros((1, 3, 128, 128), dtype=np.float32)
        input_tensor[0, 0, :, :] = s['R']
        input_tensor[0, 1, :, :] = s['G']
        input_tensor[0, 2, :, :] = s['B']
        
        # Inference
        ort_inputs = {ort_session.get_inputs()[0].name: input_tensor}
        reconstruction = ort_session.run(None, ort_inputs)[0]
        
        # Calculate Error (L_inf per pixel, then Max over grid)
        # diff: [1, 3, 128, 128]
        diff = np.abs(input_tensor - reconstruction)
        
        # Max error across channels for each pixel: [1, 128, 128]
        # Then Max across grid
        l_inf = np.max(diff)
        
        status = "DETECTED" if l_inf > L_INF_THRESH else "MISS"
        print(f"{s['name']:<25} | {s['R']:<5.2f} {s['G']:<5.2f} {s['B']:<5.2f} | {l_inf:<8.4f} | {status:<10}")

        if status != s['expected']:
            print(f"   [!] Warning: Unexpected result for {s['name']}")

if __name__ == "__main__":
    run_inference()
