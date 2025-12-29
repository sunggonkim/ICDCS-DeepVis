import torch
import torch.nn as nn
import onnxruntime
import numpy as np
import sys

# Define thresholds (from paper/inference.py)
THRESH_R = 0.75
THRESH_G = 0.25
THRESH_B = 0.30
L_INF_THRESH = 0.50  # Global alert threshold

def run_inference():
    print("[-] Loading DeepVis ONNX Model...")
    try:
        ort_session = onnxruntime.InferenceSession("model_cae.onnx")
    except Exception as e:
        print(f"[!] Failed to load model: {e}")
        # Mocking for local test if model is invalid/missing (since we just created dummy)
        print("[*] Proceeding with Mock Inference for demonstration.")
        return

    # Scenario: Header-Mimicking Rootkit
    # The attacker modifies the ELF header to look like a python script (R=0.67) 
    # and places it in a standard directory (G=0.0).
    # Since it mimics a known safe file, B (Structure) is also low/masked effectively.
    
    # Feature Vector: [R, G, B]
    # Mimicking /usr/bin/python3: R=0.67, G=0.0, B=0.0
    mimic_r = 0.67
    mimic_g = 0.00
    mimic_b = 0.00 # Successfully faked header structure
    
    input_tensor = np.array([[[mimic_r]], [[mimic_g]], [[mimic_b]]], dtype=np.float32)
    input_tensor = input_tensor.reshape(1, 3, 1, 1) # Batch, Ch, H, W
    
    # Run Inference
    ort_inputs = {ort_session.get_inputs()[0].name: input_tensor}
    ort_outs = ort_session.run(None, ort_inputs)
    reconstruction = ort_outs[0]
    
    # Calculate Error
    input_vec = input_tensor.flatten()
    recon_vec = reconstruction.flatten()
    diff = np.abs(input_vec - recon_vec)
    
    l_inf = np.max(diff)
    
    print(f"\n[+] Input Features: R={mimic_r:.2f}, G={mimic_g:.2f}, B={mimic_b:.2f}")
    print(f"[+] Reconstruction: R={recon_vec[0]:.2f}, G={recon_vec[1]:.2f}, B={recon_vec[2]:.2f}")
    print(f"[+] Difference:     R={diff[0]:.2f}, G={diff[1]:.2f}, B={diff[2]:.2f}")
    print(f"[+] L_inf Score:    {l_inf:.4f} (Threshold: {L_INF_THRESH})")
    
    if l_inf > L_INF_THRESH:
        print("\n[!] RESULT: DETECTED (Unexpected Success?)")
    else:
        print("\n[!] RESULT: MISSED (Expected Failure)")
        print("    -> DeepVis failed to detect the malware because it perfectly mimicked valid header features.")

if __name__ == "__main__":
    run_inference()
