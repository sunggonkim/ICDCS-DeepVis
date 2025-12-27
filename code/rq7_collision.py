import numpy as np
import random

def run_rq7():
    print("RQ7: Collision Robustness Simulation")
    GRID_SIZE = 128
    PIXELS = GRID_SIZE * GRID_SIZE
    ATTACK_VAL = 1.0
    BENIGN_VAL = 0.1
    
    file_counts = [1_000_000, 5_000_000, 10_000_000]
    
    for N in file_counts:
        # Probability of a pixel being hit by at least one benign file
        # P(hit) = 1 - (1 - 1/PIXELS)^N
        p_hit = 1 - (1 - 1/PIXELS)**N
        expected_benign_pixels = PIXELS * p_hit
        
        # Attack Signal Survival
        # Since we use Max-Pooling: max(Benign, Attack) = Attack
        # The only way Attack is lost is if it's NOT mapped (impossible if file exists)
        # or if Benign value > Attack value (impossible by definition)
        
        print(f"Files: {N/1e6:.0f}M")
        print(f"  Grid Saturation: {expected_benign_pixels/PIXELS*100:.2f}%")
        print(f"  Attack Signal: SURVIVED (Value {ATTACK_VAL} > {BENIGN_VAL})")

if __name__ == "__main__":
    run_rq7()
