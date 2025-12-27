#!/usr/bin/env python3
"""
Experiment 1: Sensitivity Heatmap
================================================================================
Proves the "MSE Paradox" - small attacks don't get lost in large noise.

X-Axis: Background Noise Level (benign file count)
Y-Axis: Attack Signal Strength (deviation magnitude)
Color: L-infinity Detection Score

Output: sensitivity_heatmap.csv, fig8_sensitivity_heatmap.png
================================================================================
"""

import os
import sys
import time
import hashlib
import numpy as np
import csv
from datetime import datetime

# Configuration
GRID_SIZE = 128
NOISE_LEVELS = [100, 1000, 10000, 50000]  # Number of benign files
SIGNAL_STRENGTHS = [0.1, 0.3, 0.5, 0.7, 0.9]  # Attack deviation magnitude
BENIGN_SCORE_RANGE = (0.05, 0.15)  # Low scores for benign files
NUM_TRIALS = 5  # Trials per configuration for statistical robustness

def hash_to_coords(filepath):
    """Map file path to grid coordinates using SHA256"""
    h = hashlib.sha256(filepath.encode()).digest()
    row = (h[0] << 8 | h[1]) % GRID_SIZE
    col = (h[2] << 8 | h[3]) % GRID_SIZE
    return row, col

def run_single_trial(num_benign, attack_strength, trial_id):
    """Run a single trial and return L-infinity detection score"""
    
    # Initialize grid with baseline (all zeros)
    baseline_grid = np.zeros((GRID_SIZE, GRID_SIZE), dtype=np.float32)
    current_grid = np.zeros((GRID_SIZE, GRID_SIZE), dtype=np.float32)
    
    # Generate benign files with low entropy scores
    for i in range(num_benign):
        filepath = f"/benign/file_{trial_id}_{i}.txt"
        row, col = hash_to_coords(filepath)
        score = np.random.uniform(*BENIGN_SCORE_RANGE)
        # Max-pooling: take the maximum score at each pixel
        baseline_grid[row, col] = max(baseline_grid[row, col], score)
        current_grid[row, col] = max(current_grid[row, col], score)
    
    # Inject attack file with specified signal strength
    attack_path = f"/tmp/rootkit_trial{trial_id}.ko"
    attack_row, attack_col = hash_to_coords(attack_path)
    
    # Attack file has high score (attack_strength)
    current_grid[attack_row, attack_col] = max(
        current_grid[attack_row, attack_col], 
        attack_strength
    )
    
    # Calculate L-infinity score (max absolute deviation)
    diff_grid = np.abs(current_grid - baseline_grid)
    l_infinity = np.max(diff_grid)
    
    # Calculate MSE for comparison (to show why MSE fails)
    mse = np.mean((current_grid - baseline_grid) ** 2)
    
    # Detection result
    # L-infinity detects if attack pixel has deviation > threshold
    attack_detected = diff_grid[attack_row, attack_col] > 0.2  # Threshold
    
    return {
        'l_infinity': l_infinity,
        'mse': mse,
        'attack_deviation': diff_grid[attack_row, attack_col],
        'detected': attack_detected,
        'grid_saturation': np.sum(current_grid > 0) / (GRID_SIZE * GRID_SIZE)
    }

def run_experiment(dry_run=False):
    """Run full sensitivity heatmap experiment"""
    print("=" * 60)
    print("Experiment 1: Sensitivity Heatmap")
    print("=" * 60)
    print(f"Started: {datetime.now().isoformat()}")
    print(f"Grid Size: {GRID_SIZE}x{GRID_SIZE}")
    print(f"Noise Levels: {NOISE_LEVELS}")
    print(f"Signal Strengths: {SIGNAL_STRENGTHS}")
    print()
    
    if dry_run:
        noise_levels = [100]
        signal_strengths = [0.5]
        num_trials = 1
        print("[DRY RUN MODE]")
    else:
        noise_levels = NOISE_LEVELS
        signal_strengths = SIGNAL_STRENGTHS
        num_trials = NUM_TRIALS
    
    results = []
    total_configs = len(noise_levels) * len(signal_strengths)
    config_num = 0
    
    for noise in noise_levels:
        for signal in signal_strengths:
            config_num += 1
            print(f"[{config_num}/{total_configs}] Noise={noise}, Signal={signal:.1f}...", 
                  end=" ", flush=True)
            
            trial_results = []
            for t in range(num_trials):
                result = run_single_trial(noise, signal, t)
                trial_results.append(result)
            
            # Aggregate across trials
            avg_l_inf = np.mean([r['l_infinity'] for r in trial_results])
            avg_mse = np.mean([r['mse'] for r in trial_results])
            detection_rate = np.mean([r['detected'] for r in trial_results])
            avg_saturation = np.mean([r['grid_saturation'] for r in trial_results])
            
            results.append({
                'noise_level': noise,
                'signal_strength': signal,
                'l_infinity': avg_l_inf,
                'mse': avg_mse,
                'detection_rate': detection_rate,
                'grid_saturation': avg_saturation
            })
            
            print(f"L∞={avg_l_inf:.4f}, Detection={detection_rate*100:.0f}%")
    
    # Save results
    output_csv = "sensitivity_heatmap.csv"
    with open(output_csv, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print(f"\n-> Saved: {output_csv}")
    
    # Generate heatmap visualization
    try:
        create_heatmap_figure(results)
    except Exception as e:
        print(f"[WARN] Could not generate figure: {e}")
    
    print(f"\nCompleted: {datetime.now().isoformat()}")
    return results

def create_heatmap_figure(results):
    """Generate Fig 8: Sensitivity Heatmap"""
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    
    # Reshape data for heatmap
    noise_levels = sorted(set(r['noise_level'] for r in results))
    signal_strengths = sorted(set(r['signal_strength'] for r in results))
    
    heatmap_data = np.zeros((len(signal_strengths), len(noise_levels)))
    
    for r in results:
        i = signal_strengths.index(r['signal_strength'])
        j = noise_levels.index(r['noise_level'])
        heatmap_data[i, j] = r['l_infinity']
    
    fig, ax = plt.subplots(figsize=(8, 6))
    
    im = ax.imshow(heatmap_data, cmap='RdYlGn_r', aspect='auto', 
                   vmin=0, vmax=1, origin='lower')
    
    # Labels
    ax.set_xticks(np.arange(len(noise_levels)))
    ax.set_yticks(np.arange(len(signal_strengths)))
    ax.set_xticklabels([f'{n//1000}k' if n >= 1000 else str(n) for n in noise_levels])
    ax.set_yticklabels([f'{s:.1f}' for s in signal_strengths])
    
    ax.set_xlabel('Background Noise Level (Benign Files)', fontsize=12)
    ax.set_ylabel('Attack Signal Strength', fontsize=12)
    ax.set_title('Detection Confidence (L∞ Score)', fontsize=14, fontweight='bold')
    
    # Add colorbar
    cbar = plt.colorbar(im, ax=ax)
    cbar.set_label('L∞ Score (Detection Confidence)', fontsize=11)
    
    # Annotate cells with values
    for i in range(len(signal_strengths)):
        for j in range(len(noise_levels)):
            val = heatmap_data[i, j]
            color = 'white' if val > 0.5 else 'black'
            ax.text(j, i, f'{val:.2f}', ha='center', va='center', 
                    color=color, fontsize=10, fontweight='bold')
    
    # Add "Region of Stability" annotation
    ax.annotate('Region of\nStability', xy=(len(noise_levels)-0.5, len(signal_strengths)-0.5),
                xytext=(len(noise_levels)+0.8, len(signal_strengths)-1),
                fontsize=10, ha='left',
                arrowprops=dict(arrowstyle='->', color='darkred'),
                color='darkred', fontweight='bold')
    
    plt.tight_layout()
    plt.savefig('fig8_sensitivity_heatmap.png', dpi=200, bbox_inches='tight')
    plt.close()
    print("-> Saved: fig8_sensitivity_heatmap.png")

if __name__ == "__main__":
    dry_run = '--dry-run' in sys.argv
    run_experiment(dry_run=dry_run)
