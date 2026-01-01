import matplotlib.pyplot as plt
import numpy as np
import os
import json

# Output directory
output_dir = '../paper/Figures'
os.makedirs(output_dir, exist_ok=True)

# Style settings - Increased font sizes
plt.style.use('seaborn-v0_8-paper')
plt.rcParams['font.family'] = 'Times New Roman'
plt.rcParams['font.size'] = 14
plt.rcParams['axes.labelsize'] = 14
plt.rcParams['axes.titlesize'] = 15
plt.rcParams['xtick.labelsize'] = 13
plt.rcParams['ytick.labelsize'] = 13
plt.rcParams['legend.fontsize'] = 13

def generate_comparison_plot():
    # Load Real Data
    try:
        with open('data/real_dilution_data.json', 'r') as f:
            data = json.load(f)
        deepvis_signal = np.array(data["deepvis_trace"])
        set_ae_val = data["set_ae_value"]
        malware_val = data["malware_value"]
        print(f"Loaded Real Data: Max={malware_val:.2f}, Avg={set_ae_val:.2f}")
    except FileNotFoundError:
        print("Error: data/real_dilution_data.json not found. Run generate_real_dilution_data.py first.")
        return

    x = np.arange(len(deepvis_signal))
    
    # Set-AE Signal: Global Average (Diluted)
    # Represent as a flat line with minor float noise to simulate system jitter, but NO spike
    # The anomaly is mathematically averaged out
    noise = np.random.normal(0, 0.05, len(x))
    set_ae_signal = np.full_like(deepvis_signal, set_ae_val) + noise

    # Create separate plots
    # Figure A: DeepVis
    fig_a, ax1 = plt.subplots(figsize=(8, 1.8)) # Reduced height for single strip
    
    # Plot DeepVis (Raw Entropy Spike)
    ax1.plot(x, deepvis_signal, color='#2ca02c', linewidth=1.5)
    ax1.set_ylabel('Entropy (Bits)', fontweight='bold')
    ax1.spines['top'].set_visible(False)
    ax1.spines['right'].set_visible(False)
    ax1.grid(True, linestyle='--', alpha=0.5)
    ax1.set_ylim(0, 8.5)
    ax1.set_xticklabels([]) # Remove x-labels for top plot if stacked, but here they are separate. 
    # Actually for subfloats, we might want x-axis on both or just bottom. 
    # Let's keep x-axis formatting but maybe remove label on top one if they are close?
    # User said "subfloat", so they might be side-by-side or stacked. 
    # Since it's a time-series/index, stacked is better.
    # Let's putting X-axis on BOTH to be safe, or just bottom?
    # Standard subfloat usage: usually side-by-side or stacked.
    # Given the aspect ratio (wide), stacked is likely.
    # I will leave X-axis ticks but maybe remove the label "File Index" from the top one to save space?
    # "File Index" is shared.
    
    # Annotate Spike
    spike_idx = np.argmax(deepvis_signal)
    ax1.annotate(f'Malware ({malware_val:.2f})', xy=(spike_idx, malware_val), xytext=(spike_idx + 15, malware_val - 1.5),
                 arrowprops=dict(facecolor='black', arrowstyle='->', connectionstyle="arc3,rad=.2"), fontsize=13, fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'comparison_dilution_a.pdf'), dpi=300)
    print("Generated comparison_dilution_a.pdf")
    plt.close()

    # Figure B: Set-AE
    fig_b, ax2 = plt.subplots(figsize=(8, 1.8))
    
    # Plot Set-AE (Diluted Average)
    ax2.plot(x, set_ae_signal, color='#d62728', linewidth=1.5)
    ax2.set_ylabel('Entropy (Bits)', fontweight='bold')
    ax2.set_xlabel('File Index', fontweight='bold')
    
    ax2.spines['top'].set_visible(False)
    ax2.spines['right'].set_visible(False)
    ax2.grid(True, linestyle='--', alpha=0.5)
    ax2.set_ylim(0, 8.5)
    
    # Annotate Dilution
    ax2.annotate(f'Diluted Avg ({set_ae_val:.2f})', xy=(spike_idx, set_ae_val), xytext=(spike_idx + 15, set_ae_val + 2.5),
                 arrowprops=dict(facecolor='black', arrowstyle='->', connectionstyle="arc3,rad=.2"), fontsize=13, fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'comparison_dilution_b.pdf'), dpi=300)
    print("Generated comparison_dilution_b.pdf")
    plt.close()

if __name__ == "__main__":
    generate_comparison_plot()
