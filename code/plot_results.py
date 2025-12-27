import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import os

OUTPUT_DIR = "/home/bigdatalab/skim/file system fingerprinting/paper/figures"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def plot_scalability():
    print("Plotting Scalability (RQ2)...")
    tiers = ['Low (e2-micro)', 'Mid (e2-standard-2)', 'High (c2-standard-4)']
    deepvis_times = [462.39, 50.58, 21.84]
    aide_times = [2111.00, 386.00, 168.00]
    
    x = np.arange(len(tiers))
    width = 0.35
    
    fig, ax = plt.subplots(figsize=(10, 6))
    rects1 = ax.bar(x - width/2, deepvis_times, width, label='DeepVis', color='#4285F4')
    rects2 = ax.bar(x + width/2, aide_times, width, label='AIDE', color='#EA4335')
    
    ax.set_ylabel('Execution Time (seconds)')
    ax.set_title('Scalability Comparison: DeepVis vs AIDE')
    ax.set_xticks(x)
    ax.set_xticklabels(tiers)
    ax.legend()
    
    # Add speedup labels
    for i in range(len(tiers)):
        speedup = aide_times[i] / deepvis_times[i]
        ax.text(x[i], max(deepvis_times[i], aide_times[i]) + 50, f'{speedup:.1f}x', ha='center', fontweight='bold')
        
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'scalability_rq2.png'))
    plt.close()

def plot_tradeoff():
    print("Plotting Trade-off Analysis...")
    # Data from experiment (65.13% constant)
    dims = [64, 128, 256]
    collisions = [65.13, 65.13, 65.13]
    
    plt.figure(figsize=(8, 5))
    plt.plot(dims, collisions, marker='o', linestyle='-', color='#34A853', linewidth=2)
    plt.ylim(0, 100)
    plt.xlabel('Hash Dimension (bits)')
    plt.ylabel('Collision Rate (%)')
    plt.title('Hash Dimension vs Collision Rate')
    plt.grid(True, linestyle='--', alpha=0.7)
    
    # Annotation
    plt.text(128, 70, 'Constant Rate due to\nDuplicate Files', ha='center', fontsize=10, bbox=dict(facecolor='white', alpha=0.8))
    
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'tradeoff_analysis.png'))
    plt.close()

def plot_rq7_collision():
    print("Plotting Collision Robustness (RQ7)...")
    files = ['1M', '5M', '10M']
    signal_survival = [100, 100, 100] # 100% survival
    
    plt.figure(figsize=(8, 5))
    bars = plt.bar(files, signal_survival, color='#FBBC05', width=0.5)
    plt.ylim(0, 110)
    plt.ylabel('Attack Signal Survival (%)')
    plt.xlabel('File System Size')
    plt.title('Collision Robustness (RQ7): Signal Survival vs File Count')
    
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height,
                f'{height}%', ha='center', va='bottom', fontweight='bold')
                
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'rq7_collision.png'))
    plt.close()

def plot_rq8_latency():
    print("Plotting Inference Latency (RQ8)...")
    files = np.array([10000, 100000, 1000000])
    # Linear I/O: ~15k files/sec
    snapshot_time = files / 15000.0
    # Constant Inference: 5ms
    inference_time = np.full_like(files, 0.005, dtype=float)
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    ax.stackplot(files, snapshot_time, inference_time, labels=['Snapshot (I/O)', 'Inference (O(1))'],
                 colors=['#4285F4', '#EA4335'], alpha=0.7)
                 
    ax.set_xscale('log')
    ax.set_xlabel('Number of Files (Log Scale)')
    ax.set_ylabel('Time (seconds)')
    ax.set_title('Inference Latency Decomposition (RQ8)')
    ax.legend(loc='upper left')
    
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'rq8_latency.png'))
    plt.close()

if __name__ == "__main__":
    plot_scalability()
    plot_tradeoff()
    plot_rq7_collision()
    plot_rq8_latency()
    print("All graphs generated in", OUTPUT_DIR)
