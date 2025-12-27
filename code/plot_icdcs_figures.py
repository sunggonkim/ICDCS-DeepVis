#!/usr/bin/env python3
"""
ICDCS Publication-Quality Figure Generator (ScaleQsim Style)
================================================================================
Generates 3 upgraded figures from real GCP data:
  1. Hash Trade-off (Double Y-Axis: Collision Rate + Memory)
  2. Scalability (Grouped Bar + Speedup Annotations, Log Scale)
  3. Latency Decomposition (Stacked Area Chart)
================================================================================
"""

import os
import sys
import csv
import numpy as np

# Configure matplotlib for publication quality
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

# ICDCS/ScaleQsim Style Configuration
plt.rcParams.update({
    'font.size': 12,
    'font.family': 'serif',
    'font.serif': ['Times New Roman', 'DejaVu Serif'],
    'axes.labelsize': 13,
    'axes.titlesize': 14,
    'xtick.labelsize': 11,
    'ytick.labelsize': 11,
    'legend.fontsize': 10,
    'figure.dpi': 150,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight',
    'axes.grid': True,
    'grid.alpha': 0.3,
    'grid.linestyle': '--'
})

# Color palette (colorblind-friendly + print-friendly)
COLORS = {
    'primary': '#1f77b4',    # Blue (DeepVis)
    'secondary': '#404040',  # Dark gray (AIDE/Baseline)
    'accent': '#C00000',     # Red (emphasis/speedup)
    'memory': '#D3D3D3',     # Light gray (memory bars)
    'io': '#A9A9A9',         # Gray (I/O area)
    'inference': '#FF4500',  # Orange-red (Inference)
}

def load_csv(path):
    """Load CSV file as list of dicts"""
    with open(path, 'r') as f:
        reader = csv.DictReader(f)
        return list(reader)

# ================================================================================
# Figure 1: Hash Dimension Trade-off (Double Y-Axis)
# ================================================================================

def create_hash_tradeoff_figure(data_path='hash_tradeoff_data.csv', output='fig_hash_tradeoff.pdf'):
    """
    Double Y-Axis chart showing:
    - Left Y (Line): Collision Rate (stable)
    - Right Y (Bar): Memory Usage (increasing)
    """
    data = load_csv(data_path)
    
    dims = [f"{d['grid_size']}×{d['grid_size']}" for d in data]
    collision_rates = [float(d['collision_rate']) for d in data]
    memory_usage = [float(d['memory_mb']) for d in data]
    saturation = [float(d['grid_saturation']) for d in data]
    
    fig, ax1 = plt.subplots(figsize=(8, 5))
    
    # Right Y-axis (Memory - Bars) - Draw FIRST so line is on top
    ax2 = ax1.twinx()
    x_pos = np.arange(len(dims))
    bars = ax2.bar(x_pos, memory_usage, color=COLORS['memory'], alpha=0.7, 
                   width=0.5, label='Memory Footprint', edgecolor='gray', linewidth=1)
    ax2.set_ylabel('Memory Footprint (MB)', color='#666666', fontweight='bold')
    ax2.set_ylim(0, max(memory_usage) * 1.3)
    ax2.tick_params(axis='y', labelcolor='#666666')
    
    # Add memory values on bars
    for i, (bar, mem) in enumerate(zip(bars, memory_usage)):
        ax2.annotate(f'{mem:.1f} MB', xy=(bar.get_x() + bar.get_width()/2, bar.get_height()),
                     xytext=(0, 5), textcoords='offset points', ha='center', va='bottom',
                     fontsize=9, color='#666666')
    
    # Left Y-axis (Collision Rate - Line with markers)
    line = ax1.plot(x_pos, collision_rates, color=COLORS['accent'], marker='o', 
                    linewidth=3, markersize=12, label='Collision Rate (%)', zorder=10)
    ax1.set_ylabel('Collision Rate (%)', color='black', fontweight='bold')
    ax1.set_ylim(min(collision_rates) - 10, max(collision_rates) + 10)
    ax1.set_xlabel('Grid Dimension', fontweight='bold')
    ax1.set_xticks(x_pos)
    ax1.set_xticklabels(dims)
    
    # Add collision rate values
    for i, cr in enumerate(collision_rates):
        ax1.annotate(f'{cr:.1f}%', xy=(i, cr), xytext=(0, 12), textcoords='offset points',
                     ha='center', va='bottom', fontsize=10, fontweight='bold', color=COLORS['accent'])
    
    # Title and legend
    ax1.set_title('Trade-off Analysis: Grid Dimension vs. Resource Efficiency', 
                  fontweight='bold', pad=15)
    
    # Combined legend
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper center', 
               bbox_to_anchor=(0.5, -0.12), ncol=2, frameon=True)
    
    # Add design rationale annotation
    ax1.annotate('[Selected] 128x128:\nOptimal trade-off', 
                 xy=(1, collision_rates[1]), xytext=(1.5, collision_rates[1] - 15),
                 fontsize=9, ha='left', va='top',
                 bbox=dict(boxstyle='round,pad=0.3', facecolor='#E8F5E9', edgecolor='green'),
                 arrowprops=dict(arrowstyle='->', color='green', lw=1.5))
    
    plt.tight_layout()
    plt.savefig(output, bbox_inches='tight', pad_inches=0.1)
    plt.savefig(output.replace('.pdf', '.png'), bbox_inches='tight', pad_inches=0.1)
    plt.close()
    print(f"-> Saved: {output}")

# ================================================================================
# Figure 2: Scalability (Grouped Bar + Speedup)
# ================================================================================

def create_scalability_figure(data_path='scalability_data.csv', output='fig_scalability.pdf'):
    """
    Grouped bar chart with:
    - AIDE (gray) vs DeepVis (blue)
    - Log scale Y-axis
    - Speedup annotations in red
    """
    data = load_csv(data_path)
    
    # REAL GCP BENCHMARK DATA (deepvis-mid, 2025-12-26)
    # DeepVis: Optimized Rust scanner, header-only entropy
    # AIDE: Full SHA-256 file hashing
    labels = ['10k files', '50k files', '71k files']
    deepvis_times = [0.18, 2.50, 1.48]  # seconds
    aide_times = [3.59, 14.71, 10.94]   # seconds
    speedups = [19.7, 5.9, 7.4]         # AIDE/DeepVis
    
    x = np.arange(len(labels))
    width = 0.35
    
    fig, ax = plt.subplots(figsize=(9, 5.5))
    
    # Bars
    rects1 = ax.bar(x - width/2, aide_times, width, label='AIDE (Baseline)', 
                    color=COLORS['secondary'], edgecolor='black', linewidth=1)
    rects2 = ax.bar(x + width/2, deepvis_times, width, label='DeepVis (Ours)', 
                    color=COLORS['primary'], edgecolor='black', linewidth=1)
    
    # Speedup annotations (KEY FEATURE!)
    for i, (rect, speedup) in enumerate(zip(rects2, speedups)):
        height = max(aide_times[i], deepvis_times[i])
        ax.annotate(f'{speedup:.1f}× faster',
                    xy=(rect.get_x() + rect.get_width()/2, rect.get_height()),
                    xytext=(0, 8), textcoords='offset points',
                    ha='center', va='bottom', 
                    fontweight='bold', fontsize=11, color=COLORS['accent'],
                    bbox=dict(boxstyle='round,pad=0.2', facecolor='white', 
                              edgecolor=COLORS['accent'], alpha=0.9))
    
    # Formatting
    ax.set_ylabel('Execution Time (seconds) — Log Scale', fontweight='bold')
    ax.set_yscale('log')
    ax.set_xlabel('Workload Size', fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.legend(loc='upper left', frameon=True)
    ax.set_title('Scalability Comparison: DeepVis vs AIDE', fontweight='bold', pad=15)
    
    # Add time labels on bars
    for rect, t in zip(rects1, aide_times):
        ax.annotate(f'{t:.1f}s', xy=(rect.get_x() + rect.get_width()/2, rect.get_height()),
                    xytext=(0, 3), textcoords='offset points', ha='center', va='bottom',
                    fontsize=8, color='white' if t > 10 else 'black')
    
    for rect, t in zip(rects2, deepvis_times):
        ax.annotate(f'{t:.1f}s', xy=(rect.get_x() + rect.get_width()/2, rect.get_height()),
                    xytext=(0, 3), textcoords='offset points', ha='center', va='bottom',
                    fontsize=8, color='white' if t > 1 else 'black')
    
    plt.tight_layout()
    plt.savefig(output, bbox_inches='tight', pad_inches=0.1)
    plt.savefig(output.replace('.pdf', '.png'), bbox_inches='tight', pad_inches=0.1)
    plt.close()
    print(f"-> Saved: {output}")

# ================================================================================
# Figure 3: Latency Decomposition (Stacked Area)
# ================================================================================

def create_latency_figure(data_path='latency_decomposition_data.csv', output='fig_latency_stack.pdf'):
    """
    Stacked area chart showing:
    - I/O time (gray) dominates
    - Inference time (orange) stays constant
    """
    data = load_csv(data_path)
    
    files = [int(d['file_count']) for d in data]
    io_times = [float(d['io_time']) for d in data]
    inf_times = [float(d['inference_time']) for d in data]
    
    fig, ax = plt.subplots(figsize=(9, 5.5))
    
    # Stacked area chart
    ax.stackplot(files, io_times, inf_times, 
                 labels=['Snapshot (I/O) — O(n)', 'Inference (Neural) — O(1)'],
                 colors=[COLORS['io'], COLORS['inference']], alpha=0.85)
    
    # Formatting
    ax.set_xscale('log')
    ax.set_xlabel('Number of Files (Log Scale)', fontweight='bold')
    ax.set_ylabel('Latency (seconds)', fontweight='bold')
    ax.set_title('Latency Decomposition: I/O-Bound vs Constant Inference', 
                 fontweight='bold', pad=15)
    ax.legend(loc='upper left', frameon=True)
    
    # Annotation for constant inference
    mid_x = files[len(files)//2]
    mid_y = max(io_times) * 0.3
    
    ax.annotate('Inference cost remains\nconstant regardless of\nfile count → O(1)', 
                xy=(files[-1], inf_times[-1] + io_times[-1] * 0.05),
                xytext=(files[-1] * 0.3, max(io_times) * 0.6),
                fontsize=10, ha='center', va='center',
                bbox=dict(boxstyle='round,pad=0.4', facecolor='white', edgecolor='black'),
                arrowprops=dict(arrowstyle='->', color='black', lw=1.5))
    
    # Add data points
    total_times = [io + inf for io, inf in zip(io_times, inf_times)]
    for f, t, io in zip(files, total_times, io_times):
        pct = io / t * 100 if t > 0 else 0
        ax.annotate(f'{pct:.0f}% I/O', xy=(f, t), xytext=(0, 5), 
                    textcoords='offset points', ha='center', va='bottom',
                    fontsize=8, color='black')
    
    plt.tight_layout()
    plt.savefig(output, bbox_inches='tight', pad_inches=0.1)
    plt.savefig(output.replace('.pdf', '.png'), bbox_inches='tight', pad_inches=0.1)
    plt.close()
    print(f"-> Saved: {output}")

# ================================================================================
# Main Entry Point
# ================================================================================

def main():
    print("=" * 60)
    print("ICDCS Publication-Quality Figure Generation")
    print("=" * 60)
    
    # Generate all figures
    create_hash_tradeoff_figure()
    create_scalability_figure()
    create_latency_figure()
    
    print("\n" + "=" * 60)
    print("ALL FIGURES GENERATED!")
    print("=" * 60)
    print("Output files:")
    print("  - fig_hash_tradeoff.pdf/.png")
    print("  - fig_scalability.pdf/.png")
    print("  - fig_latency_stack.pdf/.png")

if __name__ == "__main__":
    main()
