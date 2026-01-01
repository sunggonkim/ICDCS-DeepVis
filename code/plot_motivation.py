#!/usr/bin/env python3
"""
Motivating Figures for DeepVis Introduction
Updated with Cold Cache Empirical Data (AIDE-Full, AIDE-Header, DeepVis)
"""

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.lines import Line2D

# Bold, academic style matching reference image
plt.rcParams['font.family'] = 'Times New Roman'
plt.rcParams['font.size'] = 12
plt.rcParams['axes.labelsize'] = 13
plt.rcParams['axes.titlesize'] = 13
plt.rcParams['axes.labelweight'] = 'bold'
plt.rcParams['xtick.labelsize'] = 11
plt.rcParams['ytick.labelsize'] = 11

# ===== Legend (no box, bold labels, no parentheses) =====
fig_legend = plt.figure(figsize=(7, 0.35))
legend_elements = [
    Line2D([0], [0], marker='s', color='tab:red', linewidth=2, markersize=7, label='AIDE-Full'),
    Line2D([0], [0], marker='^', color='tab:orange', linewidth=2, markersize=7, label='AIDE-Header'),
    Line2D([0], [0], marker='o', color='tab:green', linewidth=2, markersize=7, label='DeepVis'),
]
fig_legend.legend(handles=legend_elements, loc='center', ncol=3, frameon=False, 
                  fontsize=11, prop={'weight': 'bold'})
plt.savefig('/Users/skim/ICDCS-DeepVis/paper/Figures/fig_motivation_legend.pdf', dpi=300, bbox_inches='tight')
plt.close()

# ===== Subplot (a): Scalability - REAL DATA (Cold Cache) =====
# AIDE-Full (Full Hash, Cold Cache): 130 files/s
# AIDE-Header (4KB, Cold Cache): 938 files/s
# DeepVis (io_uring, Cold Cache): 15,789 files/s
fig_a, ax1 = plt.subplots(figsize=(3.3, 2.4))

# X-axis: 10K to 120K files
file_counts = np.array([10, 30, 60, 90, 120])  # in thousands
aide_full_tput = 130
aide_header_tput = 938
deepvis_tput = 15789

aide_full_time = file_counts * 1000 / aide_full_tput     # seconds
aide_header_time = file_counts * 1000 / aide_header_tput # seconds
deepvis_time = file_counts * 1000 / deepvis_tput         # seconds

ax1.plot(file_counts, aide_full_time, 's-', color='tab:red', linewidth=2, markersize=6)
ax1.plot(file_counts, aide_header_time, '^-', color='tab:orange', linewidth=2, markersize=6)
ax1.plot(file_counts, deepvis_time, 'o-', color='tab:green', linewidth=2, markersize=6)
ax1.fill_between(file_counts, aide_full_time, deepvis_time, alpha=0.08, color='gray')

ax1.set_xlabel('File Count (×1000)', fontweight='bold')
ax1.set_ylabel('Scan Time (s)', fontweight='bold')
ax1.set_xlim(10, 130)  # slightly more space
ax1.set_ylim(0, 1000)  # AIDE-Full 120K = 923s
ax1.grid(True, alpha=0.3, linestyle='--')

# Annotations at 90k files
idx = 3  # 90k
# AIDE-Full: 90000/130 = 692s
# AIDE-Header: 90000/938 = 96s
# DeepVis: 90000/15789 = 5.7s

# Annotation for AIDE-Full vs DeepVis (121x)
mid_point_full = (aide_full_time[idx] + deepvis_time[idx]) / 2
ax1.annotate('', xy=(90, deepvis_time[idx]), xytext=(90, aide_full_time[idx]),
            arrowprops=dict(arrowstyle='<->', color='black', lw=1.2))
ax1.text(95, mid_point_full, '121×', fontsize=11, ha='left', va='center', fontweight='bold', color='tab:red')

# Annotation for AIDE-Header vs DeepVis (16x) - moved higher and left
mid_point_header = (aide_header_time[idx] + deepvis_time[idx]) / 2
ax1.annotate('', xy=(60, deepvis_time[idx-1]), xytext=(60, aide_header_time[idx-1]),
            arrowprops=dict(arrowstyle='<->', color='black', lw=1.0))
ax1.text(50, 120, '16×', fontsize=12, ha='left', va='center', fontweight='bold', color='tab:orange')

plt.tight_layout()
plt.savefig('/Users/skim/ICDCS-DeepVis/paper/Figures/fig_motivation_a.pdf', dpi=300, bbox_inches='tight')
plt.close()

# ===== Subplot (b): Alert Fatigue - REAL DATA =====
# No changes to logic, just regenerating
fig_b, ax2 = plt.subplots(figsize=(3.3, 2.4))

scenarios = ['Normal', 'Pkg Update', 'Container', 'Rootkit']
fim_alerts = [50, 2000, 5000, 1]        
deepvis_alerts = [0.5, 0.5, 0.5, 1]     

x = np.arange(len(scenarios))
width = 0.35

bars1 = ax2.bar(x - width/2, fim_alerts, width, color='tab:red', edgecolor='black', linewidth=0.5)
bars2 = ax2.bar(x + width/2, deepvis_alerts, width, color='tab:green', edgecolor='black', linewidth=0.5)

ax2.set_ylabel('Alerts (Log)', fontweight='bold')
ax2.set_xticks(x)
ax2.set_xticklabels(scenarios, fontsize=9, fontweight='bold', rotation=20, ha='right')
ax2.set_yscale('symlog', linthresh=10)
ax2.set_ylim(0.1, 15000)
ax2.grid(True, alpha=0.3, linestyle='--', axis='y')

plt.tight_layout()
plt.savefig('/Users/skim/ICDCS-DeepVis/paper/Figures/fig_motivation_b.pdf', dpi=300, bbox_inches='tight')
plt.close()

print("Generated Figure 1(a) with Cold Cache Data:")
print("  - DeepVis: 15,789 files/s")
print("  - AIDE-Header: 938 files/s (16.8x slower)")
print("  - AIDE-Full: 130 files/s (121.5x slower)")
print("  - 120K scan time: AIDE-Full=923s, AIDE-Header=128s, DeepVis=7.6s")
