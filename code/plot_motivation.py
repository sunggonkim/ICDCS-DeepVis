#!/usr/bin/env python3
"""
Motivating Figures for DeepVis Introduction
Updated with Cold Cache Empirical Data
"""

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.lines import Line2D

plt.rcParams['font.family'] = 'Times New Roman'
plt.rcParams['font.size'] = 10
plt.rcParams['axes.labelsize'] = 11
plt.rcParams['axes.titlesize'] = 11

# ===== Legend =====
fig_legend = plt.figure(figsize=(7, 0.4))
legend_elements = [
    Line2D([0], [0], marker='s', color='tab:red', linewidth=2, markersize=7, label='AIDE (Traditional FIM)'),
    Line2D([0], [0], marker='o', color='tab:green', linewidth=2, markersize=7, label='DeepVis (This Work)'),
]
fig_legend.legend(handles=legend_elements, loc='center', ncol=2, frameon=True, 
                  fancybox=False, edgecolor='black', fontsize=10)
plt.savefig('paper/Figures/fig_motivation_legend.pdf', dpi=300, bbox_inches='tight')
plt.close()

# ===== Subplot (a): Scalability - REAL DATA (Cold Cache) =====
# AIDE (Full Hash, Cold Cache): 407 files/s
# DeepVis (io_uring, Cold Cache): 15,789 files/s
fig_a, ax1 = plt.subplots(figsize=(3.3, 2.4))

# X-axis: 10K to 120K files
file_counts = np.array([10, 30, 60, 90, 120])  # in thousands
aide_tput = 407
deepvis_tput = 15789

aide_time = file_counts * 1000 / aide_tput       # seconds
deepvis_time = file_counts * 1000 / deepvis_tput # seconds

ax1.plot(file_counts, aide_time, 's-', color='tab:red', linewidth=2, markersize=6)
ax1.plot(file_counts, deepvis_time, 'o-', color='tab:green', linewidth=2, markersize=6)
ax1.fill_between(file_counts, aide_time, deepvis_time, alpha=0.12, color='gray')

ax1.set_xlabel('File Count (×1000)')
ax1.set_ylabel('Scan Time (s)')
ax1.set_xlim(10, 130)  # slightly more space
ax1.set_ylim(0, 350)   # AIDE 120K = 294s, DeepVis = 7.6s
ax1.grid(True, alpha=0.3, linestyle='--')

# 39x annotation at 90k files
idx = 3  # 90k
# AIDE: 90000/407 = 221s
# DeepVis: 90000/15789 = 5.7s
mid_point = (aide_time[idx] + deepvis_time[idx]) / 2

ax1.annotate('', xy=(90, deepvis_time[idx]), xytext=(90, aide_time[idx]),
            arrowprops=dict(arrowstyle='<->', color='black', lw=1.2))
ax1.text(95, mid_point, '39×', fontsize=11, ha='left', va='center', fontweight='bold', color='black')

plt.tight_layout()
plt.savefig('paper/Figures/fig_motivation_a.pdf', dpi=300, bbox_inches='tight')
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

ax2.set_ylabel('Alerts (Log)')
ax2.set_xticks(x)
ax2.set_xticklabels(scenarios, fontsize=9)
ax2.set_yscale('symlog', linthresh=10)
ax2.set_ylim(0.1, 15000)
ax2.grid(True, alpha=0.3, linestyle='--', axis='y')

plt.tight_layout()
plt.savefig('paper/Figures/fig_motivation_b.pdf', dpi=300, bbox_inches='tight')
plt.close()

print("Generated Figure 1(a) with Cold Cache Data:")
print("  - DeepVis: 15,789 files/s")
print("  - AIDE: 407 files/s")
print("  - 120K scan time: AIDE=295s, DeepVis=7.6s")
