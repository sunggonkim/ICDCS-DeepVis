#!/usr/bin/env python3
"""
Generate Key Rotation Stability Figure - Simplified Version
Shows τ stability across 50 key rotations as a simple line plot
"""

import matplotlib.pyplot as plt
import pandas as pd
import numpy as np

# Set style
plt.rcParams['font.family'] = 'serif'
plt.rcParams['font.size'] = 10

# Load data
df = pd.read_csv('/Users/skim/ICDCS-DeepVis/code/data/key_rotation.csv')

fig, ax = plt.subplots(figsize=(4.0, 2.2))

# X-axis: Key rotation iterations
x = df['key_id'].values

# Plot threshold τ - flat line showing perfect stability
ax.plot(x, df['threshold_tau'].values, 'b-', marker='o', markersize=2, 
        linewidth=1.2, label='Threshold τ')

# Add horizontal reference line
ax.axhline(y=0.4984, color='gray', linestyle='--', alpha=0.5, linewidth=0.8)

# Add Recall as separate line (all 1.0)
ax.plot(x, df['recall'].values, 'g-', marker='s', markersize=2, 
        linewidth=1.2, label='Recall', alpha=0.8)

ax.set_xlabel('# of Key Rotations', fontsize=10)
ax.set_ylabel('Value', fontsize=10)
ax.set_xlim(-1, 51)
ax.set_ylim(0.4, 1.05)

# Set x-axis ticks
ax.set_xticks([1, 10, 20, 30, 40, 50])

# Add annotation
ax.annotate('τ = 0.4984', xy=(45, 0.5), fontsize=8, color='blue')
ax.annotate('Recall = 1.0', xy=(45, 0.97), fontsize=8, color='green')

# Legend
ax.legend(loc='center right', fontsize=8, framealpha=0.9)

# Grid
ax.grid(True, alpha=0.3, linestyle='-', linewidth=0.5)

plt.tight_layout()
plt.savefig('/Users/skim/ICDCS-DeepVis/paper/Figures/fig_key_rotation.pdf', 
            format='pdf', dpi=300, bbox_inches='tight')
plt.savefig('/Users/skim/ICDCS-DeepVis/paper/Figures/fig_key_rotation.png', 
            format='png', dpi=150, bbox_inches='tight')
print("Saved: fig_key_rotation.pdf (simplified)")
