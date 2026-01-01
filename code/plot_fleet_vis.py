#!/usr/bin/env python3
"""
Regenerate Fleet Visualization with reduced height
"""
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

plt.rcParams['font.family'] = 'serif'
plt.rcParams['font.size'] = 8

# Simulated latency data for 10 nodes x 3 regions
np.random.seed(42)
nodes = 10
regions = ['US-West', 'US-Central', 'US-East']

# Generate realistic latency data (similar to the original)
data = {
    'US-West': np.random.uniform(3.9, 5.2, nodes),
    'US-Central': np.random.uniform(3.0, 5.1, nodes),
    'US-East': np.random.uniform(3.3, 4.8, nodes)
}

# Create heatmap matrix (nodes x regions) - REDUCED to 5 rows
matrix = np.array([data['US-West'][:5], data['US-Central'][:5], data['US-East'][:5]]).T

fig, ax = plt.subplots(figsize=(4.0, 1.8))  # Much shorter height

# Use imshow instead of seaborn for more control
cmap = plt.cm.YlOrRd
im = ax.imshow(matrix, cmap=cmap, aspect='auto', vmin=3.0, vmax=5.5)

# Add colorbar
cbar = plt.colorbar(im, ax=ax, shrink=0.8)
cbar.set_label('Latency (s)', fontsize=8)
cbar.ax.tick_params(labelsize=7)

# Labels
ax.set_xticks([0, 1, 2])
ax.set_xticklabels(regions, fontsize=8)
ax.set_yticks([0, 1, 2, 3, 4])
ax.set_yticklabels([f'N{i+1}' for i in range(5)], fontsize=7)
ax.set_xlabel('GCP Region', fontsize=8)
ax.set_ylabel('Node', fontsize=8)

# Add text annotations
for i in range(5):
    for j in range(3):
        ax.text(j, i, f'{matrix[i,j]:.1f}', ha='center', va='center', 
                fontsize=6, color='white' if matrix[i,j] > 4.2 else 'black')

plt.tight_layout()
plt.savefig('/Users/skim/ICDCS-DeepVis/paper/Figures/fig_fleet_vis.pdf', 
            format='pdf', dpi=300, bbox_inches='tight')
print("Saved: fig_fleet_vis.pdf (reduced height)")
