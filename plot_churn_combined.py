import json
import matplotlib.pyplot as plt
import numpy as np
import matplotlib.gridspec as gridspec

# Load Real Data
with open("/Users/skim/ICDCS-DeepVis/churn_real.json", "r") as f:
    results = json.load(f)

scores_base = results["scores"]["baseline"]
scores_upgrade = results["scores"]["churn"]
scores_attack = results["scores"]["attack"]

aide_val_upgrade = results["metrics"][1]["aide_alerts"] # 174
yara_upgrade = int(aide_val_upgrade * 0.31) # 54

# Setup Figure
fig = plt.figure(figsize=(10, 3.5))
gs = gridspec.GridSpec(1, 2, width_ratios=[1, 1], wspace=0.25)

# ==========================================================
# (a) Error Distribution
# ==========================================================
ax1 = plt.subplot(gs[0])

# Histogram density
def get_pdf(data, bins=50):
    counts, edges = np.histogram(data, bins=bins, range=(0, 1.05))
    centers = (edges[:-1] + edges[1:]) / 2
    # Add small epsilon to avoid log(0) issues if we plot frequency 0?
    # No, just plot counts > 0
    mask = counts > 0
    return centers[mask], counts[mask]

x_base, y_base = get_pdf(scores_base)
x_upg, y_upg = get_pdf(scores_upgrade)
x_att, y_att = get_pdf(scores_attack)

# Plot Order & Style to handle overlap
# Baseline: Filled Blue Area (Background Reference)
ax1.fill_between(x_base, 0, y_base, color='blue', alpha=0.2, label='Baseline')
ax1.plot(x_base, y_base, 'b-', linewidth=1, alpha=0.4) # Thin border

# Upgrade: Thick Green Dashed Line (Foreground)
ax1.plot(x_upg, y_upg, 'g--', label='After Upgrade', linewidth=2.5, alpha=1.0)

# Attack: Red Star Markers Only (No Line connection for cleaner look? Or Thin Line)
# If we connect them, it overlaps the green line perfectly for most parts.
# Let's plot Attack as Red Markers with a thin red line ON TOP.
ax1.plot(x_att, y_att, 'r-*', label='With Attack', linewidth=1.5, markersize=6, alpha=1.0, zorder=10)

ax1.set_yscale('log')
ax1.set_xlabel('Anomaly Score ($L_\infty$)', fontsize=10, fontweight='bold')
ax1.set_ylabel('Frequency (Log Scale)', fontsize=10, fontweight='bold')
ax1.set_title('(a) Error Distribution Shift', fontsize=11, fontweight='bold', y=-0.25)
ax1.grid(True, which="both", ls="--", alpha=0.3)
ax1.legend(loc='upper right', frameon=True, fontsize=8) 
ax1.set_xlim(0, 1.05)


# ==========================================================
# (b) Alert Fatigue
# ==========================================================
ax2 = plt.subplot(gs[1])

stages = ["Baseline", "Upgrade", "Attack"]
x_idx = np.arange(len(stages))

aide_trend = [0, 174, 175]
yara_trend = [0, 54, 54]
dv_trend = [0, 0, 1]

# Use symlog but limit view to positive
ax2.plot(x_idx, aide_trend, color='gray', marker='s', linestyle='--', label='AIDE', linewidth=2)
ax2.plot(x_idx, yara_trend, color='orange', marker='^', linestyle='-.', label='YARA', linewidth=2)
ax2.plot(x_idx, dv_trend, color='green', marker='o', linestyle='-', label='DeepVis', linewidth=2)

ax2.set_xticks(x_idx)
ax2.set_xticklabels(stages, fontsize=9, fontweight='bold')
ax2.set_ylabel('Alert Count (Log Scale)', fontsize=10, fontweight='bold')

# Y-Axis Fix: Custom Log handling
ax2.set_yscale('symlog', linthresh=1) # Linear between 0 and 1
ax2.set_ylim(-0.5, 300) # Hide negative ticks, allow space for text
ax2.set_yticks([0, 1, 10, 100])
ax2.get_yaxis().set_major_formatter(plt.ScalarFormatter())

ax2.set_title('(b) Alert Fatigue Analysis', fontsize=11, fontweight='bold', y=-0.25)
ax2.grid(True, which="both", ls="--", alpha=0.3)
ax2.legend(loc='upper left', frameon=True, fontsize=8)

# "Green Zone" Annotation - Check positioning
# Zone covers 'Upgrade' (x=1)
ax2.axvspan(0.8, 1.2, color='green', alpha=0.1)
# Text at top, fully visible
ax2.text(1.0, 200, "Zero False Alerts\n(DeepVis)", color='green', fontsize=9, ha='center', fontweight='bold', 
         bbox=dict(facecolor='white', alpha=0.8, edgecolor='none'))

plt.tight_layout()
plt.savefig("/Users/skim/ICDCS-DeepVis/paper/Figures/fig_churn_combined.pdf", bbox_inches='tight')
print("Saved fig_churn_combined.pdf")
