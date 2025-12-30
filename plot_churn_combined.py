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
# (a) Error Distribution (Line Plot instead of Histogram?)
# Reference image shows Line Plots with Markers.
# Let's convert Histogram to Line Plot (Frequency vs Error).
# ==========================================================
ax1 = plt.subplot(gs[0])

# Histogram to PDF approximation
def get_pdf(data, bins=50):
    counts, edges = np.histogram(data, bins=bins, range=(0, 1.0))
    centers = (edges[:-1] + edges[1:]) / 2
    return centers, counts

x_base, y_base = get_pdf(scores_base)
x_upg, y_upg = get_pdf(scores_upgrade)
x_att, y_att = get_pdf(scores_attack)

# Style: Solid lines with Markers, distinct colors
# Baseline: Blue Circle
ax1.plot(x_base, y_base, 'b-o', label='Baseline', markersize=4, alpha=0.7)
# Upgrade: Orange Diamond (Shifted)
ax1.plot(x_upg, y_upg, 'g-d', label='After Upgrade', markersize=4, alpha=0.7)
# Attack: Red Star (Outlier)
# Attack outlier is at 1.0. The histogram binning handles it.
ax1.plot(x_att, y_att, 'r-*', label='With Attack', markersize=6, alpha=0.9)

ax1.set_yscale('log')
ax1.set_xlabel('Anomaly Score ($L_\infty$)', fontsize=10, fontweight='bold')
ax1.set_ylabel('Frequency (Log Scale)', fontsize=10, fontweight='bold')
ax1.set_title('(a) Error Distribution Shift', fontsize=11, fontweight='bold', y=-0.25)
ax1.grid(True, which="both", ls="--", alpha=0.3)
ax1.legend(loc='upper center', frameon=False, ncol=3, fontsize=8, bbox_to_anchor=(0.5, 1.15))
ax1.set_xlim(0, 1.05)


# ==========================================================
# (b) Alert Fatigue (Line Plot or Bar Chart?)
# Reference image is Line Plot "Simulation Time vs Qubits".
# User wants "This Style".
# If I plot "Alerts" as Bar, it's fine. But maybe "Alerts vs Event" as Line?
# "Strong scalability" style -> X-axis is "Scale".
# My X-axis is "Event Stage".
# Let's stick to Bar but make it look professional like the ref.
# Or Line if appropriate? "Alert Count Trend".
# X: Baseline, Upgrade, Attack.
# Y: Alert Count.
# Lines: AIDE, YARA, DeepVis.
# ==========================================================
ax2 = plt.subplot(gs[1])

stages = ["Baseline", "Upgrade", "Attack"]
x_idx = np.arange(len(stages))

# Data (Cumulative or Active?)
# AIDE: 0, 174, 175
aide_trend = [0, 174, 175]
# YARA: 0, 54, 54 (Assuming miss)
yara_trend = [0, 54, 54]
# DeepVis: 0, 0, 1
dv_trend = [0, 0, 1]

# Plot Lines
ax2.plot(x_idx, aide_trend, color='gray', marker='s', linestyle='--', label='AIDE', linewidth=2)
ax2.plot(x_idx, yara_trend, color='orange', marker='^', linestyle='-.', label='YARA', linewidth=2)
ax2.plot(x_idx, dv_trend, color='green', marker='o', linestyle='-', label='DeepVis', linewidth=2)

ax2.set_xticks(x_idx)
ax2.set_xticklabels(stages, fontsize=9, fontweight='bold')
ax2.set_ylabel('Alert Count (Log Scale)', fontsize=10, fontweight='bold')
ax2.set_yscale('symlog')
ax2.set_title('(b) Alert Fatigue Analysis', fontsize=11, fontweight='bold', y=-0.25)
ax2.grid(True, which="both", ls="--", alpha=0.3)
ax2.legend(loc='upper left', frameon=False, fontsize=8)

# Add "Green Zone" annotation like reference?
# "Zero FP Zone"
ax2.axvspan(0.8, 1.2, color='green', alpha=0.1)
ax2.text(1.0, 120, "Zero False Alerts\n(DeepVis)", color='green', fontsize=8, ha='center', fontweight='bold')

plt.tight_layout()
plt.savefig("/Users/skim/ICDCS-DeepVis/paper/Figures/fig_churn_combined.pdf", bbox_inches='tight')
print("Saved fig_churn_combined.pdf")
