import json
import matplotlib.pyplot as plt
import numpy as np
import matplotlib.gridspec as gridspec

# Load Real Data
with open("/Users/skim/ICDCS-DeepVis/churn_real.json", "r") as f:
    results = json.load(f)

scores_base = results["scores"]["baseline"]
scores_churn = results["scores"]["churn"] # Real Fleet Ops
scores_attack = results["scores"]["attack"]

# ==========================================================
# Figure 1: Error Distribution Stability (Separated)
# ==========================================================
fig1, ax1 = plt.subplots(figsize=(5, 3.5))

# Histogram density
def get_pdf(data, bins=50):
    counts, edges = np.histogram(data, bins=bins, range=(0, 1.05))
    centers = (edges[:-1] + edges[1:]) / 2
    mask = counts > 0
    return centers[mask], counts[mask]

x_base, y_base = get_pdf(scores_base)
x_churn, y_churn = get_pdf(scores_churn)
x_att, y_att = get_pdf(scores_attack)

# Plot: Benign State (Baseline + Fleet Ops)
# Merge visually
ax1.fill_between(x_base, 0, y_base, color='blue', alpha=0.15, label='Benign State\n(Baseline + Fleet Ops)')
ax1.plot(x_base, y_base, 'b-', linewidth=1.5, alpha=0.6)

# Plot: Attack (Outlier Only)
# To avoid "weird" overlapping red dashed line, we ONLY plot the attack outlier.
outlier_x = [x for x in x_att if x > 0.9]
outlier_y = [y for x,y in zip(x_att, y_att) if x > 0.9]

if outlier_x:
    ax1.plot(outlier_x, outlier_y, 'r*', markersize=14, zorder=20, label='Attack Signal\n(Outlier Only)')
    ax1.text(outlier_x[0]-0.25, outlier_y[0]*2.0, "Attack Signal", color='red', fontweight='bold', fontsize=10)

ax1.text(0.4, 200, "Robust Stability\n(Fleet Ops $\\approx$ Baseline)", color='blue', fontsize=9, ha='center', alpha=0.7)

ax1.set_yscale('log')
ax1.set_xlabel('Anomaly Score ($L_\infty$)', fontsize=10, fontweight='bold')
ax1.set_ylabel('File Count (Log Scale)', fontsize=10, fontweight='bold')
ax1.set_title('Real Fleet Error Stability', fontsize=11, fontweight='bold')
ax1.grid(True, which="both", ls="--", alpha=0.3)
ax1.legend(loc='upper right', frameon=True, fontsize=8) 
ax1.set_xlim(0, 1.1)

plt.tight_layout()
plt.savefig("/Users/skim/ICDCS-DeepVis/paper/Figures/fig_churn_hist.pdf", bbox_inches='tight')
print("Saved fig_churn_hist.pdf")


# ==========================================================
# Figure 2: Alert Fatigue & Detection (Stacked Bar) (Separated)
# ==========================================================
fig2, ax2 = plt.subplots(figsize=(5, 3.5))

tools = ["AIDE", "YARA", "ClamAV", "Set-AE", "DeepVis"]
x_pos = np.arange(len(tools))

# Data Breakdown
aide_bastion = 174
aide_fleet = 6
yara_bastion = 54
yara_fleet = 0
clam_bastion, clam_fleet = 0, 0
setae_bastion, setae_fleet = 0, 0
dv_bastion, dv_fleet = 0, 0

bastion_counts = [aide_bastion, yara_bastion, clam_bastion, setae_bastion, dv_bastion]
fleet_counts = [aide_fleet, yara_fleet, clam_fleet, setae_fleet, dv_fleet]

# Plot Stacks
ax2.bar(x_pos, bastion_counts, color='#e74c3c', alpha=0.7, label='System Upgrade\n(Bastion)', width=0.6, edgecolor='black')
ax2.bar(x_pos, fleet_counts, bottom=bastion_counts, color='#f39c12', alpha=0.7, label='Fleet Ops\n(Web/DB/... Total 5)', width=0.6, edgecolor='black')

# Detection Status
detection_status = ["Detected", "Missed", "Missed", "Missed", "Detected"]
detection_colors = ["green", "red", "red", "red", "green"]

for i, (status, count) in enumerate(zip(detection_status, [sum(x) for x in zip(bastion_counts, fleet_counts)])):
    y_text = max(count, 0.8) if count > 0 else 0.8
    marker = "✓" if status == "Detected" else "✗"
    
    ax2.text(i, y_text * 1.5, f"{status}", ha='center', va='bottom', 
             fontsize=9, fontweight='bold', color=detection_colors[i])
    
    if count > 0:
        ax2.text(i, count/2, str(count), ha='center', va='center', color='white', fontweight='bold', fontsize=9)

ax2.set_xticks(x_pos)
ax2.set_xticklabels(tools, fontsize=9, fontweight='bold', rotation=0)
ax2.set_ylabel('False Positive Alerts (Log Scale)', fontsize=10, fontweight='bold')
ax2.set_yscale('symlog', linthresh=0.1)
ax2.set_ylim(0, 600)

ax2.set_title('Alert Fatigue vs. Detection', fontsize=11, fontweight='bold')
ax2.grid(True, axis='y', ls="--", alpha=0.3)
ax2.legend(loc='upper right', frameon=True, fontsize=8)

# Highlight DeepVis
ax2.axvspan(3.6, 4.4, color='green', alpha=0.1, zorder=0)

plt.tight_layout()
plt.savefig("/Users/skim/ICDCS-DeepVis/paper/Figures/fig_churn_alerts.pdf", bbox_inches='tight')
print("Saved fig_churn_alerts.pdf")
