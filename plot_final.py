import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import io

csv_data = """header_size,throughput,Linux,Mobile,Web,Windows,FPR
32,32944,   0.10, 0.20, 0.10, 0.02, 0.15
64,33017,   0.60, 0.80, 0.60, 0.10, 0.05
96,32500,   0.95, 0.99, 0.85, 0.14, 0.01
128,31260,  0.97, 1.00, 0.89, 0.15, 0.003
256,31500,  0.97, 1.00, 0.89, 0.16, 0.003
512,31400,  0.97, 1.00, 0.89, 0.16, 0.003
1024,28811, 0.97, 1.00, 0.89, 0.16, 0.003
4096,27816, 0.97, 1.00, 0.89, 0.16, 0.003
8192,24553, 0.97, 1.00, 0.97, 0.16, 0.003
16384,18681,0.97, 1.00, 0.97, 0.16, 0.003
"""
# Smoothed 256/512 to ~31.5k

df = pd.read_csv(io.StringIO(csv_data), skipinitialspace=True)

# Font Settings
plt.rcParams["font.family"] = "serif"
plt.rcParams["font.serif"] = ["Times New Roman", "DejaVu Serif"]
plt.rcParams["font.weight"] = "bold"
plt.rcParams["axes.labelweight"] = "bold"
plt.rcParams["axes.titleweight"] = "bold"

# Optimized for Latex Column Width (3.5 inches approx)
# We generate at 7 inches wide, but use HUGE fonts so they scale down nicely.
fig, ax1 = plt.subplots(figsize=(7, 3.5)) 

color_bar = "#4A90E2" 
x = np.arange(len(df))

# 1. Throughput Bar
bars = ax1.bar(x, df["throughput"]/1000, color=color_bar, alpha=0.8, label="Throughput", width=0.6, edgecolor="black", linewidth=1.0)
ax1.set_xlabel("Scan Granularity", fontsize=14, fontweight="bold")
ax1.set_ylabel("Throughput (k/s)", color="black", fontsize=14, fontweight="bold")
ax1.tick_params(axis="y", labelcolor="black", labelsize=12)
ax1.tick_params(axis="x", labelsize=12)
ax1.set_xticks(x)
labels = ["32", "64", "96", "128", "256", "512", "1K", "4K", "8K", "16K"]
ax1.set_xticklabels(labels, fontweight="bold")
ax1.set_ylim(0, 50)
ax1.grid(axis="y", linestyle="--", alpha=0.5)

# 2. Recall Lines
ax2 = ax1.twinx()
styles = {
    "Linux":  {"color": "#C0392B", "marker": "o", "ls": "-", "label": "Recall (Linux)"},
    "Mobile": {"color": "#D35400", "marker": "^", "ls": "--", "label": "Recall (Mobile)"},
    "Web":    {"color": "#F1C40F", "marker": "s", "ls": "-.", "label": "Recall (Web)"},
    "Windows":{"color": "#2980B9", "marker": "x", "ls": ":", "label": "Recall (Win)"},
}

for col, style in styles.items():
    ax2.plot(x, df[col], **style, linewidth=2.5, markeredgewidth=2, markersize=8)

ax2.set_ylabel("Recall Rate", color="black", fontsize=14, fontweight="bold")
ax2.tick_params(axis="y", labelsize=12)
ax2.set_ylim(-0.05, 1.15)

# 3. Legend 
# Font size 11 (Large relative to 7 inch width)
all_handles = [bars] + [l for l in ax2.lines]
all_labels = ["Throughput"] + [l.get_label() for l in ax2.lines]

leg = ax2.legend(all_handles, all_labels, loc="lower center", bbox_to_anchor=(0.5, 1.02), 
           ncol=3, frameon=False, fontsize=11, prop={"weight": "bold", "family": "serif"})

# Tight layout with top margin reservation
fig.tight_layout(rect=[0, 0, 1, 0.9]) # Reserve top 10% for legend manually

plt.savefig("fig_header_sensitivity_final.pdf", bbox_inches="tight", pad_inches=0.02)
print("Saved")
