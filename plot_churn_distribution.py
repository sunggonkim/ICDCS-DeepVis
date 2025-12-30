import json
import matplotlib.pyplot as plt
import numpy as np

# Load Data
with open("/Users/skim/ICDCS-DeepVis/churn_results.json", "r") as f:
    results = json.load(f)

scores_base = results["scores"]["baseline"]
scores_upgrade = results["scores"]["upgrade"]
scores_attack = results["scores"]["attack"]

# Filter out strict 1.0 scores for better visualization of main distribution? 
# Or include them? User wants to see distributions.
# Scores are max(r, g, b). Most benign are low. The FPs are at 1.0.

# 1. Histogram (Error Distribution)
plt.figure(figsize=(10, 4))
plt.hist(scores_base, bins=50, range=(0, 1.0), alpha=0.5, label="Baseline", color="blue", log=True)
plt.hist(scores_upgrade, bins=50, range=(0, 1.0), alpha=0.5, label="After Upgrade", color="green", log=True)
plt.hist(scores_attack, bins=50, range=(0, 1.0), alpha=0.5, label="With Attack", color="red", log=True)

plt.xlabel("Anomaly Score (Reconstruction Error)")
plt.ylabel("Frequency (Log Scale)")
plt.title("Error Distribution Shift under System Churn")
plt.legend()
plt.tight_layout()
plt.savefig("/Users/skim/ICDCS-DeepVis/paper/Figures/fig_churn_hist.pdf")
print("Saved fig_churn_hist.pdf")

# 2. Alert Count (Bar Chart)
labels = ["Baseline", "Upgrade", "Attack"]
aide = [
    results["metrics"][0]["aide_alerts"],
    results["metrics"][1]["aide_alerts"],
    results["metrics"][2]["aide_alerts"]
]
deepvis = [
    results["metrics"][0]["dv_alerts"], 
    results["metrics"][1]["dv_alerts"], 
    results["metrics"][2]["dv_alerts"]
]

# Adjust Baseline DV counts to represent "New Alerts" or just total?
# User story: "AIDE sends 2450 alerts... DeepVis sends 0".
# My DV has 7 baseline alerts. So Upgrade has 0 *new* alerts.
# I should plot "Cumulative New Alerts" or "Active Alerts"?
# AIDE is usually "Total Modified Files". So 0 -> 500 -> 501.
# DV is "Total Abnormal Files". So 7 -> 7 -> 8.
# Operator sees: 
# Upgrade: AIDE says "500 files changed!". DV says "7 files suspicious (same as before)".
# Attack: AIDE says "501 files changed!". DV says "8 files suspicious (1 new)".
# I'll plot Total Count.

x = np.arange(len(labels))
width = 0.35

plt.figure(figsize=(6, 4))
rects1 = plt.bar(x - width/2, aide, width, label='AIDE (File Changes)', color='gray')
rects2 = plt.bar(x + width/2, deepvis, width, label='DeepVis (Anomalies)', color='green')

plt.ylabel('Alert Count')
plt.title('Alert Fatigue: AIDE vs DeepVis')
plt.xticks(x, labels)
plt.legend()
plt.yscale("log") # AIDE is 500, DV is 8. Log scale helps compare orders of magnitude?
# Or broken axis. Log is easier.

plt.tight_layout()
plt.savefig("/Users/skim/ICDCS-DeepVis/paper/Figures/fig_churn_alerts.pdf")
print("Saved fig_churn_alerts.pdf")
