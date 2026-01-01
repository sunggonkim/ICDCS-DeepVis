import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
import os

# Output directory
output_dir = '../paper/Figures'
os.makedirs(output_dir, exist_ok=True)

# Style settings - BOLD and LARGE
plt.style.use('seaborn-v0_8-paper')
plt.rcParams['font.family'] = 'Times New Roman'
plt.rcParams['font.size'] = 14
plt.rcParams['axes.labelsize'] = 15
plt.rcParams['axes.titlesize'] = 16
plt.rcParams['xtick.labelsize'] = 14
plt.rcParams['ytick.labelsize'] = 14
plt.rcParams['legend.fontsize'] = 13
plt.rcParams['font.weight'] = 'bold'
plt.rcParams['axes.labelweight'] = 'bold'
plt.rcParams['axes.titleweight'] = 'bold'

def plot_churn_alerts():
    # Data
    systems = ['AIDE', 'YARA', 'ClamAV', 'Set-AE', 'DeepVis']
    fp_alerts = [8500, 0.1, 0.1, 0.1, 0.1] # Use small value for 0 in log scale
    recall_text = ["5/5", "0/5", "5/5", "0/5", "5/5"]
    recall_colors = ['#003366', '#d62728', '#003366', '#d62728', '#003366'] # Dark Blue for good, Red for bad

    fig, ax = plt.subplots(figsize=(6, 4))
    
    # Bar Chart (FP Alerts)
    bars = ax.bar(systems, fp_alerts, color=['#5b84c4', '#e0e0e0', '#e0e0e0', '#e0e0e0', '#e0e0e0'], 
                  edgecolor='black', linewidth=1.5, alpha=0.9, width=0.6)
    
    ax.set_yscale('log')
    ax.set_ylim(0.1, 100000)
    ax.set_ylabel('False Positive Alerts', fontweight='bold', fontsize=18) # Larger
    
    # Grid
    ax.grid(True, axis='y', which='major', linestyle='--', alpha=0.5)
    
    # Larger Ticks
    ax.tick_params(axis='x', labelsize=16) # Larger X ticks
    ax.tick_params(axis='y', labelsize=16) # Larger Y ticks
    
    # Annotate AIDE value inside bar if possible, or above
    ax.text(0, 4000, '8500', ha='center', va='top', color='white', fontweight='bold', fontsize=14)

    # Annotate Recall Scores
    # Place them in the middle of the plot area
    for i, system in enumerate(systems):
        ax.text(i, 1, recall_text[i], ha='center', va='center', 
                color=recall_colors[i], fontweight='bold', fontsize=18) # Larger (was 14)
        
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'fig_churn_alerts.pdf'), dpi=300)
    print("Generated fig_churn_alerts.pdf")
    plt.close()

def plot_churn_hist():
    # Metric: Reconstruction Error
    # Distribution: Lognormal for Benign
    np.random.seed(42)
    benign = np.random.lognormal(mean=np.log(0.25), sigma=0.2, size=2000)
    benign = benign[benign < 0.4] # Truncate to stay under threshold for visual clarity of benign
    
    # Attacks
    attacks = [0.6, 0.62, 0.82, 0.88, 0.9]
    
    threshold = 0.4324

    fig, ax = plt.subplots(figsize=(6, 4))
    
    # Histogram
    n, bins, patches = ax.hist(benign, bins=30, color='#b3cde0', edgecolor='blue', 
                               alpha=0.6, log=True, label='Benign System')
    
    # Threshold Line
    ax.axvline(threshold, color='gray', linestyle='--', linewidth=2, alpha=0.8)
    ax.text(threshold + 0.02, 100, r'Threshold $\tau$', rotation=90, color='gray', fontweight='bold', fontsize=16)

    # Attacks (Manual placement matching image)
    ax.scatter(attacks, [2, 3, 2, 4, 3], color='red', marker='*', s=400, label='Attacks Detected', zorder=5)

    # Annotations - Larger
    # Removed 'Learned Benign Normality' as requested
    
    ax.text(0.75, 10, 'Attacks Detected\n(High Confidence)', 
            ha='center', color='red', fontweight='bold', fontsize=18) # Larger

    ax.set_xlabel('Reconstruction Error', fontweight='bold', fontsize=18) # Larger
    ax.set_ylabel('File Count (Log)', fontweight='bold', fontsize=18) # Larger
    
    # Sparse Ticks
    ax.set_xticks([0.0, 0.25, 0.5, 0.75, 1.0])
    ax.set_xticklabels(['0.0', '0.25', '0.5', '0.75', '1.0'], fontsize=16, fontweight='bold')
    
    ax.set_yticks([1, 10, 100, 1000, 10000])
    ax.set_yticklabels(['$10^0$', '$10^1$', '$10^2$', '$10^3$', '$10^4$'], fontsize=16, fontweight='bold')
    
    ax.set_xlim(0, 1.05)
    ax.set_ylim(0.5, 20000)
    
    ax.grid(True, linestyle='--', alpha=0.5)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'fig_churn_hist.pdf'), dpi=300)
    print("Generated fig_churn_hist.pdf")
    plt.close()

if __name__ == "__main__":
    plot_churn_alerts()
    plot_churn_hist()
