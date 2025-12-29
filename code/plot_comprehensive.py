import matplotlib.pyplot as plt
import numpy as np

# Data (Verified)
systems = ['DeepVis', 'AIDE', 'ClamAV', 'YARA', 'Falco']
throughput = [39993, 1004, 186, 732, 0] # Falco N/A
latency_deg = [2.0, 291.0, 127.2, 546.9, 58.3] # %
cpu_load = [11.2, 99.8, 95.0, 98.0, 12.4] # %

labels = ['DeepVis', 'AIDE', 'ClamAV', 'YARA', 'Falco']
x = np.arange(len(labels))
width = 0.6
color_tp = '#1f77b4' # Blue
color_lat = '#d62728' # Red
color_cpu = '#2ca02c' # Green
edge_color = 'black'
alpha = 0.9

def save_single_col_plot(filename, data, ylabel, color, is_log=False, y_limit=None):
    fig, ax = plt.subplots(figsize=(4, 2.0)) # Compressed height
    
    plot_data = [d if d > 0 else (0.8 if is_log else 0) for d in data]
    ax.bar(x, plot_data, width, color=color, edgecolor=edge_color, alpha=0.9)
    
    ax.set_ylabel(ylabel, fontweight='bold', fontsize=9)
    if is_log:
        ax.set_yscale('log')
        ax.set_ylim(10, 500000)
    if y_limit:
        ax.set_ylim(0, y_limit)
        
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=0, fontsize=8, fontweight='bold')
    ax.tick_params(axis='y', labelsize=8)
    ax.grid(True, axis='y', linestyle='--', alpha=0.3)
    
    # Annotate
    for i, v in enumerate(data):
        if v > 0:
            offset = v * 1.5 if is_log else v + (y_limit * 0.08 if y_limit else 5)
            fontsize = 8
            if is_log:
                 txt = f"{v//1000}k" if v >= 1000 else f"{v}"
            else:
                 # Add + for latency
                 if "Overhead" in ylabel:
                     txt = f"+{v:.0f}%"
                 else:
                     txt = f"{v:.0f}%"
            
            ax.text(i, offset, txt, ha='center', va='bottom', fontsize=fontsize, fontweight='bold', color='black')
        else:
            if is_log:
                 ax.text(i, 15, "N/A", ha='center', va='bottom', fontsize=8, color='gray')

    plt.tight_layout()
    plt.savefig(f'paper/Figures/{filename}', bbox_inches='tight', dpi=300)
    print(f"Generated {filename}")
    plt.close()

# 1. Throughput (Fig 7)
save_single_col_plot('fig_final_throughput.pdf', throughput, 'Throughput (Log)', color_tp, is_log=True)

# 2. Latency (Fig 8a)
save_single_col_plot('fig_final_latency.pdf', latency_deg, 'Lat. Overhead (%)', color_lat, y_limit=650)

# 3. CPU (Fig 8b)
save_single_col_plot('fig_final_cpu.pdf', cpu_load, 'CPU Load (%)', color_cpu, y_limit=115)
