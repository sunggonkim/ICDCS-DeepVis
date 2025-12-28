import matplotlib.pyplot as plt
import pandas as pd
import os

DATA_DIR = "data"
FIG_DIR = "../paper/figures"
os.makedirs(FIG_DIR, exist_ok=True)

plt.style.use("seaborn-v0_8-paper")
plt.rcParams["font.family"] = "serif"
plt.rcParams["font.serif"] = ["DejaVu Sans"]

def plot_scalability():
    p = f"{DATA_DIR}/scalability.csv"
    if not os.path.exists(p): return
    df = pd.read_csv(p)
    
    plt.figure(figsize=(5, 3))
    plt.plot(df["Files"], df["Python"], "o--", label="Baseline (AIDE-like)")
    plt.plot(df["Files"], df["DeepVis"], "s-", linewidth=2, label="DeepVis (Rust)")
    plt.xlabel("Number of Files")
    plt.ylabel("Latency (s)")
    plt.legend()
    plt.grid(True, linestyle=":", alpha=0.6)
    plt.tight_layout()
    plt.savefig(f"{FIG_DIR}/fig_scalability.pdf")
    print(f"[Plot] Saved {FIG_DIR}/fig_scalability.pdf")

def plot_hyperscale():
    p = f"{DATA_DIR}/hyperscale.csv"
    if not os.path.exists(p): return
    df = pd.read_csv(p)
    
    fig, ax1 = plt.subplots(figsize=(5, 3))
    
    color = "tab:red"
    ax1.set_xlabel("Scale (Files)")
    ax1.set_ylabel("Collision Probability", color=color)
    ax1.plot(df["Files"], df["CollisionRate"], color=color)
    ax1.tick_params(axis="y", labelcolor=color)
    ax1.set_xscale("log")
    
    ax2 = ax1.twinx()
    color = "tab:blue"
    ax2.set_ylabel("Recall (Rootkit)", color=color)
    ax2.plot(df["Files"], df["Recall"], color=color, linestyle="--")
    ax2.tick_params(axis="y", labelcolor=color)
    
    plt.tight_layout()
    plt.savefig(f"{FIG_DIR}/fig_hyperscale.pdf")
    print(f"[Plot] Saved {FIG_DIR}/fig_hyperscale.pdf")

if __name__ == "__main__":
    plot_scalability()
    plot_hyperscale()
