#!/usr/bin/env python3
"""
DeepVis Comprehensive Evaluation Script for USENIX Paper
Generates real experimental results with detailed metrics
"""

import os
import random
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
import matplotlib.pyplot as plt
from typing import List, Dict
from sklearn.metrics import roc_auc_score, precision_score, recall_score, confusion_matrix
import json

# Import modules
import data_gen
import collect_real_data
import fs_to_img
import model
import baselines

from data_gen import (
    generate_baseline, simulate_normal_update, simulate_rootkit_attack,
    simulate_diamorphine_attack, simulate_reptile_attack, simulate_beurk_attack,
    FileEntry
)
from collect_real_data import collect_system_baseline
from fs_to_img import files_to_image
from model import CAE

# Configuration
CONFIG = {
    "NUM_TRAIN_SAMPLES": 200,
    "NUM_TEST_NORMAL": 100,
    "NUM_ATTACK_TRIALS": 30,  # Per rootkit type
    "BATCH_SIZE": 32,
    "EPOCHS": 50,  # More epochs for better convergence
    "LEARNING_RATE": 0.001,
    "IMAGE_SIZE": 128,
}

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Using device: {DEVICE}")

def compute_metrics(y_true, y_scores, threshold=None):
    """Compute comprehensive metrics"""
    if threshold is None:
        # Use 95th percentile of normal scores as threshold
        normal_scores = [s for s, y in zip(y_scores, y_true) if y == 0]
        threshold = np.percentile(normal_scores, 95)
    
    y_pred = [1 if s > threshold else 0 for s in y_scores]
    
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    
    return {
        "AUROC": roc_auc_score(y_true, y_scores),
        "Precision": tp / (tp + fp) if (tp + fp) > 0 else 0,
        "Recall": tp / (tp + fn) if (tp + fn) > 0 else 0,
        "FPR": fp / (fp + tn) if (fp + tn) > 0 else 0,
        "Threshold": threshold,
        "TP": tp, "TN": tn, "FP": fp, "FN": fn
    }

def train_cae(model, train_loader, epochs=50):
    """Train CAE with loss tracking"""
    criterion = nn.MSELoss()
    optimizer = optim.Adam(model.parameters(), lr=CONFIG["LEARNING_RATE"])
    model.train()
    
    losses = []
    for epoch in range(epochs):
        total_loss = 0
        for batch in train_loader:
            batch = batch.to(DEVICE)
            optimizer.zero_grad()
            outputs = model(batch)
            loss = criterion(outputs, batch)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        
        avg_loss = total_loss / len(train_loader)
        losses.append(avg_loss)
        if (epoch + 1) % 10 == 0:
            print(f"Epoch [{epoch+1}/{epochs}], Loss: {avg_loss:.6f}")
    
    return losses

def evaluate_deepvis(model, samples, return_per_channel=False):
    """Evaluate using Local Max and optionally per-channel scores"""
    model.eval()
    scores = []
    channel_scores = {"red": [], "green": [], "blue": []}
    
    with torch.no_grad():
        for sample in samples:
            img = files_to_image(sample)
            inp = torch.tensor(img, dtype=torch.float32).unsqueeze(0).to(DEVICE)
            rec = model(inp)
            diff = torch.abs(inp - rec).cpu().numpy()[0]  # (3, H, W)
            
            # Local Max (L_inf)
            local_max = np.max(diff)
            scores.append(local_max)
            
            if return_per_channel:
                channel_scores["red"].append(np.max(diff[0]))  # Entropy
                channel_scores["green"].append(np.max(diff[1]))  # Size
                channel_scores["blue"].append(np.max(diff[2]))  # Permissions
    
    if return_per_channel:
        return scores, channel_scores
    return scores

def main():
    print("=" * 60)
    print("DeepVis Comprehensive Evaluation - Real Data Experiment")
    print("=" * 60)
    
    # Reproducibility
    torch.manual_seed(42)
    np.random.seed(42)
    random.seed(42)
    
    # 1. Collect Real Data
    print("\n[1/6] Collecting Real File System Data...")
    real_baseline = collect_system_baseline()
    print(f"    Collected {len(real_baseline)} files from system")
    
    # 2. Generate Training Data (Normal states with variance)
    print("\n[2/6] Generating Training Data...")
    train_states = []
    for i in range(CONFIG["NUM_TRAIN_SAMPLES"]):
        base = [f.clone() for f in real_baseline]
        train_states.append(simulate_normal_update(base))
    
    train_images = np.stack([files_to_image(s) for s in train_states])
    train_tensor = torch.tensor(train_images, dtype=torch.float32)
    train_loader = torch.utils.data.DataLoader(
        train_tensor, batch_size=CONFIG["BATCH_SIZE"], shuffle=True
    )
    
    # 3. Train CAE
    print("\n[3/6] Training CAE Model...")
    cae = CAE().to(DEVICE)
    train_losses = train_cae(cae, train_loader, CONFIG["EPOCHS"])
    
    # 4. Generate Test Data
    print("\n[4/6] Generating Test Data...")
    
    # Normal updates
    test_normal = []
    for _ in range(CONFIG["NUM_TEST_NORMAL"]):
        base = [f.clone() for f in real_baseline]
        test_normal.append(simulate_normal_update(base))
    
    # Specific rootkit attacks
    attacks = {"diamorphine": [], "reptile": [], "beurk": []}
    for _ in range(CONFIG["NUM_ATTACK_TRIALS"]):
        base = [f.clone() for f in real_baseline]
        attacks["diamorphine"].append(simulate_diamorphine_attack(base))
        
        base = [f.clone() for f in real_baseline]
        attacks["reptile"].append(simulate_reptile_attack(base))
        
        base = [f.clone() for f in real_baseline]
        attacks["beurk"].append(simulate_beurk_attack(base))
    
    # 5. Evaluate
    print("\n[5/6] Evaluating Models...")
    
    results = {}
    
    # DeepVis on Normal
    normal_scores, normal_channels = evaluate_deepvis(cae, test_normal, return_per_channel=True)
    
    # DeepVis on Each Rootkit
    attack_results = {}
    for rootkit_name, samples in attacks.items():
        attack_scores, attack_channels = evaluate_deepvis(cae, samples, return_per_channel=True)
        
        # Combined evaluation
        y_true = [0] * len(normal_scores) + [1] * len(attack_scores)
        y_scores = normal_scores + attack_scores
        
        metrics = compute_metrics(y_true, y_scores)
        attack_results[rootkit_name] = {
            "metrics": metrics,
            "avg_score": np.mean(attack_scores),
            "channel_scores": {
                "red": np.mean(attack_channels["red"]),
                "green": np.mean(attack_channels["green"]),
                "blue": np.mean(attack_channels["blue"])
            }
        }
        
        print(f"\n    {rootkit_name.upper()}:")
        print(f"      AUROC: {metrics['AUROC']:.4f}")
        print(f"      Recall: {metrics['Recall']:.4f}, FPR: {metrics['FPR']:.4f}")
        print(f"      Avg Local Max Score: {np.mean(attack_scores):.4f}")
        print(f"      Channel Breakdown - R(Entropy): {np.mean(attack_channels['red']):.4f}, "
              f"G(Size): {np.mean(attack_channels['green']):.4f}, "
              f"B(Perms): {np.mean(attack_channels['blue']):.4f}")
    
    # Overall (all attacks combined)
    all_attack_samples = attacks["diamorphine"] + attacks["reptile"] + attacks["beurk"]
    all_attack_scores = evaluate_deepvis(cae, all_attack_samples)
    
    y_true_all = [0] * len(normal_scores) + [1] * len(all_attack_scores)
    y_scores_all = normal_scores + all_attack_scores
    overall_metrics = compute_metrics(y_true_all, y_scores_all)
    
    print("\n" + "=" * 40)
    print("OVERALL RESULTS (All Rootkits Combined)")
    print("=" * 40)
    print(f"DeepVis AUROC: {overall_metrics['AUROC']:.4f}")
    print(f"DeepVis Precision: {overall_metrics['Precision']:.4f}")
    print(f"DeepVis Recall: {overall_metrics['Recall']:.4f}")
    print(f"DeepVis FPR: {overall_metrics['FPR']:.4f}")
    
    # Compare with Baselines
    print("\n--- Baseline Comparisons ---")
    
    # Isolation Forest
    iso_forest = baselines.BaselineIsolationForest()
    iso_forest.train(train_states)
    
    iso_normal = [1 if iso_forest.predict(s) == -1 else 0 for s in test_normal]
    iso_attack = [1 if iso_forest.predict(s) == -1 else 0 for s in all_attack_samples]
    y_iso = iso_normal + iso_attack
    
    print(f"IsoForest AUROC: {roc_auc_score(y_true_all, y_iso):.4f}")
    
    # AIDE
    aide = baselines.BaselineAIDE()
    aide.train(train_states[0])
    
    aide_normal = [1 if len(aide.predict_files(s)) > 0 else 0 for s in test_normal]
    aide_attack = [1 if len(aide.predict_files(s)) > 0 else 0 for s in all_attack_samples]
    y_aide = aide_normal + aide_attack
    
    aide_precision = precision_score(y_true_all, y_aide) if sum(y_aide) > 0 else 0
    aide_recall = recall_score(y_true_all, y_aide) if sum(y_aide) > 0 else 0
    
    print(f"AIDE Precision: {aide_precision:.4f}")
    print(f"AIDE Recall: {aide_recall:.4f}")
    print(f"AIDE FP Alerts on Normal: {sum(aide_normal)}/{len(aide_normal)}")
    
    # 6. Save Results
    print("\n[6/6] Saving Results...")
    
    # Separation Plot
    plt.figure(figsize=(12, 5))
    
    # Subplot 1: Score Distribution
    plt.subplot(1, 2, 1)
    plt.hist(normal_scores, bins=30, alpha=0.7, label='Normal Updates', color='blue', density=True)
    plt.hist(all_attack_scores, bins=30, alpha=0.7, label='Rootkit Attacks', color='red', density=True)
    plt.axvline(overall_metrics['Threshold'], color='black', linestyle='--', label=f'Threshold ({overall_metrics["Threshold"]:.3f})')
    plt.xlabel('Local Max Reconstruction Error')
    plt.ylabel('Density')
    plt.title('DeepVis Score Distribution')
    plt.legend()
    
    # Subplot 2: Per-Rootkit Scores
    plt.subplot(1, 2, 2)
    rootkit_names = list(attacks.keys())
    x = np.arange(len(rootkit_names))
    width = 0.2
    
    for i, (name, data) in enumerate(attack_results.items()):
        cs = data["channel_scores"]
        plt.bar(i - width, cs["red"], width, color='red', alpha=0.7, label='Red (Entropy)' if i == 0 else "")
        plt.bar(i, cs["green"], width, color='green', alpha=0.7, label='Green (Size)' if i == 0 else "")
        plt.bar(i + width, cs["blue"], width, color='blue', alpha=0.7, label='Blue (Perms)' if i == 0 else "")
    
    plt.xticks(x, [n.capitalize() for n in rootkit_names])
    plt.ylabel('Avg Channel Score')
    plt.title('Per-Rootkit Channel Analysis')
    plt.legend()
    
    plt.tight_layout()
    plt.savefig('usenix_experiment_results.png', dpi=150)
    print("Saved usenix_experiment_results.png")
    
    # Save JSON results
    final_results = {
        "config": CONFIG,
        "num_files_scanned": len(real_baseline),
        "overall": overall_metrics,
        "per_rootkit": {
            k: {
                "AUROC": v["metrics"]["AUROC"],
                "Precision": v["metrics"]["Precision"],
                "Recall": v["metrics"]["Recall"],
                "FPR": v["metrics"]["FPR"],
                "avg_score": v["avg_score"],
                "channel_scores": v["channel_scores"]
            } for k, v in attack_results.items()
        },
        "baseline_comparison": {
            "IsoForest_AUROC": roc_auc_score(y_true_all, y_iso),
            "AIDE_Precision": aide_precision,
            "AIDE_Recall": aide_recall,
            "AIDE_FP_on_Normal": sum(aide_normal)
        },
        "normal_score_stats": {
            "mean": float(np.mean(normal_scores)),
            "std": float(np.std(normal_scores)),
            "max": float(np.max(normal_scores))
        },
        "attack_score_stats": {
            "mean": float(np.mean(all_attack_scores)),
            "std": float(np.std(all_attack_scores)),
            "max": float(np.max(all_attack_scores))
        }
    }
    
    with open('usenix_results.json', 'w') as f:
        json.dump(final_results, f, indent=2)
    print("Saved usenix_results.json")
    
    print("\n" + "=" * 60)
    print("EXPERIMENT COMPLETE")
    print("=" * 60)

if __name__ == "__main__":
    main()
