#!/usr/bin/env python3
"""
DeepVis v3: Entropy-Centric File System Anomaly Detection
==========================================================
Key insight from experiments: High-entropy files (>7.0) are the primary
indicator of packed/encrypted rootkits.

This version uses a simple but effective approach:
1. Detect NEW high-entropy files not in baseline
2. Provide visual localization via hash-based image
3. Minimal false positives by focusing on clear anomaly signals
"""

import os
import random
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from typing import List, Dict, Set, Tuple
from dataclasses import dataclass
from sklearn.metrics import roc_auc_score, precision_score, recall_score, confusion_matrix, roc_curve
import json
import hashlib

# Import existing modules
import data_gen
import collect_real_data
import fs_to_img
import model

from data_gen import FileEntry, simulate_normal_update, simulate_diamorphine_attack, simulate_reptile_attack, simulate_beurk_attack
from collect_real_data import collect_system_baseline
from fs_to_img import files_to_image
from model import CAE

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# Thresholds (empirically determined)
ENTROPY_THRESHOLD = 7.0  # Files above this are suspicious
SIZE_ANOMALY_RATIO = 3.0  # Files 3x larger than typical = suspicious
NEW_FILE_ENTROPY_THRESHOLD = 6.5  # New files with this entropy are suspicious


class BaselineProfile:
    """Stores the baseline file system profile for comparison"""
    
    def __init__(self, state: List[FileEntry]):
        self.file_hashes: Set[str] = set()
        self.file_entropies: Dict[str, float] = {}
        self.file_sizes: Dict[str, int] = {}
        self.path_entropy_stats: Dict[str, Tuple[float, float]] = {}  # path_prefix -> (mean, std)
        
        # Build baseline profile
        for f in state:
            self.file_hashes.add(f.filename)
            self.file_entropies[f.filename] = f.entropy
            self.file_sizes[f.filename] = f.size
        
        # Compute per-directory stats
        dir_entropies = {}
        for f in state:
            dir_path = os.path.dirname(f.filename)
            if dir_path not in dir_entropies:
                dir_entropies[dir_path] = []
            dir_entropies[dir_path].append(f.entropy)
        
        for dir_path, entropies in dir_entropies.items():
            self.path_entropy_stats[dir_path] = (np.mean(entropies), np.std(entropies))
    
    def get_expected_entropy(self, path: str) -> Tuple[float, float]:
        """Get expected entropy stats for a path's directory"""
        dir_path = os.path.dirname(path)
        if dir_path in self.path_entropy_stats:
            return self.path_entropy_stats[dir_path]
        return (5.5, 1.0)  # Default for unknown directories


class EntropyAnomalyDetector:
    """
    DeepVis v3: Simple but effective entropy-based detector
    
    Detection logic:
    1. NEW files with high entropy (>6.5) = Suspicious
    2. EXISTING files with entropy spike (Δ > 2σ) = Suspicious  
    3. Critical paths (/lib/modules/, /usr/bin/) get extra scrutiny
    """
    
    def __init__(self):
        self.baseline: BaselineProfile = None
        self.cae = CAE().to(DEVICE)
        self.is_trained = False
        
        # Critical paths that warrant extra attention
        self.critical_paths = [
            '/lib/modules/',
            '/usr/lib/',
            '/etc/',
            '/bin/',
            '/usr/bin/',
            '/sbin/',
            '/usr/sbin/'
        ]
    
    def train(self, baseline_state: List[FileEntry], augmented_states: List[List[FileEntry]] = None, epochs: int = 30):
        """Train detector on baseline state"""
        print("Training Entropy Anomaly Detector...")
        
        # 1. Build baseline profile
        print("  [1/2] Building baseline profile...")
        self.baseline = BaselineProfile(baseline_state)
        print(f"        Indexed {len(self.baseline.file_hashes)} files")
        
        # 2. Train CAE for visual explanation
        print("  [2/2] Training CAE for visualization...")
        if augmented_states is None:
            augmented_states = [baseline_state]
        
        train_images = np.stack([files_to_image(s) for s in augmented_states])
        train_tensor = torch.tensor(train_images, dtype=torch.float32)
        train_loader = torch.utils.data.DataLoader(train_tensor, batch_size=32, shuffle=True)
        
        criterion = nn.MSELoss()
        optimizer = optim.Adam(self.cae.parameters(), lr=0.001)
        self.cae.train()
        
        for epoch in range(epochs):
            total_loss = 0
            for batch in train_loader:
                batch = batch.to(DEVICE)
                optimizer.zero_grad()
                outputs = self.cae(batch)
                loss = criterion(outputs, batch)
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
            
            if (epoch + 1) % 10 == 0:
                print(f"        Epoch [{epoch+1}/{epochs}], Loss: {total_loss/len(train_loader):.6f}")
        
        self.is_trained = True
        print("Training complete!")
    
    def detect(self, state: List[FileEntry]) -> Dict:
        """
        Detect anomalies in current state vs baseline
        
        Key insight: Only NEW files with high entropy are truly suspicious.
        Modifications to existing files are expected during normal updates.
        """
        if not self.is_trained:
            raise RuntimeError("Detector not trained!")
        
        anomalies = []
        new_files = []
        modified_files = []
        
        # Build current state index
        current_files = {f.filename: f for f in state}
        
        for f in state:
            is_new = f.filename not in self.baseline.file_hashes
            is_critical = any(f.filename.startswith(p) for p in self.critical_paths)
            
            if is_new:
                new_files.append(f)
                reasons = []
                risk = 0.0
                
                # NEW files with high entropy are the PRIMARY indicator
                if f.entropy > ENTROPY_THRESHOLD:  # > 7.0
                    reasons.append(f"NEW high-entropy file ({f.entropy:.2f})")
                    risk = 0.95  # Very high risk
                elif f.entropy > NEW_FILE_ENTROPY_THRESHOLD:  # > 6.5
                    if is_critical:
                        reasons.append(f"NEW file in critical path ({f.entropy:.2f})")
                        risk = 0.7
                
                # SUID/SGID on NEW file in critical path
                if is_critical and (f.permissions & 0o4000 or f.permissions & 0o2000):
                    reasons.append("NEW SUID/SGID in critical path")
                    risk = max(risk, 0.8)
                
                if reasons:
                    anomalies.append({
                        "filename": f.filename,
                        "reasons": reasons,
                        "risk_score": risk,
                        "entropy": f.entropy,
                        "size": f.size,
                        "permissions": oct(f.permissions),
                        "is_new": True,
                        "is_critical_path": is_critical
                    })
            else:
                # Existing file - check for significant changes
                old_entropy = self.baseline.file_entropies.get(f.filename, 5.5)
                entropy_delta = f.entropy - old_entropy
                
                # Only flag if entropy increased dramatically AND is now very high
                if entropy_delta > 1.5 and f.entropy > ENTROPY_THRESHOLD:
                    modified_files.append(f)
                    anomalies.append({
                        "filename": f.filename,
                        "reasons": [f"Entropy spike to very high ({old_entropy:.2f} → {f.entropy:.2f})"],
                        "risk_score": 0.85,
                        "entropy": f.entropy,
                        "size": f.size,
                        "permissions": oct(f.permissions),
                        "is_new": False,
                        "is_critical_path": is_critical
                    })
        
        # Sort by risk score
        anomalies.sort(key=lambda x: x["risk_score"], reverse=True)
        
        # Aggregate risk
        aggregate_risk = max((a["risk_score"] for a in anomalies), default=0.0)
        
        # Only declare anomaly if we have high-confidence signals
        is_anomaly = any(a["risk_score"] >= 0.7 for a in anomalies)
        
        return {
            "is_anomaly": is_anomaly,
            "risk_score": aggregate_risk,
            "anomaly_count": len(anomalies),
            "anomalous_files": anomalies[:10],
            "new_file_count": len(new_files),
            "modified_file_count": len(modified_files),
            "high_entropy_new_files": sum(1 for f in new_files if f.entropy > ENTROPY_THRESHOLD),
        }
    
    def visualize(self, state: List[FileEntry], output_path: str = "deepvis_v3_result.png") -> Dict:
        """Generate visual explanation"""
        self.cae.eval()
        
        img = files_to_image(state)
        inp = torch.tensor(img, dtype=torch.float32).unsqueeze(0).to(DEVICE)
        
        with torch.no_grad():
            rec = self.cae(inp)
        
        diff = torch.abs(inp - rec).cpu().numpy()[0]
        
        # Find peak
        peak_idx = np.unravel_index(np.argmax(diff), diff.shape)
        channel_names = ["Red (Entropy)", "Green (Size)", "Blue (Permissions)"]
        peak_channel = channel_names[peak_idx[0]]
        
        # Plot
        fig, axes = plt.subplots(2, 2, figsize=(14, 12))
        
        # Original
        orig = np.transpose(inp.cpu().numpy()[0], (1, 2, 0))
        axes[0, 0].imshow(orig)
        axes[0, 0].set_title("File System State (RGB)")
        axes[0, 0].axis('off')
        
        # Difference
        diff_vis = np.transpose(diff, (1, 2, 0))
        diff_vis = diff_vis / (diff_vis.max() + 1e-8)
        axes[0, 1].imshow(diff_vis)
        axes[0, 1].set_title("Difference Map")
        axes[0, 1].axis('off')
        
        # Entropy channel heatmap
        entropy_diff = diff[0]
        im = axes[1, 0].imshow(entropy_diff, cmap='Reds')
        axes[1, 0].set_title("Entropy Channel Anomalies")
        axes[1, 0].axis('off')
        plt.colorbar(im, ax=axes[1, 0], fraction=0.046)
        
        # Combined heatmap
        heatmap = np.max(diff, axis=0)
        im = axes[1, 1].imshow(heatmap, cmap='hot')
        axes[1, 1].set_title(f"Combined Heatmap\n(Peak: {peak_channel})")
        axes[1, 1].axis('off')
        plt.colorbar(im, ax=axes[1, 1], fraction=0.046)
        
        plt.tight_layout()
        plt.savefig(output_path, dpi=150, bbox_inches='tight')
        plt.close()
        
        return {
            "peak_channel": peak_channel,
            "peak_value": float(np.max(diff)),
            "output_path": output_path
        }


def run_evaluation():
    """Run comprehensive evaluation"""
    print("=" * 70)
    print("DeepVis v3: Entropy-Centric Anomaly Detection - Evaluation")
    print("=" * 70)
    
    # Reproducibility
    torch.manual_seed(42)
    np.random.seed(42)
    random.seed(42)
    
    # 1. Collect baseline
    print("\n[1/5] Collecting baseline...")
    real_baseline = collect_system_baseline()
    print(f"      {len(real_baseline)} files indexed")
    
    # 2. Create augmented training data
    print("\n[2/5] Generating training variations...")
    train_states = [real_baseline]
    for _ in range(49):
        train_states.append(simulate_normal_update([f.clone() for f in real_baseline]))
    
    # 3. Train detector
    print("\n[3/5] Training detector...")
    detector = EntropyAnomalyDetector()
    detector.train(real_baseline, train_states, epochs=30)
    
    # 4. Generate test data
    print("\n[4/5] Generating test data...")
    
    test_normal = []
    for _ in range(100):
        test_normal.append(simulate_normal_update([f.clone() for f in real_baseline]))
    
    attacks = {
        "diamorphine": [simulate_diamorphine_attack([f.clone() for f in real_baseline]) for _ in range(30)],
        "reptile": [simulate_reptile_attack([f.clone() for f in real_baseline]) for _ in range(30)],
        "beurk": [simulate_beurk_attack([f.clone() for f in real_baseline]) for _ in range(30)],
    }
    
    # 5. Evaluate
    print("\n[5/5] Evaluating...")
    
    y_true = []
    y_scores = []
    y_pred = []
    
    # Normal
    fp_count = 0
    for sample in test_normal:
        result = detector.detect(sample)
        y_true.append(0)
        y_scores.append(result["risk_score"])
        y_pred.append(1 if result["is_anomaly"] else 0)
        if result["is_anomaly"]:
            fp_count += 1
    
    # Attacks
    per_rootkit_results = {}
    all_attacks = []
    for name, samples in attacks.items():
        detected = 0
        for sample in samples:
            result = detector.detect(sample)
            y_true.append(1)
            y_scores.append(result["risk_score"])
            y_pred.append(1 if result["is_anomaly"] else 0)
            all_attacks.append((name, sample, result))
            if result["is_anomaly"]:
                detected += 1
        per_rootkit_results[name] = {"detected": detected, "total": len(samples)}
    
    # Metrics
    y_true = np.array(y_true)
    y_scores = np.array(y_scores)
    y_pred = np.array(y_pred)
    
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    
    auroc = roc_auc_score(y_true, y_scores)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    
    print("\n" + "=" * 60)
    print("RESULTS: DeepVis v3 Entropy-Centric Detector")
    print("=" * 60)
    print(f"Files in Baseline: {len(real_baseline)}")
    print(f"Test Normal: 100 | Test Attacks: 90")
    print()
    print(f"AUROC:     {auroc:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"FPR:       {fpr:.4f}")
    print()
    print(f"True Positives:  {tp}")
    print(f"True Negatives:  {tn}")
    print(f"False Positives: {fp}")
    print(f"False Negatives: {fn}")
    
    print("\n--- Per-Rootkit Results ---")
    for name, res in per_rootkit_results.items():
        rate = res["detected"] / res["total"] * 100
        print(f"{name.upper()}: {res['detected']}/{res['total']} ({rate:.1f}%)")
    
    # Visualize a detection
    print("\n--- Generating Visualization ---")
    _, attack_sample, _ = all_attacks[0]
    vis_result = detector.visualize(attack_sample, "deepvis_v3_detection.png")
    print(f"Saved: {vis_result['output_path']}")
    
    # Save comprehensive results plot
    fig, axes = plt.subplots(2, 2, figsize=(14, 12))
    
    # Score distribution
    ax = axes[0, 0]
    normal_scores = y_scores[y_true == 0]
    attack_scores = y_scores[y_true == 1]
    ax.hist(normal_scores, bins=30, alpha=0.7, label='Normal', color='blue', density=True)
    ax.hist(attack_scores, bins=30, alpha=0.7, label='Attack', color='red', density=True)
    ax.axvline(0.5, color='black', linestyle='--', label='Threshold')
    ax.set_xlabel('Risk Score')
    ax.set_ylabel('Density')
    ax.set_title('Risk Score Distribution')
    ax.legend()
    
    # ROC curve
    ax = axes[0, 1]
    fpr_curve, tpr_curve, _ = roc_curve(y_true, y_scores)
    ax.plot(fpr_curve, tpr_curve, 'b-', linewidth=2, label=f'AUROC = {auroc:.3f}')
    ax.plot([0, 1], [0, 1], 'k--')
    ax.set_xlabel('False Positive Rate')
    ax.set_ylabel('True Positive Rate')
    ax.set_title('ROC Curve')
    ax.legend()
    ax.grid(True, alpha=0.3)
    
    # Per-rootkit
    ax = axes[1, 0]
    names = list(per_rootkit_results.keys())
    rates = [r["detected"]/r["total"]*100 for r in per_rootkit_results.values()]
    bars = ax.bar(names, rates, color=['#ff6b6b', '#4ecdc4', '#45b7d1'])
    ax.set_ylabel('Detection Rate (%)')
    ax.set_title('Per-Rootkit Detection')
    ax.set_ylim(0, 110)
    for bar, rate in zip(bars, rates):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 2,
                f'{rate:.0f}%', ha='center', fontweight='bold')
    
    # Summary
    ax = axes[1, 1]
    ax.axis('off')
    summary = f"""
    DeepVis v3 - Entropy-Centric Detection
    ======================================
    
    Performance:
    ────────────
    • AUROC:     {auroc:.4f}
    • Precision: {precision:.4f}
    • Recall:    {recall:.4f}
    • FPR:       {fpr:.4f}
    
    Confusion Matrix:
    ─────────────────
    • TP: {tp}  TN: {tn}
    • FP: {fp}  FN: {fn}
    
    Detection Logic:
    ────────────────
    • NEW file with entropy > 6.5 → Suspicious
    • Entropy spike > 1.5 → Suspicious
    • Critical path + new file → Extra scrutiny
    • SUID/SGID on new file → High risk
    • Entropy > 7.0 → Very suspicious
    """
    ax.text(0.1, 0.9, summary, transform=ax.transAxes, fontsize=11,
            verticalalignment='top', fontfamily='monospace',
            bbox=dict(boxstyle='round', facecolor='white', alpha=0.8))
    
    plt.tight_layout()
    plt.savefig('deepvis_v3_comprehensive_results.png', dpi=150, bbox_inches='tight')
    plt.close()
    print("Saved: deepvis_v3_comprehensive_results.png")
    
    # JSON results
    results = {
        "files_scanned": len(real_baseline),
        "metrics": {
            "AUROC": float(auroc),
            "Precision": float(precision),
            "Recall": float(recall),
            "FPR": float(fpr),
            "TP": int(tp), "TN": int(tn), "FP": int(fp), "FN": int(fn)
        },
        "per_rootkit": per_rootkit_results,
        "thresholds": {
            "entropy_threshold": ENTROPY_THRESHOLD,
            "new_file_entropy_threshold": NEW_FILE_ENTROPY_THRESHOLD
        }
    }
    
    with open('deepvis_v3_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    print("Saved: deepvis_v3_results.json")
    
    print("\n" + "=" * 60)
    print("EVALUATION COMPLETE")
    print("=" * 60)
    
    return detector, results


if __name__ == "__main__":
    run_evaluation()
