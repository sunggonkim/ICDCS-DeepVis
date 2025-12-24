#!/usr/bin/env python3
"""
DeepVis REALISTIC Evaluation: True Evasion Scenarios
=====================================================
Scenarios designed to ACTUALLY DEFEAT the detector:

1. PARASITIC: Append code to existing files (no size change threshold)
2. STEGANOGRAPHIC: Hide payload in existing compressed files
3. PURE LOTL: Only modify config files with NO suspicious extensions
4. NO-OP MIMICRY: Padded to match normal file characteristics exactly
5. TIMING ATTACK: Gradual changes below detection threshold

Based on DARPA OpTC APT patterns and real-world evasion techniques.
"""

import os
import sys
import random
import hashlib
import numpy as np
import json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from dataclasses import dataclass
from typing import List, Dict

def calculate_entropy(data: bytes) -> float:
    if len(data) == 0:
        return 0.0
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * np.log2(p)
    return entropy


@dataclass
class FileEntry:
    path: str
    size: int
    entropy: float
    permissions: int
    is_new: bool = False
    is_modified: bool = False
    is_malicious: bool = False
    attack_type: str = ""


class TrueEvasionScenarios:
    """Generate scenarios that actually evade detection"""
    
    def create_parasitic_infection(self, baseline: List[FileEntry]) -> List[FileEntry]:
        """
        PARASITIC: Append small payload to existing files
        Size change <3%, no new files, entropy change <0.1
        """
        infected = [FileEntry(**f.__dict__) for f in baseline]
        
        # Target non-executable config files (won't trigger suspicious extension)
        targets = [f for f in infected if f.path.endswith('.conf') or f.path.endswith('.cfg')]
        if len(targets) < 3:
            targets = [f for f in infected if not (f.permissions & 0o111)][:3]
        
        for target in targets[:3]:
            # Tiny size increase (1-2%)
            target.size = int(target.size * 1.02)
            # Minimal entropy change
            target.entropy = min(target.entropy + 0.05, 6.5)
            target.is_modified = True
            target.is_malicious = True
            target.attack_type = "PARASITIC"
        
        return infected
    
    def create_pure_lotl(self) -> List[FileEntry]:
        """
        PURE LOTL: Only create files with NO suspicious extensions
        Uses .conf, .txt, or no extension - NOT .py, .sh, .so, .ko
        """
        attacks = []
        
        # Sudoers modification (no extension)
        attacks.append(FileEntry(
            path="/etc/sudoers.d/admin",  # No extension!
            size=50,
            entropy=4.2,
            permissions=0o440,
            is_new=True,
            is_malicious=True,
            attack_type="PURE_LOTL"
        ))
        
        # PAM config (already .conf, might be expected)
        attacks.append(FileEntry(
            path="/etc/pam.d/common-auth-backup",
            size=200,
            entropy=4.5,
            permissions=0o644,
            is_new=True,
            is_malicious=True,
            attack_type="PURE_LOTL"
        ))
        
        # Environment variable injection
        attacks.append(FileEntry(
            path="/etc/environment.d/50-system.conf",
            size=100,
            entropy=4.3,
            permissions=0o644,
            is_new=True,
            is_malicious=True,
            attack_type="PURE_LOTL"
        ))
        
        return attacks
    
    def create_mimicry_attack(self, baseline: List[FileEntry]) -> List[FileEntry]:
        """
        MIMICRY: New malicious file that mimics normal file statistics exactly
        Copies entropy and size distribution from legit files
        """
        # Find average stats of legitimate .conf files
        conf_files = [f for f in baseline if f.path.endswith('.conf')]
        if not conf_files:
            conf_files = baseline[:50]
        
        avg_size = int(np.mean([f.size for f in conf_files]))
        avg_entropy = np.mean([f.entropy for f in conf_files])
        
        attacks = []
        
        # Malicious config that looks exactly like normal
        attacks.append(FileEntry(
            path="/etc/sysctl.d/99-custom.conf",  # Common pattern
            size=avg_size,  # Match average
            entropy=avg_entropy,  # Match average
            permissions=0o644,
            is_new=True,
            is_malicious=True,
            attack_type="MIMICRY"
        ))
        
        return attacks
    
    def create_memory_only_indicator(self) -> List[FileEntry]:
        """
        MEMORY-ONLY with minimal file footprint
        Only leaves a tiny marker file
        """
        attacks = []
        
        # Tiny marker (could be mistaken for temp file)
        attacks.append(FileEntry(
            path="/tmp/.X11-unix/.lock",  # Looks like X11 lockfile
            size=8,
            entropy=2.5,
            permissions=0o600,
            is_new=True,
            is_malicious=True,
            attack_type="MEMORY_ONLY"
        ))
        
        return attacks


class EnhancedDeepVisV2:
    """Enhanced detector with realistic limitations"""
    
    def __init__(self):
        self.entropy_threshold = 7.0
        self.size_change_threshold = 0.03  # 3%
        self.baseline_paths = set()
        self.baseline_sizes = {}
        self.baseline_entropies = {}
        self.critical_paths = [
            '/etc/cron', '/etc/ld.so', '/root/.ssh',
            '/lib/modules/', '/etc/sudoers'
        ]
        self.suspicious_extensions = ['.ko', '.so', '.py', '.sh']
        
    def train(self, baseline: List[FileEntry]):
        for f in baseline:
            self.baseline_paths.add(f.path)
            self.baseline_sizes[f.path] = f.size
            self.baseline_entropies[f.path] = f.entropy
    
    def detect(self, state: List[FileEntry]) -> Dict:
        anomalies = []
        
        for f in state:
            is_new = f.path not in self.baseline_paths
            is_critical = any(f.path.startswith(p) for p in self.critical_paths)
            is_executable = f.permissions & 0o111
            has_suspicious_ext = any(f.path.endswith(ext) for ext in self.suspicious_extensions)
            
            reasons = []
            risk = 0.0
            
            # Signal 1: NEW high-entropy file
            if is_new and f.entropy > self.entropy_threshold:
                reasons.append(f"NEW high entropy: {f.entropy:.2f}")
                risk = max(risk, 0.9)
            
            # Signal 2: New file in VERY critical path (sudoers, cron)
            if is_new and is_critical:
                reasons.append(f"Critical path: {f.path}")
                risk = max(risk, 0.7)
            
            # Signal 3: Size change in existing file (>threshold)
            if not is_new and f.path in self.baseline_sizes:
                size_delta = abs(f.size - self.baseline_sizes[f.path])
                size_ratio = size_delta / max(self.baseline_sizes[f.path], 1)
                if size_ratio > self.size_change_threshold:
                    reasons.append(f"Size changed: {size_ratio*100:.1f}%")
                    risk = max(risk, 0.6)
            
            # Signal 4: New executable with suspicious extension
            if is_new and is_executable and has_suspicious_ext:
                reasons.append("New suspicious executable")
                risk = max(risk, 0.65)
            
            # Signal 5: Script in temp/hidden location
            if is_new and has_suspicious_ext:
                if '/tmp' in f.path or '/.' in f.path:
                    reasons.append("Suspicious temp/hidden")
                    risk = max(risk, 0.6)
            
            if reasons and risk >= 0.6:
                anomalies.append({
                    "path": f.path,
                    "reasons": reasons,
                    "risk": risk,
                    "is_malicious": f.is_malicious,
                    "attack_type": f.attack_type
                })
        
        is_anomaly = len(anomalies) > 0
        max_risk = max((a["risk"] for a in anomalies), default=0.0)
        
        return {
            "is_anomaly": is_anomaly,
            "risk_score": max_risk,
            "anomalies": anomalies
        }


def run_realistic_evaluation():
    print("=" * 70)
    print("DeepVis REALISTIC Evaluation: True Evasion Scenarios")
    print("=" * 70)
    
    random.seed(42)
    np.random.seed(42)
    
    # Create baseline
    print("\n[1/5] Creating baseline...")
    baseline = []
    for directory in ['/bin', '/usr/bin', '/etc']:
        if not os.path.exists(directory):
            continue
        for root, dirs, files in os.walk(directory):
            for fn in files[:400]:
                filepath = os.path.join(root, fn)
                try:
                    stat = os.stat(filepath)
                    with open(filepath, 'rb') as f:
                        data = f.read(4096)
                    baseline.append(FileEntry(
                        path=filepath,
                        size=stat.st_size,
                        entropy=calculate_entropy(data),
                        permissions=stat.st_mode
                    ))
                except:
                    continue
    print(f"      Baseline: {len(baseline)} files")
    
    # Train detector
    detector = EnhancedDeepVisV2()
    detector.train(baseline)
    
    # Generate scenarios
    print("\n[2/5] Generating TRUE EVASION scenarios...")
    scenarios = TrueEvasionScenarios()
    
    attack_types = {
        "PARASITIC": [],     # Modifies existing files slightly
        "PURE_LOTL": [],     # No suspicious extensions
        "MIMICRY": [],       # Matches normal file stats
        "MEMORY_ONLY": [],   # Minimal footprint
        "EASY_HIGH_ENT": []  # Control: easy to detect
    }
    
    for _ in range(20):
        attack_types["PARASITIC"].append(scenarios.create_parasitic_infection(baseline))
    
    for _ in range(20):
        state = baseline + scenarios.create_pure_lotl()
        attack_types["PURE_LOTL"].append(state)
    
    for _ in range(20):
        state = baseline + scenarios.create_mimicry_attack(baseline)
        attack_types["MIMICRY"].append(state)
    
    for _ in range(20):
        state = baseline + scenarios.create_memory_only_indicator()
        attack_types["MEMORY_ONLY"].append(state)
    
    # Control: Easy high-entropy attacks
    for _ in range(20):
        attack = FileEntry(
            path="/usr/lib/malware.so",
            size=20000,
            entropy=7.8,
            permissions=0o755,
            is_new=True,
            is_malicious=True,
            attack_type="EASY_HIGH_ENT"
        )
        attack_types["EASY_HIGH_ENT"].append(baseline + [attack])
    
    # Normal tests
    normal_tests = [[FileEntry(**f.__dict__) for f in baseline] for _ in range(50)]
    
    print(f"      Normal: 50")
    for atype, trials in attack_types.items():
        print(f"      {atype}: {len(trials)}")
    
    # Evaluate
    print("\n[3/5] Evaluating...")
    
    results = {
        "per_attack": {},
        "overall": {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
    }
    
    # Normal
    for state in normal_tests:
        det = detector.detect(state)
        if det["is_anomaly"]:
            results["overall"]["FP"] += 1
        else:
            results["overall"]["TN"] += 1
    
    # Attacks
    for atype, trials in attack_types.items():
        results["per_attack"][atype] = {"detected": 0, "total": len(trials), "missed": []}
        
        for state in trials:
            det = detector.detect(state)
            if det["is_anomaly"]:
                results["per_attack"][atype]["detected"] += 1
                results["overall"]["TP"] += 1
            else:
                results["overall"]["FN"] += 1
    
    # Compute metrics
    print("\n[4/5] Computing metrics...")
    
    TP = results["overall"]["TP"]
    TN = results["overall"]["TN"]
    FP = results["overall"]["FP"]
    FN = results["overall"]["FN"]
    
    precision = TP / (TP + FP) if (TP + FP) > 0 else 0
    recall = TP / (TP + FN) if (TP + FN) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fpr = FP / (FP + TN) if (FP + TN) > 0 else 0
    
    # Print
    print("\n" + "=" * 70)
    print("REALISTIC EVALUATION RESULTS")
    print("=" * 70)
    
    print(f"\nOverall Metrics:")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall:    {recall:.4f}")
    print(f"  F1 Score:  {f1:.4f}")
    print(f"  FPR:       {fpr:.4f}")
    print(f"\n  TP={TP}, TN={TN}, FP={FP}, FN={FN}")
    
    print("\n--- Per-Attack-Type Detection ---")
    for atype, data in results["per_attack"].items():
        rate = data["detected"] / data["total"] * 100
        if rate == 100:
            status = "✓ DETECTED"
        elif rate > 50:
            status = "⚠ PARTIAL"
        else:
            status = "✗ EVADED"
        print(f"  {status}: {atype}: {data['detected']}/{data['total']} ({rate:.1f}%)")
    
    # Generate visualization
    print("\n[5/5] Generating visualization...")
    
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle('DeepVis REALISTIC Evaluation: True Evasion Attempts', fontsize=14, fontweight='bold')
    
    # 1. Detection rates
    ax = axes[0, 0]
    atypes = list(results["per_attack"].keys())
    rates = [results["per_attack"][a]["detected"] / results["per_attack"][a]["total"] * 100 for a in atypes]
    colors = ['crimson' if r < 50 else 'orange' if r < 80 else 'forestgreen' for r in rates]
    bars = ax.bar(atypes, rates, color=colors)
    ax.axhline(y=80, color='green', linestyle='--', alpha=0.5)
    ax.axhline(y=50, color='orange', linestyle='--', alpha=0.5)
    ax.set_ylabel('Detection Rate (%)')
    ax.set_title('Per-Attack-Type Detection')
    ax.set_ylim(0, 110)
    for bar, rate in zip(bars, rates):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 2,
                f'{rate:.0f}%', ha='center', fontsize=9, fontweight='bold')
    plt.setp(ax.xaxis.get_majorticklabels(), rotation=25, ha='right')
    
    # 2. Evasion success
    ax = axes[0, 1]
    evaded = [(100 - r) for r in rates]
    ax.bar(atypes, evaded, color=['forestgreen' if e > 50 else 'orange' if e > 20 else 'crimson' for e in evaded])
    ax.set_ylabel('Evasion Success (%)')
    ax.set_title('Attacker Perspective: Evasion Success')
    ax.set_ylim(0, 110)
    plt.setp(ax.xaxis.get_majorticklabels(), rotation=25, ha='right')
    
    # 3. Confusion Matrix
    ax = axes[1, 0]
    cm = np.array([[TN, FP], [FN, TP]])
    im = ax.imshow(cm, cmap='Blues')
    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(['Normal', 'Attack'])
    ax.set_yticklabels(['Normal', 'Attack'])
    ax.set_xlabel('Predicted')
    ax.set_ylabel('Actual')
    ax.set_title('Confusion Matrix')
    for i in range(2):
        for j in range(2):
            ax.text(j, i, cm[i, j], ha='center', va='center', fontsize=16, fontweight='bold')
    
    # 4. Summary
    ax = axes[1, 1]
    ax.axis('off')
    summary = f"""
    REALISTIC EVALUATION SUMMARY
    ============================
    
    EVASION TECHNIQUES TESTED:
    • PARASITIC: Append to existing (<3% size)
    • PURE_LOTL: No .py/.sh/.so extensions  
    • MIMICRY: Match normal file statistics
    • MEMORY_ONLY: Minimal file footprint
    • EASY (Control): High-entropy malware
    
    RESULTS:
    ─────────────────────────────
    Precision: {precision:.4f}
    Recall:    {recall:.4f}  
    F1 Score:  {f1:.4f}
    FPR:       {fpr:.4f}
    
    KEY FINDING:
    ─────────────────────────────
    Sophisticated evasion techniques can
    defeat entropy-based detection.
    Defense requires multi-signal approach
    including behavioral analysis.
    """
    ax.text(0.02, 0.98, summary, transform=ax.transAxes, fontsize=9,
            verticalalignment='top', fontfamily='monospace',
            bbox=dict(boxstyle='round', facecolor='white', alpha=0.9))
    
    plt.tight_layout()
    plt.savefig('deepvis_realistic_evaluation.png', dpi=150, bbox_inches='tight')
    print("Saved: deepvis_realistic_evaluation.png")
    
    with open('deepvis_realistic_results.json', 'w') as f:
        json.dump({
            "metrics": {"precision": precision, "recall": recall, "f1": f1, "fpr": fpr},
            "per_attack": {k: {"detection_rate": v["detected"]/v["total"]} for k, v in results["per_attack"].items()},
            "confusion": {"TP": TP, "TN": TN, "FP": FP, "FN": FN}
        }, f, indent=2)
    print("Saved: deepvis_realistic_results.json")
    
    print("\n" + "=" * 70)
    print("EVALUATION COMPLETE")
    print("=" * 70)
    
    return results


if __name__ == "__main__":
    run_realistic_evaluation()
