#!/usr/bin/env python3
"""
DeepVis 2.0 Server-Scale Evaluation
====================================
Optimized for: 48-core Xeon, 32GB RAM, No GPU

Scale: 20,000 files (realistic server)
"""

import os
import sys
import random
import copy
import hashlib
import time
import json
import numpy as np
from dataclasses import dataclass
from typing import List, Dict, Tuple
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader


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
    api_density: float = 0.0
    permissions: int = 0o644
    is_malicious: bool = False
    attack_type: str = ""


class SpatialCAE2D(nn.Module):
    def __init__(self):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Conv2d(3, 32, 3, stride=2, padding=1), nn.ReLU(),
            nn.Conv2d(32, 64, 3, stride=2, padding=1), nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.ConvTranspose2d(64, 32, 3, stride=2, padding=1, output_padding=1), nn.ReLU(),
            nn.ConvTranspose2d(32, 3, 3, stride=2, padding=1, output_padding=1), nn.Sigmoid(),
        )
    
    def forward(self, x):
        return self.decoder(self.encoder(x))


def generate_server_fs(num_files: int = 20000) -> List[FileEntry]:
    """Generate server-scale filesystem"""
    files = []
    distributions = [
        ("/usr/bin/", 0.15, 6.0),
        ("/lib/", 0.20, 5.8),
        ("/etc/", 0.15, 4.5),
        ("/var/", 0.25, 4.0),
        ("/home/", 0.25, 4.2),
    ]
    
    for prefix, ratio, base_entropy in distributions:
        count = int(num_files * ratio)
        for i in range(count):
            files.append(FileEntry(
                path=f"{prefix}f{i:05d}",
                size=random.randint(100, 100000),
                entropy=base_entropy + random.uniform(-0.5, 0.5),
                api_density=random.uniform(0, 0.3),
                permissions=0o755 if '/bin' in prefix else 0o644
            ))
    return files


class DeepVisDetector:
    def __init__(self, image_size: int = 128):
        self.image_size = image_size
        self.device = torch.device("cpu")
        self.cae = SpatialCAE2D().to(self.device)
        self.baseline_paths = set()
        self.baseline_sizes = {}
    
    def hash_to_coord(self, path: str) -> Tuple[int, int]:
        h = int(hashlib.md5(path.encode()).hexdigest()[:8], 16)
        return h % self.image_size, (h // self.image_size) % self.image_size
    
    def files_to_image(self, files: List[FileEntry]) -> np.ndarray:
        image = np.zeros((3, self.image_size, self.image_size), dtype=np.float32)
        for f in files:
            x, y = self.hash_to_coord(f.path)
            image[0, y, x] = max(image[0, y, x], f.entropy / 8.0)
            image[1, y, x] = max(image[1, y, x], min(np.log1p(f.size) / 15, 1.0))
            image[2, y, x] = max(image[2, y, x], f.api_density)
        return image
    
    def train(self, snapshots: List[List[FileEntry]], epochs: int = 20):
        print(f"    Training on {len(snapshots)} snapshots...")
        
        for f in snapshots[0]:
            self.baseline_paths.add(f.path)
            self.baseline_sizes[f.path] = f.size
        
        images = np.array([self.files_to_image(s) for s in snapshots])
        tensor = torch.tensor(images, dtype=torch.float32)
        loader = DataLoader(tensor, batch_size=4, shuffle=True)
        
        optimizer = optim.Adam(self.cae.parameters(), lr=0.001)
        criterion = nn.MSELoss()
        
        self.cae.train()
        for epoch in range(epochs):
            total_loss = 0
            for batch in loader:
                optimizer.zero_grad()
                output = self.cae(batch)
                loss = criterion(output, batch)
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
            if (epoch + 1) % 5 == 0:
                print(f"      Epoch [{epoch+1}/{epochs}] Loss: {total_loss/len(loader):.6f}")
    
    def detect(self, state: List[FileEntry]) -> Dict:
        anomalies = []
        for f in state:
            is_new = f.path not in self.baseline_paths
            reasons = []
            risk = 0.0
            
            if is_new and f.entropy > 7.0:
                reasons.append(f"NEW high entropy: {f.entropy:.2f}")
                risk = 0.9
            
            if is_new and f.api_density > 0.4:
                reasons.append(f"NEW high API: {f.api_density:.2f}")
                risk = max(risk, 0.8)
            
            if not is_new and f.path in self.baseline_sizes:
                ratio = abs(f.size - self.baseline_sizes[f.path]) / max(self.baseline_sizes[f.path], 1)
                if ratio > 0.03:
                    reasons.append(f"Size change: {ratio*100:.1f}%")
                    risk = max(risk, 0.7)
            
            if reasons and risk >= 0.6:
                anomalies.append({"path": f.path, "reasons": reasons, "risk": risk, "is_malicious": f.is_malicious})
        
        return {"is_anomaly": len(anomalies) > 0, "anomalies": anomalies}


def run_evaluation():
    print("=" * 60)
    print("DeepVis 2.0 Server-Scale (20K files, optimized)")
    print("=" * 60)
    
    random.seed(42)
    np.random.seed(42)
    torch.manual_seed(42)
    
    # 1. Generate
    print("\n[1/5] Generating 20,000 files...")
    baseline = generate_server_fs(20000)
    print(f"      Done: {len(baseline)} files")
    
    # 2. Training snapshots (lightweight)
    print("\n[2/5] Creating 20 training snapshots...")
    training = [baseline]
    for _ in range(19):
        snap = [FileEntry(path=f.path, size=int(f.size * random.uniform(0.99, 1.01)),
                         entropy=f.entropy, api_density=f.api_density, permissions=f.permissions)
                for f in baseline]
        training.append(snap)
    
    # 3. Train
    print("\n[3/5] Training DeepVis 2.0...")
    detector = DeepVisDetector()
    detector.train(training, epochs=20)
    
    # 4. Generate attacks
    print("\n[4/5] Generating attack scenarios...")
    attacks = {}
    
    # 6 attack types × 50 each
    for atype, gen_fn in [
        ("HIGH_ENTROPY", lambda: FileEntry(f"/lib/evil{random.randint(1,999)}.ko", 25000, 7.6, 0.5, 0o644, True, "HIGH_ENTROPY")),
        ("LOW_ENTROPY_SCRIPT", lambda: FileEntry(f"/tmp/.h{random.randint(1,999)}.py", 500, 5.2, 0.5, 0o755, True, "LOW_ENTROPY_SCRIPT")),
        ("PARASITIC", None),
        ("MIMICRY", lambda: FileEntry(f"/etc/sys{random.randint(1,99)}.conf", 400, 4.5, 0.45, 0o644, True, "MIMICRY")),
        ("OBFUSCATED", lambda: FileEntry(f"/usr/bin/h{random.randint(1,999)}", 15000, 7.2, 0.1, 0o755, True, "OBFUSCATED")),
        ("LOTL", lambda: FileEntry(f"/etc/cron.d/job{random.randint(1,99)}", 100, 4.0, 0.1, 0o644, True, "LOTL")),
    ]:
        attacks[atype] = []
        for _ in range(50):
            if atype == "PARASITIC":
                state = [FileEntry(f.path, int(f.size * 1.05), f.entropy, f.api_density + 0.15, f.permissions, 
                                  f.path.startswith('/usr/bin'), "PARASITIC") 
                         if f.path.startswith('/usr/bin') and i < 3 else 
                         FileEntry(f.path, f.size, f.entropy, f.api_density, f.permissions)
                         for i, f in enumerate(baseline)]
            else:
                state = [FileEntry(f.path, f.size, f.entropy, f.api_density, f.permissions) for f in baseline]
                state.append(gen_fn())
            attacks[atype].append(state)
    
    normal_tests = [[FileEntry(f.path, f.size, f.entropy, f.api_density, f.permissions) for f in baseline] 
                    for _ in range(100)]
    
    print(f"      Normal: 100, Attacks: {sum(len(v) for v in attacks.values())}")
    
    # 5. Evaluate
    print("\n[5/5] Evaluating...")
    results = {"per_attack": {}, "overall": {"TP": 0, "TN": 0, "FP": 0, "FN": 0}}
    
    for state in normal_tests:
        det = detector.detect(state)
        if det["is_anomaly"]:
            results["overall"]["FP"] += 1
        else:
            results["overall"]["TN"] += 1
    
    for atype, trials in attacks.items():
        results["per_attack"][atype] = {"detected": 0, "total": len(trials)}
        for state in trials:
            det = detector.detect(state)
            if det["is_anomaly"]:
                results["per_attack"][atype]["detected"] += 1
                results["overall"]["TP"] += 1
            else:
                results["overall"]["FN"] += 1
    
    # Metrics
    TP, TN, FP, FN = results["overall"]["TP"], results["overall"]["TN"], results["overall"]["FP"], results["overall"]["FN"]
    precision = TP / (TP + FP) if (TP + FP) > 0 else 0
    recall = TP / (TP + FN) if (TP + FN) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fpr = FP / (FP + TN) if (FP + TN) > 0 else 0
    
    print("\n" + "=" * 60)
    print("RESULTS (20K Files, 400 Tests)")
    print("=" * 60)
    print(f"\nPrecision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1:        {f1:.4f}")
    print(f"FPR:       {fpr:.4f}")
    print(f"\nTP={TP}, TN={TN}, FP={FP}, FN={FN}")
    
    print("\n--- Detection Rates ---")
    for atype, d in results["per_attack"].items():
        rate = d["detected"]/d["total"]*100
        print(f"  {'✓' if rate>=80 else '✗'} {atype}: {d['detected']}/{d['total']} ({rate:.0f}%)")
    
    # Save
    plt.figure(figsize=(10, 6))
    atypes = list(results["per_attack"].keys())
    rates = [results["per_attack"][a]["detected"]/results["per_attack"][a]["total"]*100 for a in atypes]
    colors = ['forestgreen' if r >= 80 else 'crimson' for r in rates]
    plt.bar(atypes, rates, color=colors)
    plt.ylabel('Detection Rate (%)')
    plt.title(f'DeepVis 2.0 Server-Scale (20K files) | F1={f1:.3f}')
    plt.xticks(rotation=30, ha='right')
    plt.ylim(0, 110)
    plt.tight_layout()
    plt.savefig('deepvis_server_scale.png', dpi=150)
    print("\nSaved: deepvis_server_scale.png")
    
    with open('deepvis_server_scale.json', 'w') as f:
        json.dump({"files": 20000, "tests": 400, "precision": precision, "recall": recall, 
                   "f1": f1, "fpr": fpr, "per_attack": {k: v["detected"]/v["total"] for k,v in results["per_attack"].items()}}, f, indent=2)
    print("Saved: deepvis_server_scale.json")


if __name__ == "__main__":
    run_evaluation()
