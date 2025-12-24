
import os
import random
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
import matplotlib.pyplot as plt
from typing import List, Tuple
import argparse
from sklearn.metrics import roc_auc_score, precision_score, recall_score

# Import modules explicitly for clarity and to match new imports
import data_gen
import collect_real_data
import fs_to_img
import model
import baselines

from data_gen import generate_baseline, simulate_normal_update, simulate_rootkit_attack, simulate_diamorphine_attack, simulate_reptile_attack, simulate_beurk_attack
from collect_real_data import collect_system_baseline
from fs_to_img import files_to_image
from model import CAE

# Configuration
NUM_TRAIN_SAMPLES = 200
NUM_TEST_SAMPLES = 100
BATCH_SIZE = 32
EPOCHS = 10
LEARNING_RATE = 0.001
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
USE_REAL_DATA = True

def generate_dataset(mode="train", count=100, real_baseline_data=None) -> List[List[data_gen.FileEntry]]:
    """Generates a dataset of fs states (list of files)."""
    print(f"Generating {mode} dataset ({count} samples)...")
    states = []
    
    # REAL DATA LOGIC
    # We scan the system ONCE to get the 'True Baseline'.
    # Then we simulate updates/attacks on top of that True Baseline.
    # This prevents scanning the FS 1000 times (slow) and ensures consistency.
    
    if USE_REAL_DATA and real_baseline_data is None:
         # This block should ideally not be hit if real_baseline_data is passed from main
         # but kept for robustness if called directly.
         real_baseline_data = collect_system_baseline()
         print(f"  [Real Data] Baseline loaded with {len(real_baseline_data)} files.")

    for i in range(count):
        if i % 50 == 0: print(f"  Sample {i}/{count}")
        
        # Decide on baseline for this sample
        if USE_REAL_DATA:
             # IMPORTANT: deep copy needed to avoid modifying the original real_baseline_data
             base = [f.clone() for f in real_baseline_data] 
        else:
             base = generate_baseline()
        
        if mode == "test_normal":
            # Simulate a legit update from a baseline
            state = simulate_normal_update(base)
        elif mode == "test_attack":
            # Simulate an attack
            state = simulate_rootkit_attack(base)
        elif mode == "train":
            # For training on Real Data, we can't just copy the SAME exact baseline 200 times.
            # The AE would overfit to that exact state and flag valid updates as anomalies.
            # We must "Augment" the data by simulating "Valid Normal Updates" on the real baseline.
            # So the training set is: [RealState, RealState_v1.1, RealState_v1.2, ...]
            # This teaches the model: "This variance is acceptable."
             state = simulate_normal_update(base)
        else:
             state = base
            
        states.append(state)
        
    return states

def train(model, train_loader):
    criterion = nn.MSELoss()
    optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE)
    model.train()
    
    for epoch in range(EPOCHS):
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
        print(f"Epoch [{epoch+1}/{EPOCHS}], Loss: {avg_loss:.6f}")

def evaluate_cae(model, data_loader):
    criterion = nn.MSELoss(reduction='none') # We want error per image
    model.eval()
    
    errors = []
    
    with torch.no_grad():
        for batch in data_loader:
            batch = batch.to(DEVICE)
            outputs = model(batch)
            
            # Loss per sample: (Batch, 3, 128, 128) -> mean over dimensions 1,2,3
            loss = criterion(outputs, batch)
            loss = loss.mean(dim=(1, 2, 3)) 
            errors.extend(loss.cpu().numpy())
            
    return errors

def visualize_results(normal_errors, attack_errors, model, sample_attack_state):
    # 1. Histogram
    plt.figure(figsize=(10, 6))
    plt.hist(normal_errors, bins=30, alpha=0.7, label='Normal Updates', color='blue')
    plt.hist(attack_errors, bins=30, alpha=0.7, label='Rootkit Attacks', color='red')
    plt.xlabel('Reconstruction Error (MSE)')
    plt.ylabel('Count')
    plt.title('Anomaly Detection: Reconstruction Error Distribution')
    plt.legend()
    plt.savefig('reconstruction_errors.png')
    print("Saved reconstruction_errors.png")
    
    # 2. Difference Map (Visual Proof)
    # Get a single attack sample image
    img_np = files_to_image(sample_attack_state)
    img_tensor = torch.tensor(img_np, dtype=torch.float32).unsqueeze(0).to(DEVICE)
    
    with torch.no_grad():
        recon_tensor = model(img_tensor)
        
    diff_tensor = torch.abs(img_tensor - recon_tensor)
    
    # Convert to standard image format (H, W, C) for plotting
    orig = img_tensor.cpu().squeeze(0).permute(1, 2, 0).numpy()
    recon = recon_tensor.cpu().squeeze(0).permute(1, 2, 0).numpy()
    diff = diff_tensor.cpu().squeeze(0).permute(1, 2, 0).numpy()
    
    # Enhance diff contrast for visualization
    diff = diff / diff.max() 
    
    fig, axes = plt.subplots(1, 3, figsize=(15, 5))
    axes[0].imshow(orig)
    axes[0].set_title("Original (Attack)")
    axes[0].axis('off')
    
    axes[1].imshow(recon)
    axes[1].set_title("Reconstructed (by Normal CAE)")
    axes[1].axis('off')
    
    axes[2].imshow(diff, cmap='hot')
    axes[2].set_title("Difference Map (Anomaly Location)")
    axes[2].axis('off')
    
    plt.savefig('difference_map.png')
    print("Saved difference_map.png")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--real-data", action="store_true", help="Use real system file scan as baseline")
    parser.add_argument("--no-entropy", action="store_true", help="Disable entropy channel (Ablation)")
    args = parser.parse_args()
    
    global USE_REAL_DATA
    USE_REAL_DATA = args.real_data or True # Default to True for this run
    
    print("Starting 'See No Evil' Prototype Pipeline (USENIX Mode)...")
    torch.manual_seed(42)
    np.random.seed(42)
    random.seed(42)
    
    # 1. Generate Data (Train)
    # Load real baseline ONCE
    real_baseline = collect_system_baseline() if USE_REAL_DATA else None
    
    train_data_states = generate_dataset("train", NUM_TRAIN_SAMPLES, real_baseline)
    # Convert states to images for CAE
    train_images = [files_to_image(s) for s in train_data_states]
    train_tensor = torch.tensor(np.stack(train_images), dtype=torch.float32)
    train_loader = torch.utils.data.DataLoader(train_tensor, batch_size=BATCH_SIZE, shuffle=True)
    
    # 2. Train CAE
    cae = CAE().to(DEVICE)
    print("Training CAE...")
    train(cae, train_loader)
    
    # 3. Train Baselines (IsoForest, AIDE)
    print("\nTraining Baselines (IsoForest, AIDE)...")
    isolation_forest = baselines.BaselineIsolationForest()
    isolation_forest.train(train_data_states)
    
    aide = baselines.BaselineAIDE()
    # AIDE needs a single 'clean' baseline state. Use the first one.
    aide.train(train_data_states[0]) 

    # 4. Generate Test Sets (Normal Churn vs Specific Attacks)
    print("Generating Test Sets...")
    test_normal = generate_dataset("test_normal", NUM_TEST_SAMPLES, real_baseline)
    
    # Generate Specific Attack Scenarios
    specific_attacks = []
    print("Generating Specific Rootkit Scenarios (Diamorphine, Reptile, Beurk)...")
    for _ in range(30):
        if real_baseline:
            base = [f.clone() for f in real_baseline]
        else:
            base = generate_baseline()
            
        s1 = simulate_diamorphine_attack(base)
        s2 = simulate_reptile_attack(base)
        s3 = simulate_beurk_attack(base)
        specific_attacks.extend([s1, s2, s3])

    # 5. Comparative Evaluation
    print("\n--- Comparative Evaluation ---")
    
    y_true = []
    deepvis_scores = []
    iso_scores = [] # -1 (anomaly), 1 (normal)
    aide_alerted = [] # Binary
    
    # Evaluate Normal (Churn)
    for sample in test_normal:
        y_true.append(0)
        
        # DeepVis (Local Max Diff)
        img = files_to_image(sample)
        inp = torch.tensor(img).unsqueeze(0).to(DEVICE)
        rec = cae(inp)
        diff = torch.abs(inp - rec).cpu().detach().numpy()
        deepvis_scores.append(np.max(diff))
        
        # Isolation Forest
        pred = isolation_forest.predict(sample) # 1 normal, -1 anomaly
        iso_scores.append(1 if pred == -1 else 0)
        
        # AIDE
        diffs = aide.predict_files(sample)
        aide_alerted.append(1 if len(diffs) > 0 else 0)
        
    # Evaluate Attacks
    for sample in specific_attacks:
        y_true.append(1)
        
        # DeepVis
        img = files_to_image(sample)
        inp = torch.tensor(img).unsqueeze(0).to(DEVICE)
        rec = cae(inp)
        diff = torch.abs(inp - rec).cpu().detach().numpy()
        deepvis_scores.append(np.max(diff))
        
        # Isolation Forest
        pred = isolation_forest.predict(sample)
        iso_scores.append(1 if pred == -1 else 0)
        
        # AIDE
        diffs = aide.predict_files(sample)
        aide_alerted.append(1 if len(diffs) > 0 else 0)

    # Metrics
    deepvis_auc = roc_auc_score(y_true, deepvis_scores)
    # For IsoForest/AIDE binary outputs, AUC is effectively (Sensitivity + Specificity)/2
    iso_auc = roc_auc_score(y_true, iso_scores)
    aide_auc = roc_auc_score(y_true, aide_alerted)
    
    print(f"\n[Final Results]")
    print(f"DeepVis AUC: {deepvis_auc:.4f}")
    print(f"IsoForest AUC: {iso_auc:.4f}")
    print(f"AIDE Precision (Simulated): {precision_score(y_true, aide_alerted):.4f}")
    print(f"AIDE Recall (Simulated): {recall_score(y_true, aide_alerted):.4f}")
    
    # Save Separation Plot
    plt.figure(figsize=(10, 6))
    normal_scores = [s for s, y in zip(deepvis_scores, y_true) if y==0]
    attack_scores = [s for s, y in zip(deepvis_scores, y_true) if y==1]
    
    plt.hist(normal_scores, bins=50, alpha=0.5, label='Normal Update (Churn)', density=True)
    plt.hist(attack_scores, bins=50, alpha=0.5, label='Specific Rootkits', density=True)
    plt.legend()
    plt.title("DeepVis Anomaly Score Distribution")
    plt.xlabel("Local Max Reconstruction Error")
    plt.savefig('deepvis_separation.png')
    print("Saved deepvis_separation.png")
    
    # Save Difference Map for last attack
    visualize_results(normal_scores, attack_scores, cae, specific_attacks[-1])

    print("Pipeline Complete.")

if __name__ == "__main__":
    main()
