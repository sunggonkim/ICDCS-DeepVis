"""
DeepVis 1×1 Convolutional Autoencoder
=====================================
ICDCS 2026 - CAE for File System Anomaly Detection

Architecture:
  Encoder: Conv1x1(3→16) → ReLU → Conv1x1(16→8)
  Decoder: Conv1x1(8→16) → ReLU → Conv1x1(16→3) → Sigmoid
  
Loss: MSE + λ·L∞ regularization

Why 1×1 Conv? Hash-based spatial mapping destroys neighborhood semantics.
1×1 convolutions learn per-pixel cross-channel correlations (R,G,B joint dist).
"""

import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from pathlib import Path

class DeepVisCAE(nn.Module):
    """1×1 Convolutional Autoencoder for tensor anomaly detection."""
    
    def __init__(self, latent_dim: int = 8):
        super().__init__()
        # Encoder: 3 → 16 → latent_dim
        self.encoder = nn.Sequential(
            nn.Conv2d(3, 16, kernel_size=1, bias=True),
            nn.ReLU(inplace=True),
            nn.Conv2d(16, latent_dim, kernel_size=1, bias=True),
        )
        # Decoder: latent_dim → 16 → 3
        self.decoder = nn.Sequential(
            nn.Conv2d(latent_dim, 16, kernel_size=1, bias=True),
            nn.ReLU(inplace=True),
            nn.Conv2d(16, 3, kernel_size=1, bias=True),
            nn.Sigmoid(),  # Output in [0, 1] for RGB normalization
        )
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        z = self.encoder(x)
        return self.decoder(z)
    
    def encode(self, x: torch.Tensor) -> torch.Tensor:
        return self.encoder(x)


def infer(model: DeepVisCAE, tensor: np.ndarray) -> dict:
    """
    Run inference on a single RGB tensor.
    
    Args:
        model: Trained DeepVisCAE model
        tensor: (H, W, 3) or (3, H, W) numpy array, values in [0, 1]
    
    Returns:
        dict with 'linf_score', 'mse', 'anomaly_map'
    """
    model.eval()
    
    # Ensure (B, C, H, W) format
    if tensor.ndim == 3:
        if tensor.shape[2] == 3:  # (H, W, 3) → (3, H, W)
            tensor = tensor.transpose(2, 0, 1)
        tensor = tensor[np.newaxis, ...]  # Add batch dim
    
    x = torch.from_numpy(tensor.astype(np.float32))
    
    with torch.no_grad():
        recon = model(x)
        diff = torch.abs(x - recon)
        
        linf_score = diff.max().item()
        mse = diff.pow(2).mean().item()
        anomaly_map = diff.squeeze().numpy()  # (3, H, W)
    
    return {
        'linf_score': linf_score,
        'mse': mse,
        'anomaly_map': anomaly_map,
    }


def train(model: DeepVisCAE, benign_tensors: list, epochs: int = 10, 
          lr: float = 1e-3, linf_lambda: float = 0.1) -> dict:
    """
    Train CAE on benign baseline tensors.
    
    Args:
        model: DeepVisCAE instance
        benign_tensors: List of (3, H, W) numpy arrays
        epochs: Training epochs
        lr: Learning rate
        linf_lambda: L∞ regularization weight
    
    Returns:
        Training history dict
    """
    model.train()
    optimizer = optim.Adam(model.parameters(), lr=lr)
    
    # Stack tensors → (N, 3, H, W)
    data = torch.from_numpy(np.stack(benign_tensors).astype(np.float32))
    
    history = {'mse': [], 'linf': [], 'total': []}
    
    for epoch in range(epochs):
        optimizer.zero_grad()
        
        recon = model(data)
        diff = torch.abs(data - recon)
        
        mse_loss = diff.pow(2).mean()
        linf_loss = diff.max()  # L∞ regularization
        total_loss = mse_loss + linf_lambda * linf_loss
        
        total_loss.backward()
        optimizer.step()
        
        history['mse'].append(mse_loss.item())
        history['linf'].append(linf_loss.item())
        history['total'].append(total_loss.item())
        
        print(f"Epoch {epoch+1}/{epochs} | MSE: {mse_loss:.4f} | L∞: {linf_loss:.4f}")
    
    return history


def export_onnx(model: DeepVisCAE, out_path: str = "model.onnx", img_size: int = 128):
    """Export trained model to ONNX for edge deployment."""
    model.eval()
    dummy_input = torch.randn(1, 3, img_size, img_size)
    torch.onnx.export(
        model, dummy_input, out_path,
        input_names=['tensor'],
        output_names=['reconstruction'],
        dynamic_axes={'tensor': {0: 'batch'}, 'reconstruction': {0: 'batch'}},
        opset_version=11,
    )
    print(f"Exported ONNX model to {out_path}")


# =============================================================================
# Quick Self-Test
# =============================================================================
if __name__ == "__main__":
    print("=== DeepVis CAE Self-Test ===")
    
    # 1. Instantiate model
    cae = DeepVisCAE(latent_dim=8)
    print(f"Model parameters: {sum(p.numel() for p in cae.parameters()):,}")
    
    # 2. Forward pass test
    x = torch.rand(1, 3, 128, 128)
    y = cae(x)
    assert y.shape == x.shape, "Shape mismatch!"
    print(f"Forward pass OK: {x.shape} → {y.shape}")
    
    # 3. Inference test
    tensor_np = np.random.rand(128, 128, 3)
    result = infer(cae, tensor_np)
    print(f"L∞ Score: {result['linf_score']:.4f}, MSE: {result['mse']:.6f}")
    
    # 4. Mini training test
    benign = [np.random.rand(3, 128, 128) * 0.3 for _ in range(5)]  # Low-valued benign
    history = train(cae, benign, epochs=3)
    
    print("\n✓ All tests passed!")
