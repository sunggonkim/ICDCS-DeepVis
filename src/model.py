
import torch
import torch.nn as nn

class CAE(nn.Module):
    def __init__(self):
        super(CAE, self).__init__()
        
        # Encoder
        # Input: (3, 128, 128)
        self.encoder = nn.Sequential(
            # Layer 1
            nn.Conv2d(3, 32, kernel_size=3, padding=1),
            nn.ReLU(True),
            nn.MaxPool2d(2, stride=2), # -> (32, 64, 64)
            
            # Layer 2
            nn.Conv2d(32, 64, kernel_size=3, padding=1),
            nn.ReLU(True),
            nn.MaxPool2d(2, stride=2), # -> (64, 32, 32)
            
            # Layer 3
            nn.Conv2d(64, 128, kernel_size=3, padding=1),
            nn.ReLU(True),
            nn.MaxPool2d(2, stride=2)  # -> (128, 16, 16)
        )
        
        # Decoder
        self.decoder = nn.Sequential(
            # Layer 1
            nn.ConvTranspose2d(128, 64, kernel_size=2, stride=2),
            nn.ReLU(True), # -> (64, 32, 32)
            
            # Layer 2
            nn.ConvTranspose2d(64, 32, kernel_size=2, stride=2),
            nn.ReLU(True), # -> (32, 64, 64)
            
            # Layer 3
            nn.ConvTranspose2d(32, 3, kernel_size=2, stride=2),
            nn.Sigmoid() # -> (3, 128, 128) Range [0, 1]
        )

    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

if __name__ == "__main__":
    # Smoke test
    model = CAE()
    dummy_input = torch.randn(1, 3, 128, 128)
    output = model(dummy_input)
    print(f"Input shape: {dummy_input.shape}")
    print(f"Output shape: {output.shape}")
    assert output.shape == (1, 3, 128, 128), "Shape mismatch!"
    print("Model architecture verified.")
