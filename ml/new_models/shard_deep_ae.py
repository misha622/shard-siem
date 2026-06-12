"""SHARD Deep Autoencoder — сжатие и восстановление для детекта аномалий (#24)"""
import numpy as np, torch, torch.nn as nn, logging, pickle
from pathlib import Path
logger = logging.getLogger("SHARD-DeepAE")

class DeepAutoencoder(nn.Module):
    def __init__(self, input_dim=76, latent_dim=16):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 256), nn.ReLU(), nn.BatchNorm1d(256),
            nn.Linear(256, 128), nn.ReLU(), nn.BatchNorm1d(128),
            nn.Linear(128, 64), nn.ReLU(), nn.BatchNorm1d(64),
            nn.Linear(64, latent_dim)
        )
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 64), nn.ReLU(), nn.BatchNorm1d(64),
            nn.Linear(64, 128), nn.ReLU(), nn.BatchNorm1d(128),
            nn.Linear(128, 256), nn.ReLU(), nn.BatchNorm1d(256),
            nn.Linear(256, input_dim), nn.Sigmoid()
        )
    def forward(self, x): return self.decoder(self.encoder(x))

class DeepAEDetector:
    def __init__(self, input_dim=76):
        self.model = DeepAutoencoder(input_dim)
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model.to(self.device)
        self.threshold = 0.0
        self.is_trained = False
    
    def train(self, X, epochs=50):
        self.model.train()
        opt = torch.optim.Adam(self.model.parameters(), lr=0.001)
        X_t = torch.FloatTensor(X).to(self.device)
        for _ in range(epochs):
            opt.zero_grad()
            recon = self.model(X_t)
            loss = nn.MSELoss()(recon, X_t)
            loss.backward()
            opt.step()
        self.model.eval()
        with torch.no_grad():
            errors = ((self.model(X_t) - X_t) ** 2).mean(dim=1).cpu().numpy()
            self.threshold = np.percentile(errors, 95)
        self.is_trained = True
        return {'threshold': float(self.threshold)}
    
    def predict(self, X):
        if not self.is_trained: return np.zeros(len(X)), np.ones(len(X))
        self.model.eval()
        X_t = torch.FloatTensor(X).to(self.device)
        with torch.no_grad():
            errors = ((self.model(X_t) - X_t) ** 2).mean(dim=1).cpu().numpy()
        scores = np.clip(errors / (self.threshold + 1e-8), 0, 2)
        return (scores > 1.0).astype(int), scores / 2.0

logger.info("✅ DeepAE ready (#24)")
