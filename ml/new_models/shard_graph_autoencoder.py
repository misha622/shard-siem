#!/usr/bin/env python3
"""SHARD Graph Autoencoder — детектор аномальных графов (модель #15)"""

import numpy as np
import logging

logger = logging.getLogger("SHARD-GraphAE")

try:
    import torch
    import torch.nn as nn
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False

if HAS_TORCH:
    class GraphAutoencoder(nn.Module):
        """Автоэнкодер для графов — находит необычные паттерны связей"""
        def __init__(self, num_nodes=50, hidden_dim=64, latent_dim=16):
            super().__init__()
            # Encoder
            self.enc_fc1 = nn.Linear(num_nodes * num_nodes, 512)
            self.enc_fc2 = nn.Linear(512, hidden_dim)
            self.enc_mu = nn.Linear(hidden_dim, latent_dim)
            self.enc_logvar = nn.Linear(hidden_dim, latent_dim)
            
            # Decoder
            self.dec_fc1 = nn.Linear(latent_dim, hidden_dim)
            self.dec_fc2 = nn.Linear(hidden_dim, 512)
            self.dec_out = nn.Linear(512, num_nodes * num_nodes)
            
        def encode(self, x):
            h = torch.relu(self.enc_fc1(x))
            h = torch.relu(self.enc_fc2(h))
            return self.enc_mu(h), self.enc_logvar(h)
        
        def reparameterize(self, mu, logvar):
            std = torch.exp(0.5 * logvar)
            eps = torch.randn_like(std)
            return mu + eps * std
        
        def decode(self, z):
            h = torch.relu(self.dec_fc1(z))
            h = torch.relu(self.dec_fc2(h))
            return torch.sigmoid(self.dec_out(h))
        
        def forward(self, x):
            mu, logvar = self.encode(x)
            z = self.reparameterize(mu, logvar)
            return self.decode(z), mu, logvar

class GraphAEDetector:
    """Обнаружение аномальных графовых паттернов (модель #15)"""
    
    def __init__(self, num_nodes=50):
        self.model = GraphAutoencoder(num_nodes) if HAS_TORCH else None
        self.is_trained = False
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu') if HAS_TORCH else None
        self.threshold = 0.0
        
        if self.model:
            self.model.to(self.device)
    
    def train(self, adj_matrices, epochs=100):
        if self.model is None:
            return None
        
        self.model.train()
        optimizer = torch.optim.Adam(self.model.parameters(), lr=0.001)
        
        X = torch.FloatTensor(adj_matrices).to(self.device)
        X_flat = X.view(X.size(0), -1)
        
        for epoch in range(epochs):
            optimizer.zero_grad()
            recon, mu, logvar = self.model(X_flat)
            recon_loss = nn.functional.mse_loss(recon, X_flat, reduction='sum')
            kl_loss = -0.5 * torch.sum(1 + logvar - mu.pow(2) - logvar.exp())
            loss = recon_loss + 0.1 * kl_loss
            loss.backward()
            optimizer.step()
        
        # Устанавливаем порог
        with torch.no_grad():
            recon, _, _ = self.model(X_flat)
            errors = ((recon - X_flat) ** 2).mean(dim=1).cpu().numpy()
            self.threshold = np.percentile(errors, 95)
        
        self.is_trained = True
        return {'status': 'trained', 'threshold': float(self.threshold)}
    
    def predict(self, adj_matrix):
        if not self.is_trained or self.model is None:
            return {'is_anomaly': False, 'score': 0.0}
        
        self.model.eval()
        X = torch.FloatTensor(adj_matrix).to(self.device)
        X_flat = X.view(1, -1)
        
        with torch.no_grad():
            recon, _, _ = self.model(X_flat)
            error = ((recon - X_flat) ** 2).mean().item()
        
        score = min(1.0, error / (self.threshold + 1e-8))
        return {'is_anomaly': error > self.threshold, 'score': score, 'recon_error': error}

logger.info("✅ Graph Autoencoder ready (model #15)")
