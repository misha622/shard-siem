#!/usr/bin/env python3
"""SHARD CNN1D — свёрточный детектор паттернов в пакетах (модель #19)"""
import numpy as np, logging
logger = logging.getLogger("SHARD-CNN1D")
try:
    import torch, torch.nn as nn
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False

if HAS_TORCH:
    class CNN1DDetector(nn.Module):
        def __init__(self, input_dim=156, num_classes=2):
            super().__init__()
            self.conv1 = nn.Conv1d(1, 32, kernel_size=3, padding=1)
            self.conv2 = nn.Conv1d(32, 64, kernel_size=5, padding=2)
            self.conv3 = nn.Conv1d(64, 128, kernel_size=7, padding=3)
            self.pool = nn.AdaptiveAvgPool1d(16)
            self.fc1 = nn.Linear(128 * 16, 256)
            self.fc2 = nn.Linear(256, num_classes)
            self.dropout = nn.Dropout(0.3)
        
        def forward(self, x):
            if x.dim() == 2: x = x.unsqueeze(1)
            x = torch.relu(self.conv1(x))
            x = torch.relu(self.conv2(x))
            x = torch.relu(self.conv3(x))
            x = self.pool(x)
            x = x.view(x.size(0), -1)
            x = self.dropout(torch.relu(self.fc1(x)))
            return self.fc2(x)

class CNN1DWrapper:
    def __init__(self, input_dim=156):
        self.model = CNN1DDetector(input_dim) if HAS_TORCH else None
        self.is_trained = False
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu') if HAS_TORCH else None
        if self.model: self.model.to(self.device)
    
    def train(self, X, y, epochs=30):
        if self.model is None: return None
        self.model.train()
        opt = torch.optim.Adam(self.model.parameters(), lr=0.001)
        crit = nn.CrossEntropyLoss()
        X_t = torch.FloatTensor(X).to(self.device)
        y_t = torch.LongTensor(y).to(self.device)
        for _ in range(epochs):
            opt.zero_grad()
            loss = crit(self.model(X_t), y_t)
            loss.backward()
            opt.step()
        self.is_trained = True
        return {'epochs': epochs}
    
    def predict(self, X):
        if not self.is_trained: return np.zeros(len(X)), np.ones(len(X))
        self.model.eval()
        X_t = torch.FloatTensor(X).to(self.device)
        with torch.no_grad():
            probs = torch.softmax(self.model(X_t), dim=-1)[:, 1].cpu().numpy()
        return (probs > 0.5).astype(int), probs

logger.info("✅ CNN1D ready (model #19)")
