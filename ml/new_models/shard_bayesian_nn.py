#!/usr/bin/env python3
"""SHARD Bayesian Neural Network — детектор с confidence (модель #14)"""

import numpy as np
import logging

logger = logging.getLogger("SHARD-BayesianNN")

try:
    import torch
    import torch.nn as nn
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False

if HAS_TORCH:
    class BayesianLayer(nn.Module):
        """Байесовский слой с dropout для оценки неопределённости"""
        def __init__(self, in_dim, out_dim, dropout=0.2):
            super().__init__()
            self.linear = nn.Linear(in_dim, out_dim)
            self.dropout = nn.Dropout(dropout)
            self.bn = nn.BatchNorm1d(out_dim)
        
        def forward(self, x):
            return self.bn(self.dropout(torch.relu(self.linear(x))))
    
    class BayesianNN(nn.Module):
        """Байесовская нейросеть — даёт confidence вместе с предсказанием"""
        def __init__(self, input_dim=156, hidden_dims=[256, 128, 64], num_classes=2):
            super().__init__()
            layers = []
            prev_dim = input_dim
            for h_dim in hidden_dims:
                layers.append(BayesianLayer(prev_dim, h_dim))
                prev_dim = h_dim
            self.encoder = nn.Sequential(*layers)
            self.classifier = nn.Linear(prev_dim, num_classes)
        
        def forward(self, x, num_samples=10):
            """Возвращает предсказание + uncertainty"""
            self.train()  # Включаем dropout для MC Dropout
            preds = []
            for _ in range(num_samples):
                h = self.encoder(x)
                preds.append(torch.softmax(self.classifier(h), dim=-1))
            preds = torch.stack(preds)
            mean = preds.mean(dim=0)
            std = preds.std(dim=0)
            return mean, std

class BayesianNNDetector:
    """Детектор с оценкой уверенности (модель #14)"""
    
    def __init__(self, input_dim=156):
        self.model = BayesianNN(input_dim) if HAS_TORCH else None
        self.is_trained = False
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu') if HAS_TORCH else None
        
        if self.model:
            self.model.to(self.device)
    
    def train(self, X, y, epochs=50):
        if self.model is None:
            return None
        
        self.model.train()
        optimizer = torch.optim.Adam(self.model.parameters(), lr=0.001)
        criterion = nn.CrossEntropyLoss()
        
        X_t = torch.FloatTensor(X).to(self.device)
        y_t = torch.LongTensor(y).to(self.device)
        
        for epoch in range(epochs):
            optimizer.zero_grad()
            mean, std = self.model(X_t, num_samples=5)
            loss = criterion(mean, y_t) + 0.01 * std.mean()
            loss.backward()
            optimizer.step()
        
        self.is_trained = True
        return {'status': 'trained', 'epochs': epochs}
    
    def predict(self, X):
        if not self.is_trained or self.model is None:
            return np.zeros(len(X)), np.zeros(len(X))
        
        self.model.eval()
        X_t = torch.FloatTensor(X).to(self.device)
        with torch.no_grad():
            mean, std = self.model(X_t, num_samples=10)
            preds = mean.argmax(dim=1).cpu().numpy()
            uncertainty = std.max(dim=1)[0].cpu().numpy()
        return preds, uncertainty

logger.info("✅ Bayesian NN ready (model #14)")
