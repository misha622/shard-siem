#!/usr/bin/env python3
"""
SHARD FT-Transformer — Feature Tokenizer Transformer (#33)
SOTA на табличных данных (2021-2024).
Преобразует признаки в токены и применяет Transformer.
"""

import numpy as np, logging
import torch, torch.nn as nn, torch.nn.functional as F

logger = logging.getLogger("SHARD-FTTransformer")

class FTTransformer(nn.Module):
    def __init__(self, input_dim=76, num_classes=2, dim=192, depth=4, heads=8, dropout=0.1):
        super().__init__()
        self.cls_token = nn.Parameter(torch.randn(1, 1, dim))
        self.feature_embed = nn.Linear(1, dim)
        self.pos_embed = nn.Parameter(torch.randn(1, input_dim + 1, dim))
        
        encoder_layer = nn.TransformerEncoderLayer(d_model=dim, nhead=heads, dropout=dropout, batch_first=True)
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=depth)
        self.norm = nn.LayerNorm(dim)
        self.head = nn.Linear(dim, num_classes)
    
    def forward(self, x):
        x = x.unsqueeze(-1)  # (B, F, 1)
        x = self.feature_embed(x)  # (B, F, dim)
        cls = self.cls_token.expand(x.size(0), -1, -1)
        x = torch.cat([cls, x], dim=1)  # (B, F+1, dim)
        x = x + self.pos_embed
        x = self.transformer(x)
        x = self.norm(x[:, 0])  # CLS token
        return self.head(x)

class FTTransformerDetector:
    def __init__(self, input_dim=76):
        self.model = FTTransformer(input_dim)
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model.to(self.device)
        self.is_trained = False
    
    def train(self, X, y, epochs=30):
        self.model.train()
        opt = torch.optim.AdamW(self.model.parameters(), lr=0.0001, weight_decay=0.01)
        sched = torch.optim.lr_scheduler.OneCycleLR(opt, max_lr=0.001, epochs=epochs, steps_per_epoch=1)
        X_t = torch.FloatTensor(X).to(self.device)
        y_t = torch.LongTensor(y).to(self.device)
        for _ in range(epochs):
            opt.zero_grad()
            loss = F.cross_entropy(self.model(X_t), y_t)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
            opt.step()
            sched.step()
        self.is_trained = True
        return {'epochs': epochs}
    
    def predict(self, X):
        if not self.is_trained: return np.zeros(len(X)), np.ones(len(X))
        self.model.eval()
        X_t = torch.FloatTensor(X).to(self.device)
        with torch.no_grad():
            probs = F.softmax(self.model(X_t), dim=-1)[:, 1].cpu().numpy()
        return (probs > 0.5).astype(int), probs

logger.info("✅ FT-Transformer ready (#33)")
