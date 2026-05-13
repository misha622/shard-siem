#!/usr/bin/env python3
"""
SHARD Multi-Modal Fusion Network
Объединяет выходы всех нейросетей в единый Threat Score
Cross-Attention между модальностями: логи, трафик, алерты, honeypot
"""

import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
import random
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SHARD-Fusion")

CONFIG = {
    'num_modalities': 7,
    'modal_dims': [13, 100, 5, 1, 1, 3, 1],
    'fusion_dim': 128,
    'num_heads': 4,
    'num_layers': 2,
    'dropout': 0.1,
    'epochs': 300,
    'lr': 0.001,
    'batch_size': 32,
}


class MultiModalFusion(nn.Module):
    
    def __init__(self, num_modalities=7, modal_dims=None, fusion_dim=128, num_heads=4, num_layers=2, dropout=0.1):
        super().__init__()
        
        if modal_dims is None:
            modal_dims = [13, 100, 5, 1, 1, 3, 1]
        
        self.projections = nn.ModuleList([
            nn.Sequential(
                nn.Linear(dim, fusion_dim),
                nn.LayerNorm(fusion_dim),
                nn.ReLU(),
            ) for dim in modal_dims
        ])
        
        self.cross_attention = nn.MultiheadAttention(
            embed_dim=fusion_dim,
            num_heads=num_heads,
            dropout=dropout,
            batch_first=True,
        )
        
        self.self_attention = nn.MultiheadAttention(
            embed_dim=fusion_dim,
            num_heads=num_heads,
            dropout=dropout,
            batch_first=True,
        )
        
        self.classifier = nn.Sequential(
            nn.Linear(fusion_dim, fusion_dim * 2),
            nn.LayerNorm(fusion_dim * 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(fusion_dim * 2, fusion_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(fusion_dim, 3),
        )
        
        self.confidence_head = nn.Sequential(
            nn.Linear(fusion_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 1),
            nn.Sigmoid(),
        )
        
        self.modal_weights = nn.Parameter(torch.ones(num_modalities) / num_modalities)
    
    def forward(self, modalities):
        projected = []
        for i, proj in enumerate(self.projections):
            p = proj(modalities[i])
            projected.append(p)
        
        stacked = torch.stack(projected, dim=1)
        
        attn_out, _ = self.cross_attention(stacked, stacked, stacked)
        
        fused, _ = self.self_attention(attn_out, attn_out, attn_out)
        
        weights = torch.softmax(self.modal_weights, dim=0)
        fused_weighted = (fused * weights.unsqueeze(0).unsqueeze(-1)).sum(dim=1)
        
        threat_logits = self.classifier(fused_weighted)
        confidence = self.confidence_head(fused_weighted)
        
        return threat_logits, confidence, weights


class FusionDataset(torch.utils.data.Dataset):
    
    def __init__(self, size=5000):
        self.size = size
        self.data = []
        
        for _ in range(size):
            is_attack = random.random() < 0.4
            
            if not is_attack:
                modalities = [
                    torch.rand(13) * 0.2,
                    torch.randn(100) * 0.1,
                    torch.tensor([0.8, 0.1, 0.05, 0.03, 0.02]),
                    torch.tensor([random.uniform(0, 0.3)]),
                    torch.tensor([random.uniform(0, 0.2)]),
                    torch.tensor([0.8, 0.15, 0.05]),
                    torch.tensor([random.uniform(0, 0.3)]),
                ]
                label = 0
            elif random.random() < 0.5:
                atype = random.randint(0, 12)
                modalities = [
                    torch.rand(13) * 0.5 + torch.tensor([1.0 if i == atype else 0.0 for i in range(13)]) * 0.5,
                    torch.randn(100) * 0.5,
                    torch.tensor([0.1, 0.2, 0.4, 0.2, 0.1]),
                    torch.tensor([random.uniform(0.3, 0.6)]),
                    torch.tensor([random.uniform(0.2, 0.5)]),
                    torch.tensor([0.1, 0.7, 0.2]),
                    torch.tensor([random.uniform(0.3, 0.6)]),
                ]
                label = 1
            else:
                atype = random.randint(0, 12)
                modalities = [
                    torch.rand(13) * 0.3 + torch.tensor([1.0 if i == atype else 0.0 for i in range(13)]) * 0.7,
                    torch.randn(100) * 0.8 + 0.5,
                    torch.tensor([0.02, 0.03, 0.05, 0.3, 0.6]),
                    torch.tensor([random.uniform(0.7, 1.0)]),
                    torch.tensor([random.uniform(0.6, 1.0)]),
                    torch.tensor([0.02, 0.08, 0.9]),
                    torch.tensor([random.uniform(0.7, 1.0)]),
                ]
                label = 2
            
            self.data.append((modalities, label))
    
    def __len__(self):
        return self.size
    
    def __getitem__(self, idx):
        return self.data[idx]


def collate_fn(batch):
    modalities_list = [[] for _ in range(len(batch[0][0]))]
    labels = []
    
    for mods, label in batch:
        for i, m in enumerate(mods):
            modalities_list[i].append(m)
        labels.append(label)
    
    return [torch.stack(m) for m in modalities_list], torch.tensor(labels, dtype=torch.long)


def train():
    logger.info("="*60)
    logger.info("🧠 SHARD Multi-Modal Fusion — Cross-Attention Ensemble")
    logger.info("="*60)
    
    dataset = FusionDataset(5000)
    dataloader = torch.utils.data.DataLoader(
        dataset, batch_size=CONFIG['batch_size'], shuffle=True, collate_fn=collate_fn
    )
    
    model = MultiModalFusion(
        num_modalities=CONFIG['num_modalities'],
        modal_dims=CONFIG['modal_dims'],
        fusion_dim=CONFIG['fusion_dim'],
        num_heads=CONFIG['num_heads'],
        num_layers=CONFIG['num_layers'],
        dropout=CONFIG['dropout'],
    )
    
    params = sum(p.numel() for p in model.parameters())
    logger.info(f"\n🧠 Model: {params:,} parameters")
    logger.info(f"   Modalities: {CONFIG['num_modalities']}, Fusion dim: {CONFIG['fusion_dim']}")
    
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.AdamW(model.parameters(), lr=CONFIG['lr'], weight_decay=0.01)
    
    logger.info(f"\n🔄 Training {CONFIG['epochs']} epochs...")
    
    best_acc = 0.0
    
    for epoch in range(CONFIG['epochs']):
        model.train()
        total_loss = 0.0
        correct = 0
        total = 0
        
        for modalities, labels in dataloader:
            logits, confidence, weights = model(modalities)
            loss = criterion(logits, labels)
            
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item()
            pred = logits.argmax(dim=1)
            correct += (pred == labels).sum().item()
            total += labels.size(0)
        
        acc = correct / total
        
        if acc > best_acc:
            best_acc = acc
        
        if epoch % 50 == 0:
            logger.info(f"   Epoch {epoch:3d}/{CONFIG['epochs']}: loss={total_loss/len(dataloader):.4f}, acc={acc:.2%}, best={best_acc:.2%}")
    
    logger.info(f"\n✅ Final: acc={acc:.2%}, best_acc={best_acc:.2%}")
    
    Path('./models/fusion').mkdir(parents=True, exist_ok=True)
    torch.save({
        'model_state_dict': model.state_dict(),
        'config': CONFIG,
        'params': params,
        'accuracy': best_acc,
    }, './models/fusion/multimodal_fusion.pt')
    
    logger.info(f"\n💾 Model saved: models/fusion/multimodal_fusion.pt")
    
    logger.info(f"\n🧪 Testing...")
    model.eval()
    
    with torch.no_grad():
        test_dataset = FusionDataset(500)
        test_loader = torch.utils.data.DataLoader(test_dataset, batch_size=50, collate_fn=collate_fn)
        
        all_correct = 0
        all_total = 0
        
        for modalities, labels in test_loader:
            logits, confidence, weights = model(modalities)
            pred = logits.argmax(dim=1)
            all_correct += (pred == labels).sum().item()
            all_total += labels.size(0)
        
        test_acc = all_correct / all_total
        logger.info(f"   Test accuracy: {test_acc:.1%}")
        logger.info(f"   Modal weights: {[f'{w:.2f}' for w in weights.tolist()]}")
    
    logger.info(f"\n{'='*60}")
    logger.info(f"✅ MULTI-MODAL FUSION READY! Accuracy: {best_acc:.1%}")
    logger.info(f"{'='*60}")


if __name__ == "__main__":
    train()
