#!/usr/bin/env python3
"""
SHARD GNN Threat Graph v2 — улучшенная версия
- Больше узлов и рёбер (100 узлов, 500 рёбер)
- Настоящий GCN + GAT гибрид
- BatchNorm + Residual connections
- Правильный multi-class Focal Loss
- 500 эпох
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
import numpy as np
import random
import logging
from pathlib import Path
from collections import defaultdict
import math

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SHARD-GNN-v2")

CONFIG = {
    'node_features': 16,
    'hidden_dim': 128,
    'gnn_layers': 4,
    'dropout': 0.3,
    'epochs': 500,
    'lr': 0.002,
    'num_nodes': 100,
    'num_edges': 500,
}


class ThreatGraphGenerator:
    ATTACK_TYPES = ['normal', 'scan', 'brute', 'ddos', 'sqli', 'c2', 'exfil', 'dns_tunnel', 'botnet']
    
    def __init__(self, num_nodes=100, num_edges=500):
        self.num_nodes = num_nodes
        self.num_edges = num_edges
    
    def generate_graph(self):
        N = self.num_nodes
        E = self.num_edges
        
        x = torch.zeros(N, CONFIG['node_features'])
        y = torch.zeros(N, dtype=torch.long)
        
        for i in range(N):
            r = random.random()
            if r < 0.4:
                x[i] = torch.tensor([random.uniform(0,0.2) for _ in range(8)] + 
                                     [0]*7 + [random.uniform(0,0.3)])
                y[i] = 0
            elif r < 0.7:
                atype = random.randint(0,8)
                x[i] = torch.tensor([random.uniform(0.3,0.6) for _ in range(3)] +
                                     [1.0 if j==atype else 0 for j in range(5)] +
                                     [random.uniform(0.3,0.7) for _ in range(8)])
                y[i] = 1
            else:
                atype = random.randint(3,8)
                x[i] = torch.tensor([random.uniform(0.7,1.0) for _ in range(3)] +
                                     [1.0 if j==atype-3 else 0 for j in range(5)] +
                                     [random.uniform(0.5,1.0) for _ in range(8)])
                y[i] = 2
        
        edge_index = []
        for _ in range(E):
            src = random.randint(0, N-1)
            dst = random.randint(0, N-1)
            if src != dst:
                edge_index.append([src, dst])
        
        edge_index = torch.tensor(edge_index, dtype=torch.long).t().contiguous()
        
        return x, edge_index, y
    
    def generate_batch(self, batch_size=16):
        return [self.generate_graph() for _ in range(batch_size)]



class GCNLayer(nn.Module):
    """Graph Convolutional Network layer"""
    def __init__(self, in_dim, out_dim):
        super().__init__()
        self.linear = nn.Linear(in_dim, out_dim)
        self.bn = nn.BatchNorm1d(out_dim)
        
    def forward(self, x, edge_index):
        src, dst = edge_index
        N = x.size(0)
        
        deg = torch.zeros(N, device=x.device)
        deg = deg.index_add(0, dst, torch.ones_like(dst, dtype=torch.float))
        deg = deg.clamp(min=1)
        norm = 1.0 / deg.sqrt()
        
        out = self.linear(x)
        out = out * norm.unsqueeze(-1)
        
        aggregated = torch.zeros_like(out)
        aggregated = aggregated.index_add(0, dst, out[src] * norm[src].unsqueeze(-1))
        
        return self.bn(F.relu(aggregated))


class GATLayer(nn.Module):
    """Graph Attention layer"""
    def __init__(self, in_dim, out_dim, heads=4, dropout=0.3):
        super().__init__()
        self.heads = heads
        self.out_dim = out_dim
        
        self.W = nn.Linear(in_dim, out_dim * heads)
        self.a_src = nn.Linear(out_dim, 1, bias=False)
        self.a_dst = nn.Linear(out_dim, 1, bias=False)
        self.bn = nn.BatchNorm1d(out_dim * heads)
        self.dropout = nn.Dropout(dropout)
        self.leaky_relu = nn.LeakyReLU(0.2)
        
    def forward(self, x, edge_index):
        src, dst = edge_index
        N = x.size(0)
        
        h = self.W(x).view(N, self.heads, self.out_dim)
        h_src, h_dst = h[src], h[dst]
        
        attn = self.a_src(h_src) + self.a_dst(h_dst)
        attn = self.leaky_relu(attn).squeeze(-1)
        
        attn_max = torch.zeros(N, self.heads, device=x.device)
        attn_max = attn_max.index_add(0, dst, attn.exp()) + 1e-8
        alpha = attn / attn_max[dst]
        alpha = self.dropout(alpha)
        
        out = torch.zeros(N, self.heads, self.out_dim, device=x.device)
        out = out.index_add(0, dst, h_src * alpha.unsqueeze(-1))
        out = out.view(N, -1)
        
        return self.bn(F.relu(out))


class ThreatGNNv2(nn.Module):
    """GCN + GAT гибрид с residual connections"""
    def __init__(self, in_dim=16, hidden_dim=128, num_layers=4, num_classes=3, dropout=0.3):
        super().__init__()
        
        self.input_proj = nn.Sequential(
            nn.Linear(in_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
        )
        
        self.layers = nn.ModuleList()
        for i in range(num_layers):
            if i % 2 == 0:
                self.layers.append(GCNLayer(hidden_dim, hidden_dim))
            else:
                self.layers.append(GATLayer(hidden_dim, hidden_dim // 4, heads=4, dropout=dropout))
        
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, num_classes),
        )
        
        self.graph_scorer = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, 1),
            nn.Sigmoid(),
        )
    
    def forward(self, x, edge_index):
        x = self.input_proj(x)
        
        for layer in self.layers:
            residual = x
            x = layer(x, edge_index)
            if x.size(-1) == residual.size(-1):
                x = x + residual
        
        node_logits = self.classifier(x)
        graph_score = self.graph_scorer(x.mean(dim=0, keepdim=True))
        
        return node_logits, graph_score



class FocalLoss(nn.Module):
    def __init__(self, alpha=None, gamma=2.0):
        super().__init__()
        self.alpha = alpha
        self.gamma = gamma
    
    def forward(self, inputs, targets):
        ce_loss = F.cross_entropy(inputs, targets, reduction='none')
        pt = torch.exp(-ce_loss)
        focal_loss = ((1 - pt) ** self.gamma) * ce_loss
        
        if self.alpha is not None:
            alpha_t = self.alpha[targets]
            focal_loss = alpha_t * focal_loss
        
        return focal_loss.mean()



def train():
    logger.info("="*60)
    logger.info("🧠 SHARD GNN Threat Graph v2 — GCN+GAT Hybrid")
    logger.info("="*60)
    
    generator = ThreatGraphGenerator(CONFIG['num_nodes'], CONFIG['num_edges'])
    
    model = ThreatGNNv2(
        in_dim=CONFIG['node_features'],
        hidden_dim=CONFIG['hidden_dim'],
        num_layers=CONFIG['gnn_layers'],
        dropout=CONFIG['dropout'],
    )
    
    params = sum(p.numel() for p in model.parameters())
    logger.info(f"\n🧠 Model: {params:,} parameters")
    logger.info(f"   GCN+GAT layers: {CONFIG['gnn_layers']}, hidden: {CONFIG['hidden_dim']}")
    
    alpha = torch.tensor([0.5, 1.0, 2.0])
    criterion = FocalLoss(alpha=alpha, gamma=2.0)
    optimizer = optim.AdamW(model.parameters(), lr=CONFIG['lr'], weight_decay=0.01)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=CONFIG['epochs'])
    
    logger.info(f"\n🔄 Training {CONFIG['epochs']} epochs...")
    
    best_acc = 0.0
    
    for epoch in range(CONFIG['epochs']):
        model.train()
        total_loss = 0.0
        total_correct = 0
        total_nodes = 0
        
        graphs = generator.generate_batch(batch_size=8)
        
        for x, edge_index, y in graphs:
            node_logits, graph_score = model(x, edge_index)
            loss = criterion(node_logits, y)
            
            optimizer.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            
            total_loss += loss.item()
            pred = node_logits.argmax(dim=1)
            total_correct += (pred == y).sum().item()
            total_nodes += y.size(0)
        
        avg_loss = total_loss / len(graphs)
        accuracy = total_correct / total_nodes
        scheduler.step()
        
        if accuracy > best_acc:
            best_acc = accuracy
        
        if epoch % 50 == 0:
            logger.info(f"   Epoch {epoch:3d}/{CONFIG['epochs']}: loss={avg_loss:.4f}, acc={accuracy:.2%}, best={best_acc:.2%}")
    
    logger.info(f"\n✅ Final: loss={avg_loss:.4f}, acc={accuracy:.2%}, best_acc={best_acc:.2%}")
    
    Path('./models/gnn').mkdir(parents=True, exist_ok=True)
    torch.save({
        'model_state_dict': model.state_dict(),
        'config': CONFIG,
        'params': params,
        'accuracy': best_acc,
    }, './models/gnn/threat_gnn_v2.pt')
    
    logger.info(f"\n💾 Model saved: models/gnn/threat_gnn_v2.pt")
    
    logger.info(f"\n🧪 Testing...")
    model.eval()
    
    with torch.no_grad():
        x, edge_index, y = generator.generate_graph()
        node_logits, graph_score = model(x, edge_index)
        pred = node_logits.argmax(dim=1)
        
        acc = (pred == y).float().mean().item()
        malicious = (pred == 2).sum().item()
        suspicious = (pred == 1).sum().item()
        normal = (pred == 0).sum().item()
        
        logger.info(f"   Accuracy: {acc:.1%}")
        logger.info(f"   Nodes — normal:{normal}, suspicious:{suspicious}, malicious:{malicious}")
        logger.info(f"   Graph threat score: {graph_score.item():.4f}")
    
    logger.info(f"\n{'='*60}")
    logger.info(f"✅ GNN v2 READY! Best accuracy: {best_acc:.1%}")
    logger.info(f"{'='*60}")


if __name__ == "__main__":
    train()
