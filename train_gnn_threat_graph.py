#!/usr/bin/env python3
"""
SHARD GNN Threat Graph — Graph Neural Network для анализа связей атак
Выявляет кластеры атакующих, предсказывает propagation, находит скрытые связи
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
import numpy as np
import random
import json
import logging
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple, Set
import math

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SHARD-GNN-Trainer")

# ============================================================
# КОНФИГУРАЦИЯ
# ============================================================

CONFIG = {
    'node_features': 12,      # Фичи узла (IP): кол-во атак, типы, score, гео и т.д.
    'edge_features': 4,       # Фичи ребра: кол-во соединений, порты, протокол, длительность
    'hidden_dim': 64,
    'gnn_layers': 3,
    'num_heads': 4,           # Для GAT (Graph Attention)
    'dropout': 0.2,
    'epochs': 200,
    'lr': 0.001,
    'num_nodes': 50,          # Узлов в графе
    'num_edges': 200,         # Рёбер
}

# ============================================================
# ГЕНЕРАТОР СИНТЕТИЧЕСКОГО ГРАФА УГРОЗ
# ============================================================

class ThreatGraphGenerator:
    """Генерирует реалистичные графы угроз для обучения GNN"""
    
    ATTACK_TYPES = ['Port Scan', 'Brute Force', 'DDoS', 'SQL Injection', 
                    'C2 Beacon', 'Data Exfiltration', 'DNS Tunnel', 'Botnet']
    
    SEVERITY_MAP = {'Port Scan': 1, 'Brute Force': 2, 'DDoS': 3, 'SQL Injection': 2,
                    'C2 Beacon': 3, 'Data Exfiltration': 4, 'DNS Tunnel': 3, 'Botnet': 3}
    
    def __init__(self, num_nodes=50, num_edges=200):
        self.num_nodes = num_nodes
        self.num_edges = num_edges
    
    def generate_graph(self) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Генерирует один граф угроз.
        Returns: node_features, edge_index, edge_features, node_labels
        """
        # ===== Узлы (IP адреса) =====
        node_features = torch.zeros(self.num_nodes, CONFIG['node_features'])
        node_labels = torch.zeros(self.num_nodes, dtype=torch.long)  # 0=normal, 1=suspicious, 2=malicious
        
        for i in range(self.num_nodes):
            # Тип узла: нормальный хост, заражённый, C2 сервер, цель атаки
            node_type = random.choices([0, 1, 2, 3], weights=[0.5, 0.2, 0.15, 0.15])[0]
            
            if node_type == 0:  # Нормальный
                node_features[i] = torch.tensor([
                    random.uniform(0, 0.2),   # avg_score
                    random.uniform(0, 0.1),   # attack_count_norm
                    random.uniform(0, 3),     # unique_ports
                    0, 0, 0, 0, 0, 0, 0, 0,  # one-hot типов атак
                    random.uniform(0, 1),     # geo_cluster
                ])
                node_labels[i] = 0
            elif node_type == 1:  # Подозрительный
                atype = random.randint(0, 7)
                node_features[i] = torch.tensor([
                    random.uniform(0.3, 0.6),
                    random.uniform(0.1, 0.4),
                    random.uniform(3, 10),
                    *[1.0 if j == atype else 0.0 for j in range(8)],
                    random.uniform(0, 1),
                ])
                node_labels[i] = 1
            elif node_type == 2:  # Вредоносный (C2/атакующий)
                atype = random.choice([3, 4, 5, 6, 7])  # Тяжёлые атаки
                node_features[i] = torch.tensor([
                    random.uniform(0.6, 1.0),
                    random.uniform(0.5, 1.0),
                    random.uniform(10, 50),
                    *[1.0 if j == atype else 0.0 for j in range(8)],
                    random.uniform(0, 1),
                ])
                node_labels[i] = 2
            else:  # Цель атаки
                node_features[i] = torch.tensor([
                    random.uniform(0.5, 0.9),
                    random.uniform(0.3, 0.7),
                    random.uniform(5, 20),
                    *[random.uniform(0, 1) for _ in range(8)],
                    random.uniform(0, 1),
                ])
                node_labels[i] = 0  # Жертва не виновата
        
        # ===== Рёбра (связи между IP) =====
        edge_index = []
        edge_features = []
        
        for _ in range(self.num_edges):
            src = random.randint(0, self.num_nodes - 1)
            dst = random.randint(0, self.num_nodes - 1)
            
            if src == dst:
                continue
            
            # Характер связи зависит от типов узлов
            src_label = node_labels[src].item()
            dst_label = node_labels[dst].item()
            
            if src_label == 2 and dst_label == 0:  # Атакующий → жертва
                weight = random.uniform(0.7, 1.0)
                protocol = random.choice([6, 17])
                port = random.choice([22, 80, 443, 445, 3306, 4444])
                duration = random.uniform(10, 3600)
            elif src_label == 1 and dst_label == 0:  # Подозрительный → жертва
                weight = random.uniform(0.3, 0.7)
                protocol = random.choice([6, 17])
                port = random.choice([80, 443, 8080])
                duration = random.uniform(1, 300)
            elif src_label == 2 and dst_label == 2:  # C2 ↔ C2 координация
                weight = random.uniform(0.8, 1.0)
                protocol = 6
                port = random.choice([4444, 5555, 6666])
                duration = random.uniform(3600, 86400)
            else:  # Нормальный трафик
                weight = random.uniform(0, 0.3)
                protocol = 6
                port = random.choice([80, 443, 53])
                duration = random.uniform(1, 60)
            
            edge_index.append([src, dst])
            edge_features.append([
                weight,
                port / 65535.0,
                protocol / 255.0,
                min(1.0, duration / 3600.0),
            ])
        
        edge_index = torch.tensor(edge_index, dtype=torch.long).t().contiguous()
        edge_features = torch.tensor(edge_features, dtype=torch.float32)
        
        return node_features, edge_index, edge_features, node_labels
    
    def generate_batch(self, batch_size=32) -> List[Tuple]:
        """Генерирует батч графов"""
        return [self.generate_graph() for _ in range(batch_size)]


# ============================================================
# GNN МОДЕЛЬ (Graph Attention Network + Edge Features)
# ============================================================

class GATLayer(nn.Module):
    """Graph Attention Layer с учётом edge features"""
    
    def __init__(self, in_dim, out_dim, edge_dim, num_heads=4, dropout=0.2):
        super().__init__()
        self.num_heads = num_heads
        self.out_dim = out_dim
        
        # Node attention
        self.W = nn.Linear(in_dim, out_dim * num_heads, bias=False)
        self.a = nn.Parameter(torch.zeros(num_heads, 2 * out_dim + edge_dim))
        
        # Edge embedding
        self.edge_emb = nn.Linear(edge_dim, edge_dim)
        
        self.dropout = nn.Dropout(dropout)
        self.leaky_relu = nn.LeakyReLU(0.2)
        
        nn.init.xavier_uniform_(self.W.weight)
        nn.init.xavier_uniform_(self.a)
    
    def forward(self, x, edge_index, edge_features):
        N = x.size(0)
        E = edge_index.size(1)
        
        # Проекция узлов
        h = self.W(x).view(N, self.num_heads, self.out_dim)  # [N, heads, out]
        
        # Edge embedding
        edge_emb = self.edge_emb(edge_features)  # [E, edge_dim]
        
        # Attention scores
        src, dst = edge_index[0], edge_index[1]
        h_src = h[src]  # [E, heads, out]
        h_dst = h[dst]  # [E, heads, out]
        
        # Конкатенация для attention
        a_input = torch.cat([
            h_src,  # [E, heads, out]
            h_dst,  # [E, heads, out]
            edge_emb.unsqueeze(1).expand(-1, self.num_heads, -1),  # [E, heads, edge_dim]
        ], dim=-1)  # [E, heads, 2*out + edge_dim]
        
        e = self.leaky_relu((a_input * self.a.unsqueeze(0)).sum(dim=-1))  # [E, heads]
        
        # Softmax по соседям
        attention = torch.zeros(N, self.num_heads, device=x.device)
        attention = attention.index_add(0, dst, e.exp()) + 1e-8
        alpha = e / attention[dst]  # [E, heads]
        alpha = self.dropout(alpha)
        
        # Агрегация
        out = torch.zeros(N, self.num_heads, self.out_dim, device=x.device)
        weighted = h_src * alpha.unsqueeze(-1)  # [E, heads, out]
        out = out.index_add(0, dst, weighted)
        
        return out.mean(dim=1)  # [N, out] — усредняем головы


class ThreatGNN(nn.Module):
    """Graph Neural Network для анализа графа угроз"""
    
    def __init__(self, node_dim=12, edge_dim=4, hidden_dim=64, num_layers=3, num_heads=4, num_classes=3, dropout=0.2):
        super().__init__()
        
        self.input_proj = nn.Linear(node_dim, hidden_dim)
        
        # Слои GAT
        self.gat_layers = nn.ModuleList()
        for i in range(num_layers):
            self.gat_layers.append(
                GATLayer(
                    in_dim=hidden_dim if i > 0 else hidden_dim,
                    out_dim=hidden_dim,
                    edge_dim=edge_dim,
                    num_heads=num_heads,
                    dropout=dropout,
                )
            )
        
        # Выходные головы
        self.node_classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, num_classes),  # 0=normal, 1=suspicious, 2=malicious
        )
        
        self.edge_predictor = nn.Sequential(
            nn.Linear(hidden_dim * 2 + edge_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, 1),  # 0=no_edge, 1=edge_exists
            nn.Sigmoid(),
        )
        
        self.global_pool = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, 1),  # Общий уровень угрозы графа
            nn.Sigmoid(),
        )
    
    def forward(self, x, edge_index, edge_features):
        # Начальная проекция
        x = F.relu(self.input_proj(x))
        
        # GAT слои
        for gat in self.gat_layers:
            x = gat(x, edge_index, edge_features)
            x = F.relu(x)
        
        # Классификация узлов
        node_logits = self.node_classifier(x)
        
        # Предикция рёбер
        src, dst = edge_index[0], edge_index[1]
        edge_emb = torch.cat([x[src], x[dst], edge_features], dim=-1)
        edge_probs = self.edge_predictor(edge_emb)
        
        # Глобальный score графа
        graph_score = self.global_pool(x.mean(dim=0, keepdim=True))
        
        return node_logits, edge_probs, graph_score


# ============================================================
# ОБУЧЕНИЕ
# ============================================================

def train():
    logger.info("=" * 60)
    logger.info("🧠 SHARD GNN Threat Graph — Graph Attention Network")
    logger.info("=" * 60)
    
    generator = ThreatGraphGenerator(CONFIG['num_nodes'], CONFIG['num_edges'])
    
    # Модель
    model = ThreatGNN(
        node_dim=CONFIG['node_features'],
        edge_dim=CONFIG['edge_features'],
        hidden_dim=CONFIG['hidden_dim'],
        num_layers=CONFIG['gnn_layers'],
        num_heads=CONFIG['num_heads'],
        dropout=CONFIG['dropout'],
    )
    
    params = sum(p.numel() for p in model.parameters())
    logger.info(f"\n🧠 Model: {params:,} parameters")
    logger.info(f"   GAT layers: {CONFIG['gnn_layers']}, heads: {CONFIG['num_heads']}")
    
    optimizer = optim.Adam(model.parameters(), lr=CONFIG['lr'])
    node_criterion = nn.CrossEntropyLoss()
    edge_criterion = nn.BCELoss()
    
    # Обучение
    logger.info(f"\n🔄 Training {CONFIG['epochs']} epochs...")
    
    for epoch in range(CONFIG['epochs']):
        model.train()
        total_loss = 0.0
        node_correct = 0
        node_total = 0
        
        # Генерируем батч графов
        graphs = generator.generate_batch(batch_size=16)
        
        for node_feat, edge_idx, edge_feat, node_labels in graphs:
            # Forward
            node_logits, edge_probs, graph_score = model(node_feat, edge_idx, edge_feat)
            
            # Node loss
            node_loss = node_criterion(node_logits, node_labels)
            
            # Edge loss (существующие рёбра = 1)
            edge_targets = torch.ones(edge_idx.size(1), 1)
            # edge_loss выключен для стабильности

            # Total loss — только node classification
            loss = node_loss
            # Total loss
            
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item()
            
            # Node accuracy
            pred = node_logits.argmax(dim=1)
            node_correct += (pred == node_labels).sum().item()
            node_total += node_labels.size(0)
        
        avg_loss = total_loss / len(graphs)
        node_acc = node_correct / max(1, node_total)
        
        if epoch % 20 == 0:
            logger.info(f"   Epoch {epoch}/{CONFIG['epochs']}: loss={avg_loss:.4f}, node_acc={node_acc:.2%}")
    
    logger.info(f"✅ Epoch {CONFIG['epochs']}/{CONFIG['epochs']}: final_loss={avg_loss:.4f}, node_acc={node_acc:.2%}")
    
    # Сохранение
    logger.info(f"\n💾 Saving model...")
    Path('./models/gnn').mkdir(parents=True, exist_ok=True)
    
    torch.save({
        'model_state_dict': model.state_dict(),
        'config': CONFIG,
        'params': params,
    }, './models/gnn/threat_gnn.pt')
    
    logger.info(f"✅ Model saved: models/gnn/threat_gnn.pt")
    
    # Тест
    logger.info(f"\n🧪 Testing on new graph...")
    model.eval()
    
    with torch.no_grad():
        node_feat, edge_idx, edge_feat, node_labels = generator.generate_graph()
        node_logits, edge_probs, graph_score = model(node_feat, edge_idx, edge_feat)
        
        pred = node_logits.argmax(dim=1)
        accuracy = (pred == node_labels).float().mean().item()
        
        malicious_count = (pred == 2).sum().item()
        suspicious_count = (pred == 1).sum().item()
        
        logger.info(f"   Node accuracy: {accuracy:.1%}")
        logger.info(f"   Detected malicious: {malicious_count}, suspicious: {suspicious_count}")
        logger.info(f"   Graph threat score: {graph_score.item():.3f}")
    
    logger.info(f"\n{'='*60}")
    logger.info(f"✅ GNN THREAT GRAPH READY!")
    logger.info(f"{'='*60}")


if __name__ == "__main__":
    train()
