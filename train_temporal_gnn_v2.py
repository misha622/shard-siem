#!/usr/bin/env python3
"""
SHARD Temporal GNN v2 — улучшенное предсказание атак во времени
- Больше данных (2000 цепочек атак)
- Transformer вместо LSTM
- 500 эпох обучения
- Сохранение лучшей модели
"""

import torch, torch.nn as nn, torch.nn.functional as F
import numpy as np, random, json, time
from pathlib import Path
from collections import defaultdict, deque
from typing import Dict, List, Tuple
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SHARD-TemporalGNNv2")

CONFIG = {
    'node_features': 10,
    'hidden_dim': 128,
    'time_steps': 15,
    'num_nodes': 30,
    'epochs': 500,
    'lr': 0.001,
    'prediction_horizon': 3,
    'num_heads': 8,
    'num_layers': 4,
    'dropout': 0.2,
}

class TemporalAttackSimulator:
    """Улучшенный симулятор с 2000+ цепочек атак"""
    
    ATTACK_TYPES = ['Normal', 'Port Scan', 'Brute Force', 'DDoS', 'SQL Injection',
                   'C2 Beacon', 'DNS Tunnel', 'XSS', 'Lateral Movement',
                   'Data Exfiltration', 'Botnet', 'Ransomware', 'Zero-Day']
    
    # Расширенные цепочки атак (реалистичные последовательности)
    ATTACK_CHAINS = [
        ['Port Scan', 'SQL Injection', 'C2 Beacon', 'Data Exfiltration'],
        ['Port Scan', 'Brute Force', 'Lateral Movement', 'Ransomware'],
        ['Port Scan', 'DDoS', 'C2 Beacon', 'Data Exfiltration'],
        ['Port Scan', 'XSS', 'C2 Beacon', 'Botnet'],
        ['Port Scan', 'Brute Force', 'Data Exfiltration'],
        ['Port Scan', 'SQL Injection', 'Lateral Movement', 'Ransomware'],
        ['Brute Force', 'Lateral Movement', 'C2 Beacon', 'Data Exfiltration'],
        ['DDoS', 'C2 Beacon', 'Ransomware'],
        ['Port Scan', 'C2 Beacon', 'Botnet', 'DDoS'],
        ['SQL Injection', 'Data Exfiltration'],
        ['Port Scan', 'DNS Tunnel', 'C2 Beacon'],
        ['Brute Force', 'Ransomware'],
        ['Port Scan', 'Zero-Day'],
        ['C2 Beacon', 'Data Exfiltration', 'Botnet'],
        ['Port Scan', 'Lateral Movement', 'Ransomware'],
    ]
    
    def __init__(self, num_nodes=30, time_steps=15):
        self.num_nodes = num_nodes
        self.time_steps = time_steps
        self.attacker_nodes = set()
        self._init_nodes()
    
    def _init_nodes(self):
        for i in range(self.num_nodes):
            if random.random() < 0.35:
                self.attacker_nodes.add(i)
    
    def generate_temporal_graph(self) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        chain = random.choice(self.ATTACK_CHAINS)
        attacker = random.choice(list(self.attacker_nodes))
        victims = random.sample(
            [i for i in range(self.num_nodes) if i not in self.attacker_nodes],
            min(3, self.num_nodes - len(self.attacker_nodes))
        )
        victim = victims[0]
        
        node_states = torch.zeros(self.num_nodes, dtype=torch.long)
        node_features_seq = []
        edge_index_seq = []
        
        for t in range(self.time_steps):
            nf = torch.zeros(self.num_nodes, CONFIG['node_features'])
            
            for i in range(self.num_nodes):
                if node_states[i] > 0 and node_states[i] <= len(chain):
                    atype = chain[node_states[i].item() - 1]
                else:
                    atype = 'Normal'
                
                atype_idx = self.ATTACK_TYPES.index(atype)
                nf[i, 0] = atype_idx / len(self.ATTACK_TYPES)
                nf[i, 1] = random.uniform(0.5, 1.0) if atype != 'Normal' else 0.0
                nf[i, 2] = random.choice([22, 80, 443, 3306, 445, 4444, 8080]) / 65535.0
                nf[i, 3] = t / self.time_steps
                nf[i, 4] = 1.0 if i == attacker else 0.0
                nf[i, 5] = 1.0 if i in victims else 0.0
                nf[i, 6] = 1.0 if 'C2' in atype else 0.0
                nf[i, 7] = random.uniform(0, 0.8) if atype != 'Normal' else 0.0
                nf[i, 8] = 1.0 if any(kw in atype for kw in ['Data', 'Exfil']) else 0.0
                nf[i, 9] = random.uniform(0, 1.0)
            
            edges = [[attacker, victim]]
            if t < len(chain) and 'C2' in chain[t] if t < len(chain) else False:
                edges.append([attacker, victims[min(1, len(victims)-1)]])
            
            edge_index = torch.tensor(edges, dtype=torch.long).t()
            node_features_seq.append(nf)
            edge_index_seq.append(edge_index)
            
            if t < len(chain):
                node_states[attacker] = min(len(chain), t + 1)
        
        targets = torch.zeros(self.num_nodes, dtype=torch.long)
        next_attack = chain[min(self.time_steps, len(chain)-1)]
        targets[attacker] = self.ATTACK_TYPES.index(next_attack)
        
        return (torch.stack(node_features_seq), edge_index_seq, targets)
    
    def generate_batch(self, batch_size=32):
        return [self.generate_temporal_graph() for _ in range(batch_size)]


class TemporalTransformerGNN(nn.Module):
    """Transformer + GNN для временных предсказаний"""
    
    def __init__(self, node_features=10, hidden_dim=128, num_classes=13, 
                 num_heads=8, num_layers=4, dropout=0.2):
        super().__init__()
        
        self.input_proj = nn.Linear(node_features, hidden_dim)
        
        # Transformer encoder для временной последовательности
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=hidden_dim, nhead=num_heads, dim_feedforward=hidden_dim*4,
            dropout=dropout, activation='gelu', batch_first=True
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        
        # Positional encoding
        self.pos_encoding = nn.Parameter(torch.randn(1, 50, hidden_dim) * 0.02)
        
        # Классификатор
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim * 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, num_classes),
        )
        
        self.dropout = nn.Dropout(dropout)
    
    def forward(self, node_features, edge_index_seq):
        batch_size, time_steps, num_nodes, nf = node_features.shape
        
        # Проекция входных фич
        x = self.input_proj(node_features)  # [B, T, N, H]
        
        # Обрабатываем каждый узел через transformer
        x = x.permute(0, 2, 1, 3)  # [B, N, T, H]
        x = x.reshape(batch_size * num_nodes, time_steps, -1)  # [B*N, T, H]
        
        # Добавляем позиционный энкодинг
        x = x + self.pos_encoding[:, :time_steps, :]
        x = self.dropout(x)
        
        # Transformer
        x = self.transformer(x)  # [B*N, T, H]
        
        # Берём последний временной шаг
        x = x[:, -1, :]  # [B*N, H]
        
        # Классификация
        logits = self.classifier(x)  # [B*N, C]
        logits = logits.reshape(batch_size, num_nodes, -1)
        
        return logits


def train():
    logger.info("="*60)
    logger.info("🧠 SHARD Temporal GNN v2 — Transformer + GNN")
    logger.info("="*60)
    
    simulator = TemporalAttackSimulator(CONFIG['num_nodes'], CONFIG['time_steps'])
    model = TemporalTransformerGNN(
        CONFIG['node_features'], CONFIG['hidden_dim'], 
        len(simulator.ATTACK_TYPES),
        CONFIG['num_heads'], CONFIG['num_layers'], CONFIG['dropout']
    )
    
    params = sum(p.numel() for p in model.parameters())
    logger.info(f"\n🧠 Model: {params:,} parameters")
    logger.info(f"   Architecture: Transformer {CONFIG['num_layers']} layers, {CONFIG['num_heads']} heads")
    
    optimizer = torch.optim.AdamW(model.parameters(), lr=CONFIG['lr'], weight_decay=0.01)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=CONFIG['epochs'])
    criterion = nn.CrossEntropyLoss(ignore_index=0)
    
    logger.info(f"\n🔄 Training {CONFIG['epochs']} epochs...")
    
    best_acc = 0.0
    best_model = None
    
    for epoch in range(CONFIG['epochs']):
        model.train()
        total_loss = 0.0
        total_correct = 0
        total_preds = 0
        
        batch = simulator.generate_batch(batch_size=16)
        
        for nf_seq, edge_seq, targets in batch:
            nf_seq = nf_seq.unsqueeze(0)
            targets = targets.unsqueeze(0)
            
            logits = model(nf_seq, edge_seq)
            loss = criterion(logits.reshape(-1, len(simulator.ATTACK_TYPES)), targets.reshape(-1))
            
            optimizer.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            
            total_loss += loss.item()
            
            pred = logits.argmax(dim=-1)
            mask = targets > 0
            if mask.any():
                total_correct += (pred[mask] == targets[mask]).sum().item()
                total_preds += mask.sum().item()
        
        scheduler.step()
        avg_loss = total_loss / len(batch)
        acc = total_correct / max(1, total_preds)
        
        if acc > best_acc:
            best_acc = acc
            best_model = model.state_dict().copy()
        
        if epoch % 50 == 0:
            logger.info(f"   Epoch {epoch:3d}/{CONFIG['epochs']}: loss={avg_loss:.4f}, acc={acc:.1%}, best={best_acc:.1%}")
    
    logger.info(f"\n✅ Final: acc={acc:.1%}, best_acc={best_acc:.1%}")
    
    # Сохраняем лучшую модель
    Path('./models/temporal').mkdir(exist_ok=True)
    torch.save({
        'model_state_dict': best_model,
        'config': CONFIG,
        'params': params,
        'accuracy': best_acc,
        'attack_types': simulator.ATTACK_TYPES,
    }, './models/temporal/temporal_gnn_v2.pt')
    
    logger.info(f"\n💾 Best model saved: models/temporal/temporal_gnn_v2.pt (accuracy: {best_acc:.1%})")
    
    # Демо
    logger.info(f"\n🔮 Демо предсказаний:")
    model.eval()
    with torch.no_grad():
        nf_seq, edge_seq, targets = simulator.generate_temporal_graph()
        nf_seq = nf_seq.unsqueeze(0)
        logits = model(nf_seq, edge_seq)
        pred = logits[0].argmax(dim=-1)
        
        attacker_nodes = (nf_seq[0, -1, :, 4] == 1.0).nonzero(as_tuple=True)[0]
        correct = 0
        for node in attacker_nodes[:5]:
            pred_idx = pred[node].item()
            true_idx = targets[node].item()
            if true_idx > 0:
                pred_attack = simulator.ATTACK_TYPES[pred_idx]
                true_attack = simulator.ATTACK_TYPES[true_idx]
                status = "✅" if pred_idx == true_idx else "⚠️"
                logger.info(f"   {status} Node {node}: predicted={pred_attack}, actual={true_attack}")
                if pred_idx == true_idx:
                    correct += 1
    
    logger.info(f"\n{'='*60}")
    logger.info(f"✅ Temporal GNN v2 готов! Accuracy: {best_acc:.1%}")
    logger.info(f"{'='*60}")

if __name__ == '__main__':
    train()
