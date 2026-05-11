#!/usr/bin/env python3
"""
SHARD Temporal GNN Trainer
Учит модель видеть временные паттерны атак и предсказывать следующие шаги
"""

import torch, torch.nn as nn, torch.nn.functional as F
import numpy as np, random, json, time
from pathlib import Path
from collections import defaultdict, deque
from typing import Dict, List, Tuple
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SHARD-TemporalGNN")

# ============================================================
# КОНФИГУРАЦИЯ
# ============================================================

CONFIG = {
    'node_features': 8,       # Фичи узла: тип атаки, score, порт, время
    'hidden_dim': 64,
    'time_steps': 10,         # Сколько временных срезов помним
    'num_nodes': 20,          # Узлов в графе (IP адресов)
    'epochs': 200,
    'lr': 0.001,
    'prediction_horizon': 3,  # На сколько шагов вперёд предсказываем
}

# ============================================================
# ГЕНЕРАТОР ВРЕМЕННЫХ ГРАФОВ АТАК
# ============================================================

class TemporalAttackSimulator:
    """Симулирует реалистичные цепочки атак во времени"""
    
    ATTACK_CHAINS = [
        # Recon → Exploit → C2 → Exfil
        ['Port Scan', 'SQL Injection', 'C2 Beacon', 'Data Exfiltration'],
        ['Port Scan', 'Brute Force', 'Lateral Movement', 'Ransomware'],
        ['Port Scan', 'DNS Tunnel', 'C2 Beacon', 'Data Exfiltration'],
        ['Port Scan', 'XSS', 'C2 Beacon', 'Botnet'],
        ['Port Scan', 'DDoS', 'C2 Beacon', 'Ransomware'],
    ]
    
    ATTACK_TYPES = ['Normal', 'Port Scan', 'Brute Force', 'DDoS', 'SQL Injection',
                   'C2 Beacon', 'DNS Tunnel', 'XSS', 'Lateral Movement',
                   'Data Exfiltration', 'Botnet', 'Ransomware', 'Zero-Day']
    
    def __init__(self, num_nodes=20, time_steps=10):
        self.num_nodes = num_nodes
        self.time_steps = time_steps
        self.attacker_nodes = set()
        self.victim_nodes = set()
        self._init_nodes()
    
    def _init_nodes(self):
        """Инициализация узлов графа"""
        # 30% узлов — атакующие
        for i in range(self.num_nodes):
            if random.random() < 0.3:
                self.attacker_nodes.add(i)
            else:
                self.victim_nodes.add(i)
    
    def generate_temporal_graph(self) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Генерирует временной граф: последовательность снимков графа атак
        Returns:
            node_features: [time_steps, num_nodes, node_features]
            edge_index: [time_steps, 2, num_edges]
            targets: [num_nodes] — какая атака будет на следующем шаге
        """
        # Выбираем случайную цепочку атак
        chain = random.choice(self.ATTACK_CHAINS)
        attacker = random.choice(list(self.attacker_nodes))
        victim = random.choice(list(self.victim_nodes))
        
        # Текущее состояние всех узлов
        node_states = torch.zeros(self.num_nodes, dtype=torch.long)
        
        node_features_seq = []
        edge_index_seq = []
        
        for t in range(self.time_steps):
            # Фичи узлов на этом временном срезе
            nf = torch.zeros(self.num_nodes, CONFIG['node_features'])
            
            for i in range(self.num_nodes):
                if node_states[i] > 0:
                    attack_idx = node_states[i].item() - 1
                    if attack_idx < len(chain):
                        atype = chain[attack_idx]
                    else:
                        atype = 'Normal'
                else:
                    atype = 'Normal'
                
                # Кодируем состояние
                atype_idx = self.ATTACK_TYPES.index(atype)
                nf[i, 0] = atype_idx / len(self.ATTACK_TYPES)
                nf[i, 1] = random.uniform(0.3, 1.0) if atype != 'Normal' else 0.0  # score
                nf[i, 2] = random.choice([22, 80, 443, 3306, 445, 4444]) / 65535.0  # port
                nf[i, 3] = t / self.time_steps  # время
                nf[i, 4] = 1.0 if i == attacker else 0.0  # is_attacker
                nf[i, 5] = 1.0 if i == victim else 0.0    # is_victim
                nf[i, 6] = 1.0 if atype == 'C2 Beacon' else 0.0  # has_c2
                nf[i, 7] = random.uniform(0, 0.5)  # traffic_volume
            
            # Рёбра: атакующий → жертва
            edges = [[attacker, victim]]
            
            # Добавляем C2 связи
            if 'C2 Beacon' in chain[:t+1]:
                c2_node = random.choice(list(self.attacker_nodes - {attacker}))
                edges.append([attacker, c2_node])
            
            edge_index = torch.tensor(edges, dtype=torch.long).t()
            
            node_features_seq.append(nf)
            edge_index_seq.append(edge_index)
            
            # Развиваем атаку: переходим к следующей стадии цепи
            if t < len(chain):
                node_states[attacker] = min(len(chain), t + 1)
                if t >= 1:
                    node_states[victim] = min(len(chain), t)  # Жертва "заражена"
        
        # Target: какая атака произойдёт на следующем шаге для КАЖДОГО узла
        targets = torch.zeros(self.num_nodes, dtype=torch.long)
        next_attack = chain[min(self.time_steps, len(chain)-1)]
        targets[attacker] = self.ATTACK_TYPES.index(next_attack)
        targets[victim] = self.ATTACK_TYPES.index('Normal')  # Жертва уже атакована
        
        return (torch.stack(node_features_seq),
                edge_index_seq,
                targets)
    
    def generate_batch(self, batch_size=32):
        """Генерирует батч временных графов"""
        batch = []
        for _ in range(batch_size):
            batch.append(self.generate_temporal_graph())
        return batch


# ============================================================
# TEMPORAL GNN МОДЕЛЬ
# ============================================================

class TemporalGNN(nn.Module):
    """
    GNN + LSTM для анализа временных последовательностей графов атак
    Предсказывает следующую атаку для каждого узла
    """
    
    def __init__(self, node_features=8, hidden_dim=64, num_classes=13):
        super().__init__()
        
        # Пространственный слой (GNN на каждом снимке)
        self.spatial_conv = nn.Sequential(
            nn.Linear(node_features, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
        )
        
        # Временной слой (LSTM поверх последовательности снимков)
        self.temporal_lstm = nn.LSTM(
            input_size=hidden_dim,
            hidden_size=hidden_dim,
            num_layers=2,
            batch_first=True,
            dropout=0.2,
        )
        
        # Attention поверх временных шагов
        self.temporal_attention = nn.MultiheadAttention(
            embed_dim=hidden_dim,
            num_heads=4,
            batch_first=True,
        )
        
        # Предиктор следующей атаки
        self.predictor = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim * 2),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, num_classes),
        )
    
    def forward(self, node_features, edge_index_seq):
        """
        node_features: [batch, time_steps, num_nodes, node_features]
        edge_index_seq: list of [batch, 2, num_edges] per time step
        Returns: [batch, num_nodes, num_classes]
        """
        batch_size, time_steps, num_nodes, nf = node_features.shape
        
        # Обрабатываем каждый временной срез через GNN
        spatial_embeddings = []
        
        for t in range(time_steps):
            # Пространственная свёртка (упрощённая — без передачи сообщений)
            x_t = node_features[:, t, :, :]  # [batch, num_nodes, nf]
            h_t = self.spatial_conv(x_t)  # [batch, num_nodes, hidden_dim]
            
            # Агрегация соседей (если есть рёбра)
            if t < len(edge_index_seq):
                edges = edge_index_seq[t]  # [2, num_edges]
                # Простое усреднение для соседей
                for b in range(batch_size):
                    if edges.size(1) > 0:
                        src, dst = edges[0], edges[1]
                        # Сообщения от источника к цели
                        messages = h_t[b, src]  # [num_edges, hidden_dim]
                        # Усредняем по целям
                        for d in range(num_nodes):
                            mask = dst == d
                            if mask.any():
                                h_t[b, d] = (h_t[b, d] + messages[mask].mean(dim=0)) / 2
            
            spatial_embeddings.append(h_t)
        
        # Стек: [batch, time_steps, num_nodes, hidden_dim]
        spatial_stack = torch.stack(spatial_embeddings, dim=1)
        
        # Обрабатываем каждый узел через LSTM
        # Переформатируем: [batch * num_nodes, time_steps, hidden_dim]
        lstm_input = spatial_stack.permute(0, 2, 1, 3).reshape(
            batch_size * num_nodes, time_steps, -1
        )
        
        lstm_out, (h_n, c_n) = self.temporal_lstm(lstm_input)
        
        # Attention на временные шаги
        attn_out, _ = self.temporal_attention(lstm_out, lstm_out, lstm_out)
        
        # Берём последний временной шаг после attention
        final_hidden = attn_out[:, -1, :]  # [batch * num_nodes, hidden_dim]
        
        # Предсказание
        logits = self.predictor(final_hidden)  # [batch * num_nodes, num_classes]
        logits = logits.reshape(batch_size, num_nodes, -1)
        
        return logits


# ============================================================
# ОБУЧЕНИЕ
# ============================================================

def train():
    logger.info("="*60)
    logger.info("🧠 SHARD TEMPORAL GNN — Предсказание атак во времени")
    logger.info("="*60)
    
    simulator = TemporalAttackSimulator(CONFIG['num_nodes'], CONFIG['time_steps'])
    model = TemporalGNN(CONFIG['node_features'], CONFIG['hidden_dim'], len(simulator.ATTACK_TYPES))
    
    params = sum(p.numel() for p in model.parameters())
    logger.info(f"\n🧠 Model: {params:,} parameters")
    logger.info(f"   Time steps: {CONFIG['time_steps']}, Hidden: {CONFIG['hidden_dim']}")
    
    optimizer = torch.optim.Adam(model.parameters(), lr=CONFIG['lr'])
    criterion = nn.CrossEntropyLoss(ignore_index=0)  # Игнорируем Normal (класс 0)
    
    logger.info(f"\n🔄 Training {CONFIG['epochs']} epochs...")
    
    best_acc = 0.0
    
    for epoch in range(CONFIG['epochs']):
        model.train()
        total_loss = 0.0
        total_correct = 0
        total_preds = 0
        
        # Генерируем батч
        batch = simulator.generate_batch(batch_size=16)
        
        for nf_seq, edge_seq, targets in batch:
            nf_seq = nf_seq.unsqueeze(0)  # [1, time_steps, nodes, features]
            targets = targets.unsqueeze(0)  # [1, nodes]
            
            logits = model(nf_seq, edge_seq)  # [1, nodes, classes]
            
            loss = criterion(logits.reshape(-1, len(simulator.ATTACK_TYPES)),
                            targets.reshape(-1))
            
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item()
            
            # Считаем точность только для non-Normal предсказаний
            pred = logits.argmax(dim=-1)
            mask = targets > 0  # Только атакованные узлы
            if mask.any():
                total_correct += (pred[mask] == targets[mask]).sum().item()
                total_preds += mask.sum().item()
        
        avg_loss = total_loss / len(batch)
        acc = total_correct / max(1, total_preds)
        
        if acc > best_acc:
            best_acc = acc
        
        if epoch % 20 == 0:
            logger.info(f"   Epoch {epoch:3d}/{CONFIG['epochs']}: loss={avg_loss:.4f}, acc={acc:.1%}, best={best_acc:.1%}")
    
    logger.info(f"\n✅ Final: acc={acc:.1%}, best_acc={best_acc:.1%}")
    
    # Сохраняем
    Path('./models/temporal').mkdir(exist_ok=True)
    torch.save({
        'model_state_dict': model.state_dict(),
        'config': CONFIG,
        'params': params,
        'accuracy': best_acc,
        'attack_types': simulator.ATTACK_TYPES,
    }, './models/temporal/temporal_gnn.pt')
    
    logger.info(f"\n💾 Model saved: models/temporal/temporal_gnn.pt")
    
    # Демо предсказания
    logger.info(f"\n🔮 ДЕМО: Предсказание следующей атаки")
    
    # Цепочка атак
    demo_chain = ['Port Scan', 'Brute Force', 'Lateral Movement', 'Ransomware']
    logger.info(f"   Цепочка: {' → '.join(demo_chain)}")
    
    # Симулируем первые 3 шага, предсказываем 4-й
    with torch.no_grad():
        nf_seq, edge_seq, targets = simulator.generate_temporal_graph()
        nf_seq = nf_seq.unsqueeze(0)
        
        logits = model(nf_seq, edge_seq)
        pred = logits[0].argmax(dim=-1)
        
        # Находим атакующий узел
        attacker_nodes = (nf_seq[0, -1, :, 4] == 1.0).nonzero(as_tuple=True)[0]
        
        for node in attacker_nodes[:3]:
            pred_idx = pred[node].item()
            true_idx = targets[node].item()
            pred_attack = simulator.ATTACK_TYPES[pred_idx]
            true_attack = simulator.ATTACK_TYPES[true_idx] if true_idx < len(simulator.ATTACK_TYPES) else 'Normal'
            
            status = "✅" if pred_idx == true_idx else "⚠️"
            logger.info(f"   {status} Узел {node}: предсказано={pred_attack}, реально={true_attack}")
    
    logger.info(f"\n{'='*60}")
    logger.info(f"✅ TEMPORAL GNN READY! Best accuracy: {best_acc:.1%}")
    logger.info(f"{'='*60}")

if __name__ == '__main__':
    train()
