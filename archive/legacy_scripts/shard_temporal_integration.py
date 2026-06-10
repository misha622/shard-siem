#!/usr/bin/env python3
"""SHARD Temporal GNN Integration — предсказание следующих атак"""
import torch, torch.nn as nn, numpy as np, logging, time
from pathlib import Path
from collections import defaultdict, deque
from typing import Dict, List, Tuple

logger = logging.getLogger("SHARD-Temporal")

class TemporalGNNPredictor(nn.Module):
    def __init__(self, node_features=8, hidden_dim=64, num_classes=13):
        super().__init__()
        self.spatial_conv = nn.Sequential(nn.Linear(node_features, hidden_dim), nn.ReLU(), nn.Linear(hidden_dim, hidden_dim))
        self.temporal_lstm = nn.LSTM(hidden_dim, hidden_dim, num_layers=2, batch_first=True, dropout=0.2)
        self.temporal_attention = nn.MultiheadAttention(hidden_dim, 4, batch_first=True)
        self.predictor = nn.Sequential(nn.Linear(hidden_dim, hidden_dim*2), nn.ReLU(), nn.Dropout(0.3), nn.Linear(hidden_dim*2, hidden_dim), nn.ReLU(), nn.Linear(hidden_dim, num_classes))
    
    def forward(self, node_features, edge_index_seq):
        batch_size, time_steps, num_nodes, nf = node_features.shape
        spatial_embeddings = []
        for t in range(time_steps):
            x_t = node_features[:, t, :, :]
            h_t = self.spatial_conv(x_t)
            if t < len(edge_index_seq) and edge_index_seq[t].size(1) > 0:
                edges = edge_index_seq[t]
                src, dst = edges[0], edges[1]
                for b in range(batch_size):
                    messages = h_t[b, src]
                    for d in range(num_nodes):
                        mask = dst == d
                        if mask.any():
                            h_t[b, d] = (h_t[b, d] + messages[mask].mean(dim=0)) / 2
            spatial_embeddings.append(h_t)
        spatial_stack = torch.stack(spatial_embeddings, dim=1)
        lstm_input = spatial_stack.permute(0, 2, 1, 3).reshape(batch_size * num_nodes, time_steps, -1)
        lstm_out, _ = self.temporal_lstm(lstm_input)
        attn_out, _ = self.temporal_attention(lstm_out, lstm_out, lstm_out)
        final_hidden = attn_out[:, -1, :]
        logits = self.predictor(final_hidden)
        return logits.reshape(batch_size, num_nodes, -1)

class ShardTemporalGNN:
    def __init__(self, model_path='./models/temporal/temporal_gnn.pt'):
        self.model = None; self.loaded = False
        self.attack_types = ['Normal', 'Port Scan', 'Brute Force', 'DDoS', 'SQL Injection',
                            'C2 Beacon', 'DNS Tunnel', 'XSS', 'Lateral Movement',
                            'Data Exfiltration', 'Botnet', 'Ransomware', 'Zero-Day']
        self.alert_history = defaultdict(lambda: deque(maxlen=20))
        self.node_id_map = {}
        self.next_id = 0
        self._load(model_path)
    
    def _load(self, path):
        try:
            if Path(path).exists():
                ckpt = torch.load(path, map_location='cpu', weights_only=False)
                self.model = TemporalGNNPredictor(**{k:ckpt['config'][k] for k in ['node_features','hidden_dim']})
                self.model.load_state_dict(ckpt['model_state_dict']); self.model.eval(); self.loaded = True
                self.attack_types = ckpt.get('attack_types', self.attack_types)
                logger.info(f"✅ Temporal GNN загружен: {ckpt['params']:,} параметров, точность {ckpt['accuracy']:.1%}")
        except Exception as e: logger.warning(f"Temporal GNN load error: {e}")
    
    def add_alert(self, ip: str, attack_type: str, score: float, port: int):
        if ip not in self.node_id_map:
            self.node_id_map[ip] = self.next_id; self.next_id += 1
        atype_idx = self.attack_types.index(attack_type) if attack_type in self.attack_types else 0
        self.alert_history[ip].append({'type_idx': atype_idx, 'score': score, 'port': port, 'time': time.time()})
    
    def predict_next_attack(self, ip: str) -> Dict:
        if not self.loaded or ip not in self.alert_history:
            return {'predicted_attack': 'Unknown', 'confidence': 0.0, 'top3': []}
        try:
            history = list(self.alert_history[ip])[-10:]
            if len(history) < 2: return {'predicted_attack': 'Normal', 'confidence': 0.5, 'top3': []}
            nf = torch.zeros(10, 1, 8)
            for t, alert in enumerate(history[-10:]):
                nf[t, 0, 0] = alert['type_idx'] / len(self.attack_types)
                nf[t, 0, 1] = alert['score']
                nf[t, 0, 2] = alert['port'] / 65535.0
                nf[t, 0, 3] = t / 10.0
                nf[t, 0, 4] = 1.0
                nf[t, 0, 7] = random.random() * 0.5
            edge_seq = [torch.tensor([[0], [0]], dtype=torch.long) for _ in range(10)]
            with torch.no_grad():
                logits = self.model(nf, edge_seq)
                probs = torch.softmax(logits[0, 0], dim=-1)
                top3_idx = probs.argsort(descending=True)[:3]
                top3 = [(self.attack_types[i], float(probs[i])) for i in top3_idx]
                return {'predicted_attack': top3[0][0], 'confidence': top3[0][1], 'top3': top3}
        except Exception as e: logger.error(f"Prediction error: {e}"); return {'predicted_attack': 'Error', 'confidence': 0.0, 'top3': []}
import random
