#!/usr/bin/env python3
"""SHARD GNN Integration — анализ графа угроз в реальном времени"""
import torch, torch.nn as nn, torch.nn.functional as F
import numpy as np, logging, time
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple

logger = logging.getLogger("SHARD-GNN")

class GCNLayer(nn.Module):
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


class ShardGNN:
    def __init__(self, model_path='./models/gnn/threat_gnn_v2.pt'):
        self.model = None; self.loaded = False; self.node_buffer = defaultdict(list); self.edge_buffer = []
        self._load(model_path)
    def _load(self, path):
        try:
            if Path(path).exists():
                ckpt = torch.load(path, map_location='cpu', weights_only=False)
                self.model = ThreatGNNv2(in_dim=ckpt['config']['node_features'], hidden_dim=ckpt['config']['hidden_dim'], num_layers=ckpt['config']['gnn_layers'], dropout=ckpt['config']['dropout'])
                self.model.load_state_dict(ckpt['model_state_dict']); self.model.eval(); self.loaded = True
                logger.info(f"✅ GNN Threat Graph загружен: {ckpt['params']:,} параметров")
        except Exception as e: logger.warning(f"GNN load error: {e}")
    def add_node(self, ip: str, features: List[float]): self.node_buffer[ip] = features
    def add_edge(self, src_ip: str, dst_ip: str): self.edge_buffer.append((src_ip, dst_ip))
    def analyze(self) -> Dict:
        if not self.loaded or len(self.node_buffer) < 3: return {'threat_score': 0.0, 'malicious_ips': [], 'suspicious_ips': []}
        try:
            ips = list(self.node_buffer.keys())[-100:]
            ip2idx = {ip:i for i,ip in enumerate(ips)}
            x = torch.tensor([self.node_buffer[ip][:16] + [0.0]*(16-len(self.node_buffer[ip])) for ip in ips], dtype=torch.float32)
            edges = [(ip2idx[s], ip2idx[d]) for s,d in self.edge_buffer[-500:] if s in ip2idx and d in ip2idx]
            if not edges: edges = [(i,i+1) for i in range(len(ips)-1)]
            ei = torch.tensor(edges, dtype=torch.long).t().contiguous()
            with torch.no_grad():
                logits, score = self.model(x, ei)
                preds = logits.argmax(dim=1)
            return {'threat_score': float(score.item()), 'malicious_ips': [ips[i] for i in range(len(ips)) if preds[i]==2], 'suspicious_ips': [ips[i] for i in range(len(ips)) if preds[i]==1], 'total_nodes': len(ips)}
        except Exception as e: logger.error(f"GNN analyze error: {e}"); return {'threat_score': 0.0, 'malicious_ips': [], 'suspicious_ips': []}
