#!/usr/bin/env python3
"""SHARD Multi-Modal Fusion Integration"""
import torch, torch.nn as nn, numpy as np, logging
from pathlib import Path
logger = logging.getLogger("SHARD-Fusion")

class MultiModalFusion(nn.Module):
    def __init__(self, num_modalities=7, modal_dims=None, fusion_dim=128, num_heads=4, num_layers=2, dropout=0.1):
        super().__init__()
        if modal_dims is None: modal_dims = [13, 100, 5, 1, 1, 3, 1]
        self.projections = nn.ModuleList([nn.Sequential(nn.Linear(d, fusion_dim), nn.LayerNorm(fusion_dim), nn.ReLU()) for d in modal_dims])
        self.cross_attention = nn.MultiheadAttention(fusion_dim, num_heads, dropout=dropout, batch_first=True)
        self.self_attention = nn.MultiheadAttention(fusion_dim, num_heads, dropout=dropout, batch_first=True)
        self.classifier = nn.Sequential(nn.Linear(fusion_dim, fusion_dim*2), nn.LayerNorm(fusion_dim*2), nn.ReLU(), nn.Dropout(dropout), nn.Linear(fusion_dim*2, fusion_dim), nn.ReLU(), nn.Dropout(dropout), nn.Linear(fusion_dim, 3))
        self.confidence_head = nn.Sequential(nn.Linear(fusion_dim, 64), nn.ReLU(), nn.Linear(64, 1), nn.Sigmoid())
        self.modal_weights = nn.Parameter(torch.ones(num_modalities)/num_modalities)
    def forward(self, modalities):
        projected = [p(m) for p, m in zip(self.projections, modalities)]
        stacked = torch.stack(projected, dim=1)
        attn, _ = self.cross_attention(stacked, stacked, stacked)
        fused, _ = self.self_attention(attn, attn, attn)
        w = torch.softmax(self.modal_weights, dim=0)
        fused_w = (fused * w.unsqueeze(0).unsqueeze(-1)).sum(dim=1)
        return self.classifier(fused_w), self.confidence_head(fused_w), w

class ShardFusion:
    def __init__(self, model_path='./models/fusion/multimodal_fusion.pt'):
        self.model = None; self.loaded = False; self.threat_levels = ['BENIGN', 'SUSPICIOUS', 'CRITICAL']
        try:
            if Path(model_path).exists():
                ckpt = torch.load(model_path, map_location='cpu', weights_only=False)
                self.model = MultiModalFusion(**{k:ckpt['config'][k] for k in ['num_modalities','fusion_dim','num_heads','num_layers','dropout']})
                self.model.load_state_dict(ckpt['model_state_dict']); self.model.eval(); self.loaded = True
                logger.info(f"✅ Multi-Modal Fusion загружен: {ckpt['params']:,} параметров")
        except Exception as e: logger.warning(f"Fusion load error: {e}")
    
    def fuse(self, signals):
        """signals: list из 7 тензоров [1, dim_i]"""
        if not self.loaded: return {'threat_level': 'UNKNOWN', 'confidence': 0.0, 'threat_score': 0.0, 'weights': []}
        try:
            mods = [torch.tensor(s, dtype=torch.float32).unsqueeze(0) if isinstance(s, (list, np.ndarray)) else torch.tensor([s], dtype=torch.float32).unsqueeze(0) for s in signals]
            with torch.no_grad():
                logits, conf, w = self.model(mods)
                pred = logits.argmax(dim=1).item()
                return {'threat_level': self.threat_levels[pred], 'confidence': float(conf.item()), 'threat_score': float(torch.softmax(logits, dim=1)[0, pred].item()), 'weights': [float(x) for x in w.tolist()]}
        except Exception as e: logger.error(f"Fusion error: {e}"); return {'threat_level': 'ERROR', 'confidence': 0.0, 'threat_score': 0.0, 'weights': []}
