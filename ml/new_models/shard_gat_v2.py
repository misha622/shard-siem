#!/usr/bin/env python3
"""
SHARD GAT v2 — Graph Attention Network с динамическим вниманием (#31)

Архитектура:
- Multi-head attention с learnable параметрами
- Dynamic attention (GATv2) — каждый узел учится КОГО слушать
- Edge features в attention механизме
- Skip connections между слоями
- Layer Normalization вместо BatchNorm (лучше для графов)

Отличие от GAT: attention коэффициенты вычисляются до применения LeakyReLU,
что даёт более выразительную модель (dynamic attention).
"""

import numpy as np
import logging
import torch
import torch.nn as nn
import torch.nn.functional as F

logger = logging.getLogger("SHARD-GATv2")


class GATv2Layer(nn.Module):
    """Один слой GATv2 с multi-head attention"""
    
    def __init__(self, in_dim: int, out_dim: int, num_heads: int = 4, 
                 dropout: float = 0.2, edge_dim: int = None, residual: bool = True):
        super().__init__()
        self.num_heads = num_heads
        self.out_dim = out_dim
        self.residual = residual
        
        # Линейная проекция входов
        self.W = nn.Linear(in_dim, out_dim * num_heads, bias=False)
        
        # Attention параметры (GATv2: a^T [Wh_i || Wh_j || e_ij])
        attn_dim = out_dim * 2 + (edge_dim if edge_dim else 0)
        self.a = nn.Parameter(torch.zeros(num_heads, attn_dim))
        nn.init.xavier_uniform_(self.a)
        
        # Edge encoding (опционально)
        self.edge_enc = nn.Linear(edge_dim, edge_dim) if edge_dim else None
        
        # Skip connection
        if residual and in_dim != out_dim * num_heads:
            self.skip = nn.Linear(in_dim, out_dim * num_heads)
        else:
            self.skip = nn.Identity() if residual else None
        
        self.dropout = nn.Dropout(dropout)
        self.layernorm = nn.LayerNorm(out_dim * num_heads)
        self.leaky_relu = nn.LeakyReLU(0.2)
    
    def forward(self, x, edge_index, edge_attr=None):
        """
        x: (N, in_dim) — признаки узлов
        edge_index: (2, E) — рёбра
        edge_attr: (E, edge_dim) — признаки рёбер (опционально)
        """
        N = x.size(0)
        
        # Проекция узлов
        Wh = self.W(x).view(N, self.num_heads, self.out_dim)  # (N, H, D)
        
        src, dst = edge_index[0], edge_index[1]
        Wh_src = Wh[src]  # (E, H, D)
        Wh_dst = Wh[dst]
        
        # Attention scores
        if edge_attr is not None and self.edge_enc is not None:
            edge_emb = self.edge_enc(edge_attr).unsqueeze(1).expand(-1, self.num_heads, -1)
            attn_input = torch.cat([Wh_src, Wh_dst, edge_emb], dim=-1)
        else:
            attn_input = torch.cat([Wh_src, Wh_dst], dim=-1)
        
        # GATv2: attention до LeakyReLU (dynamic attention)
        e = (attn_input * self.a.unsqueeze(0)).sum(dim=-1)  # (E, H)
        e = self.leaky_relu(e)
        
        # Softmax по соседям каждого узла
        alpha = torch.zeros(N, self.num_heads, device=x.device)
        alpha = alpha.index_add(0, dst, e.exp())
        alpha = e / (alpha[dst] + 1e-8)
        alpha = self.dropout(alpha)
        
        # Агрегация
        out = torch.zeros(N, self.num_heads, self.out_dim, device=x.device)
        weighted = Wh_src * alpha.unsqueeze(-1)
        out = out.index_add(0, dst, weighted)
        
        # Multi-head → конкатенация
        out = out.view(N, -1)
        
        # Skip connection
        if self.skip is not None:
            out = out + self.skip(x)
        
        return self.layernorm(F.elu(out))


class GATv2ThreatDetector(nn.Module):
    """Полная GATv2 модель для анализа графа угроз"""
    
    def __init__(self, node_dim: int = 12, edge_dim: int = 4, 
                 hidden_dim: int = 64, num_layers: int = 3,
                 num_heads: int = 4, num_classes: int = 5, dropout: float = 0.2):
        super().__init__()
        
        self.input_proj = nn.Linear(node_dim, hidden_dim)
        
        # Слои GATv2
        self.layers = nn.ModuleList()
        for i in range(num_layers):
            self.layers.append(
                GATv2Layer(
                    in_dim=hidden_dim if i > 0 else hidden_dim,
                    out_dim=hidden_dim // num_heads,
                    num_heads=num_heads,
                    dropout=dropout,
                    edge_dim=edge_dim if i == 0 else None,
                    residual=True
                )
            )
        
        # Классификатор узлов
        self.node_classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, num_classes)
        )
        
        # Предсказатель рёбер (link prediction)
        self.edge_predictor = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, 1),
            nn.Sigmoid()
        )
        
        # Глобальный threat score
        self.global_pool = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, 1),
            nn.Sigmoid()
        )
    
    def forward(self, x, edge_index, edge_attr=None):
        x = F.relu(self.input_proj(x))
        
        for layer in self.layers:
            x = layer(x, edge_index, edge_attr)
        
        node_logits = self.node_classifier(x)
        
        src, dst = edge_index[0], edge_index[1]
        edge_emb = torch.cat([x[src], x[dst]], dim=-1)
        edge_probs = self.edge_predictor(edge_emb)
        
        graph_score = self.global_pool(x.mean(dim=0, keepdim=True))
        
        return node_logits, edge_probs, graph_score


class GATv2Detector:
    """Детектор на базе GATv2 — улучшенное обнаружение Lateral Movement и APT"""
    
    def __init__(self, node_dim: int = 12, edge_dim: int = 4):
        self.model = GATv2ThreatDetector(node_dim=node_dim, edge_dim=edge_dim)
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model.to(self.device)
        self.is_trained = False
        self.optimizer = torch.optim.AdamW(self.model.parameters(), lr=0.001, weight_decay=0.01)
        self.scheduler = torch.optim.lr_scheduler.CosineAnnealingWarmRestarts(
            self.optimizer, T_0=10, T_mult=2
        )
    
    def train(self, graphs: list, epochs: int = 50):
        """graphs: список (x, edge_index, edge_attr, y_node)"""
        self.model.train()
        
        for epoch in range(epochs):
            total_loss = 0
            for x, ei, ea, y in graphs:
                x = x.to(self.device)
                ei = ei.to(self.device)
                ea = ea.to(self.device) if ea is not None else None
                y = y.to(self.device)
                
                node_logits, edge_probs, graph_score = self.model(x, ei, ea)
                
                loss = F.cross_entropy(node_logits, y)
                loss.backward()
                
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                self.optimizer.step()
                self.optimizer.zero_grad()
                
                total_loss += loss.item()
            
            self.scheduler.step()
        
        self.is_trained = True
        return {'epochs': epochs, 'final_loss': total_loss / max(1, len(graphs))}
    
    def predict(self, x, edge_index, edge_attr=None):
        if not self.is_trained:
            return np.zeros(len(x)), np.ones(len(x))
        
        self.model.eval()
        with torch.no_grad():
            x_t = x.to(self.device) if isinstance(x, torch.Tensor) else torch.FloatTensor(x).to(self.device)
            ei_t = edge_index.to(self.device) if isinstance(edge_index, torch.Tensor) else torch.LongTensor(edge_index).to(self.device)
            ea_t = edge_attr.to(self.device) if edge_attr is not None and isinstance(edge_attr, torch.Tensor) else None
            
            node_logits, edge_probs, graph_score = self.model(x_t, ei_t, ea_t)
            
            probs = F.softmax(node_logits, dim=-1)
            anomaly_scores = 1 - probs[:, 0]  # Класс 0 = норма
            predictions = (anomaly_scores > 0.5).cpu().numpy()
            
            return predictions, anomaly_scores.cpu().numpy()


    # ============================================================
    # UPGRADED: метрики, save/load, SHAP, онлайн-обучение
    # ============================================================
    
    def evaluate(self, X_test, y_test):
        """Оценить качество модели."""
        from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
        preds, scores = self.predict(X_test)
        self.metrics = {
            'f1_score': round(f1_score(y_test, preds, zero_division=0), 4),
            'precision': round(precision_score(y_test, preds, zero_division=0), 4),
            'recall': round(recall_score(y_test, preds, zero_division=0), 4),
            'roc_auc': round(roc_auc_score(y_test, scores), 4)
        }
        return self.metrics
    
    def save(self, path=None):
        """Сохранить модель."""
        import joblib
        from pathlib import Path
        save_path = Path(path) if path else Path('models') / f'{self.__class__.__name__.lower()}.joblib'
        save_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({'model': getattr(self, 'model', self), 'metrics': getattr(self, 'metrics', {})}, save_path, compress=0)
        return True
    
    def load(self, path=None):
        """Загрузить модель."""
        import joblib
        from pathlib import Path
        load_path = Path(path) if path else Path('models') / f'{self.__class__.__name__.lower()}.joblib'
        if load_path.exists():
            data = joblib.load(load_path)
            if hasattr(self, 'model'): self.model = data.get('model')
            self.metrics = data.get('metrics', {})
            self.is_trained = True
            return True
        return False
    
    def update(self, X_new, y_new=None):
        """Онлайн-дообучение."""
        try:
            self.train(X_new, y_new) if y_new is not None else self.train(X_new)
            return True
        except:
            return False
    
    def explain(self, X, top_k=10):
        """SHAP объяснения."""
        try:
            import shap
            import numpy as np
            model = getattr(self, 'model', self)
            if hasattr(model, 'predict_proba'):
                explainer = shap.TreeExplainer(model) if hasattr(model, 'feature_importances_') else shap.KernelExplainer(lambda x: self.predict(x)[1], X[:min(50, len(X))])
                shap_values = explainer.shap_values(X[:1])
                if isinstance(shap_values, list): shap_vals = shap_values[1][0] if len(shap_values) > 1 else shap_values[0][0]
                else: shap_vals = shap_values[0]
                top_idx = np.argsort(np.abs(shap_vals))[-top_k:][::-1]
                return {'top_features': [f'f_{i}' for i in top_idx], 'shap_values': shap_vals[top_idx].tolist()}
        except:
            pass
        return {'message': 'SHAP not available for this model'}

logger.info("✅ GATv2 ready (#31) — Dynamic Graph Attention Network")
