#!/usr/bin/env python3
"""
SHARD TabNet — Attentive Interpretable Tabular Learning (#32)

Архитектура Google Cloud:
- Sequential Attention — выбирает какие features важны на каждом шаге
- Feature Transformer — обрабатывает выбранные признаки
- Attentive Transformer — sparse attention маска
- Ghost Batch Normalization — для больших батчей
- Sparsemax — разреженная нормализация
"""

import numpy as np
import logging
import torch
import torch.nn as nn
import torch.nn.functional as F

logger = logging.getLogger("SHARD-TabNet")


class Sparsemax(nn.Module):
    """Sparsemax — разреженный softmax"""
    def forward(self, x):
        dim = -1
        x_sorted, _ = torch.sort(x, dim=dim, descending=True)
        cumsum = torch.cumsum(x_sorted, dim=dim)
        k = torch.arange(1, x.size(dim) + 1, device=x.device).view(
            *[1] * (x.dim() - 1), -1
        )
        k_z = 1 + k * x_sorted
        support = k_z > cumsum
        k_max = support.sum(dim=dim, keepdim=True).float()
        tau = (cumsum.gather(dim, (k_max - 1).long()) - 1) / k_max
        return torch.clamp(x - tau, min=0)


class GhostBatchNorm1d(nn.Module):
    """Ghost Batch Normalization"""
    def __init__(self, num_features, virtual_batch_size=128, momentum=0.01):
        super().__init__()
        self.bn = nn.BatchNorm1d(num_features, momentum=momentum)
        self.vbs = virtual_batch_size
    
    def forward(self, x):
        if x.size(0) <= self.vbs or self.vbs <= 0:
            return self.bn(x)
        
        chunks = x.chunk(max(1, x.size(0) // self.vbs), 0)
        res = [self.bn(c) for c in chunks]
        return torch.cat(res, dim=0)


class FeatureTransformer(nn.Module):
    """Feature Transformer блок"""
    def __init__(self, input_dim, output_dim, shared_blocks=2, independent_blocks=2, vbs=128):
        super().__init__()
        
        self.shared = nn.ModuleList()
        for _ in range(shared_blocks):
            self.shared.append(nn.ModuleDict({
                'fc': nn.Linear(output_dim, output_dim),
                'bn': GhostBatchNorm1d(output_dim, vbs)
            }))
        
        self.independent = nn.ModuleList()
        for _ in range(independent_blocks):
            self.independent.append(nn.ModuleDict({
                'fc': nn.Linear(output_dim, output_dim),
                'bn': GhostBatchNorm1d(output_dim, vbs)
            }))
        
        self.initial = nn.Linear(input_dim, output_dim)
    
    def forward(self, x, shared_coeff=1.0):
        x = self.initial(x)
        
        for layer in self.shared:
            residual = x
            x = layer['fc'](x)
            x = layer['bn'](x)
            x = F.glu(x) if x.size(-1) % 2 == 0 else F.relu(x)
            x = (residual + x) * (0.5 ** 0.5)
        
        for layer in self.independent:
            residual = x
            x = layer['fc'](x)
            x = layer['bn'](x)
            x = F.glu(x) if x.size(-1) % 2 == 0 else F.relu(x)
            x = (residual + x) * (0.5 ** 0.5)
        
        return x


class AttentiveTransformer(nn.Module):
    """Внимательный выбор признаков"""
    def __init__(self, input_dim, output_dim, vbs=128):
        super().__init__()
        self.fc = nn.Linear(input_dim, output_dim)
        self.bn = GhostBatchNorm1d(output_dim, vbs)
        self.sparsemax = Sparsemax()
        self.prior_scale = nn.Parameter(torch.ones(1))
    
    def forward(self, x, prior_scales):
        x = self.fc(x)
        x = self.bn(x)
        x = x * prior_scales
        return self.sparsemax(x)


class TabNetDetector(nn.Module):
    """Полная TabNet модель для обнаружения атак"""
    
    def __init__(self, input_dim=76, output_dim=2, n_d=32, n_a=32, n_steps=5,
                 gamma=1.5, epsilon=1e-15, vbs=128):
        super().__init__()
        
        self.n_steps = n_steps
        self.gamma = gamma
        self.epsilon = epsilon
        self.n_d = n_d
        self.n_a = n_a
        
        self.feature_transformer = FeatureTransformer(input_dim, n_d + n_a, vbs=vbs)
        self.attentive_transformers = nn.ModuleList([
            AttentiveTransformer(n_a, input_dim, vbs=vbs) for _ in range(n_steps)
        ])
        self.feature_transformers = nn.ModuleList([
            FeatureTransformer(input_dim, n_d + n_a, vbs=vbs) for _ in range(n_steps)
        ])
        
        self.final = nn.Linear(n_d, output_dim)
    
    def forward(self, x):
        batch_size = x.size(0)
        prior = torch.ones(batch_size, x.size(1), device=x.device)
        out = torch.zeros(batch_size, self.n_d, device=x.device)
        
        for step in range(self.n_steps):
            # Attention маска
            mask = self.attentive_transformers[step](out, prior)
            
            # Feature selection
            masked_x = x * mask
            
            # Transform
            ft_out = self.feature_transformers[step](masked_x)
            
            # Split на decision и attention части
            d_out = ft_out[:, :self.n_d]
            a_out = ft_out[:, self.n_d:]
            
            out = F.relu(out + d_out)
            
            # Обновление prior для разреженности
            prior = prior * (self.gamma - mask)
        
        return self.final(out)
    
    def explain(self, x):
        """Возвращает важность признаков (встроенная объяснимость)"""
        batch_size = x.size(0)
        prior = torch.ones(batch_size, x.size(1), device=x.device)
        out = torch.zeros(batch_size, self.n_d, device=x.device)
        feature_importance = torch.zeros(batch_size, x.size(1), device=x.device)
        
        for step in range(self.n_steps):
            mask = self.attentive_transformers[step](out, prior)
            feature_importance += mask
            masked_x = x * mask
            ft_out = self.feature_transformers[step](masked_x)
            d_out = ft_out[:, :self.n_d]
            out = F.relu(out + d_out)
            prior = prior * (self.gamma - mask)
        
        return self.final(out), feature_importance / self.n_steps


class TabNetWrapper:
    """Обёртка для SHARD"""
    
    def __init__(self, input_dim=76):
        self.model = TabNetDetector(input_dim=input_dim)
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model.to(self.device)
        self.is_trained = False
    
    def train(self, X, y, epochs=30):
        self.model.train()
        opt = torch.optim.Adam(self.model.parameters(), lr=0.02)
        sched = torch.optim.lr_scheduler.StepLR(opt, step_size=10, gamma=0.9)
        
        X_t = torch.FloatTensor(X).to(self.device)
        y_t = torch.LongTensor(y).to(self.device)
        
        for epoch in range(epochs):
            opt.zero_grad()
            logits = self.model(X_t)
            loss = F.cross_entropy(logits, y_t)
            loss.backward()
            opt.step()
            sched.step()
        
        self.is_trained = True
        return {'epochs': epochs}
    
    def predict(self, X):
        if not self.is_trained:
            return np.zeros(len(X)), np.ones(len(X))
        
        self.model.eval()
        X_t = torch.FloatTensor(X).to(self.device)
        with torch.no_grad():
            logits, importance = self.model.explain(X_t)
            probs = F.softmax(logits, dim=-1)[:, 1].cpu().numpy()
        
        return (probs > 0.5).astype(int), probs


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

logger.info("✅ TabNet ready (#32) — Attentive Interpretable Tabular Learning")
