#!/usr/bin/env python3
"""SHARD Graph Autoencoder — детектор аномальных графов (модель #15)"""

import numpy as np
import logging

logger = logging.getLogger("SHARD-GraphAE")

try:
    import torch
    import torch.nn as nn
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False

if HAS_TORCH:
    class GraphAutoencoder(nn.Module):
        """Автоэнкодер для графов — находит необычные паттерны связей"""
        def __init__(self, num_nodes=50, hidden_dim=64, latent_dim=16):
            super().__init__()
            # Encoder
            self.enc_fc1 = nn.Linear(num_nodes * num_nodes, 512)
            self.enc_fc2 = nn.Linear(512, hidden_dim)
            self.enc_mu = nn.Linear(hidden_dim, latent_dim)
            self.enc_logvar = nn.Linear(hidden_dim, latent_dim)
            
            # Decoder
            self.dec_fc1 = nn.Linear(latent_dim, hidden_dim)
            self.dec_fc2 = nn.Linear(hidden_dim, 512)
            self.dec_out = nn.Linear(512, num_nodes * num_nodes)
            
        def encode(self, x):
            h = torch.relu(self.enc_fc1(x))
            h = torch.relu(self.enc_fc2(h))
            return self.enc_mu(h), self.enc_logvar(h)
        
        def reparameterize(self, mu, logvar):
            std = torch.exp(0.5 * logvar)
            eps = torch.randn_like(std)
            return mu + eps * std
        
        def decode(self, z):
            h = torch.relu(self.dec_fc1(z))
            h = torch.relu(self.dec_fc2(h))
            return torch.sigmoid(self.dec_out(h))
        
        def forward(self, x):
            mu, logvar = self.encode(x)
            z = self.reparameterize(mu, logvar)
            return self.decode(z), mu, logvar

class GraphAEDetector:
    """Обнаружение аномальных графовых паттернов (модель #15)"""
    
    def __init__(self, num_nodes=50):
        self.model = GraphAutoencoder(num_nodes) if HAS_TORCH else None
        self.is_trained = False
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu') if HAS_TORCH else None
        self.threshold = 0.0
        
        if self.model:
            self.model.to(self.device)
    
    def train(self, adj_matrices, epochs=100):
        if self.model is None:
            return None
        
        self.model.train()
        optimizer = torch.optim.Adam(self.model.parameters(), lr=0.001)
        
        X = torch.FloatTensor(adj_matrices).to(self.device)
        X_flat = X.view(X.size(0), -1)
        
        for epoch in range(epochs):
            optimizer.zero_grad()
            recon, mu, logvar = self.model(X_flat)
            recon_loss = nn.functional.mse_loss(recon, X_flat, reduction='sum')
            kl_loss = -0.5 * torch.sum(1 + logvar - mu.pow(2) - logvar.exp())
            loss = recon_loss + 0.1 * kl_loss
            loss.backward()
            optimizer.step()
        
        # Устанавливаем порог
        with torch.no_grad():
            recon, _, _ = self.model(X_flat)
            errors = ((recon - X_flat) ** 2).mean(dim=1).cpu().numpy()
            self.threshold = np.percentile(errors, 95)
        
        self.is_trained = True
        return {'status': 'trained', 'threshold': float(self.threshold)}
    
    def predict(self, adj_matrix):
        if not self.is_trained or self.model is None:
            return {'is_anomaly': False, 'score': 0.0}
        
        self.model.eval()
        X = torch.FloatTensor(adj_matrix).to(self.device)
        X_flat = X.view(1, -1)
        
        with torch.no_grad():
            recon, _, _ = self.model(X_flat)
            error = ((recon - X_flat) ** 2).mean().item()
        
        score = min(1.0, error / (self.threshold + 1e-8))
        return {'is_anomaly': error > self.threshold, 'score': score, 'recon_error': error}

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

logger.info("✅ Graph Autoencoder ready (model #15)")
