#!/usr/bin/env python3
"""
SHARD Anomaly Transformer (#34)
Специализированный трансформер для обнаружения аномалий.
Ключевая идея: Association Discrepancy — разница между prior и series association.
"""
import numpy as np, logging
import torch, torch.nn as nn, torch.nn.functional as F

logger = logging.getLogger("SHARD-AnomalyTransformer")

class AnomalyTransformer(nn.Module):
    def __init__(self, input_dim=76, d_model=128, n_heads=8, num_layers=3, dropout=0.1):
        super().__init__()
        self.embed = nn.Linear(input_dim, d_model)
        encoder_layer = nn.TransformerEncoderLayer(d_model=d_model, nhead=n_heads, dropout=dropout, batch_first=True)
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        self.decoder = nn.Linear(d_model, input_dim)
        self.prior_association = nn.Sequential(nn.Linear(d_model, d_model//2), nn.ReLU(), nn.Linear(d_model//2, 1), nn.Sigmoid())
        self.series_association = nn.Sequential(nn.Linear(d_model, d_model//2), nn.ReLU(), nn.Linear(d_model//2, 1), nn.Sigmoid())
    
    def forward(self, x):
        if x.dim() == 2: x = x.unsqueeze(1)
        emb = self.embed(x)
        encoded = self.encoder(emb)
        recon = self.decoder(encoded)
        prior = self.prior_association(encoded)
        series = self.series_association(encoded)
        return recon, prior, series

class AnomalyTransformerDetector:
    def __init__(self, input_dim=76):
        self.model = AnomalyTransformer(input_dim)
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model.to(self.device)
        self.threshold = 0.0
        self.is_trained = False
    
    def train(self, X, epochs=50):
        self.model.train()
        opt = torch.optim.Adam(self.model.parameters(), lr=0.001)
        X_t = torch.FloatTensor(X).to(self.device)
        for _ in range(epochs):
            opt.zero_grad()
            recon, prior, series = self.model(X_t)
            recon_loss = F.mse_loss(recon, X_t.unsqueeze(1) if X_t.dim() == 2 else X_t)
            assoc_loss = F.kl_div(torch.log(series + 1e-8), prior + 1e-8, reduction='batchmean')
            loss = recon_loss + 0.1 * assoc_loss
            loss.backward()
            opt.step()
        self.model.eval()
        with torch.no_grad():
            recon, _, _ = self.model(X_t)
            errors = ((recon.squeeze(1) - X_t) ** 2).mean(dim=1).cpu().numpy()
            self.threshold = np.percentile(errors, 95)
        self.is_trained = True
        return {'threshold': float(self.threshold)}
    
    def predict(self, X):
        if not self.is_trained: return np.zeros(len(X)), np.ones(len(X))
        self.model.eval()
        X_t = torch.FloatTensor(X).to(self.device)
        with torch.no_grad():
            recon, _, _ = self.model(X_t)
            errors = ((recon.squeeze(1) - X_t) ** 2).mean(dim=1).cpu().numpy()
        scores = np.clip(errors / (self.threshold + 1e-8), 0, 2)
        return (scores > 1.0).astype(int), scores / 2.0

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

logger.info("✅ Anomaly Transformer ready (#34)")
