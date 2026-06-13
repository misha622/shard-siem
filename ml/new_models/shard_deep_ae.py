"""SHARD Deep Autoencoder — сжатие и восстановление для детекта аномалий (#24)"""
import numpy as np, torch, torch.nn as nn, logging, pickle
from pathlib import Path
logger = logging.getLogger("SHARD-DeepAE")

class DeepAutoencoder(nn.Module):
    def __init__(self, input_dim=76, latent_dim=16):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 256), nn.ReLU(), nn.BatchNorm1d(256),
            nn.Linear(256, 128), nn.ReLU(), nn.BatchNorm1d(128),
            nn.Linear(128, 64), nn.ReLU(), nn.BatchNorm1d(64),
            nn.Linear(64, latent_dim)
        )
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 64), nn.ReLU(), nn.BatchNorm1d(64),
            nn.Linear(64, 128), nn.ReLU(), nn.BatchNorm1d(128),
            nn.Linear(128, 256), nn.ReLU(), nn.BatchNorm1d(256),
            nn.Linear(256, input_dim), nn.Sigmoid()
        )
    def forward(self, x): return self.decoder(self.encoder(x))

class DeepAEDetector:
    def __init__(self, input_dim=76):
        self.model = DeepAutoencoder(input_dim)
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
            recon = self.model(X_t)
            loss = nn.MSELoss()(recon, X_t)
            loss.backward()
            opt.step()
        self.model.eval()
        with torch.no_grad():
            errors = ((self.model(X_t) - X_t) ** 2).mean(dim=1).cpu().numpy()
            self.threshold = np.percentile(errors, 95)
        self.is_trained = True
        return {'threshold': float(self.threshold)}
    
    def predict(self, X):
        if not self.is_trained: return np.zeros(len(X)), np.ones(len(X))
        self.model.eval()
        X_t = torch.FloatTensor(X).to(self.device)
        with torch.no_grad():
            errors = ((self.model(X_t) - X_t) ** 2).mean(dim=1).cpu().numpy()
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

logger.info("✅ DeepAE ready (#24)")
