#!/usr/bin/env python3
"""SHARD Bayesian Neural Network — детектор с confidence (модель #14)"""

import numpy as np
import logging

logger = logging.getLogger("SHARD-BayesianNN")

try:
    import torch
    import torch.nn as nn
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False

if HAS_TORCH:
    class BayesianLayer(nn.Module):
        """Байесовский слой с dropout для оценки неопределённости"""
        def __init__(self, in_dim, out_dim, dropout=0.2):
            super().__init__()
            self.linear = nn.Linear(in_dim, out_dim)
            self.dropout = nn.Dropout(dropout)
            self.bn = nn.BatchNorm1d(out_dim)
        
        def forward(self, x):
            return self.bn(self.dropout(torch.relu(self.linear(x))))
    
    class BayesianNN(nn.Module):
        """Байесовская нейросеть — даёт confidence вместе с предсказанием"""
        def __init__(self, input_dim=156, hidden_dims=[256, 128, 64], num_classes=2):
            super().__init__()
            layers = []
            prev_dim = input_dim
            for h_dim in hidden_dims:
                layers.append(BayesianLayer(prev_dim, h_dim))
                prev_dim = h_dim
            self.encoder = nn.Sequential(*layers)
            self.classifier = nn.Linear(prev_dim, num_classes)
        
        def forward(self, x, num_samples=10):
            """Возвращает предсказание + uncertainty"""
            self.train()  # Включаем dropout для MC Dropout
            preds = []
            for _ in range(num_samples):
                h = self.encoder(x)
                preds.append(torch.softmax(self.classifier(h), dim=-1))
            preds = torch.stack(preds)
            mean = preds.mean(dim=0)
            std = preds.std(dim=0)
            return mean, std

class BayesianNNDetector:
    """Детектор с оценкой уверенности (модель #14)"""
    
    def __init__(self, input_dim=156):
        self.model = BayesianNN(input_dim) if HAS_TORCH else None
        self.is_trained = False
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu') if HAS_TORCH else None
        
        if self.model:
            self.model.to(self.device)
    
    def train(self, X, y, epochs=50):
        if self.model is None:
            return None
        
        self.model.train()
        optimizer = torch.optim.Adam(self.model.parameters(), lr=0.001)
        criterion = nn.CrossEntropyLoss()
        
        X_t = torch.FloatTensor(X).to(self.device)
        y_t = torch.LongTensor(y).to(self.device)
        
        for epoch in range(epochs):
            optimizer.zero_grad()
            mean, std = self.model(X_t, num_samples=5)
            loss = criterion(mean, y_t) + 0.01 * std.mean()
            loss.backward()
            optimizer.step()
        
        self.is_trained = True
        return {'status': 'trained', 'epochs': epochs}
    
    def predict(self, X):
        if not self.is_trained or self.model is None:
            return np.zeros(len(X)), np.zeros(len(X))
        
        self.model.eval()
        X_t = torch.FloatTensor(X).to(self.device)
        with torch.no_grad():
            mean, std = self.model(X_t, num_samples=10)
            preds = mean.argmax(dim=1).cpu().numpy()
            uncertainty = std.max(dim=1)[0].cpu().numpy()
        return preds, uncertainty

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

logger.info("✅ Bayesian NN ready (model #14)")
