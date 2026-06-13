#!/usr/bin/env python3
"""SHARD KNN Detector — anomaly detection по расстоянию до соседей (модель #20)"""
import numpy as np, logging, pickle
from pathlib import Path
logger = logging.getLogger("SHARD-KNN")
try:
    from sklearn.neighbors import NearestNeighbors
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

class KNNDetector:
    def __init__(self, n_neighbors=5):
        self.nn = NearestNeighbors(n_neighbors=n_neighbors, n_jobs=-1) if HAS_SKLEARN else None
        self.threshold_ = 0.0
        self.is_fitted = False
        self.model_path = Path('models/knn_detector.pkl')
    
    def fit(self, X_normal):
        if self.nn is None: return None
        self.nn.fit(X_normal)
        distances, _ = self.nn.kneighbors(X_normal)
        mean_dists = distances.mean(axis=1)
        self.threshold_ = np.percentile(mean_dists, 95)
        self.is_fitted = True
        with open(self.model_path, 'wb') as f: pickle.dump((self.nn, self.threshold_), f)
        return {'threshold': float(self.threshold_), 'samples': len(X_normal)}
    
    def predict(self, X):
        if not self.is_fitted: return np.zeros(len(X)), np.ones(len(X))
        distances, _ = self.nn.kneighbors(X)
        scores = distances.mean(axis=1)
        scores = np.clip(scores / (self.threshold_ + 1e-8), 0, 2)
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

logger.info("✅ KNN Detector ready (model #20)")
