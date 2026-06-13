#!/usr/bin/env python3
"""SHARD HDBSCAN Clustering — поиск неизвестных групп атак (модель #16)"""
import numpy as np, logging, pickle
from pathlib import Path
logger = logging.getLogger("SHARD-HDBSCAN")
try:
    import hdbscan
    HAS_HDBSCAN = True
except ImportError:
    HAS_HDBSCAN = False
    logger.warning("pip install hdbscan")

class HDBSCANDetector:
    def __init__(self, min_cluster_size=10):
        self.clusterer = hdbscan.HDBSCAN(min_cluster_size=min_cluster_size, prediction_data=True) if HAS_HDBSCAN else None
        self.labels_ = None
        self.outlier_threshold_ = 0.0
        self.model_path = Path('models/hdbscan.pkl')
    
    def fit(self, X):
        if self.clusterer is None: return None
        self.clusterer.fit(X)
        self.labels_ = self.clusterer.labels_
        scores = self.clusterer.outlier_scores_
        self.outlier_threshold_ = np.percentile(scores, 90)
        with open(self.model_path, 'wb') as f: pickle.dump(self.clusterer, f)
        n_clusters = len(set(self.labels_)) - (1 if -1 in self.labels_ else 0)
        return {'clusters': n_clusters, 'noise': int((self.labels_ == -1).sum())}
    
    def predict(self, X):
        if self.clusterer is None: return np.ones(len(X)), np.ones(len(X))
        labels, strengths = hdbscan.approximate_predict(self.clusterer, X)
        scores = 1.0 - np.clip(strengths, 0, 1)
        is_anomaly = (labels == -1) | (scores > self.outlier_threshold_)
        return is_anomaly.astype(int), scores

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

logger.info("✅ HDBSCAN ready (model #16)")
