#!/usr/bin/env python3
"""SHARD One-Class SVM — детектор неизвестных атак (модель #13)"""

import numpy as np
import logging
from pathlib import Path
import pickle

logger = logging.getLogger("SHARD-OneClassSVM")

try:
    from sklearn.svm import OneClassSVM
    HAS_SVM = True
except ImportError:
    HAS_SVM = False

class OneClassSVMDetector:
    """One-Class SVM — идеален для обнаружения zero-day атак"""
    
    def __init__(self, nu=0.1, kernel='rbf'):
        self.model = OneClassSVM(nu=nu, kernel=kernel, gamma='scale') if HAS_SVM else None
        self.is_trained = False
        self.model_path = Path('models/oneclass_svm.pkl')
        
    def train(self, X_normal):
        if self.model is None:
            return None
        
        self.model.fit(X_normal)
        self.is_trained = True
        
        with open(self.model_path, 'wb') as f:
            pickle.dump(self.model, f)
        
        return {'status': 'trained', 'samples': len(X_normal)}
    
    def predict(self, X):
        if not self.is_trained or self.model is None:
            return np.ones(len(X))  # все аномалии по умолчанию
        # -1 = аномалия, 1 = норма
        pred = self.model.predict(X)
        return (pred == -1).astype(int)
    
    def decision_function(self, X):
        if not self.is_trained or self.model is None:
            return np.zeros(len(X))
        return -self.model.score_samples(X)  # чем выше — тем аномальнее

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

logger.info("✅ One-Class SVM ready (model #13)")
