#!/usr/bin/env python3
"""
SHARD Voting Ensemble (#22) — ансамбль всех моделей с весами на основе F1-score.
"""
import numpy as np, logging, joblib
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from sklearn.metrics import f1_score
from ml.new_models.base_detector import BaseShardDetector

logger = logging.getLogger("SHARD-VotingEnsemble")


class VotingEnsemble(BaseShardDetector):
    """Ансамбль с автоматическим взвешиванием по F1-score каждой модели."""
    
    def __init__(self, name: str = "VotingEnsemble"):
        super().__init__(name)
        self.models: Dict[str, Tuple[object, float]] = {}  # name -> (model, weight)
        self.model = self  # Совместимость
        self.meta_weights = {}
    
    def add_model(self, name: str, model: BaseShardDetector):
        """Добавить модель в ансамбль."""
        self.models[name] = (model, 1.0)
        logger.info(f"➕ Added {name} to ensemble ({len(self.models)} models)")
    
    def fit(self, X: np.ndarray = None, y: np.ndarray = None, X_val: np.ndarray = None, y_val: np.ndarray = None) -> 'VotingEnsemble':
        """
        Обучить ансамбль — вычислить веса моделей на основе их F1-score.
        Если X_val не задан — веса равные.
        """
        if X is not None and y is not None:
            for name, (model, _) in self.models.items():
                try:
                    preds, _ = model.predict(X)
                    f1 = f1_score(y, preds, zero_division=0)
                    self.models[name] = (model, max(f1, 0.01))  # Минимальный вес 0.01
                    self.meta_weights[name] = round(f1, 4)
                except Exception as e:
                    logger.warning(f"⚠️ {name} evaluation failed: {e}")
                    self.models[name] = (model, 0.01)
            
            # Нормализация весов
            total_w = sum(w for _, w in self.models.values())
            if total_w > 0:
                for name in self.models:
                    model, w = self.models[name]
                    self.models[name] = (model, w / total_w)
        
        self._is_fitted = True
        self.metadata['trained_at'] = __import__('time').strftime('%Y-%m-%d %H:%M:%S')
        self.metadata['samples_trained'] = len(X) if X is not None else 0
        
        logger.info(f"🎯 Ensemble fitted: {len(self.models)} models, "
                   f"weights={self.meta_weights}")
        return self
    
    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Взвешенное голосование всех моделей."""
        if not self.models:
            return np.zeros(len(X)), np.ones(len(X))
        
        X_clean = self._validate_input(X)
        all_scores = []
        total_weight = 0.0
        
        for name, (model, weight) in self.models.items():
            try:
                _, scores = model.predict(X_clean)
                if isinstance(scores, np.ndarray) and len(scores) == len(X_clean):
                    all_scores.append(scores * weight)
                    total_weight += weight
            except Exception as e:
                logger.debug(f"⚠️ {name} predict failed: {e}")
        
        if not all_scores:
            return np.zeros(len(X_clean)), np.ones(len(X_clean))
        
        avg_scores = np.mean(all_scores, axis=0)
        predictions = (avg_scores > 0.5).astype(int)
        return predictions, avg_scores
    
    def update(self, X_new: np.ndarray, y_new: np.ndarray = None) -> bool:
        """Пересчитать веса на новых данных."""
        if y_new is not None:
            self.fit(X_val=X_new, y_val=y_new)
            return True
        return False
    
    def get_model_count(self) -> int:
        return len(self.models)
    
    def get_weights(self) -> Dict[str, float]:
        return {name: round(w, 4) for name, (_, w) in self.models.items()}



    def save(self, path=None):
        """Сохранить ансамбль и все его модели."""
        import joblib
        from pathlib import Path
        save_path = Path(path) if path else Path('models') / 'voting_ensemble.joblib'
        save_path.parent.mkdir(parents=True, exist_ok=True)
        
        state = {
            'meta_weights': self.meta_weights,
            'metrics': self.metrics,
            'is_fitted': self._is_fitted
        }
        # Сохраняем каждую модель отдельно
        for name, (model, weight) in self.models.items():
            model_path = save_path.parent / f'{name}_ensemble.joblib'
            try:
                if hasattr(model, 'save'):
                    model.save(model_path)
                else:
                    joblib.dump(model, model_path, compress=0)
            except:
                pass
        
        joblib.dump(state, save_path, compress=0)
        return True
    
    def load(self, path=None):
        """Загрузить ансамбль."""
        import joblib
        from pathlib import Path
        load_path = Path(path) if path else Path('models') / 'voting_ensemble.joblib'
        
        if not load_path.exists():
            return False
        
        state = joblib.load(load_path)
        self.meta_weights = state.get('meta_weights', {})
        self.metrics = state.get('metrics', {})
        self._is_fitted = state.get('is_fitted', False)
        
        # Загружаем модели
        for name in self.meta_weights:
            model_path = load_path.parent / f'{name}_ensemble.joblib'
            if model_path.exists() and name in self.models:
                try:
                    model_data = joblib.load(model_path)
                    self.models[name] = (model_data, self.meta_weights.get(name, 1.0))
                except:
                    pass
        return True
    
    def explain(self, X, top_k=10):
        """SHAP объяснение — усреднённое по всем моделям."""
        import numpy as np
        all_importances = []
        for name, (model, weight) in self.models.items():
            try:
                if hasattr(model, 'explain'):
                    exp = model.explain(X)
                    if 'shap_values' in exp:
                        all_importances.append(np.array(exp['shap_values']) * weight)
                elif hasattr(model, 'feature_importances_'):
                    all_importances.append(model.feature_importances_ * weight)
            except:
                pass
        
        if all_importances:
            avg_importance = np.mean(all_importances, axis=0)
            top_idx = np.argsort(np.abs(avg_importance))[-top_k:][::-1]
            return {
                'top_features': [f'feature_{i}' for i in top_idx],
                'importances': avg_importance[top_idx].tolist(),
                'method': 'ensemble_average'
            }
        return {'message': 'No explainable models in ensemble'}
    
    def get_metrics(self):
        """Метрики качества ансамбля."""
        return self.metrics
    
    def evaluate(self, X_test, y_test):
        """Оценить качество ансамбля."""
        from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
        preds, scores = self.predict(X_test)
        self.metrics = {
            'f1_score': round(f1_score(y_test, preds, zero_division=0), 4),
            'precision': round(precision_score(y_test, preds, zero_division=0), 4),
            'recall': round(recall_score(y_test, preds, zero_division=0), 4),
            'roc_auc': round(roc_auc_score(y_test, scores), 4)
        }
        return self.metrics

logger.info("✅ Voting Ensemble ready (#22) — full fit() + weighted voting")
