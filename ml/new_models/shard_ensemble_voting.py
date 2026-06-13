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


logger.info("✅ Voting Ensemble ready (#22) — full fit() + weighted voting")
