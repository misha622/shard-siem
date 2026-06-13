#!/usr/bin/env python3
"""
SHARD BaseDetector — единый интерфейс для всех 50 моделей.

Каждая модель ОБЯЗАНА наследовать этот класс.
"""

import numpy as np
import joblib
import json
import time
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Tuple, Optional, Dict, Any
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score

logger = logging.getLogger("SHARD-BaseDetector")


class BaseShardDetector(ABC):
    """
    Единый интерфейс для всех ML/DL детекторов SHARD.
    
    Обязательные методы:
    - fit(X, y=None) -> self
    - predict(X) -> (predictions, scores)
    - is_fitted() -> bool
    - save(path) -> bool
    - load(path) -> bool
    
    Автоматически предоставляет:
    - Метрики качества (F1, Precision, Recall, AUC)
    - Сохранение/загрузку через joblib
    - Валидацию входных данных (NaN/Inf)
    - Объяснимость через SHAP (опционально)
    - Онлайн-обучение через update()
    """
    
    def __init__(self, name: str = "BaseDetector"):
        self.name = name
        self.model = None
        self._is_fitted = False
        
        # Метрики
        self.metrics = {
            'f1_score': 0.0,
            'precision': 0.0,
            'recall': 0.0,
            'roc_auc': 0.0,
            'accuracy': 0.0
        }
        
        # Метаданные
        self.metadata = {
            'name': name,
            'trained_at': None,
            'samples_trained': 0,
            'features': 0,
            'training_time': 0.0
        }
        
        # Путь к модели
        self.model_path = Path(f'models/{name.lower().replace(" ", "_")}.joblib')
    
    # ============================================================
    # Абстрактные методы (ОБЯЗАТЕЛЬНЫ к реализации)
    # ============================================================
    
    @abstractmethod
    def fit(self, X: np.ndarray, y: np.ndarray = None, **kwargs) -> 'BaseShardDetector':
        """
        Обучить модель.
        
        Args:
            X: признаки (n_samples, n_features)
            y: метки (n_samples,). None для unsupervised.
            **kwargs: дополнительные параметры (epochs, batch_size, etc.)
        
        Returns:
            self (для цепочечных вызовов)
        """
        ...
    
    @abstractmethod
    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Предсказать атаки.
        
        Returns:
            predictions: бинарные метки (0=норма, 1=атака)
            scores: уверенность [0, 1]
        """
        ...
    
    @abstractmethod
    def is_fitted(self) -> bool:
        """Проверка что модель обучена."""
        return self._is_fitted
    
    # ============================================================
    # Метрики качества
    # ============================================================
    
    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, float]:
        """
        Оценить качество модели на тестовых данных.
        Автоматически вычисляет F1, Precision, Recall, AUC.
        """
        X_clean = self._validate_input(X_test)
        predictions, scores = self.predict(X_clean)
        
        self.metrics = {
            'f1_score': round(f1_score(y_test, predictions, zero_division=0), 4),
            'precision': round(precision_score(y_test, predictions, zero_division=0), 4),
            'recall': round(recall_score(y_test, predictions, zero_division=0), 4),
            'accuracy': round(np.mean(predictions == y_test), 4)
        }
        
        try:
            self.metrics['roc_auc'] = round(roc_auc_score(y_test, scores), 4)
        except ValueError:
            self.metrics['roc_auc'] = 0.0
        
        logger.info(f"📊 {self.name} metrics: F1={self.metrics['f1_score']:.4f}, "
                   f"AUC={self.metrics['roc_auc']:.4f}")
        
        return self.metrics
    
    def get_metrics(self) -> Dict[str, float]:
        """Получить метрики качества."""
        return self.metrics
    
    # ============================================================
    # Сохранение / Загрузка
    # ============================================================
    
    def save(self, path: str = None) -> bool:
        """
        Сохранить модель через joblib (совместимо с разными Python версиями).
        """
        save_path = Path(path) if path else self.model_path
        save_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            # Сохраняем всё состояние
            state = {
                'model': self.model,
                'metrics': self.metrics,
                'metadata': self.metadata,
                '_is_fitted': self._is_fitted,
                'name': self.name
            }
            joblib.dump(state, save_path, compress=0)  # Без сжатия для совместимости
            logger.info(f"💾 {self.name} saved to {save_path}")
            return True
        except Exception as e:
            logger.error(f"❌ Failed to save {self.name}: {e}")
            return False
    
    def load(self, path: str = None) -> bool:
        """
        Загрузить модель через joblib.
        """
        load_path = Path(path) if path else self.model_path
        
        if not load_path.exists():
            logger.warning(f"⚠️ Model file not found: {load_path}")
            return False
        
        try:
            state = joblib.load(load_path)
            self.model = state.get('model')
            self.metrics = state.get('metrics', {})
            self.metadata = state.get('metadata', {})
            self._is_fitted = state.get('_is_fitted', True)
            self.name = state.get('name', self.name)
            logger.info(f"📂 {self.name} loaded from {load_path}")
            return True
        except Exception as e:
            logger.error(f"❌ Failed to load {self.name}: {e}")
            return False
    
    # ============================================================
    # Онлайн-обучение
    # ============================================================
    
    def update(self, X_new: np.ndarray, y_new: np.ndarray = None) -> bool:
        """
        Дообучить модель на новых данных без полного переобучения.
        По умолчанию — полное переобучение. Переопределите для incremental learning.
        """
        try:
            self.fit(X_new, y_new)
            self.metadata['samples_trained'] += len(X_new)
            logger.info(f"🔄 {self.name} updated with {len(X_new)} samples")
            return True
        except Exception as e:
            logger.error(f"❌ Update failed: {e}")
            return False
    
    # ============================================================
    # Объяснимость
    # ============================================================
    
    def explain(self, X: np.ndarray, top_k: int = 10) -> Dict[str, Any]:
        """
        Объяснить предсказание. По умолчанию — feature importance из модели.
        Переопределите для SHAP/LIME.
        """
        if hasattr(self.model, 'feature_importances_'):
            importances = self.model.feature_importances_
            top_idx = np.argsort(importances)[-top_k:][::-1]
            return {
                'top_features': [f'feature_{i}' for i in top_idx],
                'importances': importances[top_idx].tolist()
            }
        return {'message': 'Explainability not implemented for this model'}
    
    # ============================================================
    # Валидация входных данных
    # ============================================================
    
    def _validate_input(self, X: np.ndarray) -> np.ndarray:
        """
        Проверить и очистить входные данные.
        Исправляет NaN, Inf, слишком большие значения.
        """
        if not isinstance(X, np.ndarray):
            X = np.array(X)
        
        if X.ndim == 1:
            X = X.reshape(1, -1)
        
        # NaN -> 0
        if np.isnan(X).any():
            logger.debug(f"⚠️ NaN detected in input, replacing with 0")
            X = np.nan_to_num(X, nan=0.0)
        
        # Inf -> max float
        if np.isinf(X).any():
            logger.debug(f"⚠️ Inf detected in input, clipping")
            X = np.clip(X, -1e10, 1e10)
        
        return X.astype(np.float32)
    
    # ============================================================
    # Информация о модели
    # ============================================================
    
    def get_info(self) -> Dict[str, Any]:
        """Получить информацию о модели."""
        return {
            'name': self.name,
            'is_fitted': self._is_fitted,
            'metrics': self.metrics,
            'metadata': self.metadata
        }
    
    def __repr__(self):
        status = "✅ fitted" if self._is_fitted else "❌ not fitted"
        return f"{self.name}({status}, F1={self.metrics.get('f1_score', 0):.4f})"


logger.info("✅ BaseShardDetector ready — единый интерфейс для всех моделей")
