#!/usr/bin/env python3
"""SHARD CatBoost Detector — робастная классификация (модель #12)"""

import numpy as np
import logging
from pathlib import Path

logger = logging.getLogger("SHARD-CatBoost")

try:
    from catboost import CatBoostClassifier
    HAS_CATBOOST = True
except ImportError:
    HAS_CATBOOST = False
    logger.warning("pip install catboost")

class CatBoostDetector:
    """CatBoost — отлично работает с категориальными признаками"""
    
    def __init__(self):
        self.model = None
        self.is_trained = False
        self.model_path = Path('models/catboost_model.cbm')
        
    def train(self, X, y):
        if not HAS_CATBOOST:
            return None
        
        self.model = CatBoostClassifier(
            iterations=100,
            learning_rate=0.1,
            depth=6,
            verbose=False,
            random_seed=42
        )
        self.model.fit(X, y)
        self.is_trained = True
        self.model.save_model(str(self.model_path))
        return {'status': 'trained', 'samples': len(X)}
    
    def predict(self, X):
        if not self.is_trained or self.model is None:
            return np.zeros(len(X))
        return self.model.predict(X)
    
    def predict_proba(self, X):
        if not self.is_trained or self.model is None:
            return np.ones((len(X), 15)) / 15
        return self.model.predict_proba(X)

logger.info("✅ CatBoost Detector ready (model #12)")
