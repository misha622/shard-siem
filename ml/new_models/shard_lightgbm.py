#!/usr/bin/env python3
"""SHARD LightGBM Detector — быстрая классификация атак (модель #11)"""

import numpy as np
import logging
from pathlib import Path

logger = logging.getLogger("SHARD-LightGBM")

try:
    import lightgbm as lgb
    HAS_LIGHTGBM = True
except ImportError:
    HAS_LIGHTGBM = False
    logger.warning("pip install lightgbm")

class LightGBMDetector:
    """LightGBM классификатор — быстрее XGBoost, лучше на табличных данных"""
    
    def __init__(self, num_classes=15):
        self.model = None
        self.num_classes = num_classes
        self.is_trained = False
        self.model_path = Path('models/lgbm_model.txt')
        
    def train(self, X, y):
        if not HAS_LIGHTGBM:
            return None
        
        params = {
            'objective': 'multiclass',
            'num_class': self.num_classes,
            'metric': 'multi_logloss',
            'boosting_type': 'gbdt',
            'num_leaves': 31,
            'learning_rate': 0.05,
            'feature_fraction': 0.9,
            'bagging_fraction': 0.8,
            'bagging_freq': 5,
            'verbose': 0
        }
        
        train_data = lgb.Dataset(X, label=y)
        self.model = lgb.train(params, train_data, num_boost_round=100)
        self.is_trained = True
        self.model.save_model(str(self.model_path))
        return {'status': 'trained', 'samples': len(X)}
    
    def predict(self, X):
        if not self.is_trained or self.model is None:
            return np.zeros(len(X))
        return self.model.predict(X).argmax(axis=1)
    
    def predict_proba(self, X):
        if not self.is_trained or self.model is None:
            return np.ones((len(X), self.num_classes)) / self.num_classes
        return self.model.predict(X)

logger.info("✅ LightGBM Detector ready (model #11)")
