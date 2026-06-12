#!/usr/bin/env python3
"""SHARD Voting Ensemble — агрегирует все 21 модель (модель #22)"""
import numpy as np, logging
from collections import Counter
logger = logging.getLogger("SHARD-VotingEnsemble")

class VotingEnsemble:
    """Hard + Soft voting по всем моделям SHARD"""
    def __init__(self, weights=None):
        self.models = {}
        self.weights = weights or {}
    
    def add_model(self, name, model, weight=1.0):
        self.models[name] = (model, weight)
        logger.info(f"Added {name} (weight={weight})")
    
    def predict(self, X, method='soft'):
        if not self.models: return np.zeros(len(X)), np.ones(len(X))
        all_scores = []
        total_weight = 0
        
        for name, (model, weight) in self.models.items():
            try:
                _, scores = model.predict(X)
                if isinstance(scores, np.ndarray):
                    all_scores.append(scores * weight)
                    total_weight += weight
            except Exception as e:
                logger.debug(f"{name} failed: {e}")
        
        if not all_scores:
            return np.zeros(len(X)), np.ones(len(X))
        
        avg_scores = np.mean(all_scores, axis=0)
        predictions = (avg_scores > 0.5).astype(int)
        return predictions, avg_scores
    
    def get_model_count(self):
        return len(self.models)

logger.info("✅ Voting Ensemble ready (model #22)")
