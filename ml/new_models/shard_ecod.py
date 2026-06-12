#!/usr/bin/env python3
"""SHARD ECOD — Empirical Cumulative Outlier Detection (модель #18)"""
import numpy as np, logging
logger = logging.getLogger("SHARD-ECOD")
try:
    from pyod.models.ecod import ECOD
    HAS_PYOD = True
except ImportError:
    HAS_PYOD = False
    logger.warning("pip install pyod")

class ECODDetector:
    def __init__(self, contamination=0.1):
        self.model = ECOD(contamination=contamination) if HAS_PYOD else None
        self.is_fitted = False
    
    def fit(self, X):
        if self.model is None: return None
        self.model.fit(X)
        self.is_fitted = True
        return {'samples': len(X)}
    
    def predict(self, X):
        if not self.is_fitted: return np.zeros(len(X)), np.ones(len(X))
        scores = self.model.decision_function(X)
        scores = (scores - scores.min()) / (scores.max() - scores.min() + 1e-8)
        return (scores > 0.5).astype(int), scores

logger.info("✅ ECOD ready (model #18)")
