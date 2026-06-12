#!/usr/bin/env python3
"""SHARD UMAP + Isolation Forest — dimensional reduction + anomaly detection (модель #17)"""
import numpy as np, logging, pickle
from pathlib import Path
logger = logging.getLogger("SHARD-UMAP-IF")
try:
    import umap
    from sklearn.ensemble import IsolationForest
    HAS_UMAP = True
except ImportError:
    HAS_UMAP = False
    logger.warning("pip install umap-learn")

class UMAPIForestDetector:
    def __init__(self, n_components=10):
        self.reducer = umap.UMAP(n_components=n_components, random_state=42) if HAS_UMAP else None
        self.detector = IsolationForest(contamination=0.1, random_state=42)
        self.is_fitted = False
        self.model_path = Path('models/umap_iforest.pkl')
    
    def fit(self, X):
        if self.reducer is None: return None
        X_reduced = self.reducer.fit_transform(X)
        self.detector.fit(X_reduced)
        self.is_fitted = True
        with open(self.model_path, 'wb') as f: pickle.dump((self.reducer, self.detector), f)
        return {'components': self.reducer.n_components, 'samples': len(X)}
    
    def predict(self, X):
        if not self.is_fitted: return np.zeros(len(X)), np.ones(len(X))
        X_reduced = self.reducer.transform(X)
        scores = -self.detector.score_samples(X_reduced)
        scores = (scores - scores.min()) / (scores.max() - scores.min() + 1e-8)
        return (scores > 0.5).astype(int), scores

logger.info("✅ UMAP+IForest ready (model #17)")
