#!/usr/bin/env python3
"""SHARD KNN Detector — anomaly detection по расстоянию до соседей (модель #20)"""
import numpy as np, logging, pickle
from pathlib import Path
logger = logging.getLogger("SHARD-KNN")
try:
    from sklearn.neighbors import NearestNeighbors
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

class KNNDetector:
    def __init__(self, n_neighbors=5):
        self.nn = NearestNeighbors(n_neighbors=n_neighbors, n_jobs=-1) if HAS_SKLEARN else None
        self.threshold_ = 0.0
        self.is_fitted = False
        self.model_path = Path('models/knn_detector.pkl')
    
    def fit(self, X_normal):
        if self.nn is None: return None
        self.nn.fit(X_normal)
        distances, _ = self.nn.kneighbors(X_normal)
        mean_dists = distances.mean(axis=1)
        self.threshold_ = np.percentile(mean_dists, 95)
        self.is_fitted = True
        with open(self.model_path, 'wb') as f: pickle.dump((self.nn, self.threshold_), f)
        return {'threshold': float(self.threshold_), 'samples': len(X_normal)}
    
    def predict(self, X):
        if not self.is_fitted: return np.zeros(len(X)), np.ones(len(X))
        distances, _ = self.nn.kneighbors(X)
        scores = distances.mean(axis=1)
        scores = np.clip(scores / (self.threshold_ + 1e-8), 0, 2)
        return (scores > 1.0).astype(int), scores / 2.0

logger.info("✅ KNN Detector ready (model #20)")
