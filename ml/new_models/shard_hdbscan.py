#!/usr/bin/env python3
"""SHARD HDBSCAN Clustering — поиск неизвестных групп атак (модель #16)"""
import numpy as np, logging, pickle
from pathlib import Path
logger = logging.getLogger("SHARD-HDBSCAN")
try:
    import hdbscan
    HAS_HDBSCAN = True
except ImportError:
    HAS_HDBSCAN = False
    logger.warning("pip install hdbscan")

class HDBSCANDetector:
    def __init__(self, min_cluster_size=10):
        self.clusterer = hdbscan.HDBSCAN(min_cluster_size=min_cluster_size, prediction_data=True) if HAS_HDBSCAN else None
        self.labels_ = None
        self.outlier_threshold_ = 0.0
        self.model_path = Path('models/hdbscan.pkl')
    
    def fit(self, X):
        if self.clusterer is None: return None
        self.clusterer.fit(X)
        self.labels_ = self.clusterer.labels_
        scores = self.clusterer.outlier_scores_
        self.outlier_threshold_ = np.percentile(scores, 90)
        with open(self.model_path, 'wb') as f: pickle.dump(self.clusterer, f)
        n_clusters = len(set(self.labels_)) - (1 if -1 in self.labels_ else 0)
        return {'clusters': n_clusters, 'noise': int((self.labels_ == -1).sum())}
    
    def predict(self, X):
        if self.clusterer is None: return np.ones(len(X)), np.ones(len(X))
        labels, strengths = hdbscan.approximate_predict(self.clusterer, X)
        scores = 1.0 - np.clip(strengths, 0, 1)
        is_anomaly = (labels == -1) | (scores > self.outlier_threshold_)
        return is_anomaly.astype(int), scores

logger.info("✅ HDBSCAN ready (model #16)")
