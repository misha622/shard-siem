#!/usr/bin/env python3
"""SHARD One-Class SVM — детектор неизвестных атак (модель #13)"""

import numpy as np
import logging
from pathlib import Path
import pickle

logger = logging.getLogger("SHARD-OneClassSVM")

try:
    from sklearn.svm import OneClassSVM
    HAS_SVM = True
except ImportError:
    HAS_SVM = False

class OneClassSVMDetector:
    """One-Class SVM — идеален для обнаружения zero-day атак"""
    
    def __init__(self, nu=0.1, kernel='rbf'):
        self.model = OneClassSVM(nu=nu, kernel=kernel, gamma='scale') if HAS_SVM else None
        self.is_trained = False
        self.model_path = Path('models/oneclass_svm.pkl')
        
    def train(self, X_normal):
        if self.model is None:
            return None
        
        self.model.fit(X_normal)
        self.is_trained = True
        
        with open(self.model_path, 'wb') as f:
            pickle.dump(self.model, f)
        
        return {'status': 'trained', 'samples': len(X_normal)}
    
    def predict(self, X):
        if not self.is_trained or self.model is None:
            return np.ones(len(X))  # все аномалии по умолчанию
        # -1 = аномалия, 1 = норма
        pred = self.model.predict(X)
        return (pred == -1).astype(int)
    
    def decision_function(self, X):
        if not self.is_trained or self.model is None:
            return np.zeros(len(X))
        return -self.model.score_samples(X)  # чем выше — тем аномальнее

logger.info("✅ One-Class SVM ready (model #13)")
