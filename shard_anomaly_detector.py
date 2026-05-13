#!/usr/bin/env python3
"""
SHARD Anomaly Detector — VAE-based zero-day detection
Интегрируется в Defence Pipeline, фильтрует ложные срабатывания
"""

import torch
import torch.nn as nn
import numpy as np
import json
import logging
from pathlib import Path
from typing import Dict, Tuple

logger = logging.getLogger("SHARD-AnomalyDetector")


class VariationalAutoencoder(nn.Module):
    def __init__(self, input_dim=72, hidden_dims=[256, 128, 64], latent_dim=32):
        super().__init__()
        
        encoder_layers = []
        prev_dim = input_dim
        for h_dim in hidden_dims:
            encoder_layers.extend([
                nn.Linear(prev_dim, h_dim),
                nn.BatchNorm1d(h_dim),
                nn.ReLU(),
                nn.Dropout(0.1),
            ])
            prev_dim = h_dim
        
        self.encoder = nn.Sequential(*encoder_layers)
        self.fc_mu = nn.Linear(hidden_dims[-1], latent_dim)
        self.fc_logvar = nn.Linear(hidden_dims[-1], latent_dim)
        
        decoder_layers = []
        prev_dim = latent_dim
        for h_dim in reversed(hidden_dims):
            decoder_layers.extend([
                nn.Linear(prev_dim, h_dim),
                nn.BatchNorm1d(h_dim),
                nn.ReLU(),
                nn.Dropout(0.1),
            ])
            prev_dim = h_dim
        decoder_layers.append(nn.Linear(hidden_dims[0], input_dim))
        decoder_layers.append(nn.Sigmoid())
        
        self.decoder = nn.Sequential(*decoder_layers)
    
    def encode(self, x):
        h = self.encoder(x)
        return self.fc_mu(h), self.fc_logvar(h)
    
    def forward(self, x):
        mu, logvar = self.encode(x)
        z = mu + torch.randn_like(mu) * torch.exp(0.5 * logvar)
        return self.decoder(z), mu, logvar
    
    def anomaly_score(self, x):
        self.eval()
        with torch.no_grad():
            reconstructed, mu, logvar = self.forward(x)
            recon_error = torch.mean((x - reconstructed) ** 2, dim=1)
        return recon_error


class ShardAnomalyDetector:
    """VAE Anomaly Detector для SHARD"""
    
    def __init__(self, model_path='./models/anomaly/vae_anomaly_detector.pt'):
        self.model_path = Path(model_path)
        self.model = None
        self.mean = None
        self.std = None
        self.threshold = 1.0
        self.loaded = False
        self.input_dim = 72
        
        self._load()
    
    def _load(self):
        try:
            if self.model_path.exists():
                checkpoint = torch.load(self.model_path, map_location='cpu', weights_only=True)
                
                config = checkpoint.get('config', {})
                self.input_dim = config.get('input_dim', 72)
                hidden_dims = config.get('hidden_dims', [256, 128, 64])
                latent_dim = config.get('latent_dim', 32)
                
                self.model = VariationalAutoencoder(
                    input_dim=self.input_dim,
                    hidden_dims=hidden_dims,
                    latent_dim=latent_dim
                )
                self.model.load_state_dict(checkpoint['model_state_dict'])
                self.model.eval()
                
                self.mean = np.array(checkpoint['mean'])
                self.std = np.array(checkpoint['std'])
                self.threshold = checkpoint.get('threshold', 1.0)
                
                self.loaded = True
                params = sum(p.numel() for p in self.model.parameters())
                logger.info(f"✅ Anomaly Detector загружен: {params:,} параметров, threshold={self.threshold:.4f}")
            else:
                logger.warning(f"Модель не найдена: {self.model_path}")
        except Exception as e:
            logger.error(f"Ошибка загрузки Anomaly Detector: {e}")
    
    def extract_features(self, alert: Dict) -> np.ndarray:
        """Извлечение 72 фич из алерта"""
        features = np.zeros(self.input_dim, dtype=np.float32)
        
        features[0] = min(1.0, alert.get('score', 0))
        features[1] = 6.0 / 255.0
        features[2] = alert.get('dst_port', 80) / 65535.0
        features[3] = 0.5
        features[4] = 64.0 / 255.0
        features[5] = 0.0
        
        src_ip = alert.get('src_ip', '0.0.0.0')
        ip_class = 9 if src_ip.startswith('127.') else hash(src_ip) % 9
        features[6 + ip_class] = 1.0
        
        port_idx = 16 + (alert.get('dst_port', 80) % 15)
        features[port_idx] = 1.0
        
        import time
        t = time.localtime()
        features[31] = t.tm_hour / 24.0
        features[32] = t.tm_wday / 7.0
        features[33] = 0.5
        features[34] = alert.get('confidence', 0.5)
        features[35] = 0.5
        
        features[36] = 1.0
        
        explanation = alert.get('explanation', '')
        for i, ch in enumerate(explanation[:15]):
            features[46 + i] = ord(ch) / 255.0
        
        features[61] = alert.get('score', 0)
        features[62] = alert.get('confidence', 0)
        
        features[70] = np.random.uniform(0, 1)
        features[71] = alert.get('score', 0)
        
        return features
    
    def is_anomaly(self, alert: Dict) -> Tuple[bool, float]:
        """Проверка является ли алерт аномалией"""
        if not self.loaded:
            return False, 0.0
        
        try:
            features = self.extract_features(alert)
            features = (features - self.mean) / (self.std + 1e-8)
            
            tensor = torch.tensor([features], dtype=torch.float32)
            score = self.model.anomaly_score(tensor).item()
            
            is_anom = score > self.threshold
            
            if is_anom:
                logger.info(f"🔍 Anomaly score: {score:.4f} > threshold: {self.threshold:.4f}")
            
            return is_anom, score
        except Exception as e:
            logger.debug(f"Anomaly check error: {e}")
            return False, 0.0
