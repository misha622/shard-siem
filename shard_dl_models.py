#!/usr/bin/env python3

"""
SHARD Deep Learning Models - Production-Ready
Ансамбль нейросетевых моделей для обнаружения аномалий: LSTM Autoencoder, Transformer, VAE.

Версия: 5.0.0 - Полное обучение, ensemble с динамическими весами, онлайн-обучение

Author: SHARD Enterprise
"""

from __future__ import annotations
import os
import sys
import time
import json
import threading
import warnings
import hashlib
import math
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union, Callable
from collections import deque, defaultdict
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor
import logging

import numpy as np

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("SHARD-DLModels")

warnings.filterwarnings('ignore')
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'


TF_AVAILABLE = False
TORCH_AVAILABLE = False
SKLEARN_AVAILABLE = False

try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers, Model, optimizers, losses, metrics
    from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau, ModelCheckpoint

    TF_AVAILABLE = True
    logger.info("✅ TensorFlow loaded")
except ImportError:
    logger.warning("⚠️ TensorFlow not installed")

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset

    TORCH_AVAILABLE = True
    logger.info("✅ PyTorch loaded")
except ImportError:
    logger.warning("⚠️ PyTorch not installed")

try:
    from sklearn.preprocessing import StandardScaler, RobustScaler
    from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score

    SKLEARN_AVAILABLE = True
    logger.info("✅ Scikit-learn loaded")
except ImportError:
    logger.warning("⚠️ Scikit-learn not installed")



@dataclass
class DLModelConfig:
    """Конфигурация Deep Learning моделей"""

    lstm_enabled: bool = True
    lstm_sequence_length: int = 100
    lstm_input_dim: int = 156
    lstm_hidden_dim: int = 64
    lstm_latent_dim: int = 32
    lstm_num_layers: int = 2
    lstm_bidirectional: bool = True
    lstm_dropout: float = 0.2
    lstm_epochs: int = 50
    lstm_batch_size: int = 32
    lstm_learning_rate: float = 0.001

    transformer_enabled: bool = True
    transformer_num_heads: int = 4
    transformer_num_layers: int = 2
    transformer_d_model: int = 64
    transformer_d_ff: int = 256
    transformer_dropout: float = 0.1
    transformer_epochs: int = 50
    transformer_batch_size: int = 32
    transformer_learning_rate: float = 0.001

    vae_enabled: bool = True
    vae_latent_dim: int = 32
    vae_hidden_dims: List[int] = field(default_factory=lambda: [128, 64])
    vae_dropout: float = 0.2
    vae_epochs: int = 50
    vae_batch_size: int = 64
    vae_learning_rate: float = 0.001
    vae_kl_weight: float = 0.1

    ensemble_weights: Dict[str, float] = field(default_factory=lambda: {
        'lstm': 0.35, 'transformer': 0.35, 'vae': 0.3
    })
    ensemble_temperature: float = 2.0
    min_model_weight: float = 0.05

    online_learning_enabled: bool = True
    online_buffer_size: int = 10000
    retrain_interval: int = 3600
    min_samples_retrain: int = 100
    sequence_buffer_size: int = 100

    anomaly_threshold_percentile: float = 95.0
    use_adaptive_threshold: bool = True

    model_dir: str = './models/dl/'
    checkpoint_frequency: int = 10

    device: str = 'auto'
    use_mixed_precision: bool = True
    max_workers: int = 4
    cache_size: int = 10000
    cache_ttl: int = 60

    def save(self, path: str):
        """Сохранение конфигурации"""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            json.dump(self.__dict__, f, indent=2)

    @classmethod
    def load(cls, path: str) -> 'DLModelConfig':
        """Загрузка конфигурации"""
        with open(path, 'r') as f:
            data = json.load(f)
        return cls(**data)



if TORCH_AVAILABLE:
    class PositionalEncoding(nn.Module):
        """Позиционное кодирование для Transformer"""

        def __init__(self, d_model: int, max_len: int = 5000, dropout: float = 0.1):
            super().__init__()
            self.dropout = nn.Dropout(p=dropout)

            position = torch.arange(max_len).unsqueeze(1)
            div_term = torch.exp(torch.arange(0, d_model, 2) * -(math.log(10000.0) / d_model))

            pe = torch.zeros(max_len, d_model)
            pe[:, 0::2] = torch.sin(position * div_term)
            pe[:, 1::2] = torch.cos(position * div_term)

            self.register_buffer('pe', pe)

        def forward(self, x):
            """
            Args:
                x: (batch_size, seq_len, d_model)
            """
            x = x + self.pe[:x.size(1)]
            return self.dropout(x)


if TORCH_AVAILABLE:

    class LSTMAutoencoder(nn.Module):
        """
        LSTM Autoencoder для обнаружения аномалий в последовательностях.

        Особенности:
        - Двунаправленный LSTM
        - Attention механизм
        - Residual connections
        """

        def __init__(self, config: DLModelConfig):
            super().__init__()
            self.config = config

            self.encoder_lstm = nn.LSTM(
                input_size=config.lstm_input_dim,
                hidden_size=config.lstm_hidden_dim,
                num_layers=config.lstm_num_layers,
                batch_first=True,
                bidirectional=config.lstm_bidirectional,
                dropout=config.lstm_dropout if config.lstm_num_layers > 1 else 0
            )

            lstm_output_dim = config.lstm_hidden_dim * (2 if config.lstm_bidirectional else 1)

            self.encoder_attention = nn.MultiheadAttention(
                embed_dim=lstm_output_dim,
                num_heads=4,
                dropout=config.lstm_dropout,
                batch_first=True
            )

            self.encoder_projection = nn.Sequential(
                nn.Linear(lstm_output_dim, config.lstm_hidden_dim),
                nn.ReLU(),
                nn.Dropout(config.lstm_dropout),
                nn.Linear(config.lstm_hidden_dim, config.lstm_latent_dim)
            )

            self.decoder_projection = nn.Sequential(
                nn.Linear(config.lstm_latent_dim, config.lstm_hidden_dim),
                nn.ReLU(),
                nn.Dropout(config.lstm_dropout),
                nn.Linear(config.lstm_hidden_dim, lstm_output_dim)
            )

            self.decoder_lstm = nn.LSTM(
                input_size=lstm_output_dim,
                hidden_size=config.lstm_hidden_dim,
                num_layers=config.lstm_num_layers,
                batch_first=True,
                bidirectional=config.lstm_bidirectional,
                dropout=config.lstm_dropout if config.lstm_num_layers > 1 else 0
            )

            decoder_output_dim = config.lstm_hidden_dim * (2 if config.lstm_bidirectional else 1)

            self.output_layer = nn.Sequential(
                nn.Linear(decoder_output_dim, config.lstm_hidden_dim),
                nn.ReLU(),
                nn.Dropout(config.lstm_dropout),
                nn.Linear(config.lstm_hidden_dim, config.lstm_input_dim)
            )

            self.input_norm = nn.BatchNorm1d(config.lstm_input_dim)

        def encode(self, x):
            """
            Кодирование последовательности в латентное пространство.

            Args:
                x: (batch_size, seq_len, input_dim)
            """
            batch_size, seq_len, _ = x.shape
            x_norm = x.view(-1, self.config.lstm_input_dim)
            x_norm = self.input_norm(x_norm)
            x = x_norm.view(batch_size, seq_len, -1)

            lstm_out, (hidden, cell) = self.encoder_lstm(x)

            attn_out, _ = self.encoder_attention(lstm_out, lstm_out, lstm_out)

            lstm_out = lstm_out + attn_out

            pooled = lstm_out.mean(dim=1)

            latent = self.encoder_projection(pooled)

            return latent, lstm_out

        def decode(self, latent, seq_len):
            """
            Декодирование из латентного пространства.

            Args:
                latent: (batch_size, latent_dim)
                seq_len: длина последовательности
            """
            decoder_input = self.decoder_projection(latent)

            decoder_input = decoder_input.unsqueeze(1).repeat(1, seq_len, 1)

            lstm_out, _ = self.decoder_lstm(decoder_input)

            reconstruction = self.output_layer(lstm_out)

            return reconstruction

        def forward(self, x):
            """Forward pass"""
            seq_len = x.size(1)

            latent, _ = self.encode(x)
            reconstruction = self.decode(latent, seq_len)

            return {
                'reconstruction': reconstruction,
                'latent': latent
            }

        def anomaly_score(self, x):
            """
            Вычисление anomaly score.

            Returns:
                score: [0, 1]
                mse: reconstruction error
                is_anomaly: bool
            """
            self.eval()

            with torch.no_grad():
                result = self.forward(x)
                reconstruction = result['reconstruction']

                mse = F.mse_loss(reconstruction, x, reduction='none').mean(dim=(1, 2))

                if hasattr(self, 'threshold'):
                    score = torch.sigmoid((mse - self.threshold) / (self.threshold * 0.5))
                else:
                    score = torch.sigmoid(mse / 0.1)

                return score, mse, score > 0.5


if TORCH_AVAILABLE:
    class TransformerAnomalyDetector(nn.Module):
        """
        Transformer для обнаружения аномалий.

        Особенности:
        - Multi-head self-attention
        - Positional encoding
        - Residual connections + LayerNorm
        """

        def __init__(self, config: DLModelConfig):
            super().__init__()
            self.config = config

            self.input_projection = nn.Linear(config.lstm_input_dim, config.transformer_d_model)

            self.pos_encoder = PositionalEncoding(
                config.transformer_d_model,
                dropout=config.transformer_dropout
            )

            encoder_layer = nn.TransformerEncoderLayer(
                d_model=config.transformer_d_model,
                nhead=config.transformer_num_heads,
                dim_feedforward=config.transformer_d_ff,
                dropout=config.transformer_dropout,
                activation='gelu',
                batch_first=True
            )

            self.transformer = nn.TransformerEncoder(
                encoder_layer,
                num_layers=config.transformer_num_layers
            )

            self.attention_pool = nn.MultiheadAttention(
                embed_dim=config.transformer_d_model,
                num_heads=config.transformer_num_heads,
                dropout=config.transformer_dropout,
                batch_first=True
            )

            self.classifier = nn.Sequential(
                nn.Linear(config.transformer_d_model, config.transformer_d_model // 2),
                nn.LayerNorm(config.transformer_d_model // 2),
                nn.ReLU(),
                nn.Dropout(config.transformer_dropout),
                nn.Linear(config.transformer_d_model // 2, 1),
                nn.Sigmoid()
            )

            self.layer_norm = nn.LayerNorm(config.transformer_d_model)

        def forward(self, x):
            """
            Forward pass.

            Args:
                x: (batch_size, seq_len, input_dim)
            """
            x = self.input_projection(x)

            x = self.pos_encoder(x)

            x = self.transformer(x)
            x = self.layer_norm(x)

            attn_out, attn_weights = self.attention_pool(x, x, x)

            x = x + attn_out

            pooled = x.mean(dim=1)

            score = self.classifier(pooled)

            return {
                'score': score,
                'attention_weights': attn_weights,
                'features': pooled
            }

        def anomaly_score(self, x):
            """
            Вычисление anomaly score.
            """
            self.eval()

            with torch.no_grad():
                result = self.forward(x)
                score = result['score'].squeeze()

                return score, score, score > 0.5


if TORCH_AVAILABLE:

    class VAEAnomalyDetector(nn.Module):
        """
        Variational Autoencoder для обнаружения аномалий.

        Особенности:
        - Reparameterization trick
        - BatchNorm + Dropout
        - KL annealing
        """

        def __init__(self, config: DLModelConfig):
            super().__init__()
            self.config = config

            encoder_layers = []
            input_dim = config.lstm_input_dim

            for i, h_dim in enumerate(config.vae_hidden_dims):
                encoder_layers.extend([
                    nn.Linear(input_dim, h_dim),
                    nn.BatchNorm1d(h_dim),
                    nn.ReLU(),
                    nn.Dropout(config.vae_dropout)
                ])
                input_dim = h_dim

            self.encoder = nn.Sequential(*encoder_layers)

            self.z_mean = nn.Linear(config.vae_hidden_dims[-1], config.vae_latent_dim)
            self.z_log_var = nn.Linear(config.vae_hidden_dims[-1], config.vae_latent_dim)

            decoder_layers = []
            input_dim = config.vae_latent_dim

            for i, h_dim in enumerate(reversed(config.vae_hidden_dims)):
                decoder_layers.extend([
                    nn.Linear(input_dim, h_dim),
                    nn.BatchNorm1d(h_dim),
                    nn.ReLU(),
                    nn.Dropout(config.vae_dropout if i < len(config.vae_hidden_dims) - 1 else 0.0)
                ])
                input_dim = h_dim

            decoder_layers.append(nn.Linear(config.vae_hidden_dims[0], config.lstm_input_dim))

            self.decoder = nn.Sequential(*decoder_layers)

            self.register_buffer('kl_weight', torch.tensor(0.0))

        def encode(self, x):
            """Кодирование"""
            h = self.encoder(x)
            z_mean = self.z_mean(h)
            z_log_var = self.z_log_var(h)
            return z_mean, z_log_var

        def reparameterize(self, z_mean, z_log_var):
            """Reparameterization trick"""
            std = torch.exp(0.5 * z_log_var)
            eps = torch.randn_like(std)
            return z_mean + eps * std

        def decode(self, z):
            """Декодирование"""
            return self.decoder(z)

        def forward(self, x):
            """Forward pass"""
            z_mean, z_log_var = self.encode(x)
            z = self.reparameterize(z_mean, z_log_var)
            reconstruction = self.decode(z)

            return {
                'reconstruction': reconstruction,
                'z_mean': z_mean,
                'z_log_var': z_log_var,
                'z': z
            }

        def compute_loss(self, x, outputs, epoch=None):
            """
            Вычисление loss с KL annealing.
            """
            reconstruction = outputs['reconstruction']
            z_mean = outputs['z_mean']
            z_log_var = outputs['z_log_var']

            batch_size = x.size(0)

            recon_loss = F.mse_loss(reconstruction, x, reduction='sum') / batch_size

            kl_loss = -0.5 * torch.sum(1 + z_log_var - z_mean.pow(2) - z_log_var.exp()) / batch_size

            if epoch is not None:
                kl_weight = min(1.0, epoch / 20) * self.config.vae_kl_weight
            else:
                kl_weight = self.config.vae_kl_weight

            total_loss = recon_loss + kl_weight * kl_loss

            return {
                'total_loss': total_loss,
                'recon_loss': recon_loss,
                'kl_loss': kl_loss,
                'kl_weight': kl_weight
            }

        def anomaly_score(self, x):
            """
            Вычисление anomaly score через reconstruction error.
            """
            self.eval()

            with torch.no_grad():
                outputs = self.forward(x)
                reconstruction = outputs['reconstruction']

                mse = F.mse_loss(reconstruction, x, reduction='none').mean(dim=1)

                if hasattr(self, 'threshold'):
                    score = torch.sigmoid((mse - self.threshold) / (self.threshold * 0.5))
                else:
                    score = torch.sigmoid(mse / 0.1)

                return score, mse, score > 0.5



class DeepLearningEnsemble:
    """
    Ансамбль Deep Learning моделей с динамическими весами.

    Особенности:
    - LSTM Autoencoder + Transformer + VAE
    - Взвешенное голосование
    - Адаптивные пороги
    - Онлайн-обучение
    """

    def __init__(self, config: DLModelConfig = None):
        self.config = config or DLModelConfig()

        if self.config.device == 'auto':
            self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        else:
            self.device = torch.device(self.config.device)

        self.models = {}
        self.optimizers = {}
        self.schedulers = {}

        if TORCH_AVAILABLE:
            if self.config.lstm_enabled:
                self.models['lstm'] = LSTMAutoencoder(self.config).to(self.device)
                self.optimizers['lstm'] = optim.AdamW(
                    self.models['lstm'].parameters(),
                    lr=self.config.lstm_learning_rate
                )
                self.schedulers['lstm'] = optim.lr_scheduler.ReduceLROnPlateau(
                    self.optimizers['lstm'], mode='min', factor=0.5, patience=5
                )

            if self.config.transformer_enabled:
                self.models['transformer'] = TransformerAnomalyDetector(self.config).to(self.device)
                self.optimizers['transformer'] = optim.AdamW(
                    self.models['transformer'].parameters(),
                    lr=self.config.transformer_learning_rate
                )
                self.schedulers['transformer'] = optim.lr_scheduler.ReduceLROnPlateau(
                    self.optimizers['transformer'], mode='min', factor=0.5, patience=5
                )

            if self.config.vae_enabled:
                self.models['vae'] = VAEAnomalyDetector(self.config).to(self.device)
                self.optimizers['vae'] = optim.AdamW(
                    self.models['vae'].parameters(),
                    lr=self.config.vae_learning_rate
                )
                self.schedulers['vae'] = optim.lr_scheduler.ReduceLROnPlateau(
                    self.optimizers['vae'], mode='min', factor=0.5, patience=5
                )

        self.ensemble_weights = self.config.ensemble_weights.copy()

        self.thresholds = {name: 0.5 for name in self.models.keys()}

        self.sequence_buffer: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=self.config.lstm_sequence_length)
        )
        self.online_buffer: deque = deque(maxlen=self.config.online_buffer_size)
        self.feedback_buffer: deque = deque(maxlen=1000)

        self.is_trained = {name: False for name in self.models.keys()}

        self.stats = {
            'total_predictions': 0,
            'anomalies_detected': 0,
            'ensemble_updates': 0,
            'model_performance': {name: {'f1': 0.5, 'precision': 0.5, 'recall': 0.5}
                                  for name in self.models.keys()}
        }

        self._model_lock = threading.RLock()
        self._training_lock = threading.RLock()

        self._prediction_cache: Dict[str, Tuple[Dict, float]] = {}
        self._cache_lock = threading.RLock()

        self._executor = ThreadPoolExecutor(max_workers=self.config.max_workers)

        Path(self.config.model_dir).mkdir(parents=True, exist_ok=True)

        self._load_all_models()

        logger.info(f"✅ DeepLearningEnsemble initialized on {self.device} "
                    f"with models: {list(self.models.keys())}")

    def _load_all_models(self):
        """Загрузка всех сохранённых моделей"""
        for name in self.models.keys():
            self._load_model(name)

    def _load_model(self, name: str):
        """Загрузка модели"""
        model_path = Path(self.config.model_dir) / f'{name}_model.pt'

        if model_path.exists() and name in self.models:
            try:
                checkpoint = torch.load(model_path, map_location=self.device)
                self.models[name].load_state_dict(checkpoint['model_state_dict'])

                if name in self.optimizers:
                    self.optimizers[name].load_state_dict(checkpoint['optimizer_state_dict'])

                self.is_trained[name] = checkpoint.get('is_trained', True)

                if 'threshold' in checkpoint:
                    self.thresholds[name] = checkpoint['threshold']
                    self.models[name].threshold = checkpoint['threshold']

                logger.info(f"✅ Loaded {name} model")
            except Exception as e:
                logger.warning(f"⚠️ Failed to load {name} model: {e}")

    def _save_model(self, name: str):
        """Сохранение модели"""
        if name not in self.models:
            return

        model_path = Path(self.config.model_dir) / f'{name}_model.pt'

        try:
            checkpoint = {
                'model_state_dict': self.models[name].state_dict(),
                'is_trained': self.is_trained[name],
                'threshold': self.thresholds.get(name, 0.5)
            }

            if name in self.optimizers:
                checkpoint['optimizer_state_dict'] = self.optimizers[name].state_dict()

            torch.save(checkpoint, model_path)
            logger.debug(f"Saved {name} model")
        except Exception as e:
            logger.error(f"❌ Failed to save {name} model: {e}")

    def add_sequence(self, device: str, features: List[float]) -> Optional[np.ndarray]:
        """
        Добавление признаков в буфер последовательности.

        Returns:
            np.ndarray если накоплена полная последовательность, иначе None
        """
        self.sequence_buffer[device].append(features)

        if len(self.sequence_buffer[device]) >= self.config.lstm_sequence_length:
            sequence = list(self.sequence_buffer[device])[-self.config.lstm_sequence_length:]
            return np.array(sequence)

        return None

    def predict(self, sequence: np.ndarray, raw_features: List[float]) -> Dict:
        """
        Взвешенное предсказание ансамбля.

        Args:
            sequence: Последовательность для LSTM/Transformer (seq_len, input_dim)
            raw_features: Текущие признаки для VAE (input_dim,)

        Returns:
            Dict с результатами
        """
        start_time = time.time()
        self.stats['total_predictions'] += 1

        cache_key = self._make_cache_key(sequence, raw_features)
        with self._cache_lock:
            if cache_key in self._prediction_cache:
                result, timestamp = self._prediction_cache[cache_key]
                if time.time() - timestamp < self.config.cache_ttl:
                    return result

        result = {
            'ensemble_score': 0.0,
            'is_anomaly': False,
            'confidence': 0.0,
            'individual_scores': {},
            'timestamp': time.time()
        }

        total_weight = 0.0
        ensemble_score = 0.0
        anomaly_votes = 0.0

        with self._model_lock:
            seq_tensor = torch.FloatTensor(sequence).unsqueeze(0).to(self.device)
            feat_tensor = torch.FloatTensor(raw_features).unsqueeze(0).to(self.device)

            for name, model in self.models.items():
                if not self.is_trained.get(name, False):
                    continue

                try:
                    model.eval()

                    with torch.no_grad():
                        if name == 'lstm':
                            score, mse, is_anom = model.anomaly_score(seq_tensor)
                            score_val = score.item()
                            mse_val = mse.item()
                        elif name == 'transformer':
                            score, _, is_anom = model.anomaly_score(seq_tensor)
                            score_val = score.item()
                            mse_val = 0.0
                        elif name == 'vae':
                            score, mse, is_anom = model.anomaly_score(feat_tensor)
                            score_val = score.item()
                            mse_val = mse.item()
                        else:
                            continue

                    result['individual_scores'][name] = {
                        'score': score_val,
                        'mse': mse_val,
                        'is_anomaly': bool(is_anom),
                        'threshold': self.thresholds.get(name, 0.5)
                    }

                    weight = self.ensemble_weights.get(name, 0.0)
                    ensemble_score += score_val * weight
                    total_weight += weight

                    if is_anom:
                        anomaly_votes += weight

                except Exception as e:
                    logger.error(f"Model {name} prediction failed: {e}")
                    continue

        if total_weight > 0:
            ensemble_score /= total_weight
            result['ensemble_score'] = ensemble_score
            result['is_anomaly'] = (anomaly_votes / total_weight) > 0.5
            result['confidence'] = abs(anomaly_votes / total_weight - 0.5) * 2
        else:
            result['ensemble_score'] = 0.5
            result['confidence'] = 0.0

        result['weights'] = self.ensemble_weights.copy()

        if result['is_anomaly']:
            self.stats['anomalies_detected'] += 1

        with self._cache_lock:
            self._prediction_cache[cache_key] = (result, time.time())

            if len(self._prediction_cache) > self.config.cache_size:
                sorted_keys = sorted(
                    self._prediction_cache.keys(),
                    key=lambda k: self._prediction_cache[k][1]
                )
                for k in sorted_keys[:len(sorted_keys) // 10]:
                    del self._prediction_cache[k]

        return result

    def _make_cache_key(self, sequence: np.ndarray, features: List[float]) -> str:
        """Создаёт ключ кэша"""
        seq_flat = sequence[-5:].flatten()
        quantized_seq = np.round(seq_flat[:20], 3)
        quantized_feat = np.round(features[:10], 3)

        combined = np.concatenate([quantized_seq, quantized_feat])
        return hashlib.md5(combined.tobytes()).hexdigest()

    def train_lstm(self, normal_sequences: np.ndarray, epochs: int = None, verbose: int = 1) -> Dict:
        """Обучение LSTM Autoencoder"""
        if 'lstm' not in self.models:
            return {'error': 'LSTM model not available'}

        epochs = epochs or self.config.lstm_epochs

        dataset = TensorDataset(torch.FloatTensor(normal_sequences))
        dataloader = DataLoader(dataset, batch_size=self.config.lstm_batch_size, shuffle=True)

        history = {'loss': []}

        with self._training_lock:
            model = self.models['lstm']
            optimizer = self.optimizers['lstm']
            scheduler = self.schedulers['lstm']

            model.train()

            best_loss = float('inf')

            for epoch in range(epochs):
                epoch_loss = 0.0

                for batch in dataloader:
                    x = batch[0].to(self.device)

                    optimizer.zero_grad()

                    result = model(x)
                    reconstruction = result['reconstruction']

                    loss = F.mse_loss(reconstruction, x)

                    loss.backward()
                    optimizer.step()

                    epoch_loss += loss.item()

                avg_loss = epoch_loss / len(dataloader)
                history['loss'].append(avg_loss)

                scheduler.step(avg_loss)

                if avg_loss < best_loss:
                    best_loss = avg_loss
                    self._save_model('lstm')

                if verbose and epoch % 10 == 0:
                    logger.info(f"LSTM Epoch {epoch}: loss={avg_loss:.6f}")

            self.is_trained['lstm'] = True

            self._calibrate_threshold('lstm', normal_sequences[:500])

        return history

    def train_vae(self, normal_data: np.ndarray, epochs: int = None, verbose: int = 1) -> Dict:
        """Обучение VAE"""
        if 'vae' not in self.models:
            return {'error': 'VAE model not available'}

        epochs = epochs or self.config.vae_epochs

        dataset = TensorDataset(torch.FloatTensor(normal_data))
        dataloader = DataLoader(dataset, batch_size=self.config.vae_batch_size, shuffle=True)

        history = {'loss': [], 'recon_loss': [], 'kl_loss': []}

        with self._training_lock:
            model = self.models['vae']
            optimizer = self.optimizers['vae']
            scheduler = self.schedulers['vae']

            model.train()

            best_loss = float('inf')

            for epoch in range(epochs):
                epoch_loss = 0.0
                epoch_recon = 0.0
                epoch_kl = 0.0

                for batch in dataloader:
                    x = batch[0].to(self.device)

                    optimizer.zero_grad()

                    outputs = model(x)
                    loss_dict = model.compute_loss(x, outputs, epoch)

                    loss = loss_dict['total_loss']
                    loss.backward()
                    optimizer.step()

                    epoch_loss += loss.item()
                    epoch_recon += loss_dict['recon_loss'].item()
                    epoch_kl += loss_dict['kl_loss'].item()

                avg_loss = epoch_loss / len(dataloader)
                history['loss'].append(avg_loss)
                history['recon_loss'].append(epoch_recon / len(dataloader))
                history['kl_loss'].append(epoch_kl / len(dataloader))

                scheduler.step(avg_loss)

                if avg_loss < best_loss:
                    best_loss = avg_loss
                    self._save_model('vae')

                if verbose and epoch % 10 == 0:
                    logger.info(f"VAE Epoch {epoch}: loss={avg_loss:.6f}, "
                                f"recon={history['recon_loss'][-1]:.6f}, "
                                f"kl={history['kl_loss'][-1]:.6f}")

            self.is_trained['vae'] = True

            self._calibrate_threshold('vae', normal_data[:500])

        return history

    def _calibrate_threshold(self, name: str, normal_data: np.ndarray):
        """Калибровка порога на нормальных данных"""
        if name not in self.models:
            return

        model = self.models[name]
        model.eval()

        scores = []

        with torch.no_grad():
            for i in range(0, len(normal_data), self.config.lstm_batch_size):
                batch = normal_data[i:i + self.config.lstm_batch_size]
                x = torch.FloatTensor(batch).to(self.device)

                if name == 'lstm':
                    score, _, _ = model.anomaly_score(x)
                elif name == 'transformer':
                    score, _, _ = model.anomaly_score(x)
                elif name == 'vae':
                    if x.dim() == 3:
                        x = x.view(-1, x.size(-1))
                    score, _, _ = model.anomaly_score(x)
                else:
                    continue

                scores.extend(score.cpu().numpy().tolist())

        if scores:
            threshold = np.percentile(scores, self.config.anomaly_threshold_percentile)
            self.thresholds[name] = threshold
            model.threshold = threshold

            logger.info(f"✅ Calibrated {name} threshold: {threshold:.4f}")

    def online_retrain(self):
        """Онлайн дообучение на накопленных данных"""
        if len(self.online_buffer) < self.config.min_samples_retrain:
            return

        data = np.array(list(self.online_buffer))

        logger.info(f"🔄 Online retraining on {len(data)} samples")

        if 'vae' in self.models and self.is_trained.get('vae', False):
            self._online_retrain_vae(data)

        self.online_buffer.clear()

    def _online_retrain_vae(self, data: np.ndarray):
        """Онлайн дообучение VAE"""
        model = self.models['vae']
        optimizer = self.optimizers['vae']

        dataset = TensorDataset(torch.FloatTensor(data))
        dataloader = DataLoader(dataset, batch_size=self.config.vae_batch_size, shuffle=True)

        model.train()

        for epoch in range(5):
            for batch in dataloader:
                x = batch[0].to(self.device)

                optimizer.zero_grad()
                outputs = model(x)
                loss_dict = model.compute_loss(x, outputs)
                loss = loss_dict['total_loss']

                loss.backward()
                optimizer.step()

        self._calibrate_threshold('vae', data[:500])

        self._save_model('vae')

    def add_feedback(self, sequence: np.ndarray, features: List[float],
                     true_label: int, model_predictions: Dict):
        """
        Добавление обратной связи для обновления весов.
        """
        self.feedback_buffer.append({
            'sequence': sequence,
            'features': features,
            'true_label': true_label,
            'predictions': model_predictions,
            'timestamp': time.time()
        })

        if len(self.feedback_buffer) >= 50:
            self._update_ensemble_weights()

    def _update_ensemble_weights(self):
        """Обновление весов ансамбля на основе производительности"""
        if len(self.feedback_buffer) < 20:
            return

        feedback = list(self.feedback_buffer)[-100:]

        f1_scores = {}

        for name in self.models.keys():
            y_true = []
            y_pred = []

            for fb in feedback:
                true_label = fb['true_label']
                pred = fb['predictions'].get(name, {})
                pred_label = 1 if pred.get('is_anomaly', False) else 0

                y_true.append(true_label)
                y_pred.append(pred_label)

            if len(set(y_true)) > 1:
                f1 = f1_score(y_true, y_pred, zero_division=0)
                precision = precision_score(y_true, y_pred, zero_division=0)
                recall = recall_score(y_true, y_pred, zero_division=0)

                f1_scores[name] = f1

                self.stats['model_performance'][name] = {
                    'f1': f1,
                    'precision': precision,
                    'recall': recall
                }

        if f1_scores:
            f1_values = np.array([f1_scores.get(name, 0.5) for name in self.models.keys()])

            exp_scores = np.exp(f1_values / self.config.ensemble_temperature)
            new_weights = exp_scores / np.sum(exp_scores)

            new_weights = np.maximum(new_weights, self.config.min_model_weight)
            new_weights = new_weights / np.sum(new_weights)

            for i, name in enumerate(self.models.keys()):
                old_weight = self.ensemble_weights.get(name, 0.0)
                self.ensemble_weights[name] = 0.7 * old_weight + 0.3 * new_weights[i]

            self.stats['ensemble_updates'] += 1

            logger.info(f"✅ Ensemble weights updated: {self.ensemble_weights}")

        self.feedback_buffer.clear()

    def save_all(self):
        """Сохранение всех моделей"""
        for name in self.models.keys():
            if self.is_trained.get(name, False):
                self._save_model(name)

        ensemble_path = Path(self.config.model_dir) / 'ensemble_config.json'
        with open(ensemble_path, 'w') as f:
            json.dump({
                'weights': self.ensemble_weights,
                'thresholds': self.thresholds,
                'stats': self.stats
            }, f, indent=2)

        logger.info("✅ All models saved")

    def get_stats(self) -> Dict:
        """Получить статистику"""
        return {
            'models': {
                name: {
                    'trained': self.is_trained.get(name, False),
                    'threshold': self.thresholds.get(name, 0.5)
                }
                for name in self.models.keys()
            },
            'ensemble': {
                'weights': self.ensemble_weights,
                'updates': self.stats['ensemble_updates']
            },
            'predictions': {
                'total': self.stats['total_predictions'],
                'anomalies': self.stats['anomalies_detected']
            },
            'performance': self.stats['model_performance'],
            'buffers': {
                'online': len(self.online_buffer),
                'feedback': len(self.feedback_buffer),
                'cache': len(self._prediction_cache)
            }
        }



class DeepLearningEngine:
    """
    Интеграционный слой для Deep Learning моделей в SHARD.

    Особенности:
    - Автоматическое управление последовательностями
    - Фоновое онлайн-обучение
    - Кэширование предсказаний
    - Мониторинг
    """

    def __init__(self, config: Dict = None):
        self.config = DLModelConfig()
        if config:
            for key, value in config.items():
                if hasattr(self.config, key):
                    setattr(self.config, key, value)

        self.ensemble = DeepLearningEnsemble(self.config)

        self._running = False
        self._retrain_thread = None

        self.stats = {
            'total_packets': 0,
            'predictions_made': 0,
            'start_time': time.time()
        }

        logger.info("✅ DeepLearningEngine initialized")

    def start(self):
        """Запуск движка"""
        self._running = True

        if self.config.online_learning_enabled:
            self._retrain_thread = threading.Thread(
                target=self._retrain_loop,
                daemon=True,
                name="DL-Retrain"
            )
            self._retrain_thread.start()

        logger.info("🚀 DeepLearningEngine started")

    def stop(self):
        """Остановка движка"""
        self._running = False

        if self._retrain_thread:
            self._retrain_thread.join(timeout=5)

        self.ensemble.save_all()

        logger.info("🛑 DeepLearningEngine stopped")

    def _retrain_loop(self):
        """Фоновый цикл дообучения"""
        while self._running:
            time.sleep(self.config.retrain_interval)

            if not self._running:
                break

            self.ensemble.online_retrain()

    def predict(self, device: str, features: List[float]) -> Dict:
        """
        Предсказание для устройства.

        Args:
            device: Идентификатор устройства
            features: Вектор признаков

        Returns:
            Dict с результатами
        """
        self.stats['total_packets'] += 1

        sequence = self.ensemble.add_sequence(device, features)

        if sequence is not None:
            self.stats['predictions_made'] += 1

            result = self.ensemble.predict(sequence, features)

            if not result['is_anomaly'] and result['ensemble_score'] < 0.3:
                self.ensemble.online_buffer.append(features)

            return result

        return {
            'ensemble_score': 0.5,
            'is_anomaly': False,
            'confidence': 0.0,
            'individual_scores': {},
            'message': 'Insufficient sequence data'
        }

    def add_feedback(self, device: str, features: List[float],
                     true_label: int, model_predictions: Dict):
        """Добавление обратной связи"""
        sequence = list(self.ensemble.sequence_buffer[device])

        if len(sequence) >= self.config.lstm_sequence_length:
            seq_array = np.array(sequence[-self.config.lstm_sequence_length:])
            self.ensemble.add_feedback(seq_array, features, true_label, model_predictions)

    def train_lstm(self, normal_sequences: np.ndarray, epochs: int = None) -> Dict:
        """Обучение LSTM модели"""
        return self.ensemble.train_lstm(normal_sequences, epochs)

    def train_vae(self, normal_data: np.ndarray, epochs: int = None) -> Dict:
        """Обучение VAE модели"""
        return self.ensemble.train_vae(normal_data, epochs)

    def get_stats(self) -> Dict:
        """Получить статистику"""
        return {
            'engine': {
                **self.stats,
                'uptime': time.time() - self.stats['start_time'],
                'packets_per_second': self.stats['total_packets'] / max(1, time.time() - self.stats['start_time'])
            },
            'ensemble': self.ensemble.get_stats()
        }

    def reset_stats(self):
        """Сброс статистики"""
        self.stats = {
            'total_packets': 0,
            'predictions_made': 0,
            'start_time': time.time()
        }



def test_dl_models():
    """Тестирование DL моделей"""
    print("=" * 60)
    print("🧪 TESTING DEEP LEARNING MODELS")
    print("=" * 60)

    if not TORCH_AVAILABLE:
        print("❌ PyTorch not available")
        return

    config = DLModelConfig()
    config.lstm_epochs = 20
    config.vae_epochs = 20
    config.lstm_sequence_length = 50

    engine = DeepLearningEngine()
    engine.start()

    print("\n📊 Generating training data...")

    np.random.seed(42)

    normal_sequences = []
    for _ in range(100):
        seq = np.random.randn(config.lstm_sequence_length, config.lstm_input_dim) * 0.1
        normal_sequences.append(seq)
    normal_sequences = np.array(normal_sequences)

    normal_data = np.random.randn(500, config.lstm_input_dim) * 0.1

    print("\n🔄 Training LSTM...")
    lstm_history = engine.train_lstm(normal_sequences, epochs=10, verbose=1)

    print("\n🔄 Training VAE...")
    vae_history = engine.train_vae(normal_data, epochs=10, verbose=1)

    print("\n🔮 Testing predictions...")

    device = "test_device"

    print("\n   Normal traffic:")
    normal_scores = []
    for i in range(60):
        features = list(np.random.randn(config.lstm_input_dim) * 0.1)
        result = engine.predict(device, features)

        if result.get('ensemble_score') is not None:
            normal_scores.append(result['ensemble_score'])

    print("\n   Anomalous traffic:")
    anomaly_scores = []
    for i in range(60):
        if i < 30:
            features = list(np.random.randn(config.lstm_input_dim) * 0.1)
        else:
            features = list(np.random.randn(config.lstm_input_dim) * 1.5)

        result = engine.predict(device, features)

        if result.get('ensemble_score') is not None:
            anomaly_scores.append(result['ensemble_score'])

            if result.get('is_anomaly'):
                print(f"      ⚠️ Anomaly detected: score={result['ensemble_score']:.3f}")

    if normal_scores:
        print(f"\n   Normal mean score: {np.mean(normal_scores):.4f}")
    if anomaly_scores:
        print(f"   Anomaly mean score: {np.mean(anomaly_scores[-30:]):.4f}")

    print("\n📊 Statistics:")
    stats = engine.get_stats()
    print(f"   Total packets: {stats['engine']['total_packets']}")
    print(f"   Predictions made: {stats['engine']['predictions_made']}")
    print(f"   Models trained: {[k for k, v in stats['ensemble']['models'].items() if v['trained']]}")
    print(f"   Ensemble weights: {stats['ensemble']['ensemble']['weights']}")

    engine.stop()

    print("\n" + "=" * 60)
    print("✅ TESTING COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    test_dl_models()
ModelConfig = DLModelConfig
