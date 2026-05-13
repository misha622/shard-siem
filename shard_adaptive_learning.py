#!/usr/bin/env python3

"""
SHARD Adaptive Learning Module - Production-Ready
Самообучающаяся система с exponential forgetting, deep feature extraction и dynamic ensemble.

Версия: 5.0.0 - Полное обучение, мониторинг, отказоустойчивость

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
logger = logging.getLogger("SHARD-Adaptive")

warnings.filterwarnings('ignore')
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'


TF_AVAILABLE = False
TORCH_AVAILABLE = False
SKLEARN_AVAILABLE = False

try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers, Model, optimizers, losses, metrics
    TF_AVAILABLE = True
    logger.info("✅ TensorFlow loaded")
except ImportError:
    logger.warning("⚠️ TensorFlow not installed. Deep feature extraction limited.")

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset
    TORCH_AVAILABLE = True
    logger.info("✅ PyTorch loaded")
except ImportError:
    logger.warning("⚠️ PyTorch not installed. Alternative models available.")

try:
    from sklearn.preprocessing import StandardScaler, RobustScaler
    from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
    from sklearn.model_selection import train_test_split
    SKLEARN_AVAILABLE = True
    logger.info("✅ Scikit-learn loaded")
except ImportError:
    logger.warning("⚠️ Scikit-learn not installed. Some metrics unavailable.")


@dataclass
class AdaptiveConfig:

    forgetting_factor: float = 0.95
    anomaly_threshold: float = 3.0
    min_samples_for_profile: int = 10

    use_deep_features: bool = True
    input_dim: int = 156
    deep_feature_dims: List[int] = field(default_factory=lambda: [128, 64, 32])
    pretrain_epochs_per_layer: int = 50
    fine_tune_epochs: int = 20
    batch_size: int = 64
    learning_rate: float = 0.001

    ensemble_temperature: float = 2.0
    min_model_weight: float = 0.05
    ensemble_update_frequency: int = 100
    feedback_buffer_size: int = 1000

    online_learning_enabled: bool = True
    retrain_interval: int = 300
    min_samples_retrain: int = 100

    model_dir: str = './models/adaptive/'
    checkpoint_frequency: int = 1000

    max_workers: int = 4
    cache_size: int = 10000
    cache_ttl: int = 60

    def save(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            json.dump(self.__dict__, f, indent=2)

    @classmethod
    def load(cls, path: str) -> 'AdaptiveConfig':
        with open(path, 'r') as f:
            data = json.load(f)
        return cls(**data)


class AdaptiveBaselineProfiler:

    def __init__(self, config: AdaptiveConfig = None):
        self.config = config or AdaptiveConfig()

        self.profiles: Dict[str, Dict] = defaultdict(lambda: {
            'ewma': {},
            'ewmvar': {},
            'count': {},
            'first_seen': time.time(),
            'last_update': 0,
            'total_samples': 0,
            'anomaly_history': deque(maxlen=100)
        })

        self._cache: Dict[str, Tuple[float, float]] = {}
        self._cache_lock = threading.RLock()

        self.stats = {
            'total_devices': 0,
            'total_updates': 0,
            'anomalies_detected': 0,
            'false_positives': 0,
            'avg_anomaly_score': 0.0
        }

        self._profile_lock = threading.RLock()
        self._stats_lock = threading.RLock()

        self._executor = ThreadPoolExecutor(max_workers=self.config.max_workers)

        self._load_profiles()

        logger.info(f"✅ AdaptiveBaselineProfiler initialized "
                    f"(forgetting={self.config.forgetting_factor})")

    def _load_profiles(self):
        profile_path = Path(self.config.model_dir) / 'baseline_profiles.json'

        if profile_path.exists():
            try:
                with open(profile_path, 'r') as f:
                    saved = json.load(f)

                for device, data in saved.items():
                    self.profiles[device] = {
                        'ewma': data.get('ewma', {}),
                        'ewmvar': data.get('ewmvar', {}),
                        'count': data.get('count', {}),
                        'first_seen': data.get('first_seen', time.time()),
                        'last_update': data.get('last_update', 0),
                        'total_samples': data.get('total_samples', 0),
                        'anomaly_history': deque(maxlen=100)
                    }

                logger.info(f"✅ Loaded {len(self.profiles)} device profiles")
            except Exception as e:
                logger.warning(f"⚠️ Failed to load profiles: {e}")

    def _save_profiles(self):
        profile_path = Path(self.config.model_dir) / 'baseline_profiles.json'
        profile_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            save_data = {}
            for device, profile in self.profiles.items():
                save_data[device] = {
                    'ewma': dict(profile['ewma']),
                    'ewmvar': dict(profile['ewmvar']),
                    'count': dict(profile['count']),
                    'first_seen': profile['first_seen'],
                    'last_update': profile['last_update'],
                    'total_samples': profile['total_samples']
                }

            temp_path = profile_path.with_suffix('.tmp')
            with open(temp_path, 'w') as f:
                json.dump(save_data, f, indent=2)

            temp_path.replace(profile_path)
            logger.debug(f"Profiles saved: {len(save_data)} devices")

        except Exception as e:
            logger.error(f"❌ Failed to save profiles: {e}")

    def update(self, device: str, features: Dict[str, float]) -> Dict:
        with self._profile_lock:
            profile = self.profiles[device]
            now = time.time()

            if profile['last_update'] > 0:
                time_delta = min(now - profile['last_update'], 3600)
                weight = self.config.forgetting_factor ** time_delta
            else:
                weight = 1.0
                with self._stats_lock:
                    self.stats['total_devices'] += 1

            result = {
                'device': device,
                'weight': weight,
                'anomalies': [],
                'anomaly_scores': {},
                'overall_score': 0.0,
                'is_anomaly': False
            }

            anomaly_scores = []

            for key, value in features.items():
                if not isinstance(value, (int, float)):
                    continue

                value = float(value)

                if key not in profile['ewma']:
                    profile['ewma'][key] = value
                    profile['ewmvar'][key] = 0.01
                    profile['count'][key] = 1
                    continue

                old_avg = profile['ewma'][key]
                old_var = profile['ewmvar'][key]

                new_avg = weight * old_avg + (1 - weight) * value

                delta = value - old_avg
                new_var = weight * old_var + (1 - weight) * delta * (value - new_avg)

                profile['ewma'][key] = new_avg
                profile['ewmvar'][key] = max(new_var, 0.0001)
                profile['count'][key] += 1

                if profile['count'][key] >= self.config.min_samples_for_profile:
                    mean = new_avg
                    std = np.sqrt(max(new_var, 0.0001))

                    if std > 0:
                        z_score = abs(value - mean) / std

                        normalized_score = min(1.0, z_score / self.config.anomaly_threshold)
                        anomaly_scores.append(normalized_score)
                        result['anomaly_scores'][key] = normalized_score

                        if z_score > self.config.anomaly_threshold:
                            result['anomalies'].append({
                                'feature': key,
                                'value': value,
                                'expected': round(mean, 3),
                                'std': round(std, 3),
                                'z_score': round(z_score, 2),
                                'severity': 'HIGH' if z_score > 5 else 'MEDIUM'
                            })

            profile['last_update'] = now
            profile['total_samples'] += 1

            with self._stats_lock:
                self.stats['total_updates'] += 1

            if anomaly_scores:
                top_scores = sorted(anomaly_scores, reverse=True)[:3]
                result['overall_score'] = sum(top_scores) / len(top_scores)
                result['is_anomaly'] = result['overall_score'] > 0.5
            else:
                result['overall_score'] = 0.0
                result['is_anomaly'] = False

            if result['anomalies']:
                with self._stats_lock:
                    self.stats['anomalies_detected'] += 1
                    self.stats['avg_anomaly_score'] = (
                            0.95 * self.stats['avg_anomaly_score'] +
                            0.05 * result['overall_score']
                    )

                profile['anomaly_history'].append({
                    'timestamp': now,
                    'score': result['overall_score'],
                    'features': list(result['anomalies'])
                })

            self._invalidate_cache(device)

            if self.stats['total_updates'] % self.config.checkpoint_frequency == 0:
                self._executor.submit(self._save_profiles)

            return result

    def _invalidate_cache(self, device: str):
        with self._cache_lock:
            keys_to_remove = [k for k in self._cache.keys() if k.startswith(f"{device}:")]
            for k in keys_to_remove:
                del self._cache[k]
            self._cached_stats.pop(f"{device}_score", None)
            self._last_cache_update.pop(device, None)
            self._cached_stats.pop(f"{device}_score", None)
            self._last_cache_update.pop(device, None)

    def get_anomaly_score(self, device: str, features: Dict[str, float]) -> float:
        cache_key = self._make_cache_key(device, features)

        with self._cache_lock:
            if cache_key in self._cache:
                score, timestamp = self._cache[cache_key]
                if time.time() - timestamp < self.config.cache_ttl:
                    return score

        with self._profile_lock:
            if device not in self.profiles:
                return 0.5

            profile = self.profiles[device]
            scores = []

            for key, value in features.items():
                if not isinstance(value, (int, float)):
                    continue

                if key in profile['ewma'] and profile['count'][key] >= self.config.min_samples_for_profile:
                    mean = profile['ewma'][key]
                    std = np.sqrt(max(profile['ewmvar'][key], 0.0001))

                    if std > 0:
                        z_score = abs(float(value) - mean) / std
                        scores.append(min(1.0, z_score / self.config.anomaly_threshold))

            if scores:
                score = float(np.median(scores))
            else:
                score = 0.5

            with self._cache_lock:
                self._cache[cache_key] = (score, time.time())

                if len(self._cache) > self.config.cache_size:
                    sorted_keys = sorted(
                        self._cache.keys(),
                        key=lambda k: self._cache[k][1]
                    )
                    for k in sorted_keys[:len(sorted_keys)//10]:
                        del self._cache[k]

            return score

    def _make_cache_key(self, device: str, features: Dict[str, float]) -> str:
        sorted_keys = sorted(features.keys())
        key_parts = [device]

        for k in sorted_keys[:20]:
            v = features[k]
            if isinstance(v, (int, float)):
                quantized = round(float(v), 3)
                key_parts.append(f"{k}={quantized}")

        key_string = '|'.join(key_parts)
        return hashlib.md5(key_string.encode()).hexdigest()

    def get_profile(self, device: str) -> Optional[Dict]:
        with self._profile_lock:
            if device not in self.profiles:
                return None

            profile = self.profiles[device]

            return {
                'device': device,
                'first_seen': profile['first_seen'],
                'last_update': profile['last_update'],
                'total_samples': profile['total_samples'],
                'features': {
                    key: {
                        'mean': profile['ewma'][key],
                        'std': np.sqrt(profile['ewmvar'][key]),
                        'count': profile['count'][key]
                    }
                    for key in profile['ewma'].keys()
                },
                'recent_anomalies': list(profile['anomaly_history'])[-10:]
            }

    def reset_profile(self, device: str) -> bool:
        with self._profile_lock:
            if device in self.profiles:
                del self.profiles[device]
                self._invalidate_cache(device)
                return True
        return False

    def add_feedback(self, device: str, was_false_positive: bool):
        if was_false_positive:
            with self._stats_lock:
                self.stats['false_positives'] += 1

            fp_rate = self.stats['false_positives'] / max(1, self.stats['anomalies_detected'])
            if fp_rate > 0.3:
                self.config.anomaly_threshold = min(5.0, self.config.anomaly_threshold * 1.1)
                logger.info(f"Adjusted anomaly threshold to {self.config.anomaly_threshold:.2f} "
                            f"(FP rate: {fp_rate:.2%})")

    def get_stats(self) -> Dict:
        with self._stats_lock:
            with self._profile_lock:
                return {
                    **self.stats,
                    'active_devices': len(self.profiles),
                    'total_features_tracked': sum(len(p['ewma']) for p in self.profiles.values()),
                    'cache_size': len(self._cache),
                    'config': {
                        'forgetting_factor': self.config.forgetting_factor,
                        'anomaly_threshold': self.config.anomaly_threshold
                    }
                }

    def shutdown(self):
        self._save_profiles()
        self._executor.shutdown(wait=True)
        logger.info("Baseline profiler shut down")


class DeepFeatureExtractor:

    def __init__(self, config: AdaptiveConfig = None):
        self.config = config or AdaptiveConfig()

        self.autoencoders = []
        self.is_trained = False
        self.training_history = []

        self.online_buffer = deque(maxlen=5000)
        self.online_labels = deque(maxlen=5000)

        self.stats = {
            'total_pretrain_epochs': 0,
            'total_fine_tune_epochs': 0,
            'reconstruction_loss': [],
            'anomalies_detected': 0,
            'total_predictions': 0
        }

        self._lock = threading.RLock()

        if TF_AVAILABLE:
            self._build_tensorflow_model()
            self.backend = 'tensorflow'
        elif TORCH_AVAILABLE:
            self._build_pytorch_model()
            self.backend = 'pytorch'
        else:
            logger.warning("⚠️ No deep learning backend available")
            self.backend = None

        self._load_model()

    def _build_tensorflow_model(self):
        current_dim = self.config.input_dim

        for i, h_dim in enumerate(self.config.deep_feature_dims):
            encoder = keras.Sequential([
                layers.Dense(h_dim * 2, activation='relu', name=f'enc_{i}_dense1'),
                layers.BatchNormalization(name=f'enc_{i}_bn1'),
                layers.Dropout(0.2, name=f'enc_{i}_dropout1'),
                layers.Dense(h_dim, activation='relu', name=f'enc_{i}_dense2'),
                layers.BatchNormalization(name=f'enc_{i}_bn2')
            ], name=f'encoder_{i}')

            decoder = keras.Sequential([
                layers.Dense(h_dim * 2, activation='relu', name=f'dec_{i}_dense1'),
                layers.BatchNormalization(name=f'dec_{i}_bn1'),
                layers.Dropout(0.2, name=f'dec_{i}_dropout1'),
                layers.Dense(current_dim, activation='linear', name=f'dec_{i}_dense2')
            ], name=f'decoder_{i}')

            autoencoder = keras.Sequential([encoder, decoder], name=f'autoencoder_{i}')
            autoencoder.compile(
                optimizer=optimizers.Adam(learning_rate=self.config.learning_rate),
                loss='mse',
                metrics=['mae']
            )

            self.autoencoders.append({
                'encoder': encoder,
                'decoder': decoder,
                'model': autoencoder,
                'input_dim': current_dim,
                'hidden_dim': h_dim,
                'index': i
            })

            current_dim = h_dim

        self.feature_dim = current_dim
        logger.info(f"✅ Built TensorFlow model: {len(self.autoencoders)} layers, "
                    f"input={self.config.input_dim}, output={self.feature_dim}")

    def _build_pytorch_model(self):

        class AutoencoderStack(nn.Module):
            def __init__(self, input_dim, hidden_dims):
                super().__init__()

                self.encoders = nn.ModuleList()
                self.decoders = nn.ModuleList()

                current_dim = input_dim

                for h_dim in hidden_dims:
                    encoder = nn.Sequential(
                        nn.Linear(current_dim, h_dim * 2),
                        nn.BatchNorm1d(h_dim * 2),
                        nn.ReLU(),
                        nn.Dropout(0.2),
                        nn.Linear(h_dim * 2, h_dim),
                        nn.BatchNorm1d(h_dim),
                        nn.ReLU()
                    )

                    decoder = nn.Sequential(
                        nn.Linear(h_dim, h_dim * 2),
                        nn.BatchNorm1d(h_dim * 2),
                        nn.ReLU(),
                        nn.Dropout(0.2),
                        nn.Linear(h_dim * 2, current_dim)
                    )

                    self.encoders.append(encoder)
                    self.decoders.append(decoder)
                    current_dim = h_dim

                self.feature_dim = current_dim

            def forward(self, x, return_all=False):
                encoded = []
                current = x

                for encoder in self.encoders:
                    current = encoder(current)
                    encoded.append(current)

                reconstructed = current
                for decoder in reversed(self.decoders):
                    reconstructed = decoder(reconstructed)

                if return_all:
                    return reconstructed, encoded
                return reconstructed

            def encode(self, x):
                current = x
                for encoder in self.encoders:
                    current = encoder(current)
                return current

        self.pytorch_model = AutoencoderStack(
            self.config.input_dim,
            self.config.deep_feature_dims
        )
        self.pytorch_optimizer = optim.Adam(
            self.pytorch_model.parameters(),
            lr=self.config.learning_rate
        )
        self.feature_dim = self.pytorch_model.feature_dim

        logger.info(f"✅ Built PyTorch model: input={self.config.input_dim}, "
                    f"output={self.feature_dim}")

    def pretrain(self, data: np.ndarray, epochs_per_layer: int = None,
                 batch_size: int = None, verbose: int = 1) -> Dict:
        epochs_per_layer = epochs_per_layer or self.config.pretrain_epochs_per_layer
        batch_size = batch_size or self.config.batch_size

        if len(data) < 100:
            logger.warning(f"Insufficient data: {len(data)} samples")
            return {'error': 'Insufficient data'}

        if self.backend == 'tensorflow':
            return self._pretrain_tensorflow(data, epochs_per_layer, batch_size, verbose)
        elif self.backend == 'pytorch':
            return self._pretrain_pytorch(data, epochs_per_layer, batch_size, verbose)
        else:
            return {'error': 'No backend available'}

    def _pretrain_tensorflow(self, data: np.ndarray, epochs_per_layer: int,
                             batch_size: int, verbose: int) -> Dict:
        history = {'layers': []}
        current_data = data.copy()

        with self._lock:
            for i, ae in enumerate(self.autoencoders):
                logger.info(f"Training layer {i+1}/{len(self.autoencoders)} "
                            f"({ae['input_dim']} → {ae['hidden_dim']})")

                callbacks = [
                    keras.callbacks.EarlyStopping(
                        monitor='val_loss',
                        patience=10,
                        restore_best_weights=True
                    ),
                    keras.callbacks.ReduceLROnPlateau(
                        monitor='val_loss',
                        factor=0.5,
                        patience=5,
                        min_lr=1e-6
                    )
                ]

                layer_history = ae['model'].fit(
                    current_data, current_data,
                    epochs=epochs_per_layer,
                    batch_size=batch_size,
                    validation_split=0.1,
                    callbacks=callbacks,
                    verbose=verbose,
                    shuffle=True
                )

                history['layers'].append({
                    'layer': i,
                    'input_dim': ae['input_dim'],
                    'hidden_dim': ae['hidden_dim'],
                    'final_loss': float(layer_history.history['loss'][-1]),
                    'final_val_loss': float(layer_history.history['val_loss'][-1])
                })

                self.stats['total_pretrain_epochs'] += len(layer_history.history['loss'])
                self.stats['reconstruction_loss'].append(
                    float(layer_history.history['loss'][-1])
                )

                current_data = ae['encoder'].predict(current_data, verbose=0)

        self.is_trained = True
        self.training_history = history

        logger.info(f"✅ Pretraining complete: {self.stats['total_pretrain_epochs']} total epochs")

        return history

    def _pretrain_pytorch(self, data: np.ndarray, epochs_per_layer: int,
                          batch_size: int, verbose: int) -> Dict:
        history = {'layers': []}

        dataset = TensorDataset(torch.FloatTensor(data))
        dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

        with self._lock:
            self.pytorch_model.train()

            for epoch in range(epochs_per_layer):
                epoch_loss = 0.0

                for batch in dataloader:
                    x = batch[0]

                    self.pytorch_optimizer.zero_grad()
                    reconstructed = self.pytorch_model(x)
                    loss = nn.MSELoss()(reconstructed, x)

                    loss.backward()
                    self.pytorch_optimizer.step()

                    epoch_loss += loss.item()

                avg_loss = epoch_loss / len(dataloader)

                if verbose and epoch % 10 == 0:
                    logger.info(f"Epoch {epoch}: loss={avg_loss:.6f}")

                history['layers'].append({
                    'epoch': epoch,
                    'loss': avg_loss
                })

        self.is_trained = True
        self.training_history = history

        logger.info(f"✅ Pretraining complete: final loss={history['layers'][-1]['loss']:.6f}")

        return history

    def extract_features(self, data: np.ndarray) -> np.ndarray:
        if not self.is_trained:
            logger.warning("Model not trained, returning random features")
            return np.random.randn(len(data), self.feature_dim) * 0.1

        if self.backend == 'tensorflow':
            features = data.copy()
            for ae in self.autoencoders:
                features = ae['encoder'].predict(features, verbose=0)
            return features

        elif self.backend == 'pytorch':
            self.pytorch_model.eval()
            with torch.no_grad():
                x = torch.FloatTensor(data)
                features = self.pytorch_model.encode(x)
                return features.numpy()

        return np.random.randn(len(data), self.feature_dim) * 0.1

    def get_anomaly_score(self, data: np.ndarray) -> Tuple[float, float, bool]:
        self.stats['total_predictions'] += 1

        if not self.is_trained:
            return 0.5, 0.0, False

        if data.ndim == 1:
            data = data.reshape(1, -1)

        if self.backend == 'tensorflow':
            features = self.extract_features(data)
            reconstructed = self.reconstruct(features)
            mse = np.mean((data - reconstructed) ** 2)

        elif self.backend == 'pytorch':
            self.pytorch_model.eval()
            with torch.no_grad():
                x = torch.FloatTensor(data)
                reconstructed = self.pytorch_model(x)
                mse = nn.MSELoss()(reconstructed, x).item()

        else:
            return 0.5, 0.0, False

        if self.stats['reconstruction_loss']:
            avg_loss = np.mean(self.stats['reconstruction_loss'][-10:])
            threshold = avg_loss * 3
            score = min(1.0, mse / threshold)
            is_anomaly = mse > threshold
        else:
            score = min(1.0, mse / 0.1)
            is_anomaly = mse > 0.1

        if is_anomaly:
            self.stats['anomalies_detected'] += 1

        return score, mse, is_anomaly

    def reconstruct(self, features: np.ndarray) -> np.ndarray:
        if not self.is_trained:
            return np.random.randn(len(features), self.config.input_dim) * 0.1

        if self.backend == 'tensorflow':
            reconstructed = features.copy()
            for ae in reversed(self.autoencoders):
                reconstructed = ae['decoder'].predict(reconstructed, verbose=0)
            return reconstructed

        return np.random.randn(len(features), self.config.input_dim) * 0.1

    def online_update(self, data: np.ndarray, labels: Optional[np.ndarray] = None):
        self.online_buffer.extend(data)
        if labels is not None:
            self.online_labels.extend(labels)

        if len(self.online_buffer) >= self.config.min_samples_retrain:
            self._retrain_online()

    def _retrain_online(self):
        data = np.array(list(self.online_buffer))

        normal_data = data

        if len(normal_data) >= 50:
            logger.info(f"Online retraining on {len(normal_data)} samples")

            if self.backend == 'tensorflow':
                last_ae = self.autoencoders[-1]
                last_ae['model'].fit(
                    normal_data, normal_data,
                    epochs=5,
                    batch_size=self.config.batch_size,
                    verbose=0
                )

            elif self.backend == 'pytorch':
                dataset = TensorDataset(torch.FloatTensor(normal_data))
                dataloader = DataLoader(dataset, batch_size=self.config.batch_size, shuffle=True)

                self.pytorch_model.train()
                for epoch in range(5):
                    for batch in dataloader:
                        x = batch[0]
                        self.pytorch_optimizer.zero_grad()
                        reconstructed = self.pytorch_model(x)
                        loss = nn.MSELoss()(reconstructed, x)
                        loss.backward()
                        self.pytorch_optimizer.step()

        self.online_buffer.clear()
        self.online_labels.clear()

    def save(self, path: str = None):
        save_path = Path(path or self.config.model_dir) / 'feature_extractor'
        save_path.mkdir(parents=True, exist_ok=True)

        if self.backend == 'tensorflow':
            for i, ae in enumerate(self.autoencoders):
                ae['model'].save(save_path / f'autoencoder_{i}.keras')

        elif self.backend == 'pytorch':
            torch.save({
                'model_state_dict': self.pytorch_model.state_dict(),
                'optimizer_state_dict': self.pytorch_optimizer.state_dict(),
                'feature_dim': self.feature_dim,
                'is_trained': self.is_trained,
                'stats': self.stats
            }, save_path / 'model.pt')

        logger.info(f"✅ Model saved to {save_path}")

    def _load_model(self):
        load_path = Path(self.config.model_dir) / 'feature_extractor'

        if not load_path.exists():
            return

        try:
            if self.backend == 'tensorflow':
                for i, ae in enumerate(self.autoencoders):
                    model_path = load_path / f'autoencoder_{i}.keras'
                    if model_path.exists():
                        loaded = keras.models.load_model(model_path)
                        ae['model'] = loaded
                        ae['encoder'] = loaded.layers[0]
                        ae['decoder'] = loaded.layers[1]

                self.is_trained = True
                logger.info(f"✅ Loaded TensorFlow model")

            elif self.backend == 'pytorch':
                checkpoint = torch.load(load_path / 'model.pt')
                self.pytorch_model.load_state_dict(checkpoint['model_state_dict'])
                self.pytorch_optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
                self.is_trained = checkpoint.get('is_trained', True)
                self.stats = checkpoint.get('stats', self.stats)
                logger.info(f"✅ Loaded PyTorch model")

        except Exception as e:
            logger.error(f"❌ Failed to load model: {e}")

    def get_stats(self) -> Dict:
        with self._lock:
            return {
                'is_trained': self.is_trained,
                'backend': self.backend,
                'input_dim': self.config.input_dim,
                'feature_dim': self.feature_dim,
                'num_layers': len(self.autoencoders) if self.backend == 'tensorflow' else len(self.config.deep_feature_dims),
                **self.stats
            }


class DynamicEnsemble:

    def __init__(self, models: Dict[str, Any], config: AdaptiveConfig = None):
        self.config = config or AdaptiveConfig()
        self.models = models
        self.model_names = list(models.keys())

        self.weights = {name: 1.0 / len(models) for name in self.model_names}
        self._weight_lock = threading.RLock()

        self.performance_history = {
            name: {
                'f1_scores': deque(maxlen=100),
                'precisions': deque(maxlen=100),
                'recalls': deque(maxlen=100),
                'latencies': deque(maxlen=100)
            }
            for name in self.model_names
        }

        self.feedback_buffer: deque = deque(maxlen=self.config.feedback_buffer_size)
        self._feedback_lock = threading.RLock()

        self.stats = {
            'total_predictions': 0,
            'total_feedback': 0,
            'weight_updates': 0,
            'avg_confidence': 0.0
        }

        self._executor = ThreadPoolExecutor(max_workers=2)

        self._prediction_cache: Dict[str, Tuple[Dict, float]] = {}
        self._cache_lock = threading.RLock()

        logger.info(f"✅ DynamicEnsemble initialized with {len(models)} models")

    def predict(self, features: np.ndarray, use_cache: bool = True) -> Dict:
        if use_cache:
            cache_key = self._make_cache_key(features)
            with self._cache_lock:
                if cache_key in self._prediction_cache:
                    result, timestamp = self._prediction_cache[cache_key]
                    if time.time() - timestamp < self.config.cache_ttl:
                        return result

        start_time = time.time()
        self.stats['total_predictions'] += 1

        individual_predictions = {}
        ensemble_score = 0.0
        ensemble_confidence = 0.0
        anomaly_votes = 0.0
        total_weight = 0.0

        with self._weight_lock:
            current_weights = self.weights.copy()

        for name in self.model_names:
            model = self.models[name]

            try:
                pred_start = time.time()

                if hasattr(model, 'predict'):
                    pred = model.predict(features)
                elif hasattr(model, 'get_anomaly_score'):
                    score, _, _ = model.get_anomaly_score(features)
                    pred = {'score': score, 'is_anomaly': score > 0.5}
                else:
                    continue

                latency = (time.time() - pred_start) * 1000

                score = pred.get('score', pred.get('anomaly_score', 0.5))
                is_anomaly = pred.get('is_anomaly', score > 0.5)
                confidence = pred.get('confidence', abs(score - 0.5) * 2)

                individual_predictions[name] = {
                    'score': float(score),
                    'is_anomaly': bool(is_anomaly),
                    'confidence': float(confidence),
                    'latency_ms': latency
                }

                weight = current_weights[name]
                ensemble_score += score * weight
                ensemble_confidence += confidence * weight
                total_weight += weight

                if is_anomaly:
                    anomaly_votes += weight

                self.performance_history[name]['latencies'].append(latency)

            except Exception as e:
                logger.error(f"Model {name} prediction failed: {e}")
                continue

        if total_weight > 0:
            ensemble_score /= total_weight
            ensemble_confidence /= total_weight
            is_ensemble_anomaly = (anomaly_votes / total_weight) > 0.5
        else:
            ensemble_score = 0.5
            ensemble_confidence = 0.0
            is_ensemble_anomaly = False

        calibrated_confidence = self._calibrate_confidence(ensemble_score, ensemble_confidence)

        result = {
            'ensemble_score': float(ensemble_score),
            'ensemble_confidence': float(ensemble_confidence),
            'calibrated_confidence': calibrated_confidence,
            'is_anomaly': bool(is_ensemble_anomaly),
            'individual_predictions': individual_predictions,
            'weights': current_weights,
            'anomaly_votes_ratio': float(anomaly_votes / total_weight) if total_weight > 0 else 0.0,
            'inference_time_ms': (time.time() - start_time) * 1000
        }

        self.stats['avg_confidence'] = (
                0.95 * self.stats['avg_confidence'] +
                0.05 * ensemble_confidence
        )

        if use_cache:
            with self._cache_lock:
                self._prediction_cache[cache_key] = (result, time.time())

                if len(self._prediction_cache) > self.config.cache_size:
                    sorted_keys = sorted(
                        self._prediction_cache.keys(),
                        key=lambda k: self._prediction_cache[k][1]
                    )
                    for k in sorted_keys[:100]:
                        del self._prediction_cache[k]

        return result

    def _make_cache_key(self, features: np.ndarray) -> str:
        features_flat = features.flatten()
        quantized = np.round(features_flat[:20], 3)
        return hashlib.md5(quantized.tobytes()).hexdigest()

    def _calibrate_confidence(self, score: float, raw_confidence: float) -> float:
        temperature = 1.5
        calibrated = 1.0 / (1.0 + np.exp(-(score - 0.5) / temperature))

        return 0.7 * calibrated + 0.3 * raw_confidence

    def add_feedback(self, features: np.ndarray, true_label: int,
                     alert_resolved: bool = False, damage_prevented: float = 0.0):
        with self._feedback_lock:
            self.feedback_buffer.append({
                'features': features,
                'true_label': true_label,
                'alert_resolved': alert_resolved,
                'damage_prevented': damage_prevented,
                'timestamp': time.time()
            })
            self.stats['total_feedback'] += 1

        if len(self.feedback_buffer) >= self.config.ensemble_update_frequency:
            self._executor.submit(self.update_weights)

    def update_weights(self, min_samples: int = None) -> bool:
        min_samples = min_samples or self.config.ensemble_update_frequency

        with self._feedback_lock:
            if len(self.feedback_buffer) < min_samples:
                return False

            feedback_samples = list(self.feedback_buffer)[-min_samples:]

        f1_scores = {}

        for name in self.model_names:
            model = self.models[name]

            y_true = []
            y_pred = []

            for fb in feedback_samples:
                features = fb['features']
                true_label = fb['true_label']

                try:
                    if hasattr(model, 'predict'):
                        pred = model.predict(features)
                        pred_score = pred.get('score', 0.5)
                    elif hasattr(model, 'get_anomaly_score'):
                        pred_score, _, _ = model.get_anomaly_score(features)
                    else:
                        continue

                    pred_label = 1 if pred_score > 0.5 else 0

                    y_true.append(true_label)
                    y_pred.append(pred_label)

                except Exception as e:
                    logger.debug(f"Error evaluating {name}: {e}")
                    continue

            if len(y_true) >= 10:
                f1 = f1_score(y_true, y_pred, zero_division=0)
                precision = precision_score(y_true, y_pred, zero_division=0)
                recall = recall_score(y_true, y_pred, zero_division=0)

                f1_scores[name] = f1

                self.performance_history[name]['f1_scores'].append(f1)
                self.performance_history[name]['precisions'].append(precision)
                self.performance_history[name]['recalls'].append(recall)

        if not f1_scores:
            return False

        f1_values = np.array([f1_scores.get(name, 0.5) for name in self.model_names])

        avg_latencies = {
            name: np.mean(list(self.performance_history[name]['latencies']) or [100])
            for name in self.model_names
        }
        max_latency = max(avg_latencies.values()) or 1

        latency_penalty = np.array([
            1.0 - 0.2 * (avg_latencies[name] / max_latency)
            for name in self.model_names
        ])

        combined_scores = f1_values * latency_penalty

        exp_scores = np.exp(combined_scores / self.config.ensemble_temperature)
        new_weights = exp_scores / np.sum(exp_scores)

        new_weights = np.maximum(new_weights, self.config.min_model_weight)
        new_weights = new_weights / np.sum(new_weights)

        with self._weight_lock:
            for i, name in enumerate(self.model_names):
                old_weight = self.weights[name]
                self.weights[name] = 0.7 * old_weight + 0.3 * new_weights[i]

            self.stats['weight_updates'] += 1

        logger.info(f"✅ Ensemble weights updated: "
                    f"{', '.join(f'{n}: {w:.3f}' for n, w in self.weights.items())}")

        return True

    def get_stats(self) -> Dict:
        with self._weight_lock:
            return {
                **self.stats,
                'models': self.model_names,
                'current_weights': self.weights.copy(),
                'feedback_buffer_size': len(self.feedback_buffer),
                'performance_summary': {
                    name: {
                        'avg_f1': np.mean(list(hist['f1_scores']) or [0]),
                        'avg_precision': np.mean(list(hist['precisions']) or [0]),
                        'avg_recall': np.mean(list(hist['recalls']) or [0]),
                        'avg_latency_ms': np.mean(list(hist['latencies']) or [0])
                    }
                    for name, hist in self.performance_history.items()
                }
            }

    def shutdown(self):
        self._executor.shutdown(wait=True)


class AdaptiveLearningEngine:

    def __init__(self, config: Dict = None):
        self.config = AdaptiveConfig()
        if config:
            for key, value in config.items():
                if hasattr(self.config, key):
                    setattr(self.config, key, value)

        self.baseline_profiler = AdaptiveBaselineProfiler(self.config)

        if self.config.use_deep_features:
            self.feature_extractor = DeepFeatureExtractor(self.config)
        else:
            self.feature_extractor = None

        self.ensemble = None

        self.pretrain_buffer: deque = deque(maxlen=5000)
        self.pretrain_threshold = 1000

        self._running = False
        self._lock = threading.RLock()

        self._retrain_thread = None
        self._save_thread = None

        self.stats = {
            'total_packets_processed': 0,
            'anomalies_detected': 0,
            'false_positives_reported': 0,
            'start_time': time.time()
        }

        Path(self.config.model_dir).mkdir(parents=True, exist_ok=True)

        logger.info("✅ AdaptiveLearningEngine initialized")

    def register_models(self, models: Dict[str, Any]):
        with self._lock:
            self.ensemble = DynamicEnsemble(models, self.config)
            logger.info(f"✅ Registered {len(models)} models in ensemble")

    def start(self):
        self._running = True

        self._retrain_thread = threading.Thread(
            target=self._retrain_loop,
            daemon=True,
            name="Adaptive-Retrain"
        )
        self._retrain_thread.start()

        self._save_thread = threading.Thread(
            target=self._save_loop,
            daemon=True,
            name="Adaptive-Save"
        )
        self._save_thread.start()

        logger.info("🚀 AdaptiveLearningEngine started")

    def stop(self):
        self._running = False

        if self._retrain_thread:
            self._retrain_thread.join(timeout=5)
        if self._save_thread:
            self._save_thread.join(timeout=5)

        self.save_models()

        self.baseline_profiler.shutdown()
        if self.ensemble:
            self.ensemble.shutdown()

        logger.info("🛑 AdaptiveLearningEngine stopped")

    def _retrain_loop(self):
        while self._running:
            time.sleep(self.config.retrain_interval)

            if not self._running:
                break

            try:
                if self.feature_extractor and len(self.pretrain_buffer) >= self.pretrain_threshold:
                    data = np.array(list(self.pretrain_buffer))
                    self.feature_extractor.pretrain(data, verbose=0)
                    self.pretrain_buffer.clear()
                    logger.info("🔄 Feature extractor retrained")

                if self.ensemble:
                    self.ensemble.update_weights()

            except Exception as e:
                logger.error(f"Retrain error: {e}")

    def _save_loop(self):
        while self._running:
            time.sleep(300)

            if not self._running:
                break

            try:
                self.save_models()
            except Exception as e:
                logger.error(f"Save error: {e}")

    def process_packet(self, device: str, raw_features: List[float]) -> Dict:
        self.stats['total_packets_processed'] += 1

        result = {
            'device': device,
            'timestamp': time.time(),
            'baseline': None,
            'deep_features': None,
            'ensemble': None,
            'overall_score': 0.0,
            'is_anomaly': False,
            'confidence': 0.0
        }

        feature_dict = {f'f_{i}': float(v) for i, v in enumerate(raw_features[:50])}

        baseline_result = self.baseline_profiler.update(device, feature_dict)
        result['baseline'] = baseline_result

        if self.feature_extractor and self.feature_extractor.is_trained:
            features_array = np.array(raw_features).reshape(1, -1)

            if features_array.shape[1] < self.config.input_dim:
                padding = np.zeros((1, self.config.input_dim - features_array.shape[1]))
                features_array = np.concatenate([features_array, padding], axis=1)
            elif features_array.shape[1] > self.config.input_dim:
                features_array = features_array[:, :self.config.input_dim]

            deep_score, deep_mse, deep_anomaly = self.feature_extractor.get_anomaly_score(features_array)

            result['deep_features'] = {
                'score': float(deep_score),
                'mse': float(deep_mse),
                'is_anomaly': deep_anomaly
            }
        else:
            self.pretrain_buffer.append(raw_features[:self.config.input_dim])

        if self.ensemble:
            features_array = np.array(raw_features)
            ensemble_result = self.ensemble.predict(features_array)
            result['ensemble'] = ensemble_result
            result['overall_score'] = ensemble_result['ensemble_score']
            result['is_anomaly'] = ensemble_result['is_anomaly']
            result['confidence'] = ensemble_result['calibrated_confidence']
        else:
            result['overall_score'] = baseline_result['overall_score']
            result['is_anomaly'] = baseline_result['is_anomaly']
            result['confidence'] = 1.0 - abs(baseline_result['overall_score'] - 0.5) * 2

        if result['is_anomaly']:
            self.stats['anomalies_detected'] += 1

        return result

    def add_feedback(self, features: List[float], true_label: int,
                     alert_resolved: bool = False, damage_prevented: float = 0.0):
        features_array = np.array(features)

        if self.ensemble:
            self.ensemble.add_feedback(features_array, true_label, alert_resolved, damage_prevented)

        if true_label == 0:
            self.stats['false_positives_reported'] += 1

    def save_models(self):
        if self.feature_extractor:
            self.feature_extractor.save()

        logger.info("✅ Models saved")

    def load_models(self) -> bool:
        if self.feature_extractor:
            self.feature_extractor._load_model()

        logger.info("✅ Models loaded")
        return True

    def get_stats(self) -> Dict:
        stats = {
            'engine': {
                **self.stats,
                'uptime': time.time() - self.stats['start_time'],
                'packets_per_second': self.stats['total_packets_processed'] / max(1, time.time() - self.stats['start_time'])
            },
            'baseline': self.baseline_profiler.get_stats(),
            'feature_extractor': self.feature_extractor.get_stats() if self.feature_extractor else None,
            'ensemble': self.ensemble.get_stats() if self.ensemble else None
        }
        return stats


def test_adaptive_learning():
    print("=" * 60)
    print("🧪 TESTING ADAPTIVE LEARNING ENGINE")
    print("=" * 60)

    engine = AdaptiveLearningEngine({
        'forgetting_factor': 0.95,
        'use_deep_features': False,
        'model_dir': './test_models/'
    })

    class MockModel:
        def __init__(self, name, bias):
            self.name = name
            self.bias = bias

        def predict(self, features):
            score = np.random.random() * 0.3 + self.bias
            return {
                'score': score,
                'is_anomaly': score > 0.5,
                'confidence': abs(score - 0.5) * 2
            }

    models = {
        'model_a': MockModel('A', 0.3),
        'model_b': MockModel('B', 0.5),
        'model_c': MockModel('C', 0.7)
    }

    engine.register_models(models)
    engine.start()

    print("\n📊 Processing packets...")

    for i in range(100):
        if i < 80:
            features = list(np.random.randn(156) * 0.1)
        else:
            features = list(np.random.randn(156) * 1.5)

        result = engine.process_packet(f'device_{i%5}', features)

        if result['is_anomaly']:
            print(f"   ⚠️ Packet {i}: anomaly detected (score={result['overall_score']:.3f})")

    print("\n📊 Adding feedback...")
    for _ in range(20):
        features = list(np.random.randn(156) * 1.5)
        engine.add_feedback(features, true_label=1)

    engine.ensemble.update_weights()

    print("\n📊 Statistics:")
    stats = engine.get_stats()
    print(f"   Total packets: {stats['engine']['total_packets_processed']}")
    print(f"   Anomalies: {stats['engine']['anomalies_detected']}")
    print(f"   Baseline devices: {stats['baseline']['active_devices']}")

    if stats['ensemble']:
        print(f"   Ensemble weights: {stats['ensemble']['current_weights']}")

    engine.stop()

    print("\n" + "=" * 60)
    print("✅ TESTING COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    test_adaptive_learning()