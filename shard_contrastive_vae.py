#!/usr/bin/env python3

"""
SHARD Contrastive Variational Autoencoder - Production-Ready
Контрастивный VAE для робастного обнаружения аномалий с самообучением.

Версия: 5.0.0 - Полное обучение, SupCon loss, аугментации, калибровка

Author: SHARD Enterprise
"""

import os
import sys
import time
import json
import threading
import warnings
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any
from collections import deque
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor
import logging

import numpy as np

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("SHARD-ContrastiveVAE")

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
    from sklearn.metrics import roc_auc_score, average_precision_score

    SKLEARN_AVAILABLE = True
    logger.info("✅ Scikit-learn loaded")
except ImportError:
    logger.warning("⚠️ Scikit-learn not installed")



@dataclass
class ContrastiveVAEConfig:
    """Конфигурация Contrastive VAE"""

    input_dim: int = 156
    encoder_hidden_dims: List[int] = field(default_factory=lambda: [256, 128, 64])
    decoder_hidden_dims: List[int] = field(default_factory=lambda: [64, 128, 256])
    latent_dim: int = 32

    temperature: float = 0.1
    contrastive_weight: float = 0.3
    reconstruction_weight: float = 1.0
    kl_weight: float = 0.1
    use_augmentations: bool = True
    augmentation_noise: float = 0.05
    augmentation_dropout: float = 0.1

    learning_rate: float = 0.001
    batch_size: int = 64
    epochs: int = 100
    early_stopping_patience: int = 15
    reduce_lr_patience: int = 7
    gradient_clip_norm: float = 1.0
    weight_decay: float = 0.0001

    threshold_percentile: float = 95.0
    latent_distance_threshold: float = 2.0
    reconstruction_threshold_multiplier: float = 3.0

    online_learning_enabled: bool = True
    online_buffer_size: int = 5000
    retrain_interval: int = 300
    min_samples_retrain: int = 100

    model_dir: str = './models/contrastive_vae/'
    checkpoint_dir: str = './models/contrastive_vae/checkpoints/'
    checkpoint_frequency: int = 10

    use_mixed_precision: bool = True
    cache_size: int = 10000
    cache_ttl: int = 60
    max_workers: int = 4

    def save(self, path: str):
        """Сохранение конфигурации"""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            json.dump(self.__dict__, f, indent=2)

    @classmethod
    def load(cls, path: str) -> 'ContrastiveVAEConfig':
        """Загрузка конфигурации"""
        with open(path, 'r') as f:
            data = json.load(f)
        return cls(**data)



try:
    from tensorflow.keras import layers
except ImportError:
    layers = None

if layers is not None:
    class Sampling(layers.Layer):
        """Reparameterization trick для VAE с поддержкой mixed precision"""

        def __init__(self, **kwargs):
            super().__init__(**kwargs)

        def call(self, inputs, training=None):
            z_mean, z_log_var = inputs
            batch = tf.shape(z_mean)[0]
            dim = tf.shape(z_mean)[1]

            if training:
                epsilon = tf.random.normal(shape=(batch, dim), dtype=z_mean.dtype)
                return z_mean + tf.exp(0.5 * z_log_var) * epsilon
            else:
                return z_mean

        def get_config(self):
            return super().get_config()
else:
    class Sampling:
        """Dummy Sampling when TensorFlow not available"""
        def __init__(self, **kwargs): pass
        def call(self, inputs, training=None): return inputs[0]
        def get_config(self): return {}


if TORCH_AVAILABLE:

    class ContrastiveVAE(nn.Module):
        """
        Variational Autoencoder с Contrastive Learning.

        Loss = Reconstruction_Loss + KL_Divergence + Contrastive_Loss

        Особенности:
        - Аугментации для contrastive learning
        - Projection head для SupCon
        - Memory bank для negative samples
        """

        def __init__(self, config: ContrastiveVAEConfig):
            super().__init__()
            self.config = config

            encoder_layers = []
            input_dim = config.input_dim

            for i, h_dim in enumerate(config.encoder_hidden_dims):
                encoder_layers.extend([
                    nn.Linear(input_dim, h_dim),
                    nn.LayerNorm(h_dim),
                    nn.ReLU(),
                    nn.Dropout(0.2)
                ])
                input_dim = h_dim

            self.encoder = nn.Sequential(*encoder_layers)

            self.z_mean = nn.Linear(config.encoder_hidden_dims[-1], config.latent_dim)
            self.z_log_var = nn.Linear(config.encoder_hidden_dims[-1], config.latent_dim)

            decoder_layers = []
            input_dim = config.latent_dim

            for i, h_dim in enumerate(config.decoder_hidden_dims):
                decoder_layers.extend([
                    nn.Linear(input_dim, h_dim),
                    nn.LayerNorm(h_dim),
                    nn.ReLU(),
                    nn.Dropout(0.2 if i < len(config.decoder_hidden_dims) - 1 else 0.0)
                ])
                input_dim = h_dim

            decoder_layers.append(nn.Linear(config.decoder_hidden_dims[-1], config.input_dim))
            self.decoder = nn.Sequential(*decoder_layers)

            self.projection_head = nn.Sequential(
                nn.Linear(config.latent_dim, 128),
                nn.LayerNorm(128),
                nn.ReLU(),
                nn.Linear(128, 64),
                nn.LayerNorm(64),
                nn.ReLU(),
                nn.Linear(64, 32)
            )

            self.register_buffer('memory_bank', torch.randn(10000, config.latent_dim))
            self.register_buffer('memory_ptr', torch.zeros(1, dtype=torch.long))
            self.register_buffer('memory_filled', torch.zeros(1, dtype=torch.bool))

            self._init_weights()

        def _init_weights(self):
            """Инициализация весов Xavier"""
            for m in self.modules():
                if isinstance(m, nn.Linear):
                    nn.init.xavier_uniform_(m.weight)
                    if m.bias is not None:
                        nn.init.zeros_(m.bias)
                elif isinstance(m, nn.BatchNorm1d):
                    nn.init.ones_(m.weight)
                    nn.init.zeros_(m.bias)

        def encode(self, x):
            """Кодирование входа в параметры латентного распределения"""
            h = self.encoder(x)
            z_mean = self.z_mean(h)
            z_log_var = self.z_log_var(h)
            return z_mean, z_log_var

        def reparameterize(self, z_mean, z_log_var, training=True):
            """Reparameterization trick"""
            if training:
                std = torch.exp(0.5 * z_log_var)
                eps = torch.randn_like(std)
                return z_mean + eps * std
            return z_mean

        def decode(self, z):
            """Декодирование из латентного пространства"""
            return self.decoder(z)

        def forward(self, x, training=True):
            """
            Forward pass.

            Returns:
                Dict с reconstruction, latent параметрами и projection
            """
            z_mean, z_log_var = self.encode(x)
            z = self.reparameterize(z_mean, z_log_var, training)
            reconstruction = self.decode(z)

            projection = self.projection_head(z)

            return {
                'reconstruction': reconstruction,
                'z_mean': z_mean,
                'z_log_var': z_log_var,
                'z': z,
                'projection': projection
            }

        def augment(self, x):
            """
            Создание аугментированных версий для contrastive learning.

            Returns:
                Tuple из двух аугментированных версий
            """
            batch_size = x.size(0)

            noise = torch.randn_like(x) * self.config.augmentation_noise
            x_noisy = x + noise

            mask = torch.rand_like(x) > self.config.augmentation_dropout
            x_dropout = x * mask.float() / (1 - self.config.augmentation_dropout)

            if batch_size > 1:
                shuffle_idx = torch.randperm(batch_size)
                shuffle_ratio = 0.1
                n_shuffle = int(x.size(1) * shuffle_ratio)

                if n_shuffle > 0:
                    x_shuffle = x.clone()
                    shuffle_cols = torch.randperm(x.size(1))[:n_shuffle]
                    x_shuffle[:, shuffle_cols] = x[shuffle_idx][:, shuffle_cols]
                else:
                    x_shuffle = x
            else:
                x_shuffle = x

            return x_noisy, x_dropout, x_shuffle

        def contrastive_loss(self, projections, labels):
            """
            Supervised Contrastive Loss (SupCon).

            Args:
                projections: (batch_size, proj_dim)
                labels: (batch_size, 1) - метки классов
            """
            batch_size = projections.size(0)

            if batch_size < 2:
                return torch.tensor(0.0, device=projections.device)

            projections = F.normalize(projections, dim=1)

            sim_matrix = torch.matmul(projections, projections.T)
            sim_matrix = sim_matrix / self.config.temperature

            labels = labels.view(-1, 1)
            mask_positive = (labels == labels.T).float()

            mask_positive = mask_positive - torch.eye(batch_size, device=mask_positive.device)

            sim_matrix = sim_matrix - sim_matrix.max(dim=1, keepdim=True)[0]

            exp_sim = torch.exp(sim_matrix)

            pos_sum = (exp_sim * mask_positive).sum(dim=1)

            mask_all = 1.0 - torch.eye(batch_size, device=sim_matrix.device)
            all_sum = (exp_sim * mask_all).sum(dim=1)

            loss = -torch.log(pos_sum / (all_sum + 1e-8) + 1e-8)

            has_positives = (mask_positive.sum(dim=1) > 0).float()
            if has_positives.sum() > 0:
                loss = (loss * has_positives).sum() / has_positives.sum()
            else:
                loss = loss.mean()

            return loss

        def update_memory_bank(self, z):
            """Обновление банка памяти для negative sampling"""
            batch_size = z.size(0)
            ptr = self.memory_ptr.item()

            if ptr + batch_size > self.memory_bank.size(0):
                ptr = 0
                self.memory_filled.fill_(True)

            self.memory_bank[ptr:ptr + batch_size] = z.detach()
            self.memory_ptr.fill_((ptr + batch_size) % self.memory_bank.size(0))

        def get_memory_negatives(self, batch_size, device):
            """Получение negative samples из memory bank"""
            if not self.memory_filled:
                return None

            mem_size = self.memory_bank.size(0)
            indices = torch.randint(0, mem_size, (batch_size,), device=device)
            return self.memory_bank[indices]

        def compute_loss(self, x, labels=None, training=True):
            """
            Вычисление полного loss.

            Args:
                x: входные данные
                labels: метки для contrastive learning (опционально)
                training: режим обучения
            """
            batch_size = x.size(0)

            outputs = self.forward(x, training)

            reconstruction = outputs['reconstruction']
            z_mean = outputs['z_mean']
            z_log_var = outputs['z_log_var']
            z = outputs['z']
            projection = outputs['projection']

            recon_loss = F.mse_loss(reconstruction, x, reduction='sum') / batch_size

            kl_loss = -0.5 * torch.sum(1 + z_log_var - z_mean.pow(2) - z_log_var.exp()) / batch_size

            total_loss = (self.config.reconstruction_weight * recon_loss +
                          self.config.kl_weight * kl_loss)

            contrastive_loss = torch.tensor(0.0, device=x.device)

            if labels is not None and self.config.contrastive_weight > 0:
                contrastive_loss = self.contrastive_loss(projection, labels)

                if self.config.use_augmentations and batch_size > 1:
                    x_aug1, x_aug2, x_aug3 = self.augment(x)

                    with torch.no_grad():
                        z_aug1 = self.reparameterize(*self.encode(x_aug1), training=False)
                        z_aug2 = self.reparameterize(*self.encode(x_aug2), training=False)
                        z_aug3 = self.reparameterize(*self.encode(x_aug3), training=False)

                    proj_aug1 = self.projection_head(z_aug1)
                    proj_aug2 = self.projection_head(z_aug2)
                    proj_aug3 = self.projection_head(z_aug3)

                    all_projections = torch.cat([projection, proj_aug1, proj_aug2, proj_aug3], dim=0)
                    all_labels = torch.cat([labels] * 4, dim=0)

                    aug_contrastive_loss = self.contrastive_loss(all_projections, all_labels)
                    contrastive_loss = (contrastive_loss + aug_contrastive_loss) / 2

                total_loss = total_loss + self.config.contrastive_weight * contrastive_loss

            if training:
                self.update_memory_bank(z)

            return {
                'total_loss': total_loss,
                'reconstruction_loss': recon_loss,
                'kl_loss': kl_loss,
                'contrastive_loss': contrastive_loss,
                'reconstruction': reconstruction,
                'z': z
            }

        def anomaly_score(self, x):
            """
            Вычисление anomaly score.

            Returns:
                score: комбинированная оценка [0, 1]
                recon_error: ошибка реконструкции
                latent_score: оценка по латентному пространству
            """
            self.eval()

            with torch.no_grad():
                outputs = self.forward(x, training=False)

                reconstruction = outputs['reconstruction']
                z = outputs['z']

                recon_error = F.mse_loss(reconstruction, x, reduction='none').mean(dim=1)

                if hasattr(self, 'normal_centroid'):
                    latent_dist = torch.norm(z - self.normal_centroid, dim=1)
                    latent_score = latent_dist / (hasattr(self, 'normal_radius') and self.normal_radius or 1.0)
                else:
                    latent_score = torch.zeros_like(recon_error)

                if self.memory_filled:
                    z_norm = F.normalize(z, dim=1)
                    memory_norm = F.normalize(self.memory_bank, dim=1)
                    similarity = torch.matmul(z_norm, memory_norm.T)
                    memory_score = 1.0 - similarity.max(dim=1)[0]
                else:
                    memory_score = torch.zeros_like(recon_error)

                combined_score = (
                        0.5 * recon_error / (hasattr(self, 'recon_threshold') and self.recon_threshold or 0.1) +
                        0.3 * latent_score +
                        0.2 * memory_score
                )

                return combined_score, recon_error, latent_score



class ContrastiveVAEEngine:
    """
    Production движок для Contrastive VAE.

    Особенности:
    - Полное обучение с SupCon loss
    - Аугментации данных
    - Memory bank для negative sampling
    - Online learning
    - Калибровка порогов
    """

    def __init__(self, config: ContrastiveVAEConfig = None):
        self.config = config or ContrastiveVAEConfig()

        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

        self.model = None
        self.optimizer = None
        self.scheduler = None

        if TORCH_AVAILABLE:
            self.model = ContrastiveVAE(self.config).to(self.device)
            self.optimizer = optim.AdamW(
                self.model.parameters(),
                lr=self.config.learning_rate,
                weight_decay=self.config.weight_decay
            )
            self.scheduler = optim.lr_scheduler.ReduceLROnPlateau(
                self.optimizer, mode='min', factor=0.5, patience=self.config.reduce_lr_patience
            )

        self.recon_threshold = None
        self.latent_threshold = None
        self.normal_centroid = None
        self.normal_radius = None

        self.is_trained = False
        self.training_history = []

        self.normal_buffer: deque = deque(maxlen=self.config.online_buffer_size)
        self.anomaly_buffer: deque = deque(maxlen=self.config.online_buffer_size // 2)

        self._prediction_cache: Dict[str, Tuple[Dict, float]] = {}
        self._cache_lock = threading.RLock()

        self.stats = {
            'total_predictions': 0,
            'anomalies_detected': 0,
            'avg_inference_time_ms': 0.0,
            'training_epochs': 0,
            'best_loss': float('inf')
        }

        self._model_lock = threading.RLock()
        self._training_lock = threading.RLock()

        self._running = False
        self._retrain_thread = None

        self._executor = ThreadPoolExecutor(max_workers=self.config.max_workers)

        Path(self.config.model_dir).mkdir(parents=True, exist_ok=True)
        Path(self.config.checkpoint_dir).mkdir(parents=True, exist_ok=True)

        self._load_model()

        logger.info(f"✅ ContrastiveVAEEngine initialized on {self.device}")

    def _load_model(self):
        """Загружает сохранённую модель"""
        model_path = Path(self.config.model_dir) / 'contrastive_vae.pt'
        config_path = Path(self.config.model_dir) / 'thresholds.json'

        if model_path.exists() and self.model is not None:
            try:
                checkpoint = torch.load(model_path, map_location=self.device)
                self.model.load_state_dict(checkpoint['model_state_dict'])
                self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
                self.is_trained = checkpoint.get('is_trained', True)
                self.stats = checkpoint.get('stats', self.stats)

                logger.info(f"✅ Model loaded from {model_path}")
            except Exception as e:
                logger.warning(f"⚠️ Failed to load model: {e}")

        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    thresholds = json.load(f)
                    self.recon_threshold = thresholds.get('recon_threshold')
                    self.latent_threshold = thresholds.get('latent_threshold')
                    self.normal_centroid = torch.tensor(thresholds['normal_centroid'],
                                                        device=self.device) if thresholds.get(
                        'normal_centroid') else None
                    self.normal_radius = thresholds.get('normal_radius')
                logger.info(f"✅ Thresholds loaded")
            except Exception as e:
                logger.warning(f"⚠️ Failed to load thresholds: {e}")

    def _save_model(self):
        """Сохраняет модель и пороги"""
        if self.model is None:
            return

        model_path = Path(self.config.model_dir) / 'contrastive_vae.pt'
        config_path = Path(self.config.model_dir) / 'thresholds.json'

        try:
            torch.save({
                'model_state_dict': self.model.state_dict(),
                'optimizer_state_dict': self.optimizer.state_dict(),
                'config': self.config.__dict__,
                'is_trained': self.is_trained,
                'stats': self.stats
            }, model_path)

            thresholds = {
                'recon_threshold': self.recon_threshold,
                'latent_threshold': self.latent_threshold,
                'normal_centroid': self.normal_centroid.cpu().tolist() if self.normal_centroid is not None else None,
                'normal_radius': self.normal_radius
            }

            with open(config_path, 'w') as f:
                json.dump(thresholds, f, indent=2)

            logger.info(f"✅ Model and thresholds saved")
        except Exception as e:
            logger.error(f"❌ Failed to save model: {e}")

    def start(self):
        """Запуск движка"""
        self._running = True

        self._retrain_thread = threading.Thread(
            target=self._retrain_loop,
            daemon=True,
            name="VAE-Retrain"
        )
        self._retrain_thread.start()

        logger.info("🚀 ContrastiveVAEEngine started")

    def stop(self):
        """Остановка движка"""
        self._running = False

        if self._retrain_thread:
            self._retrain_thread.join(timeout=5)

        self._save_model()
        self._executor.shutdown(wait=True)

        logger.info("🛑 ContrastiveVAEEngine stopped")

    def _retrain_loop(self):
        """Фоновый цикл дообучения"""
        while self._running:
            time.sleep(self.config.retrain_interval)

            if not self._running:
                break

            if (self.config.online_learning_enabled and
                    len(self.normal_buffer) >= self.config.min_samples_retrain):
                normal_data = np.array(list(self.normal_buffer))
                self._online_retrain(normal_data)

    def _online_retrain(self, normal_data: np.ndarray):
        """Онлайн дообучение на новых данных"""
        logger.info(f"🔄 Online retraining on {len(normal_data)} samples")

        dataset = TensorDataset(torch.FloatTensor(normal_data))
        dataloader = DataLoader(dataset, batch_size=self.config.batch_size, shuffle=True)

        with self._training_lock:
            self.model.train()

            for epoch in range(5):
                epoch_loss = 0.0

                for batch in dataloader:
                    x = batch[0].to(self.device)

                    self.optimizer.zero_grad()
                    loss_dict = self.model.compute_loss(x, training=True)
                    loss = loss_dict['total_loss']

                    loss.backward()
                    torch.nn.utils.clip_grad_norm_(self.model.parameters(), self.config.gradient_clip_norm)
                    self.optimizer.step()

                    epoch_loss += loss.item()

                avg_loss = epoch_loss / len(dataloader)
                logger.debug(f"Online epoch: loss={avg_loss:.6f}")

        self._calibrate_thresholds(normal_data[:1000])

        self._save_model()

        self.normal_buffer.clear()

    def train(self, normal_data: np.ndarray, anomaly_data: Optional[np.ndarray] = None,
              validation_split: float = 0.1, epochs: int = None, verbose: int = 1) -> Dict:
        """
        Обучение модели.

        Args:
            normal_data: Нормальные данные
            anomaly_data: Аномальные данные для contrastive learning
            validation_split: Доля валидации
            epochs: Количество эпох
            verbose: Уровень логирования

        Returns:
            Dict с историей обучения
        """
        if self.model is None:
            return {'error': 'PyTorch not available'}

        epochs = epochs or self.config.epochs

        if len(normal_data) < 100:
            return {'error': f'Insufficient data: {len(normal_data)} samples'}

        if anomaly_data is not None and len(anomaly_data) > 0:
            X = np.concatenate([normal_data, anomaly_data])
            y = np.concatenate([np.zeros(len(normal_data)), np.ones(len(anomaly_data))])
        else:
            X = normal_data
            y = np.zeros(len(normal_data))

        if validation_split > 0:
            from sklearn.model_selection import train_test_split
            X_train, X_val, y_train, y_val = train_test_split(
                X, y, test_size=validation_split, stratify=y, random_state=42
            )
        else:
            X_train, y_train = X, y
            X_val, y_val = None, None

        train_dataset = TensorDataset(
            torch.FloatTensor(X_train),
            torch.LongTensor(y_train)
        )
        train_loader = DataLoader(
            train_dataset,
            batch_size=self.config.batch_size,
            shuffle=True
        )

        if X_val is not None:
            val_dataset = TensorDataset(
                torch.FloatTensor(X_val),
                torch.LongTensor(y_val)
            )
            val_loader = DataLoader(
                val_dataset,
                batch_size=self.config.batch_size,
                shuffle=False
            )
        else:
            val_loader = None

        history = {'loss': [], 'val_loss': [], 'recon_loss': [], 'kl_loss': [], 'contrastive_loss': []}

        with self._training_lock:
            self.model.train()

            best_val_loss = float('inf')
            patience_counter = 0

            for epoch in range(epochs):
                epoch_loss = 0.0
                epoch_recon = 0.0
                epoch_kl = 0.0
                epoch_contrast = 0.0

                for batch_x, batch_y in train_loader:
                    batch_x = batch_x.to(self.device)
                    batch_y = batch_y.to(self.device)

                    self.optimizer.zero_grad()

                    loss_dict = self.model.compute_loss(batch_x, batch_y, training=True)

                    loss = loss_dict['total_loss']
                    loss.backward()

                    torch.nn.utils.clip_grad_norm_(self.model.parameters(), self.config.gradient_clip_norm)
                    self.optimizer.step()

                    epoch_loss += loss.item()
                    epoch_recon += loss_dict['reconstruction_loss'].item()
                    epoch_kl += loss_dict['kl_loss'].item()
                    epoch_contrast += loss_dict['contrastive_loss'].item()

                avg_loss = epoch_loss / len(train_loader)
                history['loss'].append(avg_loss)
                history['recon_loss'].append(epoch_recon / len(train_loader))
                history['kl_loss'].append(epoch_kl / len(train_loader))
                history['contrastive_loss'].append(epoch_contrast / len(train_loader))

                if val_loader:
                    self.model.eval()
                    val_loss = 0.0

                    with torch.no_grad():
                        for batch_x, batch_y in val_loader:
                            batch_x = batch_x.to(self.device)
                            batch_y = batch_y.to(self.device)

                            loss_dict = self.model.compute_loss(batch_x, batch_y, training=False)
                            val_loss += loss_dict['total_loss'].item()

                    avg_val_loss = val_loss / len(val_loader)
                    history['val_loss'].append(avg_val_loss)

                    self.scheduler.step(avg_val_loss)

                    if avg_val_loss < best_val_loss:
                        best_val_loss = avg_val_loss
                        patience_counter = 0
                        self._save_model()
                    else:
                        patience_counter += 1
                        if patience_counter >= self.config.early_stopping_patience:
                            logger.info(f"Early stopping at epoch {epoch}")
                            break

                    self.model.train()

                if verbose and epoch % 10 == 0:
                    lr = self.optimizer.param_groups[0]['lr']
                    logger.info(f"Epoch {epoch}: loss={avg_loss:.4f}, recon={history['recon_loss'][-1]:.4f}, "
                                f"kl={history['kl_loss'][-1]:.4f}, contrast={history['contrastive_loss'][-1]:.4f}, lr={lr:.6f}")

                self.stats['training_epochs'] += 1

                if avg_loss < self.stats['best_loss']:
                    self.stats['best_loss'] = avg_loss

        self.is_trained = True
        self.training_history = history

        self._calibrate_thresholds(normal_data[:2000])

        self._save_model()

        logger.info(f"✅ Training complete. Best loss: {self.stats['best_loss']:.4f}")

        return history

    def _calibrate_thresholds(self, normal_data: np.ndarray):
        """Калибрует пороги на нормальных данных"""
        if len(normal_data) == 0:
            return

        dataset = TensorDataset(torch.FloatTensor(normal_data))
        dataloader = DataLoader(dataset, batch_size=self.config.batch_size, shuffle=False)

        recon_errors = []
        latent_vectors = []

        self.model.eval()
        with torch.no_grad():
            for batch in dataloader:
                x = batch[0].to(self.device)

                scores, recon_error, _ = self.model.anomaly_score(x)
                outputs = self.model(x, training=False)

                recon_errors.extend(recon_error.cpu().numpy())
                latent_vectors.append(outputs['z'].cpu())

        self.recon_threshold = np.percentile(recon_errors, self.config.threshold_percentile)

        if latent_vectors:
            all_latent = torch.cat(latent_vectors, dim=0)
            self.normal_centroid = all_latent.mean(dim=0)

            distances = torch.norm(all_latent - self.normal_centroid, dim=1)
            self.normal_radius = np.percentile(distances.cpu().numpy(), self.config.threshold_percentile)

            self.model.normal_centroid = self.normal_centroid
            self.model.normal_radius = self.normal_radius
            self.model.recon_threshold = self.recon_threshold

        logger.info(f"✅ Thresholds calibrated: recon={self.recon_threshold:.6f}, "
                    f"radius={self.normal_radius:.3f}")

    def predict(self, features: np.ndarray) -> Dict:
        """
        Предсказание anomaly score.

        Args:
            features: Вектор признаков

        Returns:
            Dict с результатами
        """
        start_time = time.time()
        self.stats['total_predictions'] += 1

        cache_key = self._make_cache_key(features)
        with self._cache_lock:
            if cache_key in self._prediction_cache:
                result, timestamp = self._prediction_cache[cache_key]
                if time.time() - timestamp < self.config.cache_ttl:
                    return result

        if not self.is_trained or self.model is None:
            return {
                'score': 0.5,
                'is_anomaly': False,
                'confidence': 0.0,
                'error': 'Model not trained'
            }

        if features.ndim == 1:
            features = np.expand_dims(features, axis=0)

        x = torch.FloatTensor(features).to(self.device)

        with self._model_lock:
            self.model.eval()

            with torch.no_grad():
                combined_score, recon_error, latent_score = self.model.anomaly_score(x)

                combined_score = combined_score.cpu().numpy()
                recon_error = recon_error.cpu().numpy()
                latent_score = latent_score.cpu().numpy()

        score = float(combined_score[0])
        recon = float(recon_error[0])
        latent = float(latent_score[0])

        is_anomaly = score > 0.5

        if is_anomaly:
            self.stats['anomalies_detected'] += 1

        confidence = min(1.0, abs(score - 0.5) * 2 + 0.3)

        result = {
            'score': score,
            'reconstruction_score': min(1.0, recon / (self.recon_threshold * 2)) if self.recon_threshold else score,
            'latent_score': min(1.0, latent) if self.normal_radius else 0.5,
            'reconstruction_error': recon,
            'latent_distance': latent,
            'is_anomaly': bool(is_anomaly),
            'confidence': confidence,
            'threshold': self.recon_threshold,
            'severity': self._get_severity(score)
        }

        with self._cache_lock:
            self._prediction_cache[cache_key] = (result, time.time())

            if len(self._prediction_cache) > self.config.cache_size:
                sorted_keys = sorted(
                    self._prediction_cache.keys(),
                    key=lambda k: self._prediction_cache[k][1]
                )
                for k in sorted_keys[:len(sorted_keys) // 10]:
                    del self._prediction_cache[k]

        inference_time = (time.time() - start_time) * 1000
        self.stats['avg_inference_time_ms'] = (
                0.95 * self.stats['avg_inference_time_ms'] +
                0.05 * inference_time
        )

        if not is_anomaly and score < 0.3:
            self.normal_buffer.append(features.flatten())
        elif is_anomaly and score > 0.7:
            self.anomaly_buffer.append(features.flatten())

        return result

    def _make_cache_key(self, features: np.ndarray) -> str:
        """Создаёт ключ кэша"""
        features_flat = features.flatten()
        quantized = np.round(features_flat[:30], 3)
        return hashlib.md5(quantized.tobytes()).hexdigest()

    def _get_severity(self, score: float) -> str:
        """Определяет серьёзность по score"""
        if score > 0.8:
            return 'CRITICAL'
        elif score > 0.6:
            return 'HIGH'
        elif score > 0.4:
            return 'MEDIUM'
        else:
            return 'LOW'

    def encode(self, features: np.ndarray) -> np.ndarray:
        """Извлечение латентного представления"""
        if not self.is_trained or self.model is None:
            return np.zeros(self.config.latent_dim)

        if features.ndim == 1:
            features = np.expand_dims(features, axis=0)

        x = torch.FloatTensor(features).to(self.device)

        with torch.no_grad():
            z_mean, _ = self.model.encode(x)
            return z_mean.cpu().numpy()

    def add_feedback(self, features: np.ndarray, is_false_positive: bool):
        """Добавление обратной связи"""
        if is_false_positive:
            if self.recon_threshold:
                self.recon_threshold *= 1.05
                logger.debug(f"Adjusted threshold to {self.recon_threshold:.6f}")

    def get_stats(self) -> Dict:
        """Получить статистику"""
        return {
            'model': {
                'is_trained': self.is_trained,
                'device': str(self.device),
                'parameters': sum(p.numel() for p in self.model.parameters()) if self.model else 0,
                'latent_dim': self.config.latent_dim
            },
            'thresholds': {
                'reconstruction': self.recon_threshold,
                'latent_radius': self.normal_radius
            },
            'inference': {
                'total_predictions': self.stats['total_predictions'],
                'anomalies_detected': self.stats['anomalies_detected'],
                'avg_inference_time_ms': round(self.stats['avg_inference_time_ms'], 2),
                'cache_size': len(self._prediction_cache)
            },
            'training': {
                'epochs': self.stats['training_epochs'],
                'best_loss': self.stats['best_loss'],
                'normal_buffer_size': len(self.normal_buffer),
                'anomaly_buffer_size': len(self.anomaly_buffer)
            }
        }



class ShardContrastiveVAEIntegration:
    """Интеграционный слой для SHARD Enterprise"""

    def __init__(self, config=None):
        self.config = ContrastiveVAEConfig()
        if config is not None:
            if isinstance(config, dict):
                for key, value in config.items():
                    if hasattr(self.config, key):
                        setattr(self.config, key, value)
            elif hasattr(config, '__dict__'):
                for key, value in config.__dict__.items():
                    if hasattr(self.config, key):
                        setattr(self.config, key, value)

        self.engine = ContrastiveVAEEngine(self.config)
        self._running = False

    def start(self):
        """Запуск интеграции"""
        self._running = True
        self.engine.start()
        logger.info("🚀 ShardContrastiveVAEIntegration started")

    def stop(self):
        """Остановка интеграции"""
        self._running = False
        self.engine.stop()
        logger.info("🛑 ShardContrastiveVAEIntegration stopped")

    def predict_anomaly(self, features: List[float]) -> Dict:
        """Предсказание аномалии"""
        features_arr = np.array(features)
        return self.engine.predict(features_arr)

    def get_latent_vector(self, features: List[float]) -> List[float]:
        """Получение латентного вектора"""
        features_arr = np.array(features)
        latent = self.engine.encode(features_arr)
        return latent[0].tolist() if len(latent) > 0 else []

    def train_on_data(self, normal_data: List[List[float]],
                      anomaly_data: List[List[float]] = None) -> Dict:
        """Обучение на данных"""
        X_normal = np.array(normal_data)
        X_anomaly = np.array(anomaly_data) if anomaly_data else None
        return self.engine.train(X_normal, X_anomaly)

    def add_feedback(self, features: List[float], is_false_positive: bool):
        """Добавление обратной связи"""
        features_arr = np.array(features)
        self.engine.add_feedback(features_arr, is_false_positive)

    def get_stats(self) -> Dict:
        """Получить статистику"""
        return self.engine.get_stats()



def test_contrastive_vae():
    """Тестирование Contrastive VAE"""
    print("=" * 60)
    print("🧪 TESTING CONTRASTIVE VAE")
    print("=" * 60)

    if not TORCH_AVAILABLE:
        print("❌ PyTorch not available")
        return

    config = ContrastiveVAEConfig()
    config.input_dim = 156
    config.epochs = 30
    config.latent_dim = 32

    engine = ContrastiveVAEEngine(config)
    engine.start()

    print("\n📊 Generating synthetic data...")

    np.random.seed(42)
    normal_data = np.random.randn(1000, config.input_dim) * 0.1
    anomaly_data = np.random.randn(200, config.input_dim) * 1.5

    print("\n🔄 Training model...")
    history = engine.train(normal_data, anomaly_data, verbose=1)

    print("\n🔮 Testing predictions...")

    normal_test = np.random.randn(20, config.input_dim) * 0.1
    normal_scores = []

    for i in range(20):
        result = engine.predict(normal_test[i])
        normal_scores.append(result['score'])

    anomaly_test = np.random.randn(20, config.input_dim) * 2.0
    anomaly_scores = []

    for i in range(20):
        result = engine.predict(anomaly_test[i])
        anomaly_scores.append(result['score'])

        if result['is_anomaly']:
            print(f"   ⚠️ Anomaly detected: score={result['score']:.3f}, "
                  f"severity={result['severity']}")

    print(f"\n📊 Summary:")
    print(f"   Normal data - mean score: {np.mean(normal_scores):.4f}")
    print(f"   Anomaly data - mean score: {np.mean(anomaly_scores):.4f}")
    print(f"   Separation: {np.mean(anomaly_scores) - np.mean(normal_scores):.4f}")

    print("\n📊 Statistics:")
    stats = engine.get_stats()
    print(f"   Trained: {stats['model']['is_trained']}")
    print(f"   Parameters: {stats['model']['parameters']:,}")
    print(f"   Threshold: {stats['thresholds']['reconstruction']:.6f}")
    print(f"   Predictions: {stats['inference']['total_predictions']}")
    print(f"   Avg inference: {stats['inference']['avg_inference_time_ms']:.2f} ms")

    engine.stop()

    print("\n" + "=" * 60)
    print("✅ TESTING COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    test_contrastive_vae()