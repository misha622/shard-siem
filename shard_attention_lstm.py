#!/usr/bin/env python3

"""
SHARD Attention LSTM Module
"""

from __future__ import annotations
import os
import json
import time
import threading
import warnings
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
from collections import deque, defaultdict
from dataclasses import dataclass, field

import numpy as np

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
warnings.filterwarnings('ignore')


TF_AVAILABLE = False
Model = None
layers = None
Adam = None

try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers
    from tensorflow.keras import Model
    from tensorflow.keras.optimizers import Adam
    from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau, ModelCheckpoint

    TF_AVAILABLE = True
except ImportError:
    print("⚠️ TensorFlow не установлен. Attention LSTM недоступен.")



@dataclass
class AttentionLSTMConfig:
    sequence_length: int = 100
    input_dim: int = 156
    lstm_units_1: int = 128
    lstm_units_2: int = 64
    num_attention_heads: int = 8
    attention_key_dim: int = 64
    latent_dim: int = 32
    dropout_rate: float = 0.2
    learning_rate: float = 0.001
    batch_size: int = 32
    epochs: int = 100
    early_stopping_patience: int = 15
    reduce_lr_patience: int = 7
    threshold_percentile: float = 95.0
    model_dir: str = './models/attention_lstm/'



if TF_AVAILABLE:
    class AttentionLSTM(Model):
        """Attention LSTM для анализа последовательностей"""

        def __init__(self, config: AttentionLSTMConfig):
            super().__init__(name='AttentionLSTM')
            self.config = config

            self.lstm1 = layers.LSTM(config.lstm_units_1, return_sequences=True, name='encoder_lstm_1')
            self.batch_norm1 = layers.BatchNormalization(name='encoder_bn_1')
            self.dropout1 = layers.Dropout(config.dropout_rate, name='encoder_dropout_1')

            self.lstm2 = layers.LSTM(config.lstm_units_2, return_sequences=True, name='encoder_lstm_2')
            self.batch_norm2 = layers.BatchNormalization(name='encoder_bn_2')

            self.attention = layers.MultiHeadAttention(
                num_heads=config.num_attention_heads,
                key_dim=config.attention_key_dim,
                dropout=config.dropout_rate,
                name='multi_head_attention'
            )
            self.attention_bn = layers.BatchNormalization(name='attention_bn')

            self.global_pool = layers.GlobalAveragePooling1D(name='global_pool')
            self.latent = layers.Dense(config.latent_dim, activation='relu', name='latent')

            self.repeat = layers.RepeatVector(config.sequence_length, name='repeat')
            self.lstm3 = layers.LSTM(config.lstm_units_2, return_sequences=True, name='decoder_lstm_1')
            self.batch_norm3 = layers.BatchNormalization(name='decoder_bn_1')
            self.dropout2 = layers.Dropout(config.dropout_rate, name='decoder_dropout_1')

            self.lstm4 = layers.LSTM(config.lstm_units_1, return_sequences=True, name='decoder_lstm_2')
            self.batch_norm4 = layers.BatchNormalization(name='decoder_bn_2')

            self.output_layer = layers.TimeDistributed(
                layers.Dense(config.input_dim, activation='linear'),
                name='output'
            )

            self.anomaly_classifier = layers.Dense(1, activation='sigmoid', name='anomaly_score')

        def call(self, inputs, training=False):
            x = self.lstm1(inputs)
            x = self.batch_norm1(x, training=training)
            x = self.dropout1(x, training=training)

            x = self.lstm2(x)
            x = self.batch_norm2(x, training=training)

            attention_output = self.attention(x, x, training=training)
            x = layers.Add()([x, attention_output])
            x = self.attention_bn(x, training=training)

            x = self.global_pool(x)
            latent = self.latent(x)

            x = self.repeat(latent)
            x = self.lstm3(x)
            x = self.batch_norm3(x, training=training)
            x = self.dropout2(x, training=training)

            x = self.lstm4(x)
            x = self.batch_norm4(x, training=training)

            reconstruction = self.output_layer(x)
            anomaly_score = self.anomaly_classifier(latent)

            return {
                'reconstruction': reconstruction,
                'latent': latent,
                'anomaly_score': anomaly_score
            }

        def get_encoder(self):
            encoder_input = self.input
            x = self.lstm1(encoder_input)
            x = self.batch_norm1(x)
            x = self.lstm2(x)
            x = self.batch_norm2(x)
            attention_output = self.attention(x, x)
            x = layers.Add()([x, attention_output])
            x = self.attention_bn(x)
            x = self.global_pool(x)
            latent = self.latent(x)
            return Model(encoder_input, latent, name='Encoder')
else:
    class AttentionLSTM:
        def __init__(self, *args, **kwargs):
            pass



class AttentionLSTMEngine:
    """Движок для Attention LSTM"""

    def __init__(self, config: AttentionLSTMConfig = None):
        self.config = config or AttentionLSTMConfig()
        self.model = None
        self.encoder = None
        self.threshold = None
        self.is_trained = False

        self.normal_buffer: deque = deque(maxlen=10000)
        self.sequence_buffer: Dict[str, deque] = defaultdict(lambda: deque(maxlen=self.config.sequence_length))

        self._lock = threading.RLock()
        self._running = False

        if TF_AVAILABLE:
            self._build_model()
            self._load_or_init()

    def _ensure_directories(self):
        Path(self.config.model_dir).mkdir(parents=True, exist_ok=True)

    def _build_model(self):
        if not TF_AVAILABLE:
            return
        self.model = AttentionLSTM(self.config)
        dummy_input = tf.random.normal((1, self.config.sequence_length, self.config.input_dim))
        _ = self.model(dummy_input)
        self.model.compile(
            optimizer=Adam(learning_rate=self.config.learning_rate),
            loss={'reconstruction': 'mse', 'anomaly_score': 'binary_crossentropy'},
            loss_weights={'reconstruction': 1.0, 'anomaly_score': 0.5}
        )
        self.encoder = self.model.get_encoder()
        print(f"✅ Attention LSTM построен")

    def _load_or_init(self):
        model_path = Path(self.config.model_dir) / 'attention_lstm.keras'
        if model_path.exists() and TF_AVAILABLE:
            try:
                self.model = keras.models.load_model(model_path)
                self.encoder = self.model.get_encoder()
                self.is_trained = True
                print(f"✅ Attention LSTM загружен")
            except:
                pass

    def add_sequence(self, device_id: str, features: List[float]) -> Optional[np.ndarray]:
        with self._lock:
            self.sequence_buffer[device_id].append(features)
            if len(self.sequence_buffer[device_id]) >= self.config.sequence_length:
                sequence = list(self.sequence_buffer[device_id])[-self.config.sequence_length:]
                return np.array(sequence)
        return None

    def predict(self, sequence: np.ndarray) -> Dict:
        if not self.is_trained or self.model is None:
            return {'score': 0.5, 'mse': 0.0, 'is_anomaly': False, 'confidence': 0.0}

        if sequence.ndim == 2:
            sequence = np.expand_dims(sequence, axis=0)

        result = self.model.predict(sequence, verbose=0)
        reconstruction = result['reconstruction']
        mse = np.mean((sequence - reconstruction) ** 2)

        is_anomaly = mse > self.threshold if self.threshold else False
        score = min(1.0, mse / (self.threshold * 2)) if self.threshold else 0.5

        return {
            'score': float(score),
            'mse': float(mse),
            'is_anomaly': bool(is_anomaly),
            'confidence': float(abs(score - 0.5) * 2)
        }

    def start(self):
        self._running = True

    def stop(self):
        self._running = False

    def get_stats(self) -> Dict:
        return {
            'is_trained': self.is_trained,
            'threshold': self.threshold,
            'buffer_normal': len(self.normal_buffer),
            'active_devices': len(self.sequence_buffer)
        }



class ShardAttentionLSTMIntegration:
    """Интеграция с SHARD"""

    def __init__(self, config: Dict = None):
        self.config = AttentionLSTMConfig()
        self.engine = AttentionLSTMEngine(self.config)
        self._running = False

    def start(self):
        self._running = True
        self.engine.start()
        print("🚀 Attention LSTM integration started")

    def stop(self):
        self._running = False
        self.engine.stop()
        print("🛑 Attention LSTM integration stopped")

    def process_packet_features(self, device_id: str, features: List[float]) -> Optional[Dict]:
        sequence = self.engine.add_sequence(device_id, features)
        if sequence is not None:
            return self.engine.predict(sequence)
        return None

    def get_stats(self) -> Dict:
        return self.engine.get_stats()