#!/usr/bin/env python3
"""SHARD MachineLearningEngine Module - Refactored Version"""
import os
import time
import threading
import json
import uuid
import sqlite3
from typing import Dict, List, Optional, Any, Tuple, Set
from collections import defaultdict, deque
from pathlib import Path
from dataclasses import dataclass, field
from abc import ABC, abstractmethod

import numpy as np

from core.base import BaseModule, ConfigManager, EventBus, LoggingService

# Conditional imports with proper fallback
try:
    import joblib

    HAS_JOBLIB = True
except ImportError:
    HAS_JOBLIB = False

try:
    from modules.ml_models import SelfSupervisedEncoder, ThreatGNN

    HAS_ML_MODELS = True
except ImportError:
    SelfSupervisedEncoder = None
    ThreatGNN = None
    HAS_ML_MODELS = False

try:
    from core.constants import shap_module, xgboost_module, sklearn_ensemble
except ImportError:
    shap_module = None
    xgboost_module = None
    sklearn_ensemble = None


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class PredictionResult:
    """Структурированный результат предсказания"""
    is_attack: bool = False
    score: float = 0.0
    confidence: float = 0.0
    attack_type: str = 'Normal'
    timestamp: float = field(default_factory=time.time)

    # Детекторы
    ml_detected: bool = False
    dl_detected: bool = False
    gnn_detected: bool = False
    vae_detected: bool = False
    adaptive_detected: bool = False

    # Детали
    details: Dict[str, Any] = field(default_factory=dict)
    explanations: List[Dict] = field(default_factory=list)
    recommended_action: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            'is_attack': self.is_attack,
            'score': self.score,
            'confidence': self.confidence,
            'attack_type': self.attack_type,
            'timestamp': self.timestamp,
            'ml_detected': self.ml_detected,
            'dl_detected': self.dl_detected,
            'gnn_detected': self.gnn_detected,
            'vae_detected': self.vae_detected,
            'adaptive_detected': self.adaptive_detected,
            'details': self.details,
            'explanations': self.explanations,
            'recommended_action': self.recommended_action
        }


@dataclass
class ModelConfig:
    """Конфигурация ML модели"""
    use_xgboost: bool = True
    use_deep_learning: bool = True
    explain_with_shap: bool = True
    online_learning: bool = True
    retrain_interval: int = 300
    retrain_min_samples: int = 100
    confidence_threshold: float = 0.7
    anomaly_threshold: float = -0.15
    model_path: Path = Path('./models/')
    autosave_interval: int = 300
    buffer_maxlen: int = 5000
    sequence_maxlen: int = 100

    # Параметры Isolation Forest
    n_estimators: int = 100
    contamination: float = 0.1

    # Коэффициенты для ненадежной модели
    unreliable_threshold_multiplier: float = 1.5
    unreliable_confidence_multiplier: float = 0.5


# ============================================================================
# Base Model Interface (Strategy Pattern)
# ============================================================================

class BaseDetector(ABC):
    """Базовый интерфейс для всех детекторов"""

    @abstractmethod
    def predict(self, features: np.ndarray) -> Tuple[float, float]:
        """
        Возвращает (score, confidence)
        score: 0.0 (normal) до 1.0 (attack)
        confidence: 0.0 до 1.0
        """
        pass

    @abstractmethod
    def is_fitted(self) -> bool:
        """Проверка, что модель обучена"""
        pass

    @abstractmethod
    def save(self, path: Path) -> bool:
        """Сохранение модели"""
        pass

    @abstractmethod
    def load(self, path: Path) -> bool:
        """Загрузка модели"""
        pass

    @abstractmethod
    def partial_fit(self, X: np.ndarray, y: Optional[np.ndarray] = None) -> bool:
        """Дообучение модели"""
        pass


class IsolationForestDetector(BaseDetector):
    """Isolation Forest детектор аномалий"""

    def __init__(self, config: ModelConfig, logger: LoggingService):
        self.config = config
        self.logger = logger
        self.model = None
        self._is_reliable = False
        self._samples_trained = 0

        self._initialize()

    def _initialize(self):
        """Инициализация модели"""
        if sklearn_ensemble is None:
            self.logger.error("sklearn не доступен, Isolation Forest не будет работать")
            return

        from sklearn.ensemble import IsolationForest

        self.model = IsolationForest(
            n_estimators=self.config.n_estimators,
            contamination=self.config.contamination,
            random_state=42,
            n_jobs=-1
        )

    def predict(self, features: np.ndarray) -> Tuple[float, float]:
        if self.model is None:
            return 0.5, 0.1

        try:
            raw_score = float(self.model.score_samples(features)[0])
            # Нормализация в [0, 1], где 1 = аномалия
            normalized_score = np.clip(1.0 - (raw_score + 0.5), 0.0, 1.0)

            threshold = self.config.anomaly_threshold
            if not self._is_reliable:
                threshold *= self.config.unreliable_threshold_multiplier

            distance = abs(raw_score - threshold)
            confidence = min(0.99, distance / 0.5)

            if not self._is_reliable:
                confidence *= self.config.unreliable_confidence_multiplier

            return normalized_score, confidence
        except Exception as e:
            self.logger.error(f"Isolation Forest prediction error: {e}")
            return 0.5, 0.1

    def is_fitted(self) -> bool:
        return self.model is not None and hasattr(self.model, 'estimators_')

    def save(self, path: Path) -> bool:
        if not HAS_JOBLIB or self.model is None:
            return False
        try:
            joblib.dump(self.model, path)
            return True
        except Exception as e:
            self.logger.error(f"Failed to save IF model: {e}")
            return False

    def load(self, path: Path) -> bool:
        if not HAS_JOBLIB or not path.exists():
            return False
        try:
            self.model = joblib.load(path)
            self._is_reliable = True
            self._samples_trained = 500  # Загруженная модель считается обученной
            self.logger.info("Isolation Forest model loaded successfully")
            return True
        except Exception as e:
            self.logger.error(f"Failed to load IF model: {e}")
            return False

    def partial_fit(self, X: np.ndarray, y: Optional[np.ndarray] = None) -> bool:
        if self.model is None or len(X) < 50:
            return False

        try:
            # Увеличиваем количество деревьев для улучшения модели
            if hasattr(self.model, 'estimators_'):
                current_trees = len(self.model.estimators_)
                self.model.set_params(n_estimators=min(current_trees + 10, self.config.n_estimators * 3))

            self.model.fit(X)
            self._samples_trained += len(X)

            if self._samples_trained >= 500:
                self._is_reliable = True
                self.logger.info("Isolation Forest marked as reliable")

            return True
        except Exception as e:
            self.logger.error(f"IF partial_fit error: {e}")
            return False

    @property
    def is_reliable(self) -> bool:
        return self._is_reliable

    @property
    def samples_trained(self) -> int:
        return self._samples_trained


class XGBoostDetector(BaseDetector):
    """XGBoost классификатор атак"""

    ATTACK_MAP = {
        1: 'DoS', 2: 'DDoS', 3: 'Brute Force',
        4: 'Web Attack', 5: 'Botnet', 8: 'Port Scan'
    }

    def __init__(self, config: ModelConfig, logger: LoggingService, num_features: int):
        self.config = config
        self.logger = logger
        self.model = None
        self._num_features = num_features

        if config.use_xgboost and xgboost_module is not None:
            self._initialize()

    def _initialize(self):
        """Инициализация XGBoost модели"""
        if xgboost_module is None:
            self.logger.error("XGBoost module not available")
            return

        self.model = xgboost_module.XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            objective='multi:softprob',
            num_class=10,
            random_state=42,
            verbosity=0
        )

    def predict(self, features: np.ndarray) -> Tuple[float, float]:
        if self.model is None or not self.is_fitted():
            return 0.0, 0.0

        try:
            proba = self.model.predict_proba(features)[0]
            attack_id = int(np.argmax(proba))
            confidence = float(proba[attack_id])

            if attack_id == 0:  # Normal class
                return 0.0, confidence

            return confidence, confidence
        except Exception as e:
            self.logger.error(f"XGBoost prediction error: {e}")
            return 0.0, 0.0

    def predict_attack_type(self, features: np.ndarray) -> Tuple[str, float]:
        """Определение типа атаки"""
        if self.model is None or not self.is_fitted():
            return 'Unknown', 0.0

        try:
            proba = self.model.predict_proba(features)[0]
            attack_id = int(np.argmax(proba))
            confidence = float(proba[attack_id])
            attack_type = self.ATTACK_MAP.get(attack_id, 'Unknown')
            return attack_type, confidence
        except Exception as e:
            self.logger.error(f"XGBoost attack type error: {e}")
            return 'Unknown', 0.0

    def is_fitted(self) -> bool:
        if self.model is None:
            return False
        try:
            self.model.get_booster()
            return True
        except:
            return False

    def save(self, path: Path) -> bool:
        if not HAS_JOBLIB or self.model is None:
            return False
        try:
            joblib.dump(self.model, path)
            return True
        except Exception as e:
            self.logger.error(f"Failed to save XGB model: {e}")
            return False

    def load(self, path: Path) -> bool:
        if not HAS_JOBLIB or not path.exists():
            return False
        try:
            self.model = joblib.load(path)
            self.logger.info("XGBoost model loaded successfully")
            return True
        except Exception as e:
            self.logger.error(f"Failed to load XGB model: {e}")
            return False

    def partial_fit(self, X: np.ndarray, y: np.ndarray) -> bool:
        if self.model is None or len(X) < 10:
            return False

        try:
            if self.is_fitted():
                # Warm start with previous model
                self.model.fit(X, y, xgb_model=self.model.get_booster())
                self.logger.info("XGBoost updated (warm start)")
            else:
                self.model.fit(X, y)
                self.logger.info("XGBoost initialized")
            return True
        except Exception as e:
            self.logger.error(f"XGBoost partial_fit error: {e}")
            # Fallback: train from scratch
            try:
                self.model.fit(X, y)
                self.logger.info("XGBoost trained from scratch (fallback)")
                return True
            except Exception as e2:
                self.logger.error(f"XGBoost fallback training failed: {e2}")
                return False


class StandardScalerWrapper:
    """Обертка над StandardScaler с проверкой состояния"""

    def __init__(self):
        self.scaler = None

    def fit(self, X: np.ndarray) -> bool:
        if sklearn_ensemble is None:
            return False
        from sklearn.preprocessing import StandardScaler
        self.scaler = StandardScaler()
        self.scaler.fit(X)
        return True

    def transform(self, X: np.ndarray) -> np.ndarray:
        if not self.is_fitted():
            return X
        try:
            return self.scaler.transform(X)
        except Exception:
            return X

    def fit_transform(self, X: np.ndarray) -> np.ndarray:
        if not self.fit(X):
            return X
        return self.transform(X)

    def is_fitted(self) -> bool:
        return (self.scaler is not None and
                hasattr(self.scaler, 'mean_') and
                hasattr(self.scaler, 'scale_'))

    def save(self, path: Path) -> bool:
        if not HAS_JOBLIB or self.scaler is None:
            return False
        try:
            joblib.dump(self.scaler, path)
            return True
        except Exception:
            return False

    def load(self, path: Path) -> bool:
        if not HAS_JOBLIB or not path.exists():
            return False
        try:
            self.scaler = joblib.load(path)
            return True
        except Exception:
            return False


# ============================================================================
# SHAP Explainer
# ============================================================================

class SHAPExplainer:
    """SHAP объяснитель с поддержкой разных моделей"""

    def __init__(self, config: ModelConfig, logger: LoggingService):
        self.config = config
        self.logger = logger
        self.explainer = None
        self.feature_names: List[str] = []
        self._background_ready = False

    def initialize(self, model, background_data: np.ndarray, feature_names: List[str]) -> bool:
        """Инициализация SHAP объяснителя"""
        if not self.config.explain_with_shap or shap_module is None:
            return False

        self.feature_names = feature_names

        try:
            import shap

            if len(background_data) > 50:
                background_data = background_data[:50]

            # Проверяем тип модели для выбора объяснителя
            if xgboost_module and isinstance(model, xgboost_module.XGBClassifier):
                self.explainer = shap.TreeExplainer(model)
                self.logger.info("SHAP TreeExplainer initialized")
            else:
                # KernelExplainer для других моделей
                def predict_fn(x):
                    scores = model.score_samples(x)
                    return (scores + 0.5) / 0.5

                self.explainer = shap.KernelExplainer(predict_fn, background_data)
                self.logger.info("SHAP KernelExplainer initialized")

            self._background_ready = True
            return True
        except Exception as e:
            self.logger.error(f"SHAP initialization failed: {e}")
            return False

    def explain(self, features: np.ndarray, class_idx: Optional[int] = None) -> List[Dict]:
        """Объяснение предсказания"""
        if not self._background_ready or self.explainer is None:
            return []

        try:
            shap_values = self.explainer.shap_values(features)

            # Handle multi-class SHAP values
            if isinstance(shap_values, list):
                if class_idx is not None and class_idx < len(shap_values):
                    shap_vals = shap_values[class_idx][0]
                else:
                    shap_vals = shap_values[0][0]
            else:
                shap_vals = shap_values[0]

            explanations = []
            for idx, shap_val in enumerate(shap_vals):
                if idx < len(self.feature_names) and abs(shap_val) > 0.01:
                    explanations.append({
                        'feature': self.feature_names[idx],
                        'shap_value': float(shap_val),
                        'impact': 'positive' if shap_val > 0 else 'negative',
                        'importance': abs(float(shap_val))
                    })

            explanations.sort(key=lambda x: x['importance'], reverse=True)
            return explanations[:10]
        except Exception as e:
            self.logger.error(f"SHAP explanation error: {e}")
            return []


# ============================================================================
# Data Buffer Manager
# ============================================================================

class DataBuffer:
    """Потокобезопасный буфер для обучающих данных"""

    def __init__(self, maxlen: int = 5000):
        self._normal_buffer: deque = deque(maxlen=maxlen)
        self._attack_buffer: deque = deque(maxlen=maxlen)
        self._lock = threading.RLock()
        self._backup_normal: List = []
        self._backup_attack: List = []

    def add_normal(self, features: List[float]):
        with self._lock:
            self._normal_buffer.append(features)

    def add_attack(self, features: List[float], attack_type: str):
        with self._lock:
            self._attack_buffer.append((features, attack_type))

    def get_and_clear(self) -> Tuple[List, List]:
        """Атомарно получить и очистить буферы (double-buffer swap)"""
        with self._lock:
            # Атомарный swap: новые буферы для продолжения сбора, старые — на обучение
            normal = list(self._normal_buffer)
            attacks = list(self._attack_buffer)
            
            # Сохраняем как бэкап (для rollback при ошибке обучения)
            self._backup_normal = normal.copy()
            self._backup_attack = attacks.copy()
            
            # Очищаем буферы — новые данные будут собираться с чистого листа
            self._normal_buffer.clear()
            self._attack_buffer.clear()

            return normal, attacks

    def commit_clear(self):
        """Подтвердить очистку после успешного обучения"""
        with self._lock:
            # Данные уже очищены в get_and_clear, просто сбрасываем бэкап
            self._backup_normal.clear()
            self._backup_attack.clear()

    def rollback(self):
        """Восстановить данные при ошибке обучения"""
        with self._lock:
            # Восстанавливаем данные из бэкапа
            self._normal_buffer.extendleft(reversed(self._backup_normal))
            self._attack_buffer.extendleft(reversed(self._backup_attack))
            self._backup_normal.clear()
            self._backup_attack.clear()

    @property
    def total_samples(self) -> int:
        with self._lock:
            return len(self._normal_buffer) + len(self._attack_buffer)

    @property
    def stats(self) -> Dict:
        with self._lock:
            return {
                'normal_count': len(self._normal_buffer),
                'attack_count': len(self._attack_buffer),
                'total': self.total_samples
            }


# ============================================================================
# Model Persistence Manager
# ============================================================================

class ModelPersistence:
    """Управление сохранением и загрузкой моделей"""

    def __init__(self, base_path: Path, logger: LoggingService):
        self.base_path = base_path
        self.logger = logger
        self.base_path.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def save_atomic(self, obj: Any, filename: str) -> bool:
        """Атомарное сохранение с временным файлом"""
        if not HAS_JOBLIB:
            return False

        with self._lock:
            temp_path = self.base_path / f"{filename}.tmp"
            final_path = self.base_path / filename

            try:
                joblib.dump(obj, temp_path)
                os.replace(str(temp_path), str(final_path))
                return True
            except Exception as e:
                self.logger.error(f"Failed to save {filename}: {e}")
                if temp_path.exists():
                    temp_path.unlink()
                return False

    def save_all(self, models: Dict[str, Any]) -> bool:
        """Атомарное сохранение всех моделей с бэкапом"""
        with self._lock:
            # Создаем бэкап текущих файлов
            backup_dir = self.base_path / 'backup'
            backup_dir.mkdir(exist_ok=True)

            timestamp = int(time.time())
            temp_files = []

            try:
                # Сохраняем во временные файлы
                for name, obj in models.items():
                    if obj is not None:
                        temp_path = self.base_path / f"{name}.pkl.tmp"
                        joblib.dump(obj, temp_path)
                        temp_files.append((temp_path, self.base_path / f"{name}.pkl"))

                # Бэкапим старые версии
                for _, final_path in temp_files:
                    if final_path.exists():
                        backup_path = backup_dir / f"{final_path.name}.{timestamp}"
                        final_path.rename(backup_path)

                # Перемещаем новые версии
                for temp_path, final_path in temp_files:
                    os.replace(str(temp_path), str(final_path))

                self.logger.debug(f"All models saved successfully (backup: {timestamp})")
                return True

            except Exception as e:
                self.logger.error(f"Failed to save models: {e}")
                # Очищаем временные файлы
                for temp_path, _ in temp_files:
                    if temp_path.exists():
                        temp_path.unlink()
                return False

    def load(self, filename: str) -> Optional[Any]:
        """Загрузка модели"""
        if not HAS_JOBLIB:
            return None

        path = self.base_path / filename
        if not path.exists():
            return None

        try:
            return joblib.load(path)
        except Exception as e:
            self.logger.warning(f"Failed to load {filename}: {e}")
            return None


# ============================================================================
# Main Machine Learning Engine
# ============================================================================

class MachineLearningEngine(BaseModule):
    """
    ML движок с модульной архитектурой для обнаружения атак.

    Поддерживает:
    - Isolation Forest (обнаружение аномалий)
    - XGBoost (классификация атак)
    - Deep Learning модели
    - SHAP объяснения
    - Онлайн-дообучение
    - Интеграцию с GNN, VAE, RL
    """

    # Константы для маппинга атак
    ATTACK_TO_ID = {
        'Normal': 0, 'DoS': 1, 'DDoS': 2, 'Brute Force': 3,
        'Web Attack': 4, 'Botnet': 5, 'Port Scan': 8
    }

    ID_TO_ATTACK = {v: k for k, v in ATTACK_TO_ID.items()}

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("ML", config, event_bus, logger)

        # Конфигурация
        self.ml_config = self._load_config(config)

        # Persistence
        self.persistence = ModelPersistence(self.ml_config.model_path, logger)

        # Инициализация компонентов
        self._init_features()
        self._init_scaler()
        self._init_detectors()

        # Data buffer
        self.buffer = DataBuffer(maxlen=self.ml_config.buffer_maxlen)

        # Sequence buffer for temporal analysis
        self.sequence_buffer: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=self.ml_config.sequence_maxlen)
        )

        # SHAP
        self.shap = SHAPExplainer(self.ml_config, logger)
        self._shap_background: List[List[float]] = []

        # Deep Learning
        self.dl_engine = None
        if self.ml_config.use_deep_learning:
            self._init_deep_learning()

        # SSL модель
        self.ssl_model = SelfSupervisedEncoder(input_dim=156) if SelfSupervisedEncoder else None

        # Внешние движки (внедряются через setter)
        self.temporal_gnn = None
        self.contrastive_vae = None
        self.rl_defense = None
        self.adaptive_engine = None

        # Состояние
        self._lock = threading.RLock()
        self._autosave_lock = threading.RLock()
        self._models_dirty = False
        self._last_save = time.time()
        self._save_thread: Optional[threading.Thread] = None
        self._gnn_packet_counter = 0

        # Контекст для GNN
        self._last_dst_ip = "unknown"
        self._last_dst_port = 0

        # DB connection pool reference
        self.siem_storage = None

        # ML Drift Monitor
        self.drift_monitor = MLDriftMonitor()

        # Загружаем сохраненные модели
        self._load_saved_models()

        # Подписываемся на события
        self.event_bus.subscribe('packet.features', self.on_features)

        self.logger.info(
            f"ML Engine initialized (XGB: {self.ml_config.use_xgboost}, "
            f"DL: {self.ml_config.use_deep_learning}, SHAP: {self.ml_config.explain_with_shap})"
        )

    # ========================================================================
    # Initialization Methods
    # ========================================================================

    def _load_config(self, config: ConfigManager) -> ModelConfig:
        """Загрузка конфигурации из ConfigManager"""
        return ModelConfig(
            use_xgboost='xgboost' in config.get('ml.ensemble', []),
            use_deep_learning=config.get('ml.use_deep_learning', True),
            explain_with_shap=config.get('ml.explain_with_shap', True),
            online_learning=config.get('ml.online_learning', True),
            retrain_interval=config.get('ml.retrain_interval', 300),
            retrain_min_samples=config.get('ml.retrain_min_samples', 100),
            confidence_threshold=config.get('ml.confidence_threshold', 0.7),
            anomaly_threshold=config.get('ml.anomaly_threshold', -0.15),
            model_path=Path(config.get('ml.model_path', './models/')),
            autosave_interval=config.get('ml.autosave_interval', 300)
        )

    def _init_features(self):
        """Инициализация списка признаков"""
        self.features = [f'payload_byte_{i + 1}' for i in range(150)]
        self.features.extend([
            'payload_entropy', 'packet_size', 'protocol',
            'ttl', 'src_port', 'dst_port'
        ])

    def _init_scaler(self):
        """Инициализация scaler"""
        self.scaler = StandardScalerWrapper()

    def _init_detectors(self):
        """Инициализация детекторов"""
        self.if_detector = IsolationForestDetector(self.ml_config, self.logger)

        if self.ml_config.use_xgboost:
            self.xgb_detector = XGBoostDetector(
                self.ml_config, self.logger, len(self.features)
            )
        else:
            self.xgb_detector = None

    def _init_deep_learning(self):
        """Инициализация Deep Learning Engine"""
        try:
            from shard_dl_models import DeepLearningEngine
            self.dl_engine = DeepLearningEngine()
            self.logger.info("Deep Learning Engine initialized")
        except ImportError:
            self.logger.warning("shard_dl_models not found, DL disabled")
            self.ml_config.use_deep_learning = False

    def _load_saved_models(self):
        """Загрузка сохраненных моделей с диска"""
        # Scaler
        scaler_obj = self.persistence.load('shard_enterprise_scaler.pkl')
        if scaler_obj:
            self.scaler.scaler = scaler_obj
            self.logger.info("Scaler loaded")

        # Features
        features_obj = self.persistence.load('shard_enterprise_features.pkl')
        if features_obj and isinstance(features_obj, list):
            self.features = features_obj
            self.logger.info(f"Features loaded ({len(self.features)} features)")

        # Isolation Forest
        self.if_detector.load(self.ml_config.model_path / 'shard_enterprise_model_if.pkl')

        # XGBoost
        if self.xgb_detector:
            self.xgb_detector.load(self.ml_config.model_path / 'shard_enterprise_model_xgb.pkl')

    # ========================================================================
    # Lifecycle Methods
    # ========================================================================

    def start(self) -> None:
        """Запуск ML движка"""
        self.running = True

        # Запуск потоков
        if self.ml_config.online_learning:
            threading.Thread(
                target=self._retrain_loop,
                daemon=True,
                name="ML-Retrain"
            ).start()

        threading.Thread(
            target=self._load_history_async,
            daemon=True,
            name="ML-LoadHistory"
        ).start()

        self._save_thread = threading.Thread(
            target=self._autosave_loop,
            daemon=True,
            name="ML-Autosave"
        )
        self._save_thread.start()

        if self.ml_config.use_deep_learning and self.dl_engine:
            self.dl_engine.start()

        # Инициализация SHAP с фоновыми данными
        if self.ml_config.explain_with_shap and len(self._shap_background) >= 50:
            threading.Thread(
                target=self._init_shap_async,
                daemon=True,
                name="ML-SHAP-Init"
            ).start()

        self.logger.info("ML Engine started")

    def stop(self) -> None:
        """Остановка ML движка"""
        self.running = False

        # Сохраняем модели перед остановкой
        self._save_all_models()

        if self._save_thread and self._save_thread.is_alive():
            self._save_thread.join(timeout=5)

        if self.ml_config.use_deep_learning and self.dl_engine:
            self.dl_engine.stop()

        self.logger.info("ML Engine stopped, models saved")

    # ========================================================================
    # External Engine Setters (Dependency Injection)
    # ========================================================================

    def set_temporal_gnn(self, gnn):
        """Внедрение Temporal GNN движка"""
        self.temporal_gnn = gnn
        self.logger.info("Temporal GNN engine injected")

    def set_contrastive_vae(self, vae):
        """Внедрение Contrastive VAE движка"""
        self.contrastive_vae = vae
        self.logger.info("Contrastive VAE engine injected")

    def set_rl_defense(self, rl):
        """Внедрение RL Defense движка"""
        self.rl_defense = rl
        self.logger.info("RL Defense engine injected")

    def set_adaptive_engine(self, adaptive):
        """Внедрение Adaptive Learning движка"""
        self.adaptive_engine = adaptive
        self.logger.info("Adaptive Learning engine injected")

    # ========================================================================
    # Event Handlers
    # ========================================================================

    def on_features(self, data: Dict) -> None:
        """Обработка извлеченных признаков пакета"""
        features = data.get('features')
        if not features:
            return

        src_ip = data.get('src_ip', 'unknown')
        dst_ip = data.get('dst_ip', 'unknown')
        dst_port = data.get('dst_port', 0)

        # Сохраняем контекст для GNN
        self._last_dst_ip = dst_ip
        self._last_dst_port = dst_port

        # Предсказание
        result = self._predict(features, src_ip)

        # Обработка результата
        if result.is_attack and result.confidence >= self.ml_config.confidence_threshold:
            self._handle_attack_detection(result, data)
        elif not result.is_attack and result.confidence >= self.ml_config.confidence_threshold:
            self._handle_normal_traffic(features)

    def _handle_attack_detection(self, result: PredictionResult, data: Dict):
        """Обработка обнаруженной атаки"""
        # Публикация алерта
        alert_data = result.to_dict()
        alert_data.update({
            'src_ip': data.get('src_ip', 'unknown'),
            'dst_ip': data.get('dst_ip', 'unknown'),
            'dst_port': data.get('dst_port', 0),
            'features': data.get('features', [])
        })

        self.event_bus.publish('alert.detected', alert_data)

        # Добавляем в буфер атак для дообучения
        if self.ml_config.online_learning:
            self.buffer.add_attack(data['features'], result.attack_type)

    def _handle_normal_traffic(self, features: List[float]):
        """Обработка нормального трафика"""
        if self.ml_config.online_learning:
            self.buffer.add_normal(features)

        # Собираем фоновые данные для SHAP
        if len(self._shap_background) < 100:
            self._shap_background.append(features)

    # ========================================================================
    # Prediction Pipeline
    # ========================================================================

    def _predict(self, features: List[float], device: str = "unknown") -> PredictionResult:
        """Основной пайплайн предсказания"""
        result = PredictionResult()

        try:
            X = np.array([features])

            # Масштабирование
            if self.scaler.is_fitted():
                X = self.scaler.transform(X)

            # 1. Isolation Forest
            if_score, if_confidence = self.if_detector.predict(X)
            result.score = if_score
            result.confidence = if_confidence
            result.ml_detected = if_score > 0.5

            # 2. XGBoost классификация
            if self.xgb_detector and self.xgb_detector.is_fitted():
                xgb_score, xgb_conf = self.xgb_detector.predict(X)
                if xgb_conf > 0:
                    attack_type, type_conf = self.xgb_detector.predict_attack_type(X)
                    result.attack_type = attack_type
                    result.confidence = max(result.confidence, type_conf)
                    result.score = max(result.score, xgb_score)

            # 3. Deep Learning
            if self.ml_config.use_deep_learning and self.dl_engine:
                self._run_dl_prediction(X, result)

            # 4. Внешние движки
            self._run_external_engines(features, X, device, result)

            # 5. Определение is_attack
            if result.score >= self.ml_config.confidence_threshold:
                result.is_attack = True
                if not result.attack_type or result.attack_type == 'Normal':
                    result.attack_type = 'Anomaly'

            # Запись score в ML Drift Monitor
            if hasattr(self, 'drift_monitor') and self.drift_monitor is not None:
                drift_event = self.drift_monitor.record_score(result.score)
                if drift_event:
                    self.event_bus.publish('ml.drift', drift_event)

            # 6. SHAP объяснения
            if result.is_attack and self.ml_config.explain_with_shap:
                result.explanations = self._generate_shap_explanations(X, result.attack_type)

            # 7. RL Defense рекомендации
            if result.is_attack and self.rl_defense:
                result.recommended_action = self._get_rl_recommendation(result, device, features)

        except Exception as e:
            self.logger.error(f"Prediction pipeline error: {e}")
            result.score = 0.1
            result.confidence = 0.1

        return result

    def _run_dl_prediction(self, X: np.ndarray, result: PredictionResult):
        """Запуск Deep Learning предсказания"""
        try:
            dl_result = self.dl_engine.predict(X)
            if dl_result and dl_result.get('is_anomaly'):
                result.dl_detected = True
                result.score = max(result.score, dl_result.get('score', 0))
                result.confidence = max(result.confidence, dl_result.get('confidence', 0))
                result.details['dl'] = dl_result
        except Exception as e:
            self.logger.debug(f"DL prediction error: {e}")

    def _run_external_engines(self, features: List[float], X: np.ndarray,
                              device: str, result: PredictionResult):
        """Запуск внешних движков обнаружения"""
        # Adaptive Engine
        if self.adaptive_engine:
            try:
                adaptive_result = self.adaptive_engine.process_packet(device, features)
                if adaptive_result.get('is_anomaly'):
                    result.adaptive_detected = True
                    result.score = max(result.score, adaptive_result.get('overall_score', 0))
            except Exception as e:
                self.logger.debug(f"Adaptive engine error: {e}")

        # SSL Model
        if self.ssl_model:
            try:
                ssl_score = self.ssl_model.get_anomaly_score(features)
                if ssl_score > 0.7:
                    result.score = max(result.score, ssl_score)
                    result.details['ssl_anomaly'] = True
            except Exception as e:
                self.logger.debug(f"SSL model error: {e}")

        # Temporal GNN (каждые 50 пакетов)
        if self.temporal_gnn:
            self._gnn_packet_counter += 1
            if self._gnn_packet_counter % 50 == 0:
                self._run_gnn_analysis(features, device, result)

        # Contrastive VAE
        if self.contrastive_vae:
            try:
                vae_result = self.contrastive_vae.predict_anomaly(features)
                if vae_result and vae_result.get('is_anomaly'):
                    result.vae_detected = True
                    result.score = max(result.score, vae_result.get('score', 0))
                    result.details['vae'] = vae_result

                    if result.attack_type == 'Anomaly':
                        result.attack_type = 'Data Exfiltration'
            except Exception as e:
                self.logger.debug(f"VAE error: {e}")

    def _run_gnn_analysis(self, features: List[float], src_ip: str, result: PredictionResult):
        """Анализ графа угроз через GNN"""
        try:
            dst_ip = self._last_dst_ip
            dst_port = self._last_dst_port

            self.temporal_gnn.add_connection(
                src_ip, dst_ip, 0, dst_port, 6,
                int(features[151]) if len(features) > 151 else 1000, 1
            )

            if self._gnn_packet_counter % 500 == 0:
                gnn_result = self.temporal_gnn.process_time_window()
                if gnn_result and gnn_result.get('is_graph_anomaly'):
                    gnn_score = gnn_result.get('graph_score', 0.5)
                    result.gnn_detected = True
                    result.score = max(result.score, gnn_score)
                    result.details['gnn'] = {
                        'graph_score': gnn_score,
                        'anomalous_nodes': gnn_result.get('anomalous_nodes', [])[:5]
                    }

                    if result.attack_type == 'Anomaly':
                        result.attack_type = 'Lateral Movement'
        except Exception as e:
            self.logger.debug(f"GNN analysis error: {e}")

    def _generate_shap_explanations(self, X: np.ndarray, attack_type: str) -> List[Dict]:
        """Генерация SHAP объяснений"""
        try:
            class_idx = self.ATTACK_TO_ID.get(attack_type, 0)
            return self.shap.explain(X, class_idx)
        except Exception as e:
            self.logger.debug(f"SHAP explanation error: {e}")
            return []

    def _get_rl_recommendation(self, result: PredictionResult, device: str,
                               features: List[float]) -> Optional[str]:
        """Получение рекомендации от RL Defense"""
        try:
            alert_state = {
                'alert_score': result.score,
                'alert_count': 1,
                'connection_rate': getattr(self, '_connection_rate', 10),
                'unique_ports': getattr(self, '_unique_ports', 1),
                'bytes_transferred': int(features[151]) if len(features) > 151 else 1000,
                'is_internal': device.startswith(('192.168.', '10.', '172.', '127.')),
                'hour_of_day': time.localtime().tm_hour,
                'day_of_week': time.localtime().tm_wday
            }
            _, action_name = self.rl_defense.agent.act(alert_state, training=False)
            return action_name
        except Exception as e:
            self.logger.debug(f"RL Defense error: {e}")
            return None

    # ========================================================================
    # Online Learning
    # ========================================================================

    def _retrain_loop(self) -> None:
        """Цикл дообучения моделей"""
        while self.running:
            time.sleep(self.ml_config.retrain_interval)

            if self.buffer.total_samples >= self.ml_config.retrain_min_samples:
                self._retrain()

    def _retrain(self) -> None:
        """Дообучение моделей на накопленных данных"""
        # Атомарно получаем данные
        normal_samples, attack_samples = self.buffer.get_and_clear()

        if not normal_samples and not attack_samples:
            return

        self.logger.info(
            f"Retraining on {len(normal_samples)} normal and "
            f"{len(attack_samples)} attack samples"
        )

        try:
            success = True

            # Дообучение Isolation Forest
            if len(normal_samples) >= 50:
                X_normal = np.array(normal_samples)
                if self.scaler.is_fitted():
                    X_normal = self.scaler.transform(X_normal)

                if not self.if_detector.partial_fit(X_normal):
                    success = False

            # Дообучение XGBoost
            if (self.xgb_detector and
                    len(attack_samples) >= 10 and
                    len(normal_samples) >= 10):
                success &= self._retrain_xgboost(normal_samples, attack_samples)

            # Дообучение SSL модели
            if self.ssl_model and normal_samples:
                for features in normal_samples[:100]:
                    self.ssl_model.train_step([features])

            if success:
                self.buffer.commit_clear()
                self._models_dirty = True
                self.logger.info("Retraining completed successfully")
            else:
                self.buffer.rollback()
                self.logger.warning("Retraining failed, data restored")

        except Exception as e:
            self.logger.error(f"Retraining error: {e}")
            self.buffer.rollback()

    def _retrain_xgboost(self, normal_samples: List, attack_samples: List) -> bool:
        """Дообучение XGBoost с балансировкой классов"""
        try:
            X_attacks = np.array([a[0] for a in attack_samples])
            y_attacks = np.array([self.ATTACK_TO_ID.get(a[1], 0) for a in attack_samples])

            # Балансировка: добавляем normal samples
            balanced_count = min(len(normal_samples), len(attack_samples))
            X_normal = np.array(normal_samples[:balanced_count])
            y_normal = np.zeros(balanced_count)

            X_balanced = np.vstack([X_attacks, X_normal])
            y_balanced = np.hstack([y_attacks, y_normal])

            # Перемешивание
            shuffle_idx = np.random.permutation(len(X_balanced))
            X_balanced = X_balanced[shuffle_idx]
            y_balanced = y_balanced[shuffle_idx]

            if self.scaler.is_fitted():
                X_balanced = self.scaler.transform(X_balanced)

            return self.xgb_detector.partial_fit(X_balanced, y_balanced)
        except Exception as e:
            self.logger.error(f"XGBoost retrain error: {e}")
            return False

    # ========================================================================
    # Persistence
    # ========================================================================

    def _autosave_loop(self) -> None:
        """Периодическое автосохранение"""
        while self.running:
            time.sleep(60)
            with self._autosave_lock:
                if (self._models_dirty and
                        time.time() - self._last_save >= self.ml_config.autosave_interval):
                    self._save_all_models()
                    self._models_dirty = False
                    self._last_save = time.time()

    def _save_all_models(self) -> bool:
        """Сохранение всех моделей"""
        models_to_save = {}

        if self.if_detector.model is not None:
            models_to_save['shard_enterprise_model_if'] = self.if_detector.model

        if self.xgb_detector and self.xgb_detector.model is not None:
            models_to_save['shard_enterprise_model_xgb'] = self.xgb_detector.model

        if self.scaler.scaler is not None:
            models_to_save['shard_enterprise_scaler'] = self.scaler.scaler

        if self.features:
            models_to_save['shard_enterprise_features'] = self.features

        return self.persistence.save_all(models_to_save)

    def save_now(self) -> None:
        """Принудительное сохранение"""
        with self._autosave_lock:
            self._save_all_models()
            self._models_dirty = False
            self._last_save = time.time()
        self.logger.info("Models saved manually")

    # ========================================================================
    # History Loading
    # ========================================================================

    def _load_history_async(self) -> None:
        """Асинхронная загрузка исторических данных"""
        try:
            conn = self._get_db_connection()
            if conn is None:
                return

            try:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()

                cursor.execute(
                    '''SELECT features_json, attack_type FROM alerts 
                       WHERE features_json IS NOT NULL 
                       ORDER BY timestamp DESC LIMIT 500'''
                )
                rows = cursor.fetchall()

                loaded = 0
                for row in rows:
                    try:
                        features = json.loads(row[0])
                        attack_type = row[1] if row[1] else 'Normal'

                        if attack_type != 'Normal':
                            self.buffer.add_attack(features, attack_type)
                        else:
                            self.buffer.add_normal(features)
                        loaded += 1
                    except json.JSONDecodeError:
                        continue

                self.logger.info(f"Loaded {loaded} historical samples")
            finally:
                self._return_db_connection(conn)

        except Exception as e:
            self.logger.warning(f"History loading error: {e}")

    def _get_db_connection(self):
        """Получение соединения с БД"""
        if hasattr(self, 'siem_storage') and self.siem_storage is not None:
            return self.siem_storage._get_sqlite_connection()
        else:
            return sqlite3.connect('shard_siem.db')

    def _return_db_connection(self, conn):
        """Возврат соединения в пул"""
        if conn is None:
            return

        if hasattr(self, 'siem_storage') and self.siem_storage is not None:
            self.siem_storage._return_sqlite_connection(conn)
        else:
            conn.close()

    # ========================================================================
    # SHAP Initialization
    # ========================================================================

    def _init_shap_async(self):
        """Асинхронная инициализация SHAP"""
        try:
            X_background = np.array(self._shap_background[:100])
            if self.scaler.is_fitted():
                X_background = self.scaler.transform(X_background)

            if self.xgb_detector and self.xgb_detector.is_fitted():
                self.shap.initialize(
                    self.xgb_detector.model,
                    X_background,
                    self.features
                )
            elif self.if_detector.is_fitted():
                self.shap.initialize(
                    self.if_detector.model,
                    X_background,
                    self.features
                )
        except Exception as e:
            self.logger.warning(f"Async SHAP initialization failed: {e}")

    # ========================================================================
    # Public API
    # ========================================================================

    def predict_single(self, features: List[float], device: str = "unknown") -> Dict:
        """Публичный метод для предсказания (для API)"""
        result = self._predict(features, device)
        return result.to_dict()

    def explain_prediction(self, features: List[float]) -> Dict:
        """Объяснение предсказания"""
        result = self._predict(features)
        return {
            'prediction': result.to_dict(),
            'explanations': result.explanations
        }

    def get_stats(self) -> Dict:
        """Статистика ML движка"""
        with self._lock:
            stats = {
                'buffer_stats': self.buffer.stats,
                'models': {
                    'if_fitted': self.if_detector.is_fitted(),
                    'if_reliable': self.if_detector.is_reliable,
                    'if_samples': self.if_detector.samples_trained,
                    'xgb_fitted': self.xgb_detector.is_fitted() if self.xgb_detector else False,
                },
                'scaler_fitted': self.scaler.is_fitted(),
                'features_count': len(self.features),
                'config': {
                    'online_learning': self.ml_config.online_learning,
                    'use_xgboost': self.ml_config.use_xgboost,
                    'use_deep_learning': self.ml_config.use_deep_learning,
                    'explain_with_shap': self.ml_config.explain_with_shap,
                },
                'engines': {
                    'gnn': self.temporal_gnn is not None,
                    'vae': self.contrastive_vae is not None,
                    'rl': self.rl_defense is not None,
                    'adaptive': self.adaptive_engine is not None,
                    'dl': self.dl_engine is not None,
                }
            }

            if self.dl_engine and hasattr(self.dl_engine, 'ensemble'):
                stats['dl_stats'] = self.dl_engine.ensemble.get_stats()

            return stats

    def reset_buffers(self) -> None:
        """Очистка буферов обучения"""
        _, _ = self.buffer.get_and_clear()
        self.buffer.commit_clear()
        self.logger.info("Training buffers cleared")

class MLDriftMonitor:
    """Мониторинг дрейфа ML-моделей (data drift + concept drift)"""

    def __init__(self, window_size: int = 1000, alert_threshold: float = 0.15):
        self.window_size = window_size
        self.alert_threshold = alert_threshold
        self.score_history: deque = deque(maxlen=window_size)
        self.baseline_mean: float = 0.0
        self.baseline_std: float = 0.0
        self.is_calibrated: bool = False
        self._lock = threading.RLock()
        self.drift_events: List[Dict] = []
        self.last_alert_time: float = 0
        self.alert_cooldown: int = 300

    def record_score(self, score: float) -> Optional[Dict]:
        """Записать score и проверить на дрейф"""
        with self._lock:
            self.score_history.append(score)

            if len(self.score_history) >= self.window_size and not self.is_calibrated:
                self._calibrate()

            if not self.is_calibrated:
                return None

            if len(self.score_history) >= 100:
                recent = list(self.score_history)[-100:]
                current_mean = sum(recent) / len(recent)

                deviation = abs(current_mean - self.baseline_mean)
                if deviation > self.alert_threshold and time.time() - self.last_alert_time > self.alert_cooldown:
                    self.last_alert_time = time.time()
                    direction = "up" if current_mean > self.baseline_mean else "down"
                    event = {
                        'timestamp': time.time(),
                        'type': 'ml_drift',
                        'direction': direction,
                        'current_mean': round(current_mean, 3),
                        'baseline_mean': round(self.baseline_mean, 3),
                        'deviation': round(deviation, 3),
                        'severity': 'HIGH' if deviation > 0.25 else 'MEDIUM'
                    }
                    self.drift_events.append(event)
                    return event
        return None

    def _calibrate(self) -> None:
        """Калибровка baseline на последних window_size сэмплах"""
        if len(self.score_history) < self.window_size:
            return
        values = list(self.score_history)
        self.baseline_mean = sum(values) / len(values)
        self.baseline_std = (sum((v - self.baseline_mean) ** 2 for v in values) / len(values)) ** 0.5
        self.is_calibrated = True

    def get_stats(self) -> Dict:
        """Статистика дрейфа"""
        with self._lock:
            return {
                'calibrated': self.is_calibrated,
                'baseline_mean': round(self.baseline_mean, 3),
                'baseline_std': round(self.baseline_std, 3),
                'samples': len(self.score_history),
                'drift_events': len(self.drift_events),
                'last_drift': self.drift_events[-1] if self.drift_events else None
            }

    def reset(self) -> None:
        """Сброс монитора"""
        with self._lock:
            self.score_history.clear()
            self.is_calibrated = False
            self.drift_events.clear()
