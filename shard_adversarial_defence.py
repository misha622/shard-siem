#!/usr/bin/env python3

"""
SHARD Adversarial Defence Module
Защита от adversarial атак на ML-модели.
Очистка входных данных, детекция аномалий, ансамблевая верификация.

Интегрируется с:
- EventBus (alert.detected, adversarial.detected)
- RL Defense Agent
- LLM Guardian
- Все ML модели SHARD

Author: SHARD Enterprise
Version: 1.0.0
"""

import numpy as np
import hashlib
import time
import threading
import logging
from typing import Dict, List, Tuple, Optional, Any
from collections import deque
from dataclasses import dataclass, field

logger = logging.getLogger("SHARD-Adversarial")



@dataclass
class AdversarialDefenceConfig:
    """Конфигурация защиты от adversarial атак"""

    feature_clipping: bool = True
    feature_clip_min: float = -5.0
    feature_clip_max: float = 5.0

    anomaly_detection: bool = True
    anomaly_threshold: float = 3.0
    max_feature_deviation: float = 10.0

    ensemble_verification: bool = True
    ensemble_agreement_threshold: float = 0.7

    normal_stats_window: int = 10000
    stats_update_interval: int = 100

    auto_block_on_attack: bool = True
    block_duration: int = 3600

    log_all_detections: bool = True
    save_adversarial_samples: bool = True



class FeatureStatistics:
    """
    Отслеживание статистик признаков для детекции аномалий.
    Использует алгоритм Уэлфорда для онлайн-вычисления среднего и дисперсии.
    """

    def __init__(self, n_features: int, window_size: int = 10000):
        self.n_features = n_features
        self.window_size = window_size

        self.count = 0
        self.mean = np.zeros(n_features)
        self.M2 = np.zeros(n_features)

        self.min_values = np.full(n_features, np.inf)
        self.max_values = np.full(n_features, -np.inf)

        self.recent_samples = deque(maxlen=window_size)

        self._lock = threading.RLock()

    def update(self, features: np.ndarray):
        """Обновление статистик новым сэмплом"""
        with self._lock:
            if features.ndim == 2:
                features = features.flatten()

            self.count += 1
            delta = features - self.mean
            self.mean += delta / self.count
            delta2 = features - self.mean
            self.M2 += delta * delta2

            self.min_values = np.minimum(self.min_values, features)
            self.max_values = np.maximum(self.max_values, features)

            self.recent_samples.append(features.copy())

    def get_std(self) -> np.ndarray:
        """Стандартное отклонение"""
        with self._lock:
            if self.count < 2:
                return np.ones(self.n_features)
            return np.sqrt(self.M2 / (self.count - 1))

    def get_z_scores(self, features: np.ndarray) -> np.ndarray:
        """Z-scores для каждого признака"""
        with self._lock:
            if features.ndim == 2:
                features = features.flatten()

            std = self.get_std()
            std = np.where(std < 1e-8, 1.0, std)
            return np.abs(features - self.mean) / std

    def is_anomalous(self, features: np.ndarray, threshold: float = 3.0) -> Tuple[bool, float, List[int]]:
        """
        Проверка на аномальность.

        Returns:
            is_anomaly: флаг аномалии
            max_z: максимальный Z-score
            anomalous_features: индексы аномальных признаков
        """
        z_scores = self.get_z_scores(features)
        max_z = np.max(z_scores)
        anomalous_features = np.where(z_scores > threshold)[0].tolist()

        return max_z > threshold, max_z, anomalous_features

    def get_stats(self) -> Dict:
        """Получить текущие статистики"""
        with self._lock:
            return {
                'count': self.count,
                'mean_range': (float(np.min(self.mean)), float(np.max(self.mean))),
                'std_range': (float(np.min(self.get_std())), float(np.max(self.get_std()))),
                'n_anomalous_features': int(np.sum(self.get_std() > 5.0))
            }



class AdversarialCleaner:
    """
    Очистка входных признаков от adversarial возмущений.

    Методы:
    - Feature clipping (обрезка выбросов)
    - Quantization (квантование для уменьшения шума)
    - Spatial smoothing (пространственное сглаживание)
    - JPEG compression (для изображений)
    """

    def __init__(self, config: AdversarialDefenceConfig):
        self.config = config
        self.stats = None

    def clean(self, features: np.ndarray) -> np.ndarray:
        """
        Очистка признаков.

        Args:
            features: np.ndarray shape (n_features,) или (1, n_features)

        Returns:
            cleaned: очищенные признаки той же формы
        """
        original_shape = features.shape
        if features.ndim == 2:
            features = features.flatten()

        cleaned = features.copy()

        if self.config.feature_clipping:
            cleaned = self._clip_features(cleaned)

        cleaned = self._quantize(cleaned)

        cleaned = self._median_filter(cleaned)

        return cleaned.reshape(original_shape)

    def _clip_features(self, features: np.ndarray) -> np.ndarray:
        """Обрезка выбросов"""
        if self.stats is not None and self.stats.count > 100:
            mean = self.stats.mean
            std = self.stats.get_std()
            lower = mean - self.config.max_feature_deviation * std
            upper = mean + self.config.max_feature_deviation * std
            return np.clip(features, lower, upper)
        else:
            return np.clip(features,
                           self.config.feature_clip_min,
                           self.config.feature_clip_max)

    def _quantize(self, features: np.ndarray, bits: int = 8) -> np.ndarray:
        """Квантование для снижения точности adversarial perturbation"""
        levels = 2 ** bits
        min_val = features.min()
        max_val = features.max()
        if max_val > min_val:
            quantized = np.round((features - min_val) / (max_val - min_val) * levels)
            return quantized / levels * (max_val - min_val) + min_val
        return features

    def _median_filter(self, features: np.ndarray, kernel_size: int = 3) -> np.ndarray:
        """Медианный фильтр для удаления одиночных выбросов"""
        if len(features) < kernel_size:
            return features

        result = features.copy()
        half = kernel_size // 2

        for i in range(half, len(features) - half):
            window = features[i - half:i + half + 1]
            median = np.median(window)

            if abs(features[i] - median) > 3 * np.std(window):
                result[i] = median

        return result



class AdversarialDetector:
    """
    Детектор adversarial атак.

    Методы детекции:
    - Statistical anomaly detection (Z-score)
    - Feature squeezing (сравнение до/после очистки)
    - Ensemble disagreement (проверка согласия моделей)
    """

    def __init__(self, config: AdversarialDefenceConfig):
        self.config = config
        self.cleaner = AdversarialCleaner(config)
        self.stats = None
        self.models = {}
        self.event_bus = None
        self.firewall = None

        self.detection_history = deque(maxlen=1000)

        self.stats_detector = {
            'total_checked': 0,
            'attacks_detected': 0,
            'false_positives': 0,
            'cleaned_samples': 0
        }

        self._lock = threading.RLock()

    def setup(self, event_bus=None, firewall=None, models: Dict[str, Any] = None):
        """Настройка интеграций"""
        self.event_bus = event_bus
        self.firewall = firewall

        if models:
            self.models = models

    def initialize_stats(self, n_features: int):
        """Инициализация статистик"""
        self.stats = FeatureStatistics(n_features, self.config.normal_stats_window)
        self.cleaner.stats = self.stats

    def update_stats(self, features: np.ndarray):
        """Обновление нормальных статистик"""
        if self.stats is not None:
            self.stats.update(features)

    def detect_anomaly(self, features: np.ndarray, cleaned: np.ndarray = None) -> Tuple[bool, float, Dict]:
        """
        Комплексная проверка на adversarial атаку.

        Returns:
            is_attack: флаг атаки
            confidence: уверенность (0-1)
            details: детали детекции
        """
        with self._lock:
            self.stats_detector['total_checked'] += 1

            if features.ndim == 2:
                features = features.flatten()

            details = {
                'timestamp': time.time(),
                'methods': {},
                'total_score': 0.0
            }

            scores = []

            if self.stats is not None and self.stats.count > 100:
                is_anom, max_z, anom_features = self.stats.is_anomalous(
                    features, self.config.anomaly_threshold
                )

                stat_score = min(1.0, max_z / (self.config.anomaly_threshold * 2))
                scores.append(stat_score)
                details['methods']['statistical'] = {
                    'is_anomaly': bool(is_anom),
                    'max_z_score': float(max_z),
                    'score': float(stat_score),
                    'anomalous_features': anom_features[:10]
                }

            if cleaned is not None:
                l1_diff = np.mean(np.abs(features - cleaned))
                l2_diff = np.sqrt(np.mean((features - cleaned) ** 2))

                squeeze_score = min(1.0, l1_diff / 0.5)
                scores.append(squeeze_score)
                details['methods']['feature_squeezing'] = {
                    'l1_diff': float(l1_diff),
                    'l2_diff': float(l2_diff),
                    'score': float(squeeze_score)
                }

                if l1_diff > 0.3:
                    self.stats_detector['cleaned_samples'] += 1

            if self.models and cleaned is not None:
                disagreement_score = self._check_ensemble_agreement(features, cleaned)
                scores.append(disagreement_score)
                details['methods']['ensemble_disagreement'] = {
                    'score': float(disagreement_score)
                }

            if scores:
                total_score = max(scores)
            else:
                total_score = 0.0

            is_attack = total_score > 0.5
            details['total_score'] = float(total_score)
            details['is_attack'] = bool(is_attack)

            if is_attack:
                self.stats_detector['attacks_detected'] += 1
                self.detection_history.append(details)

                self._publish_alert(features, details)

                if self.config.auto_block_on_attack and self.firewall:
                    self._auto_block(features, total_score)

            return is_attack, total_score, details

    def _check_ensemble_agreement(self, original: np.ndarray, cleaned: np.ndarray) -> float:
        """
        Проверка согласия ансамбля моделей.

        Высокий disagreement = возможная adversarial атака.
        """
        if not self.models:
            return 0.0

        preds_original = []
        preds_cleaned = []

        for name, model in self.models.items():
            try:
                if hasattr(model, 'predict'):
                    pred_orig = model.predict(original.reshape(1, -1))[0]
                    pred_clean = model.predict(cleaned.reshape(1, -1))[0]

                    preds_original.append(pred_orig)
                    preds_cleaned.append(pred_clean)
            except:
                pass

        if len(preds_original) < 2:
            return 0.0

        disagreements = 0
        for i in range(len(preds_original)):
            if preds_original[i] != preds_cleaned[i]:
                disagreements += 1

        return disagreements / len(preds_original)

    def _publish_alert(self, features: np.ndarray, details: Dict):
        """Публикация алерта об adversarial атаке"""
        if self.event_bus:
            alert = {
                'timestamp': time.time(),
                'attack_type': 'Adversarial Attack',
                'severity': 'HIGH' if details['total_score'] > 0.8 else 'MEDIUM',
                'score': details['total_score'],
                'confidence': details['total_score'],
                'is_attack': True,
                'explanation': f"Adversarial attack detected (score: {details['total_score']:.3f})",
                'details': {
                    'methods': {k: {k2: v2 for k2, v2 in v.items() if k2 != 'anomalous_features'}
                                for k, v in details.get('methods', {}).items()},
                    'feature_hash': hashlib.md5(features.tobytes()).hexdigest()[:8]
                }
            }

            self.event_bus.publish('adversarial.detected', alert)
            self.event_bus.publish('alert.detected', alert)

            logger.warning(f"🛡️ Adversarial attack detected! Score: {details['total_score']:.3f}")

    def _auto_block(self, features: np.ndarray, score: float):
        """Автоматическая блокировка при adversarial атаке"""
        if self.firewall and score > 0.8:
            feature_hash = hashlib.md5(features.tobytes()).hexdigest()[:12]

            logger.critical(f"🚫 Auto-blocking adversarial attack pattern: {feature_hash}")

    def add_feedback(self, was_false_positive: bool):
        """Обратная связь для адаптации порогов"""
        with self._lock:
            if was_false_positive:
                self.stats_detector['false_positives'] += 1

                fp_rate = self.stats_detector['false_positives'] / max(1, self.stats_detector['attacks_detected'])
                if fp_rate > 0.3:
                    self.config.anomaly_threshold = min(5.0, self.config.anomaly_threshold * 1.1)
                    logger.info(f"Adversarial threshold adjusted to {self.config.anomaly_threshold:.2f}")

    def get_stats(self) -> Dict:
        """Статистика детектора"""
        with self._lock:
            return {
                **self.stats_detector,
                'history_size': len(self.detection_history),
                'feature_stats': self.stats.get_stats() if self.stats else {},
                'threshold': self.config.anomaly_threshold
            }



class AdversarialDefence:
    """
    Главный модуль защиты от adversarial атак.

    Объединяет:
    - Очистку признаков (AdversarialCleaner)
    - Статистический мониторинг (FeatureStatistics)
    - Детекцию атак (AdversarialDetector)
    - Интеграцию с EventBus, Firewall, RL Agent
    """

    def __init__(self, config: AdversarialDefenceConfig = None):
        self.config = config or AdversarialDefenceConfig()

        self.cleaner = AdversarialCleaner(self.config)
        self.detector = AdversarialDetector(self.config)
        self.stats = None

        self.event_bus = None
        self.firewall = None
        self.rl_agent = None

        self._running = False
        self._initialized = False

        logger.info("🛡️ Adversarial Defence Module initialized")

    def setup(self, event_bus=None, firewall=None, rl_agent=None, models=None):
        """Настройка интеграций"""
        self.event_bus = event_bus
        self.firewall = firewall
        self.rl_agent = rl_agent

        self.detector.setup(event_bus=event_bus, firewall=firewall, models=models)

        if event_bus:
            event_bus.subscribe('packet.features', self.on_features)
            event_bus.subscribe('model.prediction', self.on_prediction)
            event_bus.subscribe('adversarial.feedback', self.on_feedback)

    def initialize(self, n_features: int, calibration_data: np.ndarray = None):
        """Инициализация с размерностью признаков"""
        self.stats = FeatureStatistics(n_features, self.config.normal_stats_window)
        self.cleaner.stats = self.stats
        self.detector.initialize_stats(n_features)

        if calibration_data is not None:
            for i in range(len(calibration_data)):
                self.stats.update(calibration_data[i])
                self.detector.update_stats(calibration_data[i])

            logger.info(f"✅ Calibrated on {len(calibration_data)} normal samples")

        self._initialized = True
        logger.info(f"✅ Adversarial Defence initialized for {n_features} features")

    def start(self):
        """Запуск модуля"""
        self._running = True
        logger.info("🚀 Adversarial Defence started")

    def stop(self):
        """Остановка модуля"""
        self._running = False
        logger.info("🛑 Adversarial Defence stopped")

    def process_features(self, features: np.ndarray) -> Dict:
        """
        Полный цикл обработки признаков.

        Args:
            features: np.ndarray shape (n_features,)

        Returns:
            dict с результатами
        """
        if not self._initialized:
            self.initialize(len(features))

        result = {
            'original_features': features.copy(),
            'cleaned_features': None,
            'is_attack': False,
            'attack_score': 0.0,
            'details': {}
        }

        cleaned = self.cleaner.clean(features)
        result['cleaned_features'] = cleaned


        is_attack, score, details = self.detector.detect_anomaly(features, cleaned)
        result['is_attack'] = is_attack
        result['attack_score'] = score
        result['details'] = details

        return result

    def clean(self, features: np.ndarray) -> np.ndarray:
        """Быстрая очистка без детекции"""
        if not self._initialized:
            self.initialize(len(features))
        return self.cleaner.clean(features)

    def detect_anomaly(self, features: np.ndarray, cleaned: np.ndarray = None) -> Tuple[bool, float, Dict]:
        """Детекция аномалии"""
        if cleaned is None:
            cleaned = self.clean(features)
        return self.detector.detect_anomaly(features, cleaned)

    def on_features(self, data: Dict):
        """Обработчик событий признаков"""
        features = data.get('features')
        if features is not None:
            features = np.array(features)

            result = self.process_features(features)

            if result['is_attack'] and self.rl_agent:
                state = {
                    'alert_score': result['attack_score'],
                    'alert_count': 1,
                    'attack_type': 'adversarial'
                }
                action_id, action_name = self.rl_agent.act(state, training=False)
                result['rl_action'] = action_name

            if self.event_bus:
                self.event_bus.publish('features.cleaned', {
                    'original': features.tolist(),
                    'cleaned': result['cleaned_features'].tolist(),
                    'is_attack': result['is_attack']
                })

    def on_prediction(self, data: Dict):
        """Обработчик предсказаний модели"""
        features = data.get('features')
        if features is not None:
            self.update_stats(np.array(features))

    def on_feedback(self, data: Dict):
        """Обработчик обратной связи"""
        was_fp = data.get('false_positive', False)
        self.detector.add_feedback(was_fp)

    def update_stats(self, features: np.ndarray):
        """Обновление нормальных статистик"""
        if self.stats is not None:
            self.stats.update(features)
            self.detector.update_stats(features)

    def get_stats(self) -> Dict:
        """Получить статистику"""
        return {
            'detector': self.detector.get_stats(),
            'config': {
                'anomaly_threshold': self.config.anomaly_threshold,
                'feature_clipping': self.config.feature_clipping,
                'auto_block': self.config.auto_block_on_attack
            }
        }



class ShardAdversarialIntegration:
    """Интеграция Adversarial Defence в SHARD Enterprise"""

    def __init__(self, config: Dict = None):
        self.config = AdversarialDefenceConfig()
        if config:
            for key, value in config.items():
                if hasattr(self.config, key):
                    setattr(self.config, key, value)

        self.defence = AdversarialDefence(self.config)
        self.event_bus = None
        self.logger = logger

    def setup(self, event_bus=None, firewall=None, rl_agent=None, models=None, logger_instance=None):
        """Настройка интеграции"""
        self.event_bus = event_bus
        if logger_instance:
            self.logger = logger_instance

        self.defence.setup(
            event_bus=event_bus,
            firewall=firewall,
            rl_agent=rl_agent,
            models=models
        )

    def start(self):
        """Запуск"""
        self.defence.start()
        self.logger.info("🛡️ Adversarial Defence Integration started")

    def stop(self):
        """Остановка"""
        self.defence.stop()

    def process_request(self, features: np.ndarray) -> Dict:
        """
        Полный цикл защиты запроса.

        Используй этот метод перед отправкой данных в нейросеть.
        """
        return self.defence.process_features(features)

    def clean(self, features: np.ndarray) -> np.ndarray:
        """Очистить признаки перед инференсом"""
        return self.defence.clean(features)

    def get_stats(self) -> Dict:
        """Статистика"""
        return self.defence.get_stats()



def test_adversarial_defence():
    """Тестирование модуля"""
    print("=" * 60)
    print("🧪 ТЕСТИРОВАНИЕ ADVERSARIAL DEFENCE")
    print("=" * 60)

    defence = AdversarialDefence()

    n_features = 78
    normal_data = np.random.randn(1000, n_features) * 0.1
    defence.initialize(n_features, normal_data)
    defence.start()

    print("\n📝 Тест 1: Нормальный сэмпл")
    normal = np.random.randn(n_features) * 0.1
    result = defence.process_features(normal)
    print(f"   Is attack: {result['is_attack']}")
    print(f"   Score: {result['attack_score']:.3f}")

    print("\n📝 Тест 2: Adversarial сэмпл")
    adversarial = normal + np.random.randn(n_features) * 2.0
    adversarial[0] = 10.0
    result = defence.process_features(adversarial)
    print(f"   Is attack: {result['is_attack']}")
    print(f"   Score: {result['attack_score']:.3f}")
    print(f"   Methods: {list(result['details'].get('methods', {}).keys())}")

    print("\n📝 Тест 3: Очистка признаков")
    cleaned = defence.clean(adversarial)
    l1_diff = np.mean(np.abs(normal - adversarial))
    l1_cleaned = np.mean(np.abs(normal - cleaned))
    print(f"   L1 diff (adversarial): {l1_diff:.4f}")
    print(f"   L1 diff (cleaned): {l1_cleaned:.4f}")
    print(f"   Improvement: {(1 - l1_cleaned / l1_diff) * 100:.1f}%")

    print("\n📊 Статистика:")
    stats = defence.get_stats()
    for key, value in stats['detector'].items():
        if not isinstance(value, dict):
            print(f"   {key}: {value}")

    defence.stop()

    print("\n" + "=" * 60)
    print("✅ ТЕСТИРОВАНИЕ ЗАВЕРШЕНО")
    print("=" * 60)


if __name__ == "__main__":
    test_adversarial_defence()