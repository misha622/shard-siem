import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.cluster import KMeans
from sklearn.metrics.pairwise import cosine_similarity
from collections import deque
import random
from datetime import datetime
import json


class ActiveLearningEngine:
    """
    Активное обучение для SHARD
    Спрашивает у администратора в спорных случаях
    """

    def __init__(self, model, uncertainty_threshold=0.3):
        self.model = model
        self.uncertainty_threshold = uncertainty_threshold

        self.uncertainty_buffer = deque(maxlen=1000)

        self.sampling_strategies = {
            'uncertainty': self._uncertainty_sampling,
            'margin': self._margin_sampling,
            'entropy': self._entropy_sampling,
            'diversity': self._diversity_sampling,
            'random': self._random_sampling
        }

        self.query_history = []

        self.active_model = None

    def _uncertainty_sampling(self, probabilities):
        """Сэмплирование по неопределённости (least confidence)"""
        uncertainties = 1 - np.max(probabilities, axis=1)
        return np.argsort(uncertainties)[-self.batch_size:]

    def _margin_sampling(self, probabilities):
        """Сэмплирование по маржинальной разнице"""
        sorted_probs = np.sort(probabilities, axis=1)
        margins = sorted_probs[:, -1] - sorted_probs[:, -2]
        return np.argsort(margins)[:self.batch_size]

    def _entropy_sampling(self, probabilities):
        """Сэмплирование по энтропии"""
        entropies = -np.sum(probabilities * np.log(probabilities + 1e-10), axis=1)
        return np.argsort(entropies)[-self.batch_size:]

    def _diversity_sampling(self, features, labeled_indices, batch_size=10):
        """Сэмплирование для максимального разнообразия"""
        if len(labeled_indices) < 2:
            return self._random_sampling(len(features), batch_size)

        labeled_features = features[labeled_indices]
        similarities = cosine_similarity(features, labeled_features)
        max_similarities = np.max(similarities, axis=1)

        diverse_indices = np.argsort(max_similarities)[:batch_size]
        return diverse_indices

    def _random_sampling(self, n_samples, batch_size):
        """Случайное сэмплирование"""
        return random.sample(range(n_samples), min(batch_size, n_samples))

    def add_uncertain_sample(self, features, prediction, confidence, raw_prediction):
        """
        Добавляет образец с низкой уверенностью в буфер
        """
        if confidence < self.uncertainty_threshold:
            self.uncertainty_buffer.append({
                'features': features,
                'prediction': prediction,
                'confidence': confidence,
                'raw_prediction': raw_prediction,
                'timestamp': datetime.now(),
                'reviewed': False,
                'true_label': None
            })
            return True
        return False

    def request_human_review(self, strategy='uncertainty', batch_size=5):
        """
        Запрашивает у администратора разметку неопределённых образцов
        """
        if len(self.uncertainty_buffer) < batch_size:
            return []

        buffer_list = list(self.uncertainty_buffer)
        features = np.array([s['features'] for s in buffer_list])

        probabilities = np.array([s['raw_prediction'] for s in buffer_list])

        if strategy == 'diversity':
            labeled_indices = [i for i, s in enumerate(buffer_list) if s['reviewed']]
            indices = self.sampling_strategies[strategy](
                features, labeled_indices, batch_size
            )
        else:
            indices = self.sampling_strategies[strategy](probabilities)

        reviewed_samples = []

        print("\n" + "=" * 60)
        print(f"🔄 АКТИВНОЕ ОБУЧЕНИЕ: {len(indices)} образцов требуют разметки")
        print("=" * 60)

        for idx in indices[:batch_size]:
            sample = buffer_list[idx]

            print(f"\n📊 Образец от {sample['timestamp'].strftime('%H:%M:%S')}:")
            print(f"   Модель предсказала: {sample['prediction']}")
            print(f"   Уверенность: {sample['confidence']:.2%}")
            print(f"   Признаки: {sample['features'][:10]}...")

            print("\n   Варианты:")
            print("   1 - Нормальный трафик")
            print("   2 - Атака (DoS)")
            print("   3 - Атака (DDoS)")
            print("   4 - Атака (Brute Force)")
            print("   5 - Атака (Web Attack)")
            print("   6 - Атака (Botnet)")
            print("   7 - Атака (Port Scan)")

            choice = input("   Ваш выбор (1-7): ")

            label_map = {
                '1': 0,
                '2': 1,
                '3': 2,
                '4': 3,
                '5': 4,
                '6': 5,
                '7': 8
            }

            true_label = label_map.get(choice, 0)
            sample['true_label'] = true_label
            sample['reviewed'] = True

            reviewed_samples.append(sample)

            print(f"   ✅ Отмечено как: {'Атака' if true_label != 0 else 'Нормальный'}")

        self.uncertainty_buffer = deque(
            [s for s in buffer_list if not s['reviewed']],
            maxlen=1000
        )

        self.query_history.append({
            'timestamp': datetime.now(),
            'strategy': strategy,
            'samples_count': len(reviewed_samples),
            'samples': reviewed_samples
        })

        return reviewed_samples

    def retrain_on_feedback(self, reviewed_samples):
        """
        Дообучение модели на размеченных образцах
        """
        if not reviewed_samples:
            return

        X_new = np.array([s['features'] for s in reviewed_samples])
        y_new = np.array([s['true_label'] for s in reviewed_samples])

        if hasattr(self.model, 'partial_fit'):
            self.model.partial_fit(X_new, y_new)
        else:
            self._save_training_data(X_new, y_new)

        print(f"✅ Модель дообучена на {len(reviewed_samples)} новых образцах")

    def _save_training_data(self, X, y):
        """Сохраняет новые данные для дообучения"""
        data_file = 'active_learning_data.npz'

        try:
            existing = np.load(data_file)
            X_all = np.vstack([existing['X'], X])
            y_all = np.concatenate([existing['y'], y])
        except:
            X_all = X
            y_all = y

        np.savez(data_file, X=X_all, y=y_all)

    def get_statistics(self):
        """Статистика активного обучения"""
        return {
            'uncertainty_buffer_size': len(self.uncertainty_buffer),
            'total_queries': len(self.query_history),
            'total_labeled_samples': sum(q['samples_count'] for q in self.query_history),
            'last_query_time': self.query_history[-1]['timestamp'] if self.query_history else None
        }


class UncertaintyAwareDetector:
    """
    Детектор, учитывающий неопределённость предсказаний
    Интеграция с SHARD
    """

    def __init__(self, base_detector, active_learning_engine):
        self.detector = base_detector
        self.active_learning = active_learning_engine
        self.uncertainty_threshold = 0.3

    def predict_with_uncertainty(self, features, n_estimates=10):
        """
        Предсказание с оценкой неопределённости (Monte Carlo Dropout)
        """
        predictions = []
        confidences = []

        for _ in range(n_estimates):
            result = self.detector.predict(features, dropout=True)
            predictions.append(result['is_attack'])
            confidences.append(result['confidence'])

        mean_prediction = np.mean(predictions)
        std_prediction = np.std(predictions)
        mean_confidence = np.mean(confidences)
        std_confidence = np.std(confidences)

        uncertainty = std_prediction

        final_prediction = mean_prediction > 0.5
        final_confidence = mean_confidence * (1 - uncertainty)

        return {
            'is_attack': final_prediction,
            'confidence': final_confidence,
            'uncertainty': uncertainty,
            'prediction_distribution': predictions,
            'needs_review': uncertainty > self.uncertainty_threshold
        }

    def process_packet(self, features):
        """
        Обработка пакета с учётом неопределённости
        """
        result = self.predict_with_uncertainty(features)

        if result['needs_review']:
            self.active_learning.add_uncertain_sample(
                features,
                result['is_attack'],
                result['confidence'],
                result['prediction_distribution']
            )

            if len(self.active_learning.uncertainty_buffer) >= 20:
                reviewed = self.active_learning.request_human_review(batch_size=10)
                if reviewed:
                    self.active_learning.retrain_on_feedback(reviewed)

        return result

