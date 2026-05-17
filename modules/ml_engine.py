#!/usr/bin/env python3
"""SHARD MachineLearningEngine Module"""
from core.base import BaseModule, ConfigManager, EventBus, LoggingService
import os, time, threading, json, joblib, numpy as np
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict, deque
from pathlib import Path

# Импорты из главного файла (для обратной совместимости)
try:
    # Models imported from shared module
        from modules.ml_models import SelfSupervisedEncoder, ThreatGNN
except ImportError:
    SelfSupervisedEncoder = None
    ThreatGNN = None

# Глобальные переменные из главного файла
try:
    from shard_enterprise_complete import shap_module, xgboost_module, sklearn_ensemble
except ImportError:
    shap_module = None
    xgboost_module = None
    sklearn_ensemble = None

class MachineLearningEngine(BaseModule):
    """ML движок с дообучением и Deep Learning моделями (LSTM + VAE + Transformer)"""

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("ML", config, event_bus, logger)
        self.model_path = Path(config.get('ml.model_path', './models/'))
        self.model_path.mkdir(parents=True, exist_ok=True)

        self.models = {}
        self.scaler = None
        self.features = []
        self.normal_buffer: deque = deque(maxlen=5000)
        self.attack_buffer: deque = deque(maxlen=5000)
        self.online_learning = config.get('ml.online_learning', True)
        self.retrain_interval = config.get('ml.retrain_interval', 300)
        self.retrain_min_samples = config.get('ml.retrain_min_samples', 100)
        self.confidence_threshold = config.get('ml.confidence_threshold', 0.7)
        self.anomaly_threshold = config.get('ml.anomaly_threshold', -0.15)
        self.use_xgboost = 'xgboost' in config.get('ml.ensemble', [])
        self.explain_with_shap = config.get('ml.explain_with_shap', True)
        self.use_deep_learning = config.get('ml.use_deep_learning', True)

        self.shap_explainer = None
        self.shap_background_data = []
        self.ssl_model = SelfSupervisedEncoder(input_dim=156) if SelfSupervisedEncoder else None
        self.gnn_model = ThreatGNN() if ThreatGNN else None

        # Deep Learning Engine
        self.dl_engine = None
        if self.use_deep_learning:
            try:
                from shard_dl_models import DeepLearningEngine
                self.dl_engine = DeepLearningEngine()
                self.logger.info("Deep Learning Engine инициализирован")
            except ImportError:
                self.logger.warning("shard_dl_models не найден, Deep Learning отключен")
                self.use_deep_learning = False

        # Автосохранение (ТОЛЬКО ОДИН РАЗ)
        self._autosave_interval = 300
        self._last_save = time.time()
        self._save_thread = None
        self._models_dirty = False
        self._model_reliable = False
        self._samples_since_init = 0
        self._save_lock = threading.RLock()

        # Буфер для последовательностей (ТОЛЬКО ОДИН РАЗ)
        self.sequence_buffer: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))

        # Счётчик для GNN
        self._gnn_packet_counter = 0
        self._last_dst_ip = "0.0.0.0"
        self._last_dst_port = 0

        # Ссылки на улучшения
        self.temporal_gnn = None
        self.contrastive_vae = None
        self.rl_defense = None

        self._lock = threading.RLock()
        self._load_models()
        self._init_shap()

        self.event_bus.subscribe('packet.features', self.on_features)

    def _init_shap(self) -> None:
        """Инициализация SHAP объяснителя"""
        if not self.explain_with_shap:
            return

        if shap_module is None:
            self.logger.warning("SHAP не установлен, объяснения отключены")
            self.explain_with_shap = False
            return

        self.shap_background_data = []
        self.logger.debug("SHAP будет инициализирован при накоплении данных")

    def _initialize_shap_explainer(self, background_samples: List[List[float]]) -> None:
        """Создание SHAP объяснителя с фоновыми данными"""
        if not self.explain_with_shap or shap_module is None:
            return

        try:
            import shap
            import numpy as np

            X_background = np.array(background_samples)
            if self.scaler and self._is_scaler_fitted():
                X_background = self.scaler.transform(X_background)

            if 'xgb' in self.models and self.use_xgboost:
                model = self.models['xgb']
                self.shap_explainer = shap.TreeExplainer(model)
                self.logger.info("SHAP TreeExplainer инициализирован для XGBoost")

            elif 'if' in self.models:
                model = self.models['if']
                if len(X_background) > 50:
                    X_background = X_background[:50]

                def predict_fn(x):
                    scores = model.score_samples(x)
                    return (scores + 0.5) / 0.5

                self.shap_explainer = shap.KernelExplainer(predict_fn, X_background)
                self.logger.info("SHAP KernelExplainer инициализирован для Isolation Forest")

        except Exception as e:
            self.logger.error(f"Ошибка инициализации SHAP: {e}")
            self.explain_with_shap = False

    def _is_scaler_fitted(self) -> bool:
        """Проверка что scaler обучен"""
        if self.scaler is None:
            return False
        try:
            return hasattr(self.scaler, 'mean_') and hasattr(self.scaler, 'scale_')
        except:
            return False

    def _get_class_index(self, attack_type: str) -> int:
        """Получение индекса класса для SHAP"""
        class_map = {
            'Normal': 0,
            'DoS': 1,
            'DDoS': 2,
            'Brute Force': 3,
            'Web Attack': 4,
            'Botnet': 5,
            'Port Scan': 8
        }
        return class_map.get(attack_type, 0)

    def explain_prediction(self, features: List[float]) -> Dict:
        """Подробное объяснение предсказания"""
        if not self.explain_with_shap or not self.shap_explainer:
            return {'error': 'SHAP не инициализирован'}

        try:
            import numpy as np

            X = np.array([features])
            if self.scaler and self._is_scaler_fitted():
                X = self.scaler.transform(X)

            shap_values = self.shap_explainer.shap_values(X)

            if isinstance(shap_values, list):
                shap_vals = shap_values[0][0] if len(shap_values) > 0 else []
            else:
                shap_vals = shap_values[0]

            explanations = []
            for idx, shap_val in enumerate(shap_vals):
                if idx < len(self.features) and abs(shap_val) > 0.01:
                    explanations.append({
                        'feature': self.features[idx],
                        'value': features[idx] if idx < len(features) else None,
                        'shap_value': float(shap_val),
                        'impact': 'positive' if shap_val > 0 else 'negative',
                        'importance': abs(float(shap_val))
                    })

            explanations.sort(key=lambda x: x['importance'], reverse=True)
            total_impact = sum(e['shap_value'] for e in explanations)

            expected_value = 0.0
            if hasattr(self.shap_explainer, 'expected_value'):
                ev = self.shap_explainer.expected_value
                if isinstance(ev, (list, np.ndarray)) and len(ev) > 0:
                    expected_value = float(ev[0]) if isinstance(ev[0], (int, float)) else 0.0
                else:
                    expected_value = float(ev) if isinstance(ev, (int, float)) else 0.0

            return {
                'explanations': explanations[:10],
                'total_impact': float(total_impact),
                'prediction': 'attack' if total_impact > 0 else 'normal',
                'base_value': expected_value
            }

        except Exception as e:
            return {'error': str(e)}

    def _load_models(self) -> None:
        """Загрузка моделей"""
        try:
            import joblib

            if_path = self.model_path / 'shard_enterprise_model_if.pkl'
            if if_path.exists() and joblib:
                self.models['if'] = joblib.load(if_path)
                self.logger.info("Isolation Forest загружен")
            else:
                self._init_isolation_forest()

            if self.use_xgboost and xgboost_module:
                xgb_path = self.model_path / 'shard_enterprise_model_xgb.pkl'
                if xgb_path.exists() and joblib:
                    self.models['xgb'] = joblib.load(xgb_path)
                    self.logger.info("XGBoost загружен")
                else:
                    self._init_xgboost()

            rf_path = self.model_path / 'shard_enterprise_model_rf.pkl'
            if rf_path.exists() and joblib:
                self.models['rf'] = joblib.load(rf_path)

            scaler_path = self.model_path / 'shard_enterprise_scaler.pkl'
            if scaler_path.exists() and joblib:
                self.scaler = joblib.load(scaler_path)

            features_path = self.model_path / 'shard_enterprise_features.pkl'
            if features_path.exists() and joblib:
                self.features = joblib.load(features_path)
            else:
                self._init_features()

        except Exception as e:
            self.logger.warning(f"Ошибка загрузки моделей: {e}")
            self._init_features()
            self._init_isolation_forest()

    def _init_features(self) -> None:
        """Инициализация признаков"""
        self.features = [f'payload_byte_{i + 1}' for i in range(150)]
        self.features.extend([
            'payload_entropy', 'packet_size', 'protocol',
            'ttl', 'src_port', 'dst_port'
        ])

    def _init_isolation_forest(self) -> None:
        """Инициализация Isolation Forest"""
        if sklearn_ensemble:
            from sklearn.ensemble import IsolationForest
            import numpy as np

            self.models['if'] = IsolationForest(
                n_estimators=100,
                contamination=0.1,
                random_state=42,
                n_jobs=-1
            )

            pretrained_path = self.model_path / 'shard_enterprise_model_if_pretrained.pkl'
            if pretrained_path.exists() and joblib:
                try:
                    self.models['if'] = joblib.load(pretrained_path)
                    self.logger.info("✅ Загружена предобученная Isolation Forest модель")
                    self._model_reliable = True
                    return
                except Exception as e:
                    self.logger.warning(f"Ошибка загрузки предобученной модели: {e}")

            saved_path = self.model_path / 'shard_enterprise_model_if.pkl'
            if saved_path.exists() and joblib:
                try:
                    self.models['if'] = joblib.load(saved_path)
                    self.logger.info("✅ Загружена сохранённая Isolation Forest модель")
                    self._model_reliable = True
                    return
                except Exception as e:
                    self.logger.warning(f"Ошибка загрузки сохранённой модели: {e}")

            dummy_data = np.random.randn(100, len(self.features))
            for i in range(len(dummy_data)):
                dummy_data[i] = dummy_data[i] * 0.3
                if len(dummy_data[i]) > 150:
                    dummy_data[i][150] = np.random.uniform(0, 0.3)
                    dummy_data[i][151] = np.random.uniform(64, 1500)

            self.models['if'].fit(dummy_data)
            self._model_reliable = False
            self._samples_since_init = 0

            self.logger.warning(
                "⚠️ Isolation Forest инициализирован на синтетических данных. "
                "Требуется дообучение на реальном трафике!"
            )

    def _init_xgboost(self) -> None:
        """Инициализация XGBoost с предустановленными классами"""
        if xgboost_module:
            self.models['xgb'] = xgboost_module.XGBClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                objective='multi:softprob',
                num_class=10,
                random_state=42,
                verbosity=0
            )
            self.logger.info("XGBoost инициализирован")

    def start(self) -> None:
        self.running = True
        if self.online_learning:
            threading.Thread(target=self._retrain_loop, daemon=True, name="ML-Retrain").start()
        threading.Thread(target=self._load_history_async, daemon=True, name="ML-LoadHistory").start()
        self._save_thread = threading.Thread(target=self._autosave_loop, daemon=True, name="ML-Autosave")
        self._save_thread.start()

        if self.use_deep_learning and self.dl_engine:
            self.dl_engine.start()

        self.logger.info(
            f"ML запущен (online: {self.online_learning}, XGBoost: {self.use_xgboost}, DL: {self.use_deep_learning})")

    def stop(self) -> None:
        self.running = False
        with self._save_lock:
            self._save_models()
            self._models_dirty = False
        if self._save_thread and self._save_thread.is_alive():
            self._save_thread.join(timeout=2)

        if self.use_deep_learning and self.dl_engine:
            self.dl_engine.stop()

        self.logger.info("ML остановлен, модели сохранены")

    def _autosave_loop(self) -> None:
        """Периодическое автосохранение моделей"""
        while self.running:
            time.sleep(60)
            with self._save_lock:
                if self._models_dirty and time.time() - self._last_save >= self._autosave_interval:
                    self._save_models()
                    self._models_dirty = False
                    self._last_save = time.time()

    def _save_models(self) -> None:
        """Атомарное сохранение моделей"""
        if not joblib:
            return

        try:
            temp_files = []

            if 'if' in self.models:
                temp_path = self.model_path / 'shard_enterprise_model_if.pkl.tmp'
                joblib.dump(self.models['if'], temp_path)
                temp_files.append((temp_path, self.model_path / 'shard_enterprise_model_if.pkl'))

            if 'xgb' in self.models:
                temp_path = self.model_path / 'shard_enterprise_model_xgb.pkl.tmp'
                joblib.dump(self.models['xgb'], temp_path)
                temp_files.append((temp_path, self.model_path / 'shard_enterprise_model_xgb.pkl'))

            if self.scaler:
                temp_path = self.model_path / 'shard_enterprise_scaler.pkl.tmp'
                joblib.dump(self.scaler, temp_path)
                temp_files.append((temp_path, self.model_path / 'shard_enterprise_scaler.pkl'))

            temp_path = self.model_path / 'shard_enterprise_features.pkl.tmp'
            joblib.dump(self.features, temp_path)
            temp_files.append((temp_path, self.model_path / 'shard_enterprise_features.pkl'))

            for temp_path, final_path in temp_files:
                if temp_path.exists():
                    import os
                    os.replace(str(temp_path), str(final_path))

            self.logger.debug("Модели сохранены (автосохранение)")

        except Exception as e:
            self.logger.error(f"Ошибка сохранения: {e}")

    def _load_history_async(self) -> None:
        """Асинхронная загрузка исторических данных (через общий пул)"""
        try:
            # Пробуем через общий SIEM пул
            if hasattr(self, 'siem_storage') and self.siem_storage:
                conn = self.siem_storage._get_sqlite_connection()
                own_conn = False
            else:
                import sqlite3
                conn = sqlite3.connect('shard_siem.db')
                own_conn = True
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute(
                '''SELECT features_json, attack_type FROM alerts 
                   WHERE features_json IS NOT NULL 
                   ORDER BY timestamp DESC LIMIT 500'''
            )
            rows = cursor.fetchall()
            if own_conn:
                conn.close()
            elif hasattr(self, 'siem_storage') and self.siem_storage:
                self.siem_storage._return_sqlite_connection(conn)

            loaded = 0
            for row in rows:
                try:
                    features = json.loads(row[0])
                    attack_type = row[1] if row[1] else 'Normal'

                    with self._lock:
                        if attack_type != 'Normal':
                            self.attack_buffer.append((features, attack_type))
                        else:
                            self.normal_buffer.append(features)
                    loaded += 1
                except:
                    pass

            self.logger.info(f"Загружено {loaded} исторических сэмплов")
        except Exception as e:
            self.logger.warning(f"Ошибка загрузки истории: {e}")

    def on_features(self, data: Dict) -> None:
        """Обработка признаков"""
        features = data.get('features')
        if not features:
            return
        
        src_ip = data.get('src_ip', 'unknown')
        
        # Инициализируем adaptive_result
        adaptive_result = {'is_anomaly': False, 'overall_score': 0.0}
        
        if hasattr(self, 'adaptive_engine') and self.adaptive_engine:
            adaptive_result = self.adaptive_engine.process_packet(src_ip, features)
            if adaptive_result['is_anomaly']:
                self.logger.info(f"Adaptive Learning anomaly: score={adaptive_result['overall_score']:.3f}")
        
        prediction = self._predict(features, src_ip)
        
        if prediction['is_attack'] and prediction['confidence'] >= self.confidence_threshold:
            prediction['src_ip'] = src_ip
            prediction['dst_ip'] = data.get('dst_ip', 'unknown')
            prediction['dst_port'] = data.get('dst_port', 0)
            
            ssl_score = self.ssl_model.get_anomaly_score(features) if self.ssl_model else 0.5
            if ssl_score > 0.7:
                prediction['score'] = max(prediction['score'], ssl_score)
                prediction['ssl_anomaly'] = True
            
            if hasattr(self, 'adaptive_engine') and self.adaptive_engine:
                if adaptive_result.get('is_anomaly', False):
                    prediction['score'] = max(prediction['score'], adaptive_result['overall_score'])
                    prediction['adaptive_detected'] = True
            
            self.event_bus.publish('alert.detected', prediction)
            
            if self.online_learning:
                with self._lock:
                    self.attack_buffer.append((features, prediction['attack_type']))
        
        elif not prediction['is_attack'] and prediction['confidence'] >= self.confidence_threshold:
            if self.online_learning:
                with self._lock:
                    self.normal_buffer.append(features)
                    self._samples_since_init += 1

    def _predict(self, features: List[float], device: str = "unknown") -> Dict:
        """Предсказание с использованием ML и DL моделей"""
        result = {
            'is_attack': False,
            'score': 0.0,
            'confidence': 0.0,
            'attack_type': 'Normal',
            'timestamp': time.time()
        }

        try:
            import numpy as np

            X = np.array([features])

            if self.scaler and self._is_scaler_fitted():
                X = self.scaler.transform(X)

            # Isolation Forest
            if 'if' in self.models:
                if_score = float(self.models['if'].score_samples(X)[0])
                normalized_score = 1.0 - (if_score + 0.5)
                normalized_score = max(0.0, min(1.0, normalized_score))

                result['score'] = normalized_score

                threshold = self.anomaly_threshold
                if not self._model_reliable:
                    threshold = threshold * 1.5

                result['is_attack'] = if_score < threshold
                distance = abs(if_score - threshold)
                result['confidence'] = min(0.99, distance / 0.5)

                if not self._model_reliable:
                    result['confidence'] *= 0.5

            # ========== ИНТЕГРАЦИЯ С УЛУЧШЕНИЯМИ ==========

            # Temporal GNN - анализ графа угроз
            if hasattr(self, 'temporal_gnn') and self.temporal_gnn is not None:
                try:
                    # Обновляем граф каждые 50 пакетов для производительности
                    self._gnn_packet_counter = getattr(self, '_gnn_packet_counter', 0) + 1

                    if self._gnn_packet_counter % 50 == 0:
                        # Получаем данные о соединении из контекста (если доступны)
                        src_ip = device
                        dst_ip = getattr(self, '_last_dst_ip', '0.0.0.0')
                        dst_port = getattr(self, '_last_dst_port', 0)
                        protocol = 6  # TCP по умолчанию
                        bytes_count = int(features[151]) if len(features) > 151 else 1000

                        self.temporal_gnn.add_connection(src_ip, dst_ip, 0, dst_port, protocol, bytes_count, 1)

                        # Анализируем граф каждые 500 пакетов
                        if self._gnn_packet_counter % 500 == 0:
                            gnn_result = self.temporal_gnn.process_time_window()
                            if gnn_result and gnn_result.get('is_graph_anomaly'):
                                gnn_score = gnn_result.get('graph_score', 0.5)
                                result['is_attack'] = result['is_attack'] or (gnn_score > 0.6)
                                result['score'] = max(result['score'], gnn_score)
                                result['confidence'] = max(result['confidence'], 0.7)
                                result['gnn_detected'] = True
                                result['gnn_details'] = {
                                    'graph_score': gnn_score,
                                    'anomalous_nodes': gnn_result.get('anomalous_nodes', [])[:5],
                                    'num_nodes': gnn_result.get('num_nodes', 0),
                                    'num_edges': gnn_result.get('num_edges', 0)
                                }
                                self.logger.debug(f"GNN detected anomaly: score={gnn_score:.3f}")
                except Exception as e:
                    self.logger.debug(f"GNN prediction error: {e}")

            # Contrastive VAE - анализ вектора признаков
            if hasattr(self, 'contrastive_vae') and self.contrastive_vae is not None:
                try:
                    vae_result = self.contrastive_vae.predict_anomaly(features)
                    if vae_result and vae_result.get('is_anomaly'):
                        vae_score = vae_result.get('score', 0.5)
                        result['is_attack'] = result['is_attack'] or (vae_score > 0.55)
                        result['score'] = max(result['score'], vae_score)
                        result['confidence'] = max(result['confidence'], vae_score)
                        result['vae_detected'] = True
                        result['vae_details'] = {
                            'reconstruction_score': vae_result.get('reconstruction_score', 0),
                            'latent_score': vae_result.get('latent_score', 0),
                            'mse': vae_result.get('mse', 0)
                        }
                        self.logger.debug(f"VAE detected anomaly: score={vae_score:.3f}")
                except Exception as e:
                    self.logger.debug(f"VAE prediction error: {e}")

            # Определение типа атаки
            if result['is_attack']:
                if 'xgb' in self.models and self.use_xgboost:
                    try:
                        proba = self.models['xgb'].predict_proba(X)[0]
                        attack_id = int(np.argmax(proba))
                        confidence = float(proba[attack_id])

                        attack_map = {
                            1: 'DoS', 2: 'DDoS', 3: 'Brute Force',
                            4: 'Web Attack', 5: 'Botnet', 8: 'Port Scan'
                        }
                        result['attack_type'] = attack_map.get(attack_id, 'Unknown')
                        result['confidence'] = max(result['confidence'], confidence)
                    except Exception as e:
                        self.logger.debug(f"XGBoost prediction error: {e}")
                        result['attack_type'] = 'Anomaly'
                else:
                    result['attack_type'] = 'Anomaly'

                # Если обнаружено через GNN или VAE, уточняем тип атаки
                if result.get('gnn_detected') and not result.get('vae_detected'):
                    if result['attack_type'] == 'Anomaly':
                        result['attack_type'] = 'Lateral Movement'
                elif result.get('vae_detected') and not result.get('gnn_detected'):
                    if result['attack_type'] == 'Anomaly':
                        result['attack_type'] = 'Data Exfiltration'

                # SHAP объяснение
                if self.explain_with_shap and self.shap_explainer:
                    try:
                        shap_values = self.shap_explainer.shap_values(X)
                        if isinstance(shap_values, list):
                            shap_values = shap_values[0]

                        if len(shap_values) > 0 and len(shap_values[0]) > 0:
                            top_indices = np.argsort(np.abs(shap_values[0]))[-3:]
                            explanations = []
                            for idx in top_indices:
                                if idx < len(self.features):
                                    explanations.append(self.features[idx])

                            if explanations:
                                result['shap_explanation'] = f"Важные признаки: {', '.join(explanations)}"
                    except Exception as e:
                        self.logger.debug(f"SHAP error: {e}")

            # ========== RL DEFENSE - РЕКОМЕНДАЦИЯ ПО ЗАЩИТЕ ==========
            if hasattr(self, 'rl_defense') and self.rl_defense is not None and result['is_attack']:
                try:
                    alert_state = {
                        'alert_score': result['score'],
                        'alert_count': 1,
                        'connection_rate': getattr(self, '_connection_rate', 10),
                        'unique_ports': getattr(self, '_unique_ports', 1),
                        'bytes_transferred': int(features[151]) if len(features) > 151 else 1000,
                        'is_internal': device.startswith(('192.168.', '10.', '172.', '127.')),
                        'hour_of_day': time.localtime().tm_hour,
                        'day_of_week': time.localtime().tm_wday
                    }
                    action_id, action_name = self.rl_defense.agent.act(alert_state, training=False)
                    result['rl_recommended_action'] = action_name
                    result['rl_action_id'] = action_id
                    self.logger.debug(f"RL Defense recommends: {action_name} (score={result['score']:.3f})")
                except Exception as e:
                    self.logger.debug(f"RL Defense error: {e}")

        except Exception as e:
            self.logger.debug(f"Prediction error: {e}")
            result['score'] = 0.5
            result['confidence'] = 0.3

        return result

    def _retrain_loop(self) -> None:
        """Цикл дообучения"""
        while self.running:
            time.sleep(self.retrain_interval)

            with self._lock:
                total = len(self.normal_buffer) + len(self.attack_buffer)
                if total >= self.retrain_min_samples:
                    self._retrain()

    def _retrain(self) -> None:
        """Дообучение моделей (без потери данных при ошибке)"""
        with self._lock:
            normal = list(self.normal_buffer)
            attacks = list(self.attack_buffer)
            # Очищаем только после успешного обучения
            _normal_backup = normal.copy()
            _attacks_backup = attacks.copy()

        if not normal and not attacks:
            return

        self.logger.info(f"🔄 Дообучение на {len(normal)} нормальных и {len(attacks)} атаках")

        try:
            import numpy as np
            scaler_fitted = self._is_scaler_fitted()

            # Isolation Forest
            if 'if' in self.models and len(normal) >= 50:
                X_normal = np.array(normal)

                if scaler_fitted and self.scaler:
                    try:
                        X_normal = self.scaler.transform(X_normal)
                    except Exception as e:
                        self.logger.warning(f"Ошибка масштабирования IF: {e}")

                if hasattr(self.models['if'], 'estimators_'):
                    current_trees = len(self.models['if'].estimators_)
                    self.models['if'].set_params(n_estimators=current_trees + 10)
                    self.models['if'].fit(X_normal)
                    self.logger.info(f"   IF: +10 деревьев (всего {current_trees + 10})")
                else:
                    self.models['if'].fit(X_normal)
                    self.logger.info(f"   IF: инициализирован на {len(normal)} сэмплах")

            # SSL модель
            for features in normal[:100]:
                self.ssl_model.train_step([features])

            # XGBoost с балансированным дообучением
            if 'xgb' in self.models and len(attacks) >= 10 and len(normal) >= 10:
                X_attacks = np.array([a[0] for a in attacks])
                y_attacks = np.array([self._attack_to_id(a[1]) for a in attacks])
                
                # Добавляем нормальные сэмплы чтобы модель не смещалась
                X_normal = np.array(normal[:len(attacks)])
                y_normal = np.zeros(len(X_normal))
                
                X_balanced = np.vstack([X_attacks, X_normal])
                y_balanced = np.hstack([y_attacks, y_normal])
                
                shuffle_idx = np.random.permutation(len(X_balanced))
                X_balanced = X_balanced[shuffle_idx]
                y_balanced = y_balanced[shuffle_idx]

                if scaler_fitted and self.scaler:
                    try:
                        X_balanced = self.scaler.transform(X_balanced)
                    except Exception as e:
                        self.logger.warning(f"XGBoost scaling error: {e}")

                is_fitted = False
                try:
                    if hasattr(self.models['xgb'], 'get_booster'):
                        self.models['xgb'].get_booster()
                        is_fitted = True
                    elif hasattr(self.models['xgb'], '_Booster'):
                        is_fitted = self.models['xgb']._Booster is not None
                except:
                    pass

                if is_fitted:
                    try:
                        self.models['xgb'].fit(X_balanced, y_balanced, xgb_model=self.models['xgb'].get_booster())
                        self.logger.info("   XGBoost: дообучен (сбалансированный батч)")
                    except Exception as e:
                        self.logger.warning(f"XGBoost warm-start error: {e}")
                        self.models['xgb'].fit(X_balanced, y_balanced)
                        self.logger.info("   XGBoost: переобучен (сбалансированный батч)")
                else:
                    self.models['xgb'].fit(X_balanced, y_balanced)
                    self.logger.info("   XGBoost: инициализирован (сбалансированный батч)")

            # Отметка о надёжности
            if len(normal) >= 500:
                self._model_reliable = True
                self.logger.info("Модель помечена как надёжная")

            with self._save_lock:
                self._models_dirty = True

        except Exception as e:
            self.logger.error(f"Ошибка дообучения: {e}")
            with self._lock:
                self.normal_buffer.extend(_normal_backup)
                self.attack_buffer.extend(_attacks_backup)
            return
            import traceback
            self.logger.debug(traceback.format_exc())

    def _attack_to_id(self, attack_type: str) -> int:
        """Преобразование типа атаки в ID"""
        mapping = {
            'Normal': 0, 'DoS': 1, 'DDoS': 2, 'Brute Force': 3,
            'Web Attack': 4, 'Botnet': 5, 'Port Scan': 8
        }
        return mapping.get(attack_type, 99)

    def get_stats(self) -> Dict:
        """Получить статистику ML"""
        with self._lock:
            stats = {
                'normal_buffer_size': len(self.normal_buffer),
                'attack_buffer_size': len(self.attack_buffer),
                'online_learning': self.online_learning,
                'use_xgboost': self.use_xgboost,
                'explain_with_shap': self.explain_with_shap,
                'use_deep_learning': self.use_deep_learning,
                'scaler_fitted': self._is_scaler_fitted(),
                'models_loaded': list(self.models.keys()),
                'features_count': len(self.features),
                'autosave_interval': self._autosave_interval,
                'models_dirty': self._models_dirty,
                'model_reliable': self._model_reliable
            }

            if self.use_deep_learning and self.dl_engine:
                stats['dl_stats'] = self.dl_engine.ensemble.get_stats()

            return stats

    def save_now(self) -> None:
        """Принудительное сохранение моделей"""
        with self._save_lock:
            self._save_models()
            self._models_dirty = False
            self._last_save = time.time()
        self.logger.info("Модели сохранены принудительно")

    def reset_buffers(self) -> None:
        """Очистка буферов обучения"""
        with self._lock:
            self.normal_buffer.clear()
            self.attack_buffer.clear()
        self.logger.info("Буферы обучения очищены")

# ============================================================

# ============================================================
# THREAT GRAPH NETWORK
# ============================================================

