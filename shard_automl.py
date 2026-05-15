#!/usr/bin/env python3
"""
SHARD AutoML — автоматический выбор лучшей модели под конкретную атаку
"""

import numpy as np
from collections import defaultdict
from typing import Dict, List, Tuple
import logging

logger = logging.getLogger("SHARD-AutoML")

class AutoMLSelector:
    """Автоматически выбирает лучшую модель для каждого типа атаки"""
    
    def __init__(self):
        self.model_scores = defaultdict(lambda: defaultdict(list))
        self.best_model_per_attack = {}
        
        # Модели которые можно выбрать
        self.available_models = [
            'xgboost', 'seq2seq', 'rl_agent', 'vae', 'gnn', 
            'fusion', 'temporal_gnn', 'attention_lstm'
        ]
        
        # Начальные веса — каждая модель специализируется на своём
        self.model_specialization = {
            'xgboost': ['SQL Injection', 'Brute Force', 'DDoS', 'Port Scan', 'XSS'],
            'seq2seq': ['SQL Injection', 'Brute Force', 'DDoS', 'C2 Beacon'],
            'rl_agent': ['Brute Force', 'DDoS', 'Data Exfiltration', 'Ransomware'],
            'vae': ['Zero-Day', 'DNS Tunnel', 'C2 Beacon'],
            'gnn': ['Botnet', 'Lateral Movement', 'C2 Beacon'],
            'fusion': ['ALL'],
            'temporal_gnn': ['C2 Beacon', 'Data Exfiltration', 'Lateral Movement'],
            'attention_lstm': ['Brute Force', 'Port Scan', 'DDoS'],
        }
    
    def record_result(self, attack_type: str, model_name: str, success: bool, confidence: float):
        """Записывает результат работы модели"""
        score = confidence if success else -confidence
        self.model_scores[attack_type][model_name].append(score)
        
        # Обновляем лучшую модель
        self._update_best_model(attack_type)
    
    def _update_best_model(self, attack_type: str):
        """Обновляет лучшую модель для типа атаки"""
        if attack_type not in self.model_scores:
            return
        
        best_model = None
        best_score = -999
        
        for model, scores in self.model_scores[attack_type].items():
            if len(scores) < 5:
                continue
            avg_score = sum(scores[-20:]) / len(scores[-20:])
            if avg_score > best_score:
                best_score = avg_score
                best_model = model
        
        if best_model:
            self.best_model_per_attack[attack_type] = best_model
    
    def get_best_model(self, attack_type: str) -> str:
        """Возвращает лучшую модель для атаки"""
        if attack_type in self.best_model_per_attack:
            return self.best_model_per_attack[attack_type]
        
        # Возвращаем модель по специализации
        for model, attacks in self.model_specialization.items():
            if attack_type in attacks or 'ALL' in attacks:
                return model
        
        return 'fusion'  # По умолчанию — fusion ансамбль
    
    def get_top_models(self, attack_type: str, top_k: int = 3) -> List[Tuple[str, float]]:
        """Топ-K моделей для атаки"""
        if attack_type not in self.model_scores:
            return [(self.get_best_model(attack_type), 1.0)]
        
        model_avgs = []
        for model, scores in self.model_scores[attack_type].items():
            if len(scores) >= 3:
                avg = sum(scores[-10:]) / len(scores[-10:])
                model_avgs.append((model, avg))
        
        model_avgs.sort(key=lambda x: -x[1])
        return model_avgs[:top_k]
    
    def get_stats(self) -> Dict:
        """Статистика AutoML"""
        return {
            'attacks_tracked': len(self.model_scores),
            'best_models': dict(self.best_model_per_attack),
            'total_predictions': sum(
                len(scores) 
                for attack in self.model_scores.values() 
                for scores in attack.values()
            ),
        }

# Глобальный селектор
_automl = AutoMLSelector()

def get_automl() -> AutoMLSelector:
    return _automl

def select_model_for_attack(attack_type: str) -> str:
    """Выбрать лучшую модель для атаки"""
    return _automl.get_best_model(attack_type)

def record_model_result(attack_type: str, model: str, success: bool, confidence: float):
    """Записать результат для обучения AutoML"""
    _automl.record_result(attack_type, model, success, confidence)
