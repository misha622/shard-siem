#!/usr/bin/env python3
"""
SHARD RL Defence Integration — связывает DQN агента с Defence Pipeline
Принимает решения о блокировке на основе обученной RL модели
"""

import torch
import torch.nn as nn
import numpy as np
import logging
import time
from pathlib import Path
from typing import Dict, Tuple

logger = logging.getLogger("SHARD-RL-Integration")


class DQN(nn.Module):
    def __init__(self, state_dim=10, hidden_dim=128, n_actions=5):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(state_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, n_actions),
        )
    
    def forward(self, x):
        return self.net(x)


ACTIONS = {
    0: ('ignore', 'Игнорировать', 0),
    1: ('log_increased', 'Усилить логирование', 10),
    2: ('throttle', 'Замедлить трафик', 50),
    3: ('block_temp', 'Временно заблокировать IP (1 час)', 200),
    4: ('block_perm', 'Перманентно заблокировать IP', 500),
}

class RLDefenseAgent:
    
    def __init__(self, model_path='./models/rl_defense/dqn_model.pt'):
        self.model_path = Path(model_path)
        self.model = None
        self.config = None
        self.loaded = False
        self.optimal_actions = {}
        self.severity_map = {}
        
        self.stats = {
            'decisions': 0,
            'blocks': 0,
            'throttles': 0,
            'ignores': 0,
            'logs': 0,
        }
        
        self._load()
    
    def _load(self):
        try:
            if self.model_path.exists():
                checkpoint = torch.load(self.model_path, map_location='cpu', weights_only=False)
                
                self.config = checkpoint.get('config', {})
                state_dim = self.config.get('state_dim', 10)
                hidden_dim = self.config.get('hidden_dim', 128)
                n_actions = self.config.get('n_actions', 5)
                
                self.model = DQN(state_dim, hidden_dim, n_actions)
                self.model.load_state_dict(checkpoint['policy_net'])
                self.model.eval()
                
                self.optimal_actions = checkpoint.get('optimal_actions', {})
                self.severity_map = checkpoint.get('severity_map', {})
                
                self.loaded = True
                logger.info(f"✅ RL Defence Agent загружен: {n_actions} действий, "
                           f"ε={checkpoint.get('epsilon', 0.05):.3f}")
            else:
                logger.warning(f"RL модель не найдена: {self.model_path}")
        except Exception as e:
            logger.error(f"Ошибка загрузки RL модели: {e}")
    
    def _extract_state(self, alert: Dict) -> np.ndarray:
        try:
            attack_type = alert.get('attack_type', 'Unknown')
            severity_str = alert.get('severity', 'LOW')
            
            severity_map = {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
            severity_num = severity_map.get(severity_str, 1)
            
            state = np.array([
                alert.get('score', 0.5),
                alert.get('confidence', 0.5),
                severity_num / 4.0,
                alert.get('dst_port', 80) / 65535.0,
                time.localtime().tm_hour / 24.0,
                time.localtime().tm_wday / 7.0,
                6.0 / 255.0,
                min(1.0, alert.get('connection_rate', 0.1)),
                min(1.0, alert.get('unique_ips', 1) / 100.0),
                min(1.0, alert.get('bytes_sent', 0) / 1e9),
            ], dtype=np.float32)
            
            return state
        except Exception as e:
            logger.debug(f"State extraction error: {e}")
            return np.zeros(10, dtype=np.float32)
    
    def decide_action(self, alert: Dict) -> Tuple[int, str, str]:
        if not self.loaded:
            severity = alert.get('severity', 'LOW')
            score = alert.get('score', 0)
            
            if severity in ['CRITICAL'] or score > 0.85:
                return 4, 'block_perm', 'Перманентная блокировка'
            elif severity in ['HIGH'] or score > 0.7:
                return 3, 'block_temp', 'Временная блокировка'
            elif severity in ['MEDIUM'] or score > 0.5:
                return 2, 'throttle', 'Замедление трафика'
            elif score > 0.3:
                return 1, 'log_increased', 'Усиленное логирование'
            else:
                return 0, 'ignore', 'Игнорировать'
        
        try:
            state = self._extract_state(alert)
            state_tensor = torch.tensor(state, dtype=torch.float32).unsqueeze(0)
            
            with torch.no_grad():
                q_values = self.model(state_tensor)
                action_id = q_values.argmax().item()
            
            self.stats['decisions'] += 1
            if action_id >= 3:
                self.stats['blocks'] += 1
            elif action_id == 2:
                self.stats['throttles'] += 1
            elif action_id == 1:
                self.stats['logs'] += 1
            else:
                self.stats['ignores'] += 1
            
            action_name, action_desc, cost = ACTIONS.get(action_id, ('unknown', 'Неизвестно', 0))
            
            logger.info(f"🤖 RL Decision: {action_name} "
                       f"(score={alert.get('score', 0):.2f}, severity={alert.get('severity', '?')})")
            
            return action_id, action_name, action_desc
            
        except Exception as e:
            logger.error(f"RL decision error: {e}")
            return 2, 'throttle', 'Замедление трафика (fallback)'
    
    def get_action_cost(self, action_id: int) -> int:
        return ACTIONS.get(action_id, ('unknown', 'Неизвестно', 0))[2]
    
    def get_stats(self) -> Dict:
        return {
            **self.stats,
            'loaded': self.loaded,
            'model_path': str(self.model_path),
        }
