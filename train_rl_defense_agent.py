#!/usr/bin/env python3
"""
SHARD RL Defence Agent — Deep Q-Network (DQN)
Обучается на симулированных атаках выбирать оптимальную защиту
Без имитаций — реальный RL с reward за правильные действия
"""

import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
import random
import pickle
import json
import logging
from pathlib import Path
from collections import deque
from typing import Tuple, Dict, List

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SHARD-RL-Trainer")


CONFIG = {
    'state_dim': 10,
    'hidden_dim': 128,
    'n_actions': 5,
    'memory_size': 10000,
    'batch_size': 64,
    'gamma': 0.95,
    'epsilon_start': 1.0,
    'epsilon_end': 0.05,
    'epsilon_decay': 0.995,
    'lr': 0.001,
    'episodes': 500,
    'target_update': 10,
}

ACTIONS = {
    0: ('ignore', 'Игнорировать'),
    1: ('log', 'Усилить логирование'),
    2: ('throttle', 'Замедлить трафик'),
    3: ('block_temp', 'Заблокировать на 1 час'),
    4: ('block_perm', 'Перманентная блокировка'),
}


class DQN(nn.Module):
    """Deep Q-Network для выбора защитного действия"""
    
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


class ReplayMemory:
    """Experience Replay Buffer"""
    
    def __init__(self, capacity=10000):
        self.memory = deque(maxlen=capacity)
    
    def push(self, state, action, reward, next_state, done):
        self.memory.append((state, action, reward, next_state, done))
    
    def sample(self, batch_size):
        batch = random.sample(self.memory, min(batch_size, len(self.memory)))
        states, actions, rewards, next_states, dones = zip(*batch)
        return (
            torch.tensor(np.array(states), dtype=torch.float32),
            torch.tensor(actions, dtype=torch.long),
            torch.tensor(rewards, dtype=torch.float32),
            torch.tensor(np.array(next_states), dtype=torch.float32),
            torch.tensor(dones, dtype=torch.float32),
        )
    
    def __len__(self):
        return len(self.memory)



class AttackSimulator:
    """Генерирует реалистичные атаки для обучения RL"""
    
    def __init__(self):
        self.attack_types = [
            'Port Scan', 'Brute Force', 'DDoS', 'SQL Injection', 
            'C2 Beacon', 'Data Exfiltration', 'DNS Tunnel',
            'XSS', 'Botnet', 'Ransomware', 'Phishing', 'Zero-Day',
        ]
        
        self.severity_map = {
            'Port Scan': 1, 'Brute Force': 2, 'DDoS': 3, 'SQL Injection': 2,
            'C2 Beacon': 3, 'Data Exfiltration': 4, 'DNS Tunnel': 3,
            'XSS': 2, 'Botnet': 3, 'Ransomware': 4, 'Phishing': 2, 'Zero-Day': 4,
        }
        
        self.optimal_actions = {
            'Port Scan': 2,
            'Brute Force': 3,
            'DDoS': 4,
            'SQL Injection': 3,
            'C2 Beacon': 4,
            'Data Exfiltration': 4,
            'DNS Tunnel': 3,
            'XSS': 3,
            'Botnet': 4,
            'Ransomware': 4,
            'Phishing': 3,
            'Zero-Day': 4,
        }
    
    def generate_state(self) -> Tuple[np.ndarray, str, int]:
        """Генерирует состояние для RL агента"""
        attack_type = random.choice(self.attack_types)
        severity = self.severity_map[attack_type]
        
        state = np.array([
            np.random.uniform(0.3, 1.0),
            np.random.uniform(0.5, 0.99),
            severity / 4.0,
            random.choice([22,80,443,3306,445,3389,4444,5555]) / 65535.0,
            np.random.randint(0, 24) / 24.0,
            np.random.randint(0, 7) / 7.0,
            random.choice([6, 17]) / 255.0,
            np.random.uniform(0, 1.0),
            np.random.uniform(0, 0.3),
            np.random.uniform(0, 1.0),
        ], dtype=np.float32)
        
        return state, attack_type, severity
    
    def get_reward(self, action: int, attack_type: str, blocked_before: bool) -> float:
        """
        Вычисляет награду за действие.
        Положительная — правильная блокировка.
        Отрицательная — ложное срабатывание или пропуск атаки.
        """
        optimal = self.optimal_actions[attack_type]
        severity = self.severity_map[attack_type]
        
        if action == optimal:
            return 1.0 * severity
        
        if abs(action - optimal) == 1:
            return 0.3 * severity
        
        if action < optimal and severity >= 3:
            return -1.0 * severity
        
        if action > optimal and severity <= 2:
            return -0.5
        
        if action == 0 and optimal >= 3:
            return -2.0 * severity
        
        if action >= 3 and severity <= 1:
            return -1.0
        
        return 0.0



class RLDefenseTrainer:
    """Тренер RL Defence Agent"""
    
    def __init__(self):
        self.policy_net = DQN(CONFIG['state_dim'], CONFIG['hidden_dim'], CONFIG['n_actions'])
        self.target_net = DQN(CONFIG['state_dim'], CONFIG['hidden_dim'], CONFIG['n_actions'])
        self.target_net.load_state_dict(self.policy_net.state_dict())
        
        self.optimizer = optim.Adam(self.policy_net.parameters(), lr=CONFIG['lr'])
        self.memory = ReplayMemory(CONFIG['memory_size'])
        self.simulator = AttackSimulator()
        
        self.epsilon = CONFIG['epsilon_start']
        self.episode_rewards: List[float] = []
        self.episode_losses: List[float] = []
        self.action_counts = {i: 0 for i in range(CONFIG['n_actions'])}
    
    def select_action(self, state: np.ndarray, training: bool = True) -> int:
        """Выбор действия: ε-greedy"""
        if training and random.random() < self.epsilon:
            return random.randint(0, CONFIG['n_actions'] - 1)
        
        with torch.no_grad():
            state_tensor = torch.tensor(state, dtype=torch.float32).unsqueeze(0)
            q_values = self.policy_net(state_tensor)
            return q_values.argmax().item()
    
    def train_episode(self) -> float:
        """Один эпизод обучения"""
        state, attack_type, severity = self.simulator.generate_state()
        total_reward = 0.0
        
        action = self.select_action(state, training=True)
        self.action_counts[action] += 1
        
        reward = self.simulator.get_reward(action, attack_type, False)
        total_reward += reward
        
        next_state = state + np.random.normal(0, 0.05, size=state.shape)
        next_state = np.clip(next_state, 0, 1)
        
        done = True
        
        self.memory.push(state, action, reward, next_state, done)
        
        loss = 0.0
        if len(self.memory) >= CONFIG['batch_size']:
            loss = self._optimize()
        
        return total_reward, loss
    
    def _optimize(self) -> float:
        """Один шаг оптимизации"""
        states, actions, rewards, next_states, dones = self.memory.sample(CONFIG['batch_size'])
        
        q_values = self.policy_net(states)
        q_values = q_values.gather(1, actions.unsqueeze(1)).squeeze()
        
        with torch.no_grad():
            next_q_values = self.target_net(next_states).max(1)[0]
            target_q = rewards + CONFIG['gamma'] * next_q_values * (1 - dones)
        
        loss = nn.functional.smooth_l1_loss(q_values, target_q)
        
        self.optimizer.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(self.policy_net.parameters(), 10.0)
        self.optimizer.step()
        
        return loss.item()
    
    def train(self, episodes: int = None):
        """Полный цикл обучения"""
        episodes = episodes or CONFIG['episodes']
        
        logger.info(f"\n🔄 Training RL Agent: {episodes} episodes...")
        logger.info(f"   Actions: {[ACTIONS[i][0] for i in range(CONFIG['n_actions'])]}")
        
        for episode in range(1, episodes + 1):
            reward, loss = self.train_episode()
            
            self.episode_rewards.append(reward)
            if loss > 0:
                self.episode_losses.append(loss)
            
            self.epsilon = max(CONFIG['epsilon_end'], self.epsilon * CONFIG['epsilon_decay'])
            
            if episode % CONFIG['target_update'] == 0:
                self.target_net.load_state_dict(self.policy_net.state_dict())
            
            if episode % 100 == 0:
                avg_reward = np.mean(self.episode_rewards[-100:])
                avg_loss = np.mean(self.episode_losses[-100:]) if self.episode_losses else 0
                logger.info(f"   Episode {episode}/{episodes}: avg_reward={avg_reward:.3f}, "
                           f"avg_loss={avg_loss:.4f}, ε={self.epsilon:.3f}")
        
        logger.info(f"✅ Training complete! Final ε={self.epsilon:.3f}")
    
    def evaluate(self, n_tests=100) -> float:
        """Оценка точности агента"""
        correct = 0
        total = 0
        
        for _ in range(n_tests):
            state, attack_type, _ = self.simulator.generate_state()
            action = self.select_action(state, training=False)
            optimal = self.simulator.optimal_actions[attack_type]
            
            if action == optimal or abs(action - optimal) == 1:
                correct += 1
            total += 1
        
        accuracy = correct / total
        logger.info(f"\n🧪 Evaluation: {accuracy:.1%} correct actions ({correct}/{total})")
        return accuracy
    
    def save(self, path='./models/rl_defense/dqn_model.pt'):
        """Сохранение модели"""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        
        torch.save({
            'policy_net': self.policy_net.state_dict(),
            'target_net': self.target_net.state_dict(),
            'config': CONFIG,
            'epsilon': self.epsilon,
            'episode_rewards': self.episode_rewards,
            'action_counts': self.action_counts,
            'optimal_actions': self.simulator.optimal_actions,
            'severity_map': self.simulator.severity_map,
        }, path)
        
        logger.info(f"✅ Model saved: {path}")
    
    def get_action_info(self, action_id: int) -> Tuple[str, str]:
        """Информация о действии"""
        return ACTIONS.get(action_id, ('unknown', 'Неизвестно'))


def train():
    logger.info("=" * 60)
    logger.info("🧠 SHARD RL Defence Agent — Deep Q-Network")
    logger.info("=" * 60)
    
    trainer = RLDefenseTrainer()
    
    trainer.train(episodes=CONFIG['episodes'])
    
    accuracy = trainer.evaluate(n_tests=200)
    
    logger.info(f"\n📊 Action distribution:")
    total_actions = sum(trainer.action_counts.values())
    for action_id, count in trainer.action_counts.items():
        name, desc = ACTIONS[action_id]
        pct = count / max(1, total_actions) * 100
        logger.info(f"   {name}: {count} ({pct:.1f}%)")
    
    trainer.save()
    
    logger.info(f"\n🧪 Test predictions:")
    simulator = AttackSimulator()
    for attack_type in ['Brute Force', 'DDoS', 'Port Scan', 'Data Exfiltration', 'SQL Injection']:
        state, at, sev = simulator.generate_state()
        state[0] = 0.85
        state[2] = simulator.severity_map[attack_type] / 4.0
        
        action = trainer.select_action(state, training=False)
        optimal = simulator.optimal_actions[attack_type]
        name, desc = ACTIONS[action]
        opt_name, _ = ACTIONS[optimal]
        
        status = "✅" if action == optimal or abs(action - optimal) <= 1 else "⚠️"
        logger.info(f"   {status} {attack_type}: {name} (optimal: {opt_name})")
    
    logger.info(f"\n{'='*60}")
    logger.info(f"✅ RL DEFENCE AGENT READY!")
    logger.info(f"   Accuracy: {accuracy:.1%}")
    logger.info(f"   Model: models/rl_defense/dqn_model.pt")
    logger.info(f"{'='*60}")


if __name__ == "__main__":
    train()
