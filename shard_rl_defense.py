

"""
SHARD Reinforcement Learning Defense Agent
Production-ready RL agent for adaptive cyber defense.
Learns optimal defense strategies through interaction with the environment.

Author: SHARD Enterprise
Version: 2.0.0
"""

from __future__ import annotations
import os
import json
import time
import threading
import random
from typing import Dict, List, Optional, Tuple, Union
import warnings
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set, Callable
from collections import deque
from dataclasses import dataclass, field

import numpy as np

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
warnings.filterwarnings('ignore')

try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers, Model
    from tensorflow.keras.optimizers import Adam

    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False
    print("❌ TensorFlow not installed")


@dataclass
class RLDefenseConfig:
    state_size: int = 156
    action_size: int = 8

    gamma: float = 0.95
    epsilon: float = 1.0
    epsilon_min: float = 0.01
    epsilon_decay: float = 0.995
    learning_rate: float = 0.001
    batch_size: int = 32
    memory_size: int = 10000
    target_update_freq: int = 100

    episodes: int = 1000
    steps_per_episode: int = 500

    use_double_dqn: bool = True
    use_dueling: bool = True
    use_prioritized_replay: bool = True
    per_alpha: float = 0.6
    per_beta: float = 0.4

    min_action_interval: float = 1.0
    max_blocks_per_minute: int = 10
    adaptive_threshold: bool = True

    model_dir: str = './models/rl_defense/'
    checkpoint_dir: str = './models/rl_defense/checkpoints/'


    def items(self):
        """Совместимость с dict-like доступом"""
        return self.__dict__.items()
    
    def get(self, key, default=None):
        """Совместимость с dict-like доступом"""
        return getattr(self, key, default)


class DefenseAction:

    ACTIONS = [
        'no_action',
        'throttle',
        'block_port',
        'block_ip_temp',
        'block_ip_perm',
        'increase_logging',
        'enable_honeypot',
        'isolate_subnet'
    ]

    COSTS = {
        'no_action': 0.0,
        'throttle': -0.05,
        'block_port': -0.1,
        'block_ip_temp': -0.2,
        'block_ip_perm': -0.5,
        'increase_logging': -0.05,
        'enable_honeypot': -0.15,
        'isolate_subnet': -0.8
    }

    @classmethod
    def get_action_name(cls, action_id: int) -> str:
        return cls.ACTIONS[action_id] if 0 <= action_id < len(cls.ACTIONS) else 'unknown'

    @classmethod
    def get_cost(cls, action_id: int) -> float:
        action_name = cls.get_action_name(action_id)
        return cls.COSTS.get(action_name, 0.0)


class PrioritizedReplayBuffer:

    def __init__(self, capacity: int, alpha: float = 0.6, beta: float = 0.4):
        self.capacity = capacity
        self.alpha = alpha
        self.beta = beta
        self.beta_increment = 0.001

        self.buffer: List[Tuple] = []
        self.priorities = np.zeros(capacity, dtype=np.float32)
        self.position = 0
        self.size = 0

    def push(self, state, action, reward, next_state, done):
        priority = self.priorities.max() if self.size > 0 else 1.0

        if self.size < self.capacity:
            self.buffer.append((state, action, reward, next_state, done))
            self.size += 1
        else:
            self.buffer[self.position] = (state, action, reward, next_state, done)

        self.priorities[self.position] = priority
        self.position = (self.position + 1) % self.capacity

    def sample(self, batch_size: int) -> Tuple[np.ndarray, np.ndarray, np.ndarray,
    np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        if self.size == 0:
            return None

        probs = self.priorities[:self.size] ** self.alpha
        probs /= probs.sum()

        indices = np.random.choice(self.size, batch_size, p=probs, replace=False)

        total = self.size
        weights = (total * probs[indices]) ** (-self.beta)
        weights /= weights.max()

        self.beta = min(1.0, self.beta + self.beta_increment)

        states, actions, rewards, next_states, dones = [], [], [], [], []
        for idx in indices:
            s, a, r, ns, d = self.buffer[idx]
            states.append(s)
            actions.append(a)
            rewards.append(r)
            next_states.append(ns)
            dones.append(d)

        return (np.array(states), np.array(actions), np.array(rewards),
                np.array(next_states), np.array(dones), indices, weights)

    def update_priorities(self, indices: np.ndarray, td_errors: np.ndarray):
        for idx, td_error in zip(indices, td_errors):
            self.priorities[idx] = abs(td_error) + 1e-6


try:
    from tensorflow.keras import Model
except ImportError:
    Model = object

class DuelingDQN(Model):

    def __init__(self, state_size: int, action_size: int, hidden_layers: List[int] = [128, 64]):
        super().__init__(name='DuelingDQN')

        self.state_size = state_size
        self.action_size = action_size

        self.feature_layers = []
        for i, units in enumerate(hidden_layers):
            self.feature_layers.append(layers.Dense(units, activation='relu', name=f'feature_{i}'))
            self.feature_layers.append(layers.BatchNormalization(name=f'bn_{i}'))
            self.feature_layers.append(layers.Dropout(0.2, name=f'dropout_{i}'))

        self.value_stream = [
            layers.Dense(64, activation='relu', name='value_dense'),
            layers.Dense(1, name='value_output')
        ]

        self.advantage_stream = [
            layers.Dense(64, activation='relu', name='advantage_dense'),
            layers.Dense(action_size, name='advantage_output')
        ]

    def call(self, state, training=False):
        x = state
        for layer in self.feature_layers:
            if isinstance(layer, (layers.BatchNormalization, layers.Dropout)):
                x = layer(x, training=training)
            else:
                x = layer(x)

        value = x
        for layer in self.value_stream:
            value = layer(value)

        advantage = x
        for layer in self.advantage_stream:
            advantage = layer(advantage)

        q_values = value + (advantage - tf.reduce_mean(advantage, axis=1, keepdims=True))

        return q_values


class RLDefenseAgent:

    def __init__(self, config: RLDefenseConfig = None):
        self.config = config or RLDefenseConfig()

        self.policy_net = None
        self.target_net = None

        self.memory = None

        self.step_count = 0
        self.episode_count = 0
        self.last_action_time = 0
        self.recent_actions: deque = deque(maxlen=100)
        self.blocked_ips: Set[str] = set()

        self.stats = {
            'total_steps': 0,
            'total_episodes': 0,
            'total_rewards': 0.0,
            'avg_q_value': 0.0,
            'epsilon': self.config.epsilon
        }

        self._lock = threading.RLock()
        self._training_thread = None
        self._running = False

        self.state_encoder = None

        Path(self.config.model_dir).mkdir(parents=True, exist_ok=True)
        Path(self.config.checkpoint_dir).mkdir(parents=True, exist_ok=True)

        if TF_AVAILABLE:
            self._init_networks()
            self.memory = PrioritizedReplayBuffer(
                self.config.memory_size,
                self.config.per_alpha,
                self.config.per_beta
            )
            self._load_or_init()

    def _init_networks(self):
        self.policy_net = DuelingDQN(
            self.config.state_size,
            self.config.action_size
        )
        self.target_net = DuelingDQN(
            self.config.state_size,
            self.config.action_size
        )

        dummy_state = tf.random.normal((1, self.config.state_size))
        _ = self.policy_net(dummy_state)
        _ = self.target_net(dummy_state)

        self.target_net.set_weights(self.policy_net.get_weights())

        self.policy_net.compile(optimizer=Adam(learning_rate=self.config.learning_rate))

        print(f"✅ RL Defense Agent initialized")

    def _load_or_init(self):
        model_path = Path(self.config.model_dir) / 'policy_net.keras'

        if model_path.exists():
            try:
                self.policy_net = keras.models.load_model(model_path)
                self.target_net = keras.models.load_model(
                    Path(self.config.model_dir) / 'target_net.keras'
                )
                print(f"✅ RL model loaded")
            except Exception as e:
                print(f"⚠️ Failed to load model: {e}")

    def set_state_encoder(self, encoder: Callable[[Dict], np.ndarray]):
        self.state_encoder = encoder

    def _encode_state(self, raw_state: Dict) -> np.ndarray:
        if self.state_encoder:
            return self.state_encoder(raw_state)

        encoded = np.zeros(self.config.state_size)

        features = [
            raw_state.get('alert_score', 0.0),
            raw_state.get('alert_count', 0) / 100,
            raw_state.get('connection_rate', 0) / 1000,
            raw_state.get('unique_ports', 0) / 100,
            raw_state.get('bytes_transferred', 0) / 1_000_000,
            raw_state.get('is_internal', False),
            raw_state.get('hour_of_day', 0) / 24,
            raw_state.get('day_of_week', 0) / 7
        ]

        for i, val in enumerate(features[:len(features)]):
            encoded[i] = float(val)
        # Добавляем шумовые признаки для совместимости с 156-мерным входом
        if self.config.state_size > len(features):
            encoded[len(features):] = np.random.normal(0, 0.1, self.config.state_size - len(features))

        return encoded

    def start(self):
        self._running = True
        print(f"🚀 RL Defense Agent started (ε={self.config.epsilon:.3f})")

    def stop(self):
        self._running = False
        self.save()
        print("🛑 RL Defense Agent stopped")

    def act(self, state: Dict, training: bool = True) -> Tuple[int, str]:
        encoded_state = self._encode_state(state)

        with self._lock:
            now = time.time()
            if now - self.last_action_time < self.config.min_action_interval:
                return 0, DefenseAction.get_action_name(0)

            if len(self.recent_actions) >= self.config.max_blocks_per_minute:
                recent_blocks = sum(1 for a in self.recent_actions if a in [3, 4])
                if recent_blocks >= self.config.max_blocks_per_minute:
                    return 1, DefenseAction.get_action_name(1)

            if training and np.random.random() < self.config.epsilon:
                action = np.random.randint(self.config.action_size)
            else:
                state_tensor = tf.convert_to_tensor([encoded_state], dtype=tf.float32)
                q_values = self.policy_net(state_tensor, training=False)
                action = int(tf.argmax(q_values[0]))

                self.stats['avg_q_value'] = 0.99 * self.stats['avg_q_value'] + 0.01 * float(tf.reduce_max(q_values))

            self.last_action_time = now
            self.recent_actions.append(action)
            self.stats['total_steps'] += 1

            return action, DefenseAction.get_action_name(action)

    def remember(self, state: Dict, action: int, reward: float, next_state: Dict, done: bool):
        encoded_state = self._encode_state(state)
        encoded_next_state = self._encode_state(next_state)

        self.memory.push(encoded_state, action, reward, encoded_next_state, done)
        self.stats['total_rewards'] += reward

    def replay(self) -> Optional[float]:
        if self.memory.size < self.config.batch_size:
            return None

        batch = self.memory.sample(self.config.batch_size)
        if batch is None:
            return None

        states, actions, rewards, next_states, dones, indices, weights = batch

        states_t = tf.convert_to_tensor(states, dtype=tf.float32)
        next_states_t = tf.convert_to_tensor(next_states, dtype=tf.float32)
        actions_t = tf.convert_to_tensor(actions, dtype=tf.int32)
        rewards_t = tf.convert_to_tensor(rewards, dtype=tf.float32)
        dones_t = tf.convert_to_tensor(dones, dtype=tf.float32)
        weights_t = tf.convert_to_tensor(weights, dtype=tf.float32)

        with tf.GradientTape() as tape:
            current_q = self.policy_net(states_t, training=True)
            current_q = tf.gather(current_q, actions_t, batch_dims=1)

            if self.config.use_double_dqn:
                next_actions = tf.argmax(self.policy_net(next_states_t, training=False), axis=1)
                next_q = self.target_net(next_states_t, training=False)
                next_q = tf.gather(next_q, next_actions, batch_dims=1)
            else:
                next_q = self.target_net(next_states_t, training=False)
                next_q = tf.reduce_max(next_q, axis=1)

            target_q = rewards_t + (1 - dones_t) * self.config.gamma * next_q

            td_errors = target_q - current_q
            loss = tf.reduce_mean(weights_t * tf.where(
                tf.abs(td_errors) < 1.0,
                0.5 * tf.square(td_errors),
                tf.abs(td_errors) - 0.5
            ))

        grads = tape.gradient(loss, self.policy_net.trainable_variables)
        self.policy_net.optimizer.apply_gradients(zip(grads, self.policy_net.trainable_variables))

        if self.config.use_prioritized_replay:
            self.memory.update_priorities(indices, tf.abs(td_errors).numpy())

        self.step_count += 1
        if self.step_count % self.config.target_update_freq == 0:
            self.target_net.set_weights(self.policy_net.get_weights())

        self.config.epsilon = max(self.config.epsilon_min,
                                  self.config.epsilon * self.config.epsilon_decay)
        self.stats['epsilon'] = self.config.epsilon

        return float(loss)

    def calculate_reward(self, state: Dict, action: int, next_state: Dict,
                         alert_resolved: bool, damage_prevented: float) -> float:
        reward = 0.0

        if alert_resolved:
            reward += 1.0

        reward += damage_prevented * 2.0

        reward += DefenseAction.get_cost(action)

        recent_same_action = sum(1 for a in self.recent_actions if a == action)
        if recent_same_action > 3:
            reward -= 0.1 * recent_same_action

        return reward

    def train_episode(self, env_simulator, max_steps: int = 500) -> float:
        state = env_simulator.reset()
        total_reward = 0.0

        for step in range(max_steps):
            action, _ = self.act(state, training=True)
            next_state, reward, done, info = env_simulator.step(action)

            self.remember(state, action, reward, next_state, done)

            loss = self.replay()

            state = next_state
            total_reward += reward

            if done:
                break

        self.episode_count += 1
        self.stats['total_episodes'] += 1

        if self.episode_count % 100 == 0:
            self.save()

        return total_reward

    def save(self):
        if self.policy_net is None:
            return

        policy_path = Path(self.config.model_dir) / 'policy_net.keras'
        target_path = Path(self.config.model_dir) / 'target_net.keras'
        stats_path = Path(self.config.model_dir) / 'stats.json'

        self.policy_net.save(policy_path)
        self.target_net.save(target_path)

        with open(stats_path, 'w') as f:
            json.dump(self.stats, f, indent=2)

        print(f"✅ RL model saved to {self.config.model_dir}")

    def get_stats(self) -> Dict:
        with self._lock:
            return {
                'episodes': self.stats['total_episodes'],
                'steps': self.stats['total_steps'],
                'epsilon': self.config.epsilon,
                'avg_q_value': self.stats['avg_q_value'],
                'memory_size': self.memory.size if self.memory else 0,
                'recent_actions': list(self.recent_actions)[-10:]
            }


class DefenseEnvironmentSimulator:

    def __init__(self):
        self.state = self._reset_state()
        self.step_count = 0
        self.alert_active = False
        self.attack_severity = 0.0

    def _reset_state(self) -> Dict:
        return {
            'alert_score': 0.0,
            'alert_count': 0,
            'connection_rate': 0,
            'unique_ports': 0,
            'bytes_transferred': 0,
            'is_internal': False,
            'hour_of_day': time.localtime().tm_hour,
            'day_of_week': time.localtime().tm_wday
        }

    def reset(self) -> Dict:
        self.state = self._reset_state()
        self.step_count = 0
        self.alert_active = False
        self.attack_severity = np.random.random() * 0.5 + 0.3
        return self.state.copy()

    def step(self, action: int) -> Tuple[Dict, float, bool, Dict]:
        self.step_count += 1

        if self.alert_active:
            if action in [3, 4, 7]:
                self.alert_active = False
                reward = 1.0
                damage_prevented = self.attack_severity
            else:
                self.attack_severity = min(1.0, self.attack_severity + 0.05)
                reward = -0.1
                damage_prevented = 0.0
        else:
            if np.random.random() < 0.1:
                self.alert_active = True
                self.attack_severity = np.random.random() * 0.3 + 0.2
                reward = 0.0
                damage_prevented = 0.0
            else:
                reward = 0.01
                damage_prevented = 0.0

        self.state['alert_score'] = self.attack_severity if self.alert_active else 0.0
        self.state['alert_count'] = 1 if self.alert_active else 0
        self.state['connection_rate'] = np.random.random() * 100 if self.alert_active else np.random.random() * 10
        self.state['unique_ports'] = np.random.randint(1, 50) if self.alert_active else np.random.randint(1, 5)
        self.state[
            'bytes_transferred'] = np.random.random() * 1_000_000 if self.alert_active else np.random.random() * 10000

        done = self.step_count >= 500

        info = {'alert_active': self.alert_active, 'severity': self.attack_severity}

        return self.state.copy(), reward, done, info


class ShardRLDefenseIntegration:

    def __init__(self, config: Dict = None):
        self.config = RLDefenseConfig()
        if config:
            for key, value in config.items():
                if hasattr(self.config, key):
                    setattr(self.config, key, value)

        self.agent = RLDefenseAgent(self.config)
        self.env_simulator = DefenseEnvironmentSimulator()
        self._training_thread = None
        self._running = False

    def start(self, train: bool = False):
        self._running = True
        self.agent.start()

        if train:
            self._training_thread = threading.Thread(target=self._training_loop, daemon=True)
            self._training_thread.start()
            print("🎮 RL training mode enabled")

    def stop(self):
        self._running = False
        self.agent.stop()
        if self._training_thread:
            self._training_thread.join(timeout=5)

    def _training_loop(self):
        while self._running:
            total_reward = self.agent.train_episode(self.env_simulator)
            if self.agent.episode_count % 10 == 0:
                print(
                    f"📊 Episode {self.agent.episode_count}: reward={total_reward:.2f}, ε={self.agent.config.epsilon:.3f}")

    def get_defense_action(self, alert: Dict) -> Tuple[int, str]:
        state = {
            'alert_score': alert.get('score', 0.0),
            'alert_count': 1,
            'connection_rate': alert.get('connection_count', 0),
            'unique_ports': len(alert.get('ports', [])),
            'bytes_transferred': alert.get('bytes', 0),
            'is_internal': alert.get('is_internal', False),
            'hour_of_day': time.localtime().tm_hour,
            'day_of_week': time.localtime().tm_wday
        }

        action_id, action_name = self.agent.act(state, training=False)
        return action_id, action_name

    def provide_feedback(self, alert: Dict, action: int, resolved: bool, damage: float):
        state = {
            'alert_score': alert.get('score', 0.0),
            'alert_count': 1,
            'connection_rate': alert.get('connection_count', 0),
            'unique_ports': len(alert.get('ports', [])),
            'bytes_transferred': alert.get('bytes', 0),
            'is_internal': alert.get('is_internal', False),
            'hour_of_day': time.localtime().tm_hour,
            'day_of_week': time.localtime().tm_wday
        }

        next_state = state.copy()
        next_state['alert_score'] = 0.0 if resolved else state['alert_score']

        reward = self.agent.calculate_reward(state, action, next_state, resolved, damage)

        self.agent.remember(state, action, reward, next_state, resolved)
        self.agent.replay()

    def get_stats(self) -> Dict:
        return {
            'agent_stats': self.agent.get_stats(),
            'training_mode': self._training_thread is not None
        }


def test_rl_defense():
    print("=" * 60)
    print("TESTING RL DEFENSE AGENT")
    print("=" * 60)

    if not TF_AVAILABLE:
        print("❌ TensorFlow not available")
        return

    config = RLDefenseConfig()
    config.episodes = 50
    config.steps_per_episode = 200

    agent = RLDefenseAgent(config)
    agent.start()

    env = DefenseEnvironmentSimulator()

    print("\n🔄 Training agent...")
    total_rewards = []

    for episode in range(config.episodes):
        state = env.reset()
        episode_reward = 0

        for step in range(config.steps_per_episode):
            action, action_name = agent.act(state, training=True)
            next_state, reward, done, info = env.step(action)

            agent.remember(state, action, reward, next_state, done)
            loss = agent.replay()

            state = next_state
            episode_reward += reward

            if done:
                break

        total_rewards.append(episode_reward)

        if episode % 10 == 0:
            print(f"   Episode {episode}: reward={episode_reward:.2f}, ε={agent.config.epsilon:.3f}")

    print("\n🔮 Testing inference...")
    test_state = {'alert_score': 0.8, 'alert_count': 5, 'connection_rate': 500}
    action, name = agent.act(test_state, training=False)
    print(f"   Alert score 0.8 -> Action: {name}")

    test_state = {'alert_score': 0.2, 'alert_count': 1, 'connection_rate': 10}
    action, name = agent.act(test_state, training=False)
    print(f"   Alert score 0.2 -> Action: {name}")

    agent.stop()

    print("\n📊 Final stats:")
    print(json.dumps(agent.get_stats(), indent=2))

    print("\n" + "=" * 60)
    print("✅ TESTING COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    test_rl_defense()
