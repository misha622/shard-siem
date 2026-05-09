#!/usr/bin/env python3
"""
SHARD CodeGen Trainer
Обучение собственной модели для генерации защитного кода.
Без внешних API — всё локально на TensorFlow/PyTorch.
"""

import json
import time
import pickle
import threading
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from collections import defaultdict
from datetime import datetime

import numpy as np

logger = None  # Будет установлен при инициализации


# ============================================================
# ДАТАСЕТ ДЛЯ ОБУЧЕНИЯ
# ============================================================

class DefenseCodeDataset:
    """
    Датасет пар: (атака → защитный код)
    Обучаем модель генерировать код защиты для каждого типа атаки.
    """

    def __init__(self):
        self.samples: List[Dict] = []
        self.token_to_id: Dict[str, int] = {'<PAD>': 0, '<START>': 1, '<END>': 2, '<UNK>': 3}
        self.id_to_token: Dict[int, str] = {0: '<PAD>', 1: '<START>', 2: '<END>', 3: '<UNK>'}
        self.max_input_len = 0
        self.max_output_len = 0

        self._init_base_dataset()
        self._build_vocabulary()

    def _init_base_dataset(self):
        """Создание базового датасета для обучения"""
        base_samples = [
            # SQL Injection
            {
                'attack': 'SQL Injection on port 80 from EXTERNAL_IP to INTERNAL_IP',
                'defense': '''
iptables -A INPUT -s EXTERNAL_IP -p tcp --dport 80 -j DROP
# WAF rule for SQLi
SecRule REQUEST_URI "@rx union.*select" "id:1001,phase:2,deny,status:403"
# Rate limit
iptables -A INPUT -p tcp --dport 80 -m state --state NEW -m recent --update --seconds 60 --hitcount 5 -j DROP
'''
            },
            {
                'attack': 'SQL Injection via POST parameter on port 443',
                'defense': '''
iptables -A INPUT -s EXTERNAL_IP -p tcp --dport 443 -j DROP
# WAF rule for POST SQLi
SecRule REQUEST_BODY "@rx ' OR '1'='1" "id:1002,phase:2,deny,status:403"
iptables -A INPUT -p tcp --dport 443 -m string --string "UNION SELECT" --algo bm -j DROP
'''
            },

            # Brute Force
            {
                'attack': 'SSH Brute Force from EXTERNAL_IP to INTERNAL_IP port 22',
                'defense': '''
iptables -A INPUT -s EXTERNAL_IP -p tcp --dport 22 -j DROP
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 300 --hitcount 3 -j DROP
# Block for 24 hours
iptables -A INPUT -s EXTERNAL_IP -j DROP
at now + 24 hours <<< "iptables -D INPUT -s EXTERNAL_IP -j DROP"
'''
            },
            {
                'attack': 'FTP Brute Force on port 21',
                'defense': '''
iptables -A INPUT -s EXTERNAL_IP -p tcp --dport 21 -j DROP
iptables -A INPUT -p tcp --dport 21 -m state --state NEW -m recent --update --seconds 60 --hitcount 3 -j DROP
# Notify admin
logger "FTP brute force blocked: EXTERNAL_IP"
'''
            },

            # DDoS
            {
                'attack': 'DDoS SYN flood on port 443',
                'defense': '''
iptables -A INPUT -p tcp --syn -m limit --limit 10/s --limit-burst 20 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP
iptables -A INPUT -p tcp --dport 443 -m state --state NEW -m recent --update --seconds 1 --hitcount 10 -j DROP
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
sysctl -w net.ipv4.tcp_max_syn_backlog=2048
'''
            },
            {
                'attack': 'UDP flood DDoS on port 53',
                'defense': '''
iptables -A INPUT -p udp --dport 53 -m limit --limit 100/s -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j DROP
iptables -A INPUT -s EXTERNAL_IP -j DROP
'''
            },

            # Port Scan
            {
                'attack': 'Port scan from EXTERNAL_IP scanning multiple ports',
                'defense': '''
iptables -A INPUT -s EXTERNAL_IP -p tcp -m multiport --dports 1:65535 -j DROP
iptables -A INPUT -s EXTERNAL_IP -j DROP
iptables -A INPUT -m recent --name portscan --rcheck --seconds 60 -j DROP
iptables -A INPUT -m recent --name portscan --set -j DROP
'''
            },

            # C2 Beacon
            {
                'attack': 'C2 Beacon on non-standard port 4444',
                'defense': '''
iptables -A INPUT -s EXTERNAL_IP -p tcp --dport 4444 -j DROP
iptables -A OUTPUT -d EXTERNAL_IP -p tcp --dport 4444 -j DROP
iptables -A FORWARD -s EXTERNAL_IP -j DROP
iptables -A INPUT -s EXTERNAL_IP -j LOG --log-prefix "C2-BLOCKED: "
'''
            },

            # DNS Tunnel
            {
                'attack': 'DNS tunneling detected on port 53',
                'defense': '''
iptables -A INPUT -s EXTERNAL_IP -p udp --dport 53 -m string --hex-string "|0000|" --algo bm -j DROP
iptables -A INPUT -s EXTERNAL_IP -p udp --dport 53 -m length --length 512:65535 -j DROP
iptables -A INPUT -s EXTERNAL_IP -j DROP
'''
            },

            # Web Attack (XSS)
            {
                'attack': 'XSS attack on web application port 80',
                'defense': '''
iptables -A INPUT -s EXTERNAL_IP -p tcp --dport 80 -j DROP
# WAF XSS rule
SecRule REQUEST_URI "@rx <script" "id:2001,phase:2,deny,status:403"
SecRule REQUEST_URI "@rx javascript:" "id:2002,phase:2,deny,status:403"
'''
            },

            # Lateral Movement
            {
                'attack': 'Lateral movement via SMB on port 445',
                'defense': '''
iptables -A INPUT -s EXTERNAL_IP -p tcp --dport 445 -j DROP
iptables -A INPUT -s EXTERNAL_IP -p tcp --dport 139 -j DROP
iptables -A INPUT -s EXTERNAL_IP -p tcp --dport 135 -j DROP
iptables -A FORWARD -s EXTERNAL_IP -j DROP
iptables -A INPUT -s EXTERNAL_IP -j LOG --log-prefix "LATERAL-MOVEMENT: "
'''
            },

            # Data Exfiltration
            {
                'attack': 'Data exfiltration detected to external IP on port 443',
                'defense': '''
iptables -A OUTPUT -d EXTERNAL_IP -p tcp --dport 443 -j DROP
iptables -A OUTPUT -d EXTERNAL_IP -p tcp --dport 80 -j DROP
iptables -A OUTPUT -d EXTERNAL_IP -j DROP
iptables -A OUTPUT -d EXTERNAL_IP -j LOG --log-prefix "EXFIL-BLOCKED: "
'''
            },

            # Botnet
            {
                'attack': 'Botnet C2 communication detected',
                'defense': '''
iptables -A INPUT -s EXTERNAL_IP -j DROP
iptables -A OUTPUT -d EXTERNAL_IP -j DROP
iptables -A FORWARD -s EXTERNAL_IP -j DROP
iptables -A FORWARD -d EXTERNAL_IP -j DROP
iptables -A INPUT -m state --state NEW -m recent --update --seconds 60 --hitcount 10 -j DROP
'''
            },

            # Ransomware
            {
                'attack': 'Ransomware encryption activity detected',
                'defense': '''
iptables -A INPUT -s EXTERNAL_IP -j DROP
iptables -A OUTPUT -d EXTERNAL_IP -j DROP
# Block common ransomware ports
iptables -A OUTPUT -p tcp --dport 445 -j DROP
iptables -A OUTPUT -p tcp --dport 139 -j DROP
# Isolate infected host
iptables -A FORWARD -s INTERNAL_HOST -j DROP
iptables -A FORWARD -d INTERNAL_HOST -j DROP
'''
            },
        ]

        self.samples = base_samples

        # Аугментация датасета
        self._augment_dataset()

    def _augment_dataset(self):
        """Аугментация датасета для улучшения обучения"""
        augmented = []

        for sample in self.samples:
            # Вариация IP адресов
            for ip in ['10.0.0.1', '172.16.0.1', '192.168.1.1']:
                new_sample = {
                    'attack': sample['attack'].replace('EXTERNAL_IP', '185.142.53.101')
                                             .replace('INTERNAL_IP', ip),
                    'defense': sample['defense'].replace('EXTERNAL_IP', '185.142.53.101')
                                                .replace('INTERNAL_IP', ip)
                }
                augmented.append(new_sample)

            # Вариация портов
            for port in ['8080', '8443', '9090']:
                if 'port 80' in sample['attack']:
                    new_sample = {
                        'attack': sample['attack'].replace('port 80', f'port {port}'),
                        'defense': sample['defense'].replace('--dport 80', f'--dport {port}')
                    }
                    augmented.append(new_sample)

        self.samples.extend(augmented)

    def _build_vocabulary(self):
        """Построение словаря токенов"""
        vocab = set()

        for sample in self.samples:
            # Токенизация по словам и символам
            for text in [sample['attack'], sample['defense']]:
                words = text.split()
                vocab.update(words)

                # Добавляем отдельные символы для пунктуации
                for char in text:
                    if not char.isalnum() and char not in [' ', '\n', '\t']:
                        vocab.add(char)

        # Назначаем ID
        for token in sorted(vocab):
            if token not in self.token_to_id:
                idx = len(self.token_to_id)
                self.token_to_id[token] = idx
                self.id_to_token[idx] = token

        # Вычисляем максимальные длины
        self.max_input_len = max(
            len(s['attack'].split()) for s in self.samples
        )
        self.max_output_len = max(
            len(s['defense'].split()) for s in self.samples
        )

    def encode(self, text: str, max_len: int = None) -> np.ndarray:
        """Кодирование текста в последовательность токенов"""
        words = text.split()
        max_len = max_len or len(words)

        encoded = np.zeros(max_len, dtype=np.int32)
        for i, word in enumerate(words[:max_len]):
            encoded[i] = self.token_to_id.get(word, self.token_to_id['<UNK>'])

        return encoded

    def decode(self, encoded: np.ndarray) -> str:
        """Декодирование токенов в текст"""
        words = []
        for idx in encoded:
            if idx == self.token_to_id['<END>']:
                break
            if idx == self.token_to_id['<PAD>']:
                continue
            word = self.id_to_token.get(idx, '<UNK>')
            if word not in ['<START>', '<UNK>']:
                words.append(word)
        return ' '.join(words)

    def get_training_data(self) -> Tuple[np.ndarray, np.ndarray]:
        """Получение данных для обучения"""
        X = np.zeros((len(self.samples), self.max_input_len), dtype=np.int32)
        y = np.zeros((len(self.samples), self.max_output_len), dtype=np.int32)

        for i, sample in enumerate(self.samples):
            X[i] = self.encode(sample['attack'], self.max_input_len)
            y[i] = self.encode(sample['defense'], self.max_output_len)

        return X, y


# ============================================================
# МОДЕЛЬ ДЛЯ ГЕНЕРАЦИИ КОДА
# ============================================================

class CodeGenModel:
    """
    Seq2Seq модель с attention для генерации защитного кода.
    Encoder: LSTM
    Decoder: LSTM + Attention
    """

    def __init__(self, vocab_size: int, embed_dim: int = 128, hidden_dim: int = 256):
        self.vocab_size = vocab_size
        self.embed_dim = embed_dim
        self.hidden_dim = hidden_dim

        # Инициализация весов
        self.encoder_embedding = np.random.randn(vocab_size, embed_dim) * 0.01
        self.decoder_embedding = np.random.randn(vocab_size, embed_dim) * 0.01

        # LSTM веса (упрощённая реализация)
        self.encoder_lstm = self._init_lstm_weights(embed_dim, hidden_dim)
        self.decoder_lstm = self._init_lstm_weights(embed_dim, hidden_dim)

        # Attention веса
        self.attention_w = np.random.randn(hidden_dim, hidden_dim) * 0.01

        # Выходной слой
        self.output_w = np.random.randn(hidden_dim, vocab_size) * 0.01

        # Статистика обучения
        self.train_losses: List[float] = []
        self.trained = False

    def _init_lstm_weights(self, input_dim: int, hidden_dim: int) -> Dict:
        """Инициализация весов LSTM"""
        return {
            'Wf': np.random.randn(input_dim + hidden_dim, hidden_dim) * 0.01,
            'bf': np.zeros(hidden_dim),
            'Wi': np.random.randn(input_dim + hidden_dim, hidden_dim) * 0.01,
            'bi': np.zeros(hidden_dim),
            'Wo': np.random.randn(input_dim + hidden_dim, hidden_dim) * 0.01,
            'bo': np.zeros(hidden_dim),
            'Wc': np.random.randn(input_dim + hidden_dim, hidden_dim) * 0.01,
            'bc': np.zeros(hidden_dim),
        }

    def _lstm_forward(self, x, h_prev, c_prev, weights):
        """Один шаг LSTM"""
        combined = np.concatenate([x, h_prev])

        f = self._sigmoid(np.dot(combined, weights['Wf']) + weights['bf'])
        i = self._sigmoid(np.dot(combined, weights['Wi']) + weights['bi'])
        o = self._sigmoid(np.dot(combined, weights['Wo']) + weights['bo'])
        c_tilde = np.tanh(np.dot(combined, weights['Wc']) + weights['bc'])

        c = f * c_prev + i * c_tilde
        h = o * np.tanh(c)

        return h, c

    def _sigmoid(self, x):
        return 1.0 / (1.0 + np.exp(-np.clip(x, -10, 10)))

    def _softmax(self, x):
        e_x = np.exp(x - np.max(x))
        return e_x / e_x.sum()

    def encode(self, input_seq: np.ndarray) -> Tuple[np.ndarray, np.ndarray, List[np.ndarray]]:
        """Кодирование входной последовательности"""
        h = np.zeros(self.hidden_dim)
        c = np.zeros(self.hidden_dim)
        encoder_outputs = []

        for token_id in input_seq:
            if token_id == 0:  # PAD
                continue
            x = self.encoder_embedding[token_id]
            h, c = self._lstm_forward(x, h, c, self.encoder_lstm)
            encoder_outputs.append(h)

        return h, c, encoder_outputs

    def decode_step(self, token_id, h_prev, c_prev, encoder_outputs):
        """Один шаг декодирования с attention"""
        x = self.decoder_embedding[token_id]
        h, c = self._lstm_forward(x, h_prev, c_prev, self.decoder_lstm)

        # Attention
        if encoder_outputs:
            attention_scores = np.array([
                np.dot(h, np.dot(self.attention_w, enc_h))
                for enc_h in encoder_outputs
            ])
            attention_weights = self._softmax(attention_scores)
            context = np.sum(
                np.array(encoder_outputs) * attention_weights[:, np.newaxis],
                axis=0
            )
            h = np.tanh(h + context)

        # Output
        logits = np.dot(h, self.output_w)
        probs = self._softmax(logits)

        return probs, h, c

    def generate(self, input_text: str, dataset: DefenseCodeDataset,
                 max_len: int = 100, temperature: float = 0.7) -> str:
        """Генерация защитного кода для атаки"""
        input_seq = dataset.encode(input_text, dataset.max_input_len)
        h, c, encoder_outputs = self.encode(input_seq)

        # Начинаем с START токена
        current_token = dataset.token_to_id['<START>']
        generated = [current_token]

        for _ in range(max_len):
            probs, h, c = self.decode_step(
                current_token, h, c, encoder_outputs
            )

            # Temperature sampling
            probs = np.exp(np.log(probs + 1e-8) / temperature)
            probs = probs / probs.sum()
            current_token = np.random.choice(len(probs), p=probs)

            if current_token == dataset.token_to_id['<END>']:
                break

            generated.append(current_token)

        # Декодируем
        generated_text = dataset.decode(np.array(generated))

        # Пост-обработка: заменяем плейсхолдеры на реальные значения из входного текста
        words = input_text.split()
        for i, word in enumerate(words):
            if word in ['EXTERNAL_IP', 'INTERNAL_IP', 'INTERNAL_HOST']:
                # Находим IP в тексте
                for w in words:
                    if '.' in w and any(c.isdigit() for c in w):
                        generated_text = generated_text.replace(word, w)
                        break

        return generated_text

    def train(self, X, y, dataset, epochs=50, lr=0.001, verbose=True):
        """Обучение модели"""
        n_samples = len(X)

        for epoch in range(epochs):
            epoch_loss = 0.0

            for i in range(n_samples):
                # Кодирование
                h, c, encoder_outputs = self.encode(X[i])
                loss = 0.0

                # Декодирование с teacher forcing
                h_dec, c_dec = h, c
                for t, token_id in enumerate(y[i]):
                    if token_id == 0:  # PAD
                        break

                    probs, h_dec, c_dec = self.decode_step(
                        token_id, h_dec, c_dec, encoder_outputs
                    )

                    # Cross-entropy loss
                    target = np.zeros(self.vocab_size)
                    target[token_id] = 1.0
                    loss += -np.log(probs[token_id] + 1e-8)

                    # Простой градиентный спуск
                    error = probs - target
                    self.output_w -= lr * np.outer(h_dec, error)

                epoch_loss += loss

            avg_loss = epoch_loss / n_samples
            self.train_losses.append(avg_loss)

            if verbose and epoch % 10 == 0:
                logger.info(f"Epoch {epoch}: loss={avg_loss:.4f}") if logger else print(f"Epoch {epoch}: loss={avg_loss:.4f}")

        self.trained = True

    def save(self, path: str = './models/codegen_model.pkl'):
        """Сохранение модели"""
        Path(path).parent.mkdir(exist_ok=True)
        with open(path, 'wb') as f:
            pickle.dump({
                'encoder_embedding': self.encoder_embedding,
                'decoder_embedding': self.decoder_embedding,
                'encoder_lstm': self.encoder_lstm,
                'decoder_lstm': self.decoder_lstm,
                'attention_w': self.attention_w,
                'output_w': self.output_w,
                'train_losses': self.train_losses,
                'trained': self.trained,
                'vocab_size': self.vocab_size,
                'embed_dim': self.embed_dim,
                'hidden_dim': self.hidden_dim,
            }, f)
        logger.info(f"✅ Модель сохранена: {path}") if logger else print(f"✅ Модель сохранена: {path}")

    @classmethod
    def load(cls, path: str = './models/codegen_model.pkl') -> 'CodeGenModel':
        """Загрузка модели"""
        with open(path, 'rb') as f:
            data = pickle.load(f)

        model = cls(data['vocab_size'], data['embed_dim'], data['hidden_dim'])
        model.encoder_embedding = data['encoder_embedding']
        model.decoder_embedding = data['decoder_embedding']
        model.encoder_lstm = data['encoder_lstm']
        model.decoder_lstm = data['decoder_lstm']
        model.attention_w = data['attention_w']
        model.output_w = data['output_w']
        model.train_losses = data['train_losses']
        model.trained = data['trained']
        return model


# ============================================================
# ТРЕНИРОВКА
# ============================================================

def train_codegen_model():
    """Обучение модели генерации кода"""
    import logging
    global logger
    logger = logging.getLogger("SHARD-CodeGen-Train")
    logging.basicConfig(level=logging.INFO)

    print("=" * 60)
    print("🧠 ОБУЧЕНИЕ SHARD CODE GENERATOR")
    print("=" * 60)

    # 1. Датасет
    print("\n📊 Подготовка датасета...")
    dataset = DefenseCodeDataset()
    print(f"   Сэмплов: {len(dataset.samples)}")
    print(f"   Словарь: {len(dataset.token_to_id)} токенов")
    print(f"   Max input: {dataset.max_input_len}")
    print(f"   Max output: {dataset.max_output_len}")

    X, y = dataset.get_training_data()

    # 2. Модель
    print(f"\n🧠 Создание модели...")
    model = CodeGenModel(
        vocab_size=len(dataset.token_to_id),
        embed_dim=128,
        hidden_dim=256
    )
    print(f"   Vocab size: {model.vocab_size}")
    print(f"   Parameters: ~{model.vocab_size * 128 * 3:,}")

    # 3. Обучение
    print(f"\n🔄 Обучение...")
    model.train(X, y, dataset, epochs=50, lr=0.001, verbose=True)

    # 4. Сохранение
    model.save('./models/codegen_model.pkl')

    # 5. Тест генерации
    print(f"\n🧪 Тест генерации:")
    test_attacks = [
        "SQL Injection from 185.142.53.101 to 192.168.1.50 port 80",
        "SSH Brute Force from 45.155.205.233 port 22",
        "DDoS attack from 194.61.23.45 on port 443",
    ]

    for attack in test_attacks:
        print(f"\n   Атака: {attack}")
        generated = model.generate(attack, dataset, temperature=0.5)
        print(f"   Защита:\n{generated[:200]}...")

    print(f"\n{'='*60}")
    print(f"✅ Модель готова!")
    print(f"📁 Сохранена: ./models/codegen_model.pkl")
    print(f"{'='*60}")


if __name__ == "__main__":
    train_codegen_model()