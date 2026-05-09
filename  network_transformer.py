# network_transformer.py
import torch
import torch.nn as nn
import torch.nn.functional as F
import math
import numpy as np
from typing import Optional, Tuple


class NetworkTrafficTransformer(nn.Module):
    """
    Transformer архитектура для анализа сетевого трафика
    Аналогично GPT, но для пакетов и потоков
    """

    def __init__(self,
                 vocab_size=256,  # Байтовый словарь (0-255)
                 d_model=512,
                 nhead=8,
                 num_encoder_layers=6,
                 num_decoder_layers=6,
                 dim_feedforward=2048,
                 max_seq_length=1500,  # Максимальная длина пакета
                 dropout=0.1):
        super().__init__()

        # Встраивание позиций и байтов
        self.byte_embedding = nn.Embedding(vocab_size, d_model)
        self.position_embedding = PositionalEncoding(d_model, max_seq_length, dropout)

        # Трансформер для пакетов
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=nhead,
            dim_feedforward=dim_feedforward,
            dropout=dropout,
            batch_first=True
        )
        self.transformer_encoder = nn.TransformerEncoder(encoder_layer, num_encoder_layers)

        # Временная размерность (для потоков)
        self.temporal_projection = nn.Linear(d_model, d_model)
        self.temporal_transformer = nn.TransformerEncoder(
            encoder_layer,
            num_layers=2
        )

        # Классификация атак
        self.classifier = nn.Sequential(
            nn.Linear(d_model, 256),
            nn.LayerNorm(256),
            nn.GELU(),
            nn.Dropout(0.3),
            nn.Linear(256, 128),
            nn.GELU(),
            nn.Linear(128, 9)  # 9 классов атак
        )

        # Детектор аномалий (регрессия)
        self.anomaly_scorer = nn.Sequential(
            nn.Linear(d_model, 128),
            nn.ReLU(),
            nn.Linear(128, 1),
            nn.Sigmoid()
        )

    def forward(self, packet_bytes, return_attention=False):
        """
        packet_bytes: (batch, seq_len) - байты пакета
        """
        batch_size, seq_len = packet_bytes.shape

        # Встраивание
        x = self.byte_embedding(packet_bytes)  # (batch, seq_len, d_model)
        x = self.position_embedding(x)

        # Трансформер
        encoded = self.transformer_encoder(x)

        # Global pooling (берём среднее по последовательности)
        pooled = encoded.mean(dim=1)  # (batch, d_model)

        # Классификация
        attack_logits = self.classifier(pooled)
        anomaly_scores = self.anomaly_scorer(pooled)

        if return_attention:
            return attack_logits, anomaly_scores, encoded

        return attack_logits, anomaly_scores


class PacketStreamTransformer(nn.Module):
    """
    Transformer для потоков пакетов (анализ последовательности пакетов)
    """

    def __init__(self, packet_encoder, d_model=512, nhead=8, num_layers=4):
        super().__init__()

        self.packet_encoder = packet_encoder  # Предобученный энкодер пакетов

        # Проекция для последовательности пакетов
        self.sequence_projection = nn.Linear(d_model, d_model)

        # Позиционное кодирование для потока
        self.positional_encoding = PositionalEncoding(d_model, max_len=1000)

        # Трансформер для последовательности
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=nhead,
            dim_feedforward=2048,
            batch_first=True
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers)

        # Классификация потока
        self.flow_classifier = nn.Sequential(
            nn.Linear(d_model, 256),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(256, 9)
        )

    def forward(self, packet_sequence):
        """
        packet_sequence: (batch, seq_len, packet_len) - последовательность пакетов
        """
        batch_size, seq_len, packet_len = packet_sequence.shape

        # Кодируем каждый пакет
        packet_embeddings = []
        for i in range(seq_len):
            # Извлекаем признаки пакета
            packet = packet_sequence[:, i, :]
            attack_logits, anomaly_scores, encoded = self.packet_encoder(
                packet, return_attention=True
            )
            # Берём представление пакета
            packet_embedding = encoded.mean(dim=1)  # (batch, d_model)
            packet_embeddings.append(packet_embedding)

        # Стек пакетов
        sequence = torch.stack(packet_embeddings, dim=1)  # (batch, seq_len, d_model)

        # Проекция и позиционное кодирование
        sequence = self.sequence_projection(sequence)
        sequence = self.positional_encoding(sequence)

        # Трансформер потока
        flow_representation = self.transformer(sequence)

        # Global pooling
        flow_pooled = flow_representation.mean(dim=1)

        # Классификация
        flow_logits = self.flow_classifier(flow_pooled)

        return flow_logits


class PositionalEncoding(nn.Module):
    """Позиционное кодирование для Transformer"""

    def __init__(self, d_model: int, max_len: int = 5000, dropout: float = 0.1):
        super().__init__()
        self.dropout = nn.Dropout(p=dropout)

        position = torch.arange(max_len).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2) * (-math.log(10000.0) / d_model))
        pe = torch.zeros(max_len, 1, d_model)
        pe[:, 0, 0::2] = torch.sin(position * div_term)
        pe[:, 0, 1::2] = torch.cos(position * div_term)
        self.register_buffer('pe', pe)

    def forward(self, x):
        """x: (batch, seq_len, d_model)"""
        x = x + self.pe[:x.size(1)].permute(1, 0, 2)
        return self.dropout(x)


class PreTrainedNetworkTransformer:
    """Предобученная модель для сетевого трафика"""

    def __init__(self, model_path='network_transformer.pth'):
        self.model = NetworkTrafficTransformer()

        if model_path and os.path.exists(model_path):
            self.model.load_state_dict(torch.load(model_path))
            print(f"✅ Загружена предобученная модель: {model_path}")

        self.model.eval()

    @torch.no_grad()
    def analyze_packet(self, packet_bytes):
        """Анализ отдельного пакета"""
        packet_tensor = torch.tensor(packet_bytes).unsqueeze(0)
        attack_logits, anomaly_scores = self.model(packet_tensor)

        attack_probs = F.softmax(attack_logits, dim=1)
        predicted_attack = torch.argmax(attack_probs, dim=1).item()
        confidence = attack_probs[0, predicted_attack].item()
        anomaly_score = anomaly_scores.item()

        return {
            'predicted_attack': predicted_attack,
            'confidence': confidence,
            'anomaly_score': anomaly_score,
            'attack_distribution': attack_probs.squeeze().tolist()
        }

    def get_attention_map(self, packet_bytes):
        """Визуализация внимания модели"""
        packet_tensor = torch.tensor(packet_bytes).unsqueeze(0)
        _, _, encoded = self.model(packet_tensor, return_attention=True)
        return encoded.squeeze().cpu().numpy()

# Использование:
# transformer = PreTrainedNetworkTransformer()
# result = transformer.analyze_packet(packet_bytes)
# if result['anomaly_score'] > 0.7:
#     print(f"Обнаружена атака: {result['predicted_attack']} с уверенностью {result['confidence']:.2%}")