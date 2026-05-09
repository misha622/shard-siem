#!/usr/bin/env python3
"""
SHARD Anomaly Detection Autoencoder
Обучается на Normal Traffic, выявляет zero-day без сигнатур
Архитектура: Variational Autoencoder (VAE) на PyTorch
"""

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
import numpy as np
import pickle
import json
import logging
import random
from pathlib import Path
from collections import deque
import time

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SHARD-AnomalyAE")

# ============================================================
# КОНФИГУРАЦИЯ
# ============================================================

CONFIG = {
    'input_dim': 72,
    'hidden_dims': [256, 128, 64],
    'latent_dim': 32,
    'batch_size': 64,
    'epochs': 100,
    'lr': 0.001,
    'beta': 0.001,
    'anomaly_threshold': None,
}

# ============================================================
# ГЕНЕРАТОР СИНТЕТИЧЕСКОГО НОРМАЛЬНОГО ТРАФИКА
# ============================================================

class TrafficFeatureExtractor:
    """Извлекает 78 фич из трафика — те же что использует SHARD ML"""
    
    @staticmethod
    def extract_normal_traffic(n_samples=10000):
        """Генерация синтетического НОРМАЛЬНОГО трафика для обучения"""
        features = []
        
        for _ in range(n_samples):
            # Базовые параметры нормального трафика
            packet_size = int(np.random.gamma(2, 500))  # Средний размер пакета
            protocol = np.random.choice([6, 17], p=[0.85, 0.15])  # TCP=85%, UDP=15%
            
            # Нормальные порты
            normal_ports = [80, 443, 8080, 8443, 22, 53, 3306, 5432, 6379]
            dst_port = np.random.choice(normal_ports)
            src_port = random.randint(49152, 65535)  # Эфемерные порты
            
            # IP фичи (one-hot для /8 подсетей)
            private_subnet = np.random.choice([10, 172, 192], p=[0.3, 0.3, 0.4])
            if private_subnet == 10:
                ip_class = 0
            elif private_subnet == 172:
                ip_class = 1
            else:
                ip_class = 2
            
            # Временные паттерны (нормальное распределение активности)
            hour = int(np.random.normal(12, 4)) % 24  # Пик днём
            day = int(np.random.normal(3, 2)) % 7    # Пик в среду
            
            # TTL
            ttl = np.random.choice([64, 128, 255], p=[0.6, 0.3, 0.1])
            
            # Флаги TCP
            if protocol == 6:
                tcp_flags = np.random.choice([2, 16, 24, 17], p=[0.4, 0.3, 0.2, 0.1])
            else:
                tcp_flags = 0
            
            # Энтропия payload (нормальная — низкая)
            entropy = np.random.beta(2, 8)  # Скошена влево
            
            # Интервал между пакетами (мс)
            interval = np.random.exponential(50)  # Среднее 50мс
            
            # Собираем все 78 фич
            feat = [
                # Packet stats (6)
                min(1.0, packet_size / 1500.0),
                protocol / 255.0,
                dst_port / 65535.0,
                src_port / 65535.0,
                ttl / 255.0,
                tcp_flags / 255.0,
                
                # IP class one-hot (10)
                *[1.0 if i == ip_class else 0.0 for i in range(10)],
                
                # Port features (15)
                *[1.0 if dst_port == p else 0.0 for p in normal_ports[:15]],
                
                # Timing features (5)
                hour / 24.0,
                day / 7.0,
                min(1.0, interval / 1000.0),
                entropy,
                np.random.beta(5, 5),  # Connection rate (нормальный)
                
                # Protocol features (10)
                *[1.0 if i == (0 if protocol == 6 else 1) else 0.0 for i in range(10)],
                
                # Payload features (15)
                *[np.random.beta(2, 5) for _ in range(15)],
                
                # Statistical features (15)
                *[np.random.normal(0.5, 0.15) for _ in range(15)],
                
                # Sequence features (2)
                np.random.uniform(0, 1),
                np.random.uniform(0, 1),
            ]
            
            features.append(feat[:78])  # Ровно 78 фич
        
        return np.array(features, dtype=np.float32)
    
    @staticmethod
    def generate_anomaly(n_samples=500):
        """Генерация АНОМАЛЬНОГО трафика для тестирования"""
        normal = TrafficFeatureExtractor.extract_normal_traffic(n_samples)
        
        # Добавляем аномалии: меняем распределение
        anomalies = normal.copy()
        
        for i in range(n_samples):
            anomaly_type = random.choice(['port_scan', 'large_packet', 'night_activity', 'high_entropy'])
            
            if anomaly_type == 'port_scan':
                # Много разных портов + короткие интервалы
                for j in range(10, 25):
                    anomalies[i, j] = np.random.uniform(0, 1)
                anomalies[i, 2] = np.random.uniform(0, 1)
                anomalies[i, 4] = np.random.uniform(0, 0.2)
                anomalies[i, 20] = np.random.uniform(0, 0.1)  # Очень быстрые пакеты
            elif anomaly_type == 'large_packet':
                anomalies[i, 0] = 1.0
                anomalies[i, 7] = 1.0
                anomalies[i, 20] = np.random.uniform(0.8, 1.0)
                for j in range(30, 45):
                    anomalies[i, j] = np.random.uniform(0.7, 1.0)  # Необычный payload
            elif anomaly_type == 'night_activity':
                anomalies[i, 18] = np.random.uniform(0, 0.15)
                anomalies[i, 19] = np.random.uniform(0, 0.2)
                anomalies[i, 2] = np.random.uniform(0, 1)
                anomalies[i, 4] = np.random.uniform(0, 0.5)
            elif anomaly_type == 'high_entropy':
                anomalies[i, 20] = np.random.uniform(0.85, 1.0)
                anomalies[i, 21] = np.random.uniform(0.85, 1.0)
                for j in range(45, 60):
                    anomalies[i, j] = np.random.uniform(0.8, 1.0)
                for j in range(10, 25):
                    anomalies[i, j] = np.random.uniform(0, 1)
        
        return anomalies


# ============================================================
# VARIATIONAL AUTOENCODER
# ============================================================

class VariationalAutoencoder(nn.Module):
    """VAE для anomaly detection на трафике"""
    
    def __init__(self, input_dim=78, hidden_dims=[128, 64], latent_dim=16):
        super().__init__()
        
        # Энкодер
        encoder_layers = []
        prev_dim = input_dim
        for h_dim in hidden_dims:
            encoder_layers.extend([
                nn.Linear(prev_dim, h_dim),
                nn.BatchNorm1d(h_dim),
                nn.ReLU(),
                nn.Dropout(0.1),
            ])
            prev_dim = h_dim
        
        self.encoder = nn.Sequential(*encoder_layers)
        self.fc_mu = nn.Linear(hidden_dims[-1], latent_dim)
        self.fc_logvar = nn.Linear(hidden_dims[-1], latent_dim)
        
        # Декодер
        decoder_layers = []
        prev_dim = latent_dim
        for h_dim in reversed(hidden_dims):
            decoder_layers.extend([
                nn.Linear(prev_dim, h_dim),
                nn.BatchNorm1d(h_dim),
                nn.ReLU(),
                nn.Dropout(0.1),
            ])
            prev_dim = h_dim
        
        decoder_layers.append(nn.Linear(hidden_dims[0], input_dim))
        decoder_layers.append(nn.Sigmoid())  # Фичи нормализованы в [0,1]
        
        self.decoder = nn.Sequential(*decoder_layers)
        
    def encode(self, x):
        h = self.encoder(x)
        mu = self.fc_mu(h)
        logvar = self.fc_logvar(h)
        return mu, logvar
    
    def reparameterize(self, mu, logvar):
        std = torch.exp(0.5 * logvar)
        eps = torch.randn_like(std)
        return mu + eps * std
    
    def forward(self, x):
        mu, logvar = self.encode(x)
        z = self.reparameterize(mu, logvar)
        reconstructed = self.decoder(z)
        return reconstructed, mu, logvar
    
    def anomaly_score(self, x):
        """Вычисление anomaly score на основе ошибки восстановления"""
        self.eval()
        with torch.no_grad():
            reconstructed, mu, logvar = self.forward(x)
            
            # Reconstruction error (MSE)
            recon_error = torch.mean((x - reconstructed) ** 2, dim=1)
            
            # KL divergence
            kl_div = -0.5 * torch.sum(1 + logvar - mu.pow(2) - logvar.exp(), dim=1)
            
            # Комбинированный score
            score = recon_error + CONFIG['beta'] * kl_div
            
        return score


# ============================================================
# ОБУЧЕНИЕ
# ============================================================

class TrafficDataset(Dataset):
    def __init__(self, features):
        self.features = torch.tensor(features, dtype=torch.float32)
    
    def __len__(self):
        return len(self.features)
    
    def __getitem__(self, idx):
        return self.features[idx]


def train():
    logger.info("=" * 60)
    logger.info("🧠 SHARD Anomaly Detection — Variational Autoencoder")
    logger.info("=" * 60)
    
    # Генерация нормального трафика
    logger.info("\n📊 Generating normal traffic samples...")
    normal_data = TrafficFeatureExtractor.extract_normal_traffic(25000)
    logger.info(f"   Normal samples: {len(normal_data)}")
    
    # Нормализация
    mean = normal_data.mean(axis=0)
    std = normal_data.std(axis=0) + 1e-8
    normal_data = (normal_data - mean) / std
    
    # Датасет
    dataset = TrafficDataset(normal_data)
    dataloader = DataLoader(dataset, batch_size=CONFIG['batch_size'], shuffle=True)
    
    # Модель
    logger.info(f"\n🧠 Creating VAE model...")
    model = VariationalAutoencoder(
        input_dim=CONFIG['input_dim'],
        hidden_dims=CONFIG['hidden_dims'],
        latent_dim=CONFIG['latent_dim']
    )
    
    params = sum(p.numel() for p in model.parameters())
    logger.info(f"   Parameters: {params:,}")
    logger.info(f"   Architecture: {CONFIG['input_dim']} → {CONFIG['hidden_dims']} → {CONFIG['latent_dim']}")
    
    optimizer = optim.Adam(model.parameters(), lr=CONFIG['lr'])
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=CONFIG['epochs'])
    
    # Обучение
    logger.info(f"\n🔄 Training {CONFIG['epochs']} epochs...")
    
    for epoch in range(CONFIG['epochs']):
        model.train()
        total_loss = 0.0
        
        for batch in dataloader:
            reconstructed, mu, logvar = model(batch)
            
            # Reconstruction loss
            recon_loss = nn.functional.mse_loss(reconstructed, batch, reduction='sum')
            
            # KL divergence
            kl_loss = -0.5 * torch.sum(1 + logvar - mu.pow(2) - logvar.exp())
            
            # Total loss
            loss = recon_loss + CONFIG['beta'] * kl_loss
            
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item()
        
        avg_loss = total_loss / len(dataset)
        scheduler.step()
        
        if epoch % 10 == 0:
            logger.info(f"   Epoch {epoch}/{CONFIG['epochs']}: loss={avg_loss:.4f}")
    
    logger.info(f"✅ Epoch {CONFIG['epochs']}/{CONFIG['epochs']}: final_loss={avg_loss:.4f}")
    
    # Вычисление порога аномалии
    logger.info(f"\n📊 Computing anomaly threshold...")
    model.eval()
    with torch.no_grad():
        normal_tensor = torch.tensor(normal_data[:5000], dtype=torch.float32)
        scores = model.anomaly_score(normal_tensor)
        threshold = scores.mean().item() + 3 * scores.std().item()
    
    logger.info(f"   Anomaly threshold: {threshold:.4f} (mean + 3*std)")
    
    # Тест на аномалиях
    logger.info(f"\n🧪 Testing on anomalies...")
    anomalies = TrafficFeatureExtractor.generate_anomaly(1000)
    anomalies = (anomalies - mean) / std
    
    with torch.no_grad():
        anomaly_tensor = torch.tensor(anomalies, dtype=torch.float32)
        anomaly_scores = model.anomaly_score(anomaly_tensor)
        
    detected = (anomaly_scores > threshold).sum().item()
    detection_rate = detected / len(anomaly_scores) * 100
    
    normal_scores_sample = scores[:500]
    false_positive_rate = (normal_scores_sample > threshold).sum().item() / 500 * 100
    
    logger.info(f"   Detection rate: {detection_rate:.1f}% ({detected}/{len(anomaly_scores)})")
    logger.info(f"   False positive rate: {false_positive_rate:.1f}%")
    logger.info(f"   Mean anomaly score: {anomaly_scores.mean().item():.4f}")
    logger.info(f"   Mean normal score: {scores.mean().item():.4f}")
    
    # Сохранение
    logger.info(f"\n💾 Saving model...")
    Path('./models/anomaly').mkdir(parents=True, exist_ok=True)
    
    torch.save({
        'model_state_dict': model.state_dict(),
        'config': CONFIG,
        'mean': mean.tolist(),
        'std': std.tolist(),
        'threshold': threshold,
        'params': params,
    }, './models/anomaly/vae_anomaly_detector.pt')
    
    logger.info(f"✅ Model saved: models/anomaly/vae_anomaly_detector.pt")
    logger.info(f"   Threshold: {threshold:.4f}")
    logger.info(f"   Detection rate: {detection_rate:.1f}%")
    
    logger.info(f"\n{'='*60}")
    logger.info(f"✅ ANOMALY DETECTOR READY!")
    logger.info(f"{'='*60}")


if __name__ == "__main__":
    train()
