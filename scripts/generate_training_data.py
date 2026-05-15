#!/usr/bin/env python3
"""
Генератор синтетических датасетов для SHARD.
Создаёт размеченные данные для всех 10 нейросетей.
"""
import json, random, math, sys
from pathlib import Path
from datetime import datetime, timedelta

def generate_normal_traffic(n_samples: int = 10000):
    """Генерация нормального трафика"""
    samples = []
    base_time = datetime.now()
    
    for i in range(n_samples):
        ts = base_time + timedelta(seconds=random.uniform(0, 86400))
        samples.append({
            'timestamp': ts.timestamp(),
            'src_ip': f"192.168.1.{random.randint(2, 254)}",
            'dst_ip': random.choice([
                '8.8.8.8', '1.1.1.1', '142.250.74.46',
                '13.107.42.14', '31.13.72.36'
            ]),
            'src_port': random.randint(49152, 65535),
            'dst_port': random.choice([80, 443, 53, 22, 8080]),
            'protocol': random.choice(['TCP', 'UDP']),
            'packet_size': int(random.gauss(500, 200)),
            'entropy': random.uniform(0.1, 0.4),
            'ttl': random.choice([64, 128, 255]),
            'label': 'BENIGN',
            'features': [random.gauss(0, 0.3) for _ in range(156)]
        })
    return samples

def generate_port_scan(n_samples: int = 500):
    """Генерация сканирования портов"""
    samples = []
    base_time = datetime.now()
    attacker_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    
    for i in range(n_samples):
        ts = base_time + timedelta(seconds=i * random.uniform(0.01, 0.1))
        samples.append({
            'timestamp': ts.timestamp(),
            'src_ip': attacker_ip,
            'dst_ip': f"192.168.1.{random.randint(1, 20)}",
            'src_port': random.randint(40000, 60000),
            'dst_port': random.randint(1, 65535),
            'protocol': 'TCP',
            'packet_size': random.randint(40, 60),
            'entropy': random.uniform(0.1, 0.3),
            'ttl': 64,
            'label': 'Port Scan',
            'features': [random.gauss(0.5, 0.3) for _ in range(156)]
        })
    return samples

def generate_brute_force(n_samples: int = 300):
    """Генерация подбора паролей"""
    samples = []
    base_time = datetime.now()
    attacker_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    
    for i in range(n_samples):
        ts = base_time + timedelta(seconds=i * random.uniform(0.05, 0.5))
        samples.append({
            'timestamp': ts.timestamp(),
            'src_ip': attacker_ip,
            'dst_ip': '192.168.1.10',
            'src_port': random.randint(40000, 60000),
            'dst_port': random.choice([22, 3389, 21, 3306]),
            'protocol': 'TCP',
            'packet_size': random.randint(60, 200),
            'entropy': random.uniform(0.3, 0.6),
            'ttl': 64,
            'label': 'Brute Force',
            'features': [random.gauss(0.6, 0.3) for _ in range(156)]
        })
    return samples

def generate_ddos(n_samples: int = 1000):
    """Генерация DDoS атаки"""
    samples = []
    base_time = datetime.now()
    target_ip = '192.168.1.10'
    
    bots = [f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}" 
            for _ in range(50)]
    
    for i in range(n_samples):
        ts = base_time + timedelta(seconds=i * random.uniform(0.001, 0.01))
        samples.append({
            'timestamp': ts.timestamp(),
            'src_ip': random.choice(bots),
            'dst_ip': target_ip,
            'src_port': random.randint(1, 65535),
            'dst_port': 80,
            'protocol': random.choice(['TCP', 'UDP']),
            'packet_size': random.randint(64, 1500),
            'entropy': random.uniform(0.4, 0.8),
            'ttl': random.randint(32, 255),
            'label': 'DDoS',
            'features': [random.gauss(0.8, 0.2) for _ in range(156)]
        })
    return samples

def generate_data_exfiltration(n_samples: int = 200):
    """Генерация утечки данных"""
    samples = []
    base_time = datetime.now()
    src_ip = '192.168.1.50'
    dst_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    
    for i in range(n_samples):
        ts = base_time + timedelta(seconds=i * random.uniform(0.1, 2))
        samples.append({
            'timestamp': ts.timestamp(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': random.randint(40000, 60000),
            'dst_port': random.choice([443, 8080, 53, 4444]),
            'protocol': 'TCP',
            'packet_size': int(random.gauss(1400, 100)),
            'entropy': random.uniform(0.5, 0.9),
            'ttl': 64,
            'label': 'Data Exfiltration',
            'features': [random.gauss(0.7, 0.3) for _ in range(156)]
        })
    return samples

def generate_c2_beacon(n_samples: int = 400):
    """Генерация C2 beaconing"""
    samples = []
    base_time = datetime.now()
    src_ip = '192.168.1.75'
    dst_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    
    interval = random.uniform(30, 120)  # Интервал beaconing
    for i in range(n_samples):
        ts = base_time + timedelta(seconds=i * interval)
        samples.append({
            'timestamp': ts.timestamp(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': random.randint(40000, 60000),
            'dst_port': random.choice([443, 8443, 4444, 5555]),
            'protocol': 'TCP',
            'packet_size': random.randint(100, 500),
            'entropy': random.uniform(0.6, 0.9),
            'ttl': 64,
            'label': 'C2 Beacon',
            'features': [random.gauss(0.75, 0.2) for _ in range(156)]
        })
    return samples

def main():
    print("🔄 Генерация синтетических датасетов для SHARD...")
    print("=" * 50)
    
    all_data = []
    
    print("📊 Генерация нормального трафика...")
    all_data.extend(generate_normal_traffic(10000))
    
    print("🔍 Генерация Port Scan...")
    all_data.extend(generate_port_scan(500))
    
    print("🔐 Генерация Brute Force...")
    all_data.extend(generate_brute_force(300))
    
    print("💥 Генерация DDoS...")
    all_data.extend(generate_ddos(1000))
    
    print("📤 Генерация Data Exfiltration...")
    all_data.extend(generate_data_exfiltration(200))
    
    print("🕵️ Генерация C2 Beacon...")
    all_data.extend(generate_c2_beacon(400))
    
    # Перемешиваем
    random.shuffle(all_data)
    
    # Сохраняем
    output_dir = Path('data/training')
    output_dir.mkdir(parents=True, exist_ok=True)
    
    output_path = output_dir / 'synthetic_dataset.json'
    with open(output_path, 'w') as f:
        json.dump({'samples': all_data, 'total': len(all_data)}, f, indent=2)
    
    # Статистика
    labels = {}
    for s in all_data:
        labels[s['label']] = labels.get(s['label'], 0) + 1
    
    print("\n" + "=" * 50)
    print("✅ Датасет создан:")
    print(f"   Всего сэмплов: {len(all_data)}")
    for label, count in sorted(labels.items()):
        print(f"   {label}: {count}")
    print(f"   Сохранён в: {output_path}")
    print("=" * 50)

if __name__ == '__main__':
    main()
