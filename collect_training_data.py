#!/usr/bin/env python3
"""
📊 СБОР И РАЗМЕТКА ЛОГОВ SHARD ДЛЯ ДООБУЧЕНИЯ
Создаёт датасет с правильными метками (атака / не атака)
"""

import os
import json
import re
from datetime import datetime
from typing import Dict, List, Tuple
import sys


class SHARDLogCollector:
    """Сбор и автоматическая разметка логов SHARD"""

    def __init__(self):
        self.training_data = []

        self.attack_patterns = [
            (r'🍯.*Honeypot.*triggered', 'honeypot', 1.0),
            (r'🔔 ALERT:.*Deception trap', 'honeypot', 1.0),
            (r'SQL Injection', 'web_attack', 1.0),
            (r'XSS Attack', 'web_attack', 1.0),
            (r'Brute Force', 'brute_force', 1.0),
            (r'Port Scan from', 'scan', 1.0),
            (r'DDoS from', 'dos', 1.0),
            (r'🎯 Trained Model: (honeypot|web_attack|scan|dos|brute_force)', 'attack', 0.9),
            (r'⚠️ Trained Model подтверждает атаку', 'attack', 0.95),
        ]

        self.system_patterns = [
            (r'INFO:SHARD\\.(ML|Dashboard|Prometheus|Capture)', 'benign', 1.0),
            (r'✅.*загружен', 'benign', 1.0),
            (r'🚀.*запущен', 'benign', 1.0),
            (r'📊.*Adaptive', 'benign', 1.0),
            (r'DeepFeatureExtractor', 'benign', 1.0),
            (r'TensorFlow', 'benign', 1.0),
            (r'Epoch \d+', 'benign', 1.0),
            (r'Batch \d+', 'benign', 1.0),
            (r'werkzeug', 'benign', 1.0),
            (r'urllib3', 'benign', 1.0),
            (r'Error fetching feed', 'benign', 1.0),
            (r'Read timed out', 'benign', 1.0),
            (r'ConnectionPool', 'benign', 1.0),
            (r'OT/IoT.*EtherNet/IP', 'benign', 1.0),
            (r'🏭', 'benign', 1.0),
        ]

    def extract_features(self, log_line: str) -> Dict:
        """Извлечение признаков из строки лога"""
        features = {
            'raw_log': log_line[:500],
            'length': len(log_line),
            'has_emoji': any(c in log_line for c in ['🍯', '🔔', '✅', '🚀', '📊', '⚠️', '🎯', '🤖', '🧠']),
            'has_ip': bool(re.search(r'\d+\.\d+\.\d+\.\d+', log_line)),
            'has_port': bool(re.search(r':\d{2,5}', log_line)),
            'log_level': self._extract_log_level(log_line),
            'component': self._extract_component(log_line),
        }
        return features

    def _extract_log_level(self, log_line: str) -> str:
        """Извлечение уровня логирования"""
        if 'ERROR' in log_line:
            return 'ERROR'
        elif 'WARNING' in log_line:
            return 'WARNING'
        elif 'INFO' in log_line:
            return 'INFO'
        elif 'DEBUG' in log_line:
            return 'DEBUG'
        return 'UNKNOWN'

    def _extract_component(self, log_line: str) -> str:
        """Извлечение компонента SHARD"""
        match = re.search(r'SHARD\.(\w+)', log_line)
        if match:
            return match.group(1)
        return 'UNKNOWN'

    def classify_log(self, log_line: str) -> Tuple[str, float]:
        """
        Автоматическая классификация лога
        Returns: (label, confidence)
        """
        for pattern, label, confidence in self.attack_patterns:
            if re.search(pattern, log_line):
                return label, confidence

        for pattern, label, confidence in self.system_patterns:
            if re.search(pattern, log_line):
                return label, confidence

        return 'unknown', 0.5

    def collect_from_file(self, log_file: str) -> int:
        """Сбор данных из файла лога"""
        print(f"📥 Обработка {log_file}...")

        if not os.path.exists(log_file):
            print(f"   ⚠️ Файл не найден: {log_file}")
            return 0

        count = 0
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or len(line) < 10:
                    continue

                label, confidence = self.classify_log(line)

                features = self.extract_features(line)

                self.training_data.append({
                    'log': line[:300],
                    'label': label,
                    'confidence': confidence,
                    'features': features,
                    'is_attack': label not in ['benign', 'unknown'],
                    'timestamp': datetime.now().isoformat()
                })
                count += 1

        print(f"   ✅ Обработано {count} строк")
        return count

    def get_statistics(self) -> Dict:
        """Статистика собранных данных"""
        stats = {
            'total': len(self.training_data),
            'attacks': sum(1 for d in self.training_data if d['is_attack']),
            'benign': sum(1 for d in self.training_data if d['label'] == 'benign'),
            'unknown': sum(1 for d in self.training_data if d['label'] == 'unknown'),
            'by_label': {},
            'by_component': {},
            'by_log_level': {},
        }

        for item in self.training_data:
            label = item['label']
            stats['by_label'][label] = stats['by_label'].get(label, 0) + 1

            comp = item['features']['component']
            stats['by_component'][comp] = stats['by_component'].get(comp, 0) + 1

            level = item['features']['log_level']
            stats['by_log_level'][level] = stats['by_log_level'].get(level, 0) + 1

        return stats

    def save_dataset(self, output_file: str = 'shard_logs_dataset.jsonl'):
        """Сохранение датасета"""
        with open(output_file, 'w', encoding='utf-8') as f:
            for item in self.training_data:
                f.write(json.dumps(item, ensure_ascii=False) + '\n')

        print(f"💾 Датасет сохранён: {output_file}")
        print(f"   Всего записей: {len(self.training_data)}")

        csv_file = output_file.replace('.jsonl', '.csv')
        import csv
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['log', 'label', 'confidence', 'is_attack', 'component', 'log_level'])
            for item in self.training_data:
                writer.writerow([
                    item['log'][:100],
                    item['label'],
                    item['confidence'],
                    item['is_attack'],
                    item['features']['component'],
                    item['features']['log_level']
                ])
        print(f"   CSV сохранён: {csv_file}")


def main():
    print("=" * 60)
    print("📊 СБОР И РАЗМЕТКА ЛОГОВ SHARD")
    print("=" * 60)

    collector = SHARDLogCollector()

    log_files = [
        'shard.log',
        'shard_security.log',
    ]

    total = 0
    for log_file in log_files:
        total += collector.collect_from_file(log_file)

    if total == 0:
        print("\n⚠️ Логи не найдены. Создаю синтетический датасет...")
        collector._create_synthetic_dataset()

    print("\n" + "=" * 60)
    print("📊 СТАТИСТИКА СОБРАННЫХ ДАННЫХ")
    print("=" * 60)

    stats = collector.get_statistics()
    print(f"Всего записей: {stats['total']}")
    print(f"  🔴 Атаки: {stats['attacks']} ({stats['attacks'] / max(1, stats['total']) * 100:.1f}%)")
    print(f"  🟢 Benign: {stats['benign']} ({stats['benign'] / max(1, stats['total']) * 100:.1f}%)")
    print(f"  ⚪ Unknown: {stats['unknown']} ({stats['unknown'] / max(1, stats['total']) * 100:.1f}%)")

    print("\n📊 По меткам:")
    for label, count in sorted(stats['by_label'].items(), key=lambda x: -x[1]):
        print(f"  {label}: {count}")

    print("\n📊 По компонентам:")
    for comp, count in sorted(stats['by_component'].items(), key=lambda x: -x[1])[:10]:
        print(f"  {comp}: {count}")

    collector.save_dataset('shard_logs_dataset.jsonl')

    print("\n" + "=" * 60)
    print("🎉 СБОР ДАННЫХ ЗАВЕРШЁН!")
    print("=" * 60)
    print("\n📝 Следующий шаг:")
    print("   python3 train_on_shard_logs_v2.py")
    print("=" * 60)


if __name__ == "__main__":
    main()