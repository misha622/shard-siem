#!/usr/bin/env python3
"""Конвертер датасетов в формат SHARD"""
import csv, json, sys, os
from pathlib import Path

def parse_cic_ids_2017(csv_path: str, output_dir: str):
    """Парсинг CIC-IDS-2017 в формат SHARD"""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    normal_samples = []
    attack_samples = []
    
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            label = row.get('Label', '').strip()
            
            features = []
            for key in ['Destination Port', 'Flow Duration', 'Total Fwd Packets',
                       'Total Backward Packets', 'Fwd Packet Length Mean',
                       'Bwd Packet Length Mean', 'Flow Bytes/s', 'Flow Packets/s']:
                try:
                    features.append(float(row.get(key, 0)))
                except:
                    features.append(0.0)
            
            sample = {
                'features': features,
                'label': label,
                'src_ip': row.get('Source IP', '0.0.0.0'),
                'dst_ip': row.get('Destination IP', '0.0.0.0'),
                'dst_port': int(float(row.get('Destination Port', 0)))
            }
            
            if label == 'BENIGN':
                normal_samples.append(sample)
            else:
                attack_samples.append(sample)
    
    with open(os.path.join(output_dir, 'normal_samples.json'), 'w') as f:
        json.dump(normal_samples[:100000], f)
    
    with open(os.path.join(output_dir, 'attack_samples.json'), 'w') as f:
        json.dump(attack_samples[:50000], f)
    
    print(f"✅ Извлечено: {len(normal_samples)} нормальных, {len(attack_samples)} атак")
    return len(normal_samples), len(attack_samples)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Использование: python parse_dataset.py <путь_к_csv>")
        sys.exit(1)
    parse_cic_ids_2017(sys.argv[1], 'data/training/')
