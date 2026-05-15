#!/usr/bin/env python3
"""Дообучение Temporal GNN на цепочках MITRE ATT&CK"""
import json, time, sys
from pathlib import Path

def create_attack_chains():
    chains = [
        {
            'name': 'Recon → Initial Access → C2',
            'stages': [
                {'attack_type': 'Port Scan', 'duration': 60, 'ports': [22, 80, 443, 3389]},
                {'attack_type': 'Brute Force', 'duration': 120, 'port': 22},
                {'attack_type': 'C2 Beacon', 'duration': 300, 'interval': 30},
            ],
            'severity': 'HIGH'
        },
        {
            'name': 'Initial Access → Execution → Exfiltration',
            'stages': [
                {'attack_type': 'Web Attack', 'duration': 30, 'port': 443},
                {'attack_type': 'Malware', 'duration': 60},
                {'attack_type': 'Data Exfiltration', 'duration': 180, 'volume_mb': 50},
            ],
            'severity': 'CRITICAL'
        },
        {
            'name': 'Recon → Lateral Movement → Credential Access',
            'stages': [
                {'attack_type': 'Port Scan', 'duration': 30, 'ports': [445, 135, 139]},
                {'attack_type': 'Lateral Movement', 'duration': 120, 'targets': 5},
                {'attack_type': 'Brute Force', 'duration': 60, 'port': 445},
            ],
            'severity': 'CRITICAL'
        },
        {
            'name': 'DNS Tunnel → C2 → Exfiltration',
            'stages': [
                {'attack_type': 'DNS Tunnel', 'duration': 600},
                {'attack_type': 'C2 Beacon', 'duration': 300, 'interval': 60},
                {'attack_type': 'Data Exfiltration', 'duration': 120, 'volume_mb': 100},
            ],
            'severity': 'CRITICAL'
        },
    ]
    
    sequences = []
    for chain in chains:
        seq = []
        base_time = time.time()
        for i, stage in enumerate(chain['stages']):
            seq.append({
                'timestamp': base_time + sum(s['duration'] for s in chain['stages'][:i]),
                **stage
            })
        sequences.append({
            'chain_name': chain['name'],
            'severity': chain['severity'],
            'events': seq
        })
    
    Path('data/training').mkdir(parents=True, exist_ok=True)
    with open('data/training/mitre_chains.json', 'w') as f:
        json.dump({'chains': sequences, 'version': '1.0', 'source': 'MITRE ATT&CK'}, f, indent=2)
    
    print(f"✅ Создано {len(sequences)} цепочек атак MITRE ATT&CK")

if __name__ == '__main__':
    create_attack_chains()
