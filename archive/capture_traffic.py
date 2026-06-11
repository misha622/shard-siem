#!/usr/bin/env python3
"""Захват реального трафика для обучения SHARD"""
import time, json, os
from collections import defaultdict
from pathlib import Path

import subprocess, signal, sys

capture_duration = int(os.environ.get('CAPTURE_HOURS', '1')) * 3600
output_file = Path('data/captured_traffic.jsonl')

print(f"📡 Захват трафика на {capture_duration/3600:.1f} часов...")
print(f"📁 Сохранение: {output_file}")
print("⏳ Нажми Ctrl+C для остановки\n")

proc = subprocess.Popen(
    ['python3', 'run_shard.py', '--no-capture'],
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    text=True
)

packets = []
start = time.time()

try:
    for line in proc.stdout:
        packets.append({'timestamp': time.time(), 'log': line.strip()})
        if len(packets) % 1000 == 0:
            elapsed = time.time() - start
            print(f"   Захвачено: {len(packets)} записей ({elapsed:.0f}с)")
        
        if time.time() - start > capture_duration:
            break
except KeyboardInterrupt:
    print("\n🛑 Остановка...")

finally:
    proc.terminate()
    proc.wait(timeout=5)
    
    output_file.parent.mkdir(exist_ok=True)
    with open(output_file, 'w') as f:
        for p in packets:
            f.write(json.dumps(p) + '\n')
    
    print(f"\n✅ Захвачено {len(packets)} записей")
    print(f"📁 Файл: {output_file} ({output_file.stat().st_size / 1024:.1f} KB)")
