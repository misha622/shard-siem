#!/usr/bin/env python3
"""
SHARD Enterprise SIEM — Нагрузочное тестирование
Генерация 100K+ пакетов/сек, замеры latency, CPU, RAM, profiling
"""

import socket
import time
import threading
import random
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
from datetime import datetime
import subprocess
import signal

# ============================================================
# КОНФИГУРАЦИЯ ТЕСТА
# ============================================================

TARGET_HOST = os.environ.get('SHARD_HOST', '127.0.0.1')
TARGET_PORTS = [2222, 3306, 5432, 6379, 8080, 8443, 21, 23, 27017, 9200]
CONCURRENT_WORKERS = int(os.environ.get('SHARD_WORKERS', '300'))
PACKETS_PER_WORKER = int(os.environ.get('SHARD_PACKETS', '500'))
TEST_DURATION = int(os.environ.get('SHARD_DURATION', '30'))  # секунд

# Симулируем реальный трафик
NORMAL_TRAFFIC = 0.7  # 70% нормального, 30% атакующего

NORMAL_PAYLOADS = [
    b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    b"GET /api/status HTTP/1.1\r\n\r\n",
    b"POST /login HTTP/1.1\r\nContent-Length: 20\r\n\r\nuser=admin&pass=test",
    b"GET /images/logo.png HTTP/1.1\r\n\r\n",
    b"HEAD /health HTTP/1.1\r\n\r\n",
    b"GET /favicon.ico HTTP/1.1\r\n\r\n",
    *([b"\x00" * 64] * 3),  # Бинарный трафик
]

ATTACK_PAYLOADS = [
    # SQL Injection
    b"GET /?id=1' UNION SELECT password FROM users-- HTTP/1.0\r\n\r\n",
    b"POST /login HTTP/1.0\r\n\r\nuser=admin' OR '1'='1",
    # Brute Force
    b"SSH-2.0-OpenSSH\r\nroot:admin123\n",
    b"FTP USER admin\r\nFTP PASS password123\r\n",
    # DDoS
    b"GET / HTTP/1.0\r\n" * 100,
    b"\x00" * 1500,
    # C2 Beacon
    b"\x16\x03\x01\x00\x62" + b"\x00" * 200,
    # Data Exfiltration
    b"POST /upload HTTP/1.0\r\nContent-Length: 99999\r\n\r\n" + b"A" * 2000,
    # Web attacks
    b"GET /wp-admin HTTP/1.0\r\n\r\n",
    b"GET /.env HTTP/1.0\r\n\r\n",
    b"GET /config.php.bak HTTP/1.0\r\n\r\n",
]

# Метрики
stats = {
    'sent': 0,
    'errors': 0,
    'connections': 0,
    'bytes_sent': 0,
    'latency_samples': [],
    'start_time': 0,
    'end_time': 0,
    'by_port': defaultdict(int),
    'by_type': defaultdict(int),
}
stats_lock = threading.Lock()
running = True


def send_packet(host, port, payload, is_attack=False):
    """Отправка одного пакета с замером latency"""
    try:
        start = time.perf_counter()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect((host, port))
        s.send(payload)
        s.close()
        elapsed = time.perf_counter() - start
        
        with stats_lock:
            stats['sent'] += 1
            stats['bytes_sent'] += len(payload)
            stats['by_port'][port] += 1
            stats['by_type']['attack' if is_attack else 'normal'] += 1
            if len(stats['latency_samples']) < 10000:
                stats['latency_samples'].append(elapsed)
        return True
    except Exception as e:
        with stats_lock:
            stats['errors'] += 1
        return False


def traffic_worker(worker_id):
    """Рабочий поток — генерирует трафик"""
    for _ in range(PACKETS_PER_WORKER):
        if not running:
            break
        
        is_attack = random.random() > NORMAL_TRAFFIC
        port = random.choice(TARGET_PORTS)
        
        if is_attack:
            payload = random.choice(ATTACK_PAYLOADS)
        else:
            payload = random.choice(NORMAL_PAYLOADS)
        
        send_packet(TARGET_HOST, port, payload, is_attack)
        
        # Небольшая пауза между пакетами для реалистичности
        time.sleep(random.uniform(0, 0.001))


def resource_monitor():
    """Мониторинг CPU и RAM во время теста"""
    start = time.time()
    cpu_samples = []
    mem_samples = []
    
    while running:
        try:
            # Получаем метрики из Docker если доступен
            result = subprocess.run(
                ['docker', 'stats', '--no-stream', '--format', 
                 '{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}', 'shard-enterprise'],
                capture_output=True, text=True, timeout=2
            )
            if result.stdout.strip():
                cpu, mem, mem_pct = result.stdout.strip().split('|')
                cpu_samples.append(float(cpu.replace('%', '')))
                mem_samples.append(float(mem_pct.replace('%', '')))
        except:
            pass
        time.sleep(1)
    
    return cpu_samples, mem_samples


def print_header():
    print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║         🔥 SHARD ENTERPRISE SIEM — НАГРУЗОЧНОЕ ТЕСТИРОВАНИЕ        ║
╠══════════════════════════════════════════════════════════════════════╣
║  Цель: {TARGET_HOST}:{TARGET_PORTS}                              ║
║  Потоков: {CONCURRENT_WORKERS}                                               ║
║  Пакетов на поток: {PACKETS_PER_WORKER}                                         ║
║  Всего пакетов: ~{CONCURRENT_WORKERS * PACKETS_PER_WORKER // 1000}K                                              ║
║  Длительность: {TEST_DURATION}s                                                   ║
╚══════════════════════════════════════════════════════════════════════╝
""")


def run_benchmark():
    global running, stats
    
    print_header()
    
    # Запускаем мониторинг ресурсов
    monitor_thread = threading.Thread(target=resource_monitor)
    monitor_thread.start()
    
    # Запускаем генерацию трафика
    stats['start_time'] = time.time()
    
    print("⏳ Генерация трафика...")
    
    with ThreadPoolExecutor(max_workers=CONCURRENT_WORKERS) as executor:
        futures = []
        for i in range(CONCURRENT_WORKERS):
            futures.append(executor.submit(traffic_worker, i))
        
        # Ждём завершения или таймаута
        done_count = 0
        update_interval = max(1, len(futures) // 10)
        for i, future in enumerate(futures):
            try:
                future.result(timeout=TEST_DURATION)
                done_count += 1
                if done_count % update_interval == 0:
                    pct = done_count / len(futures) * 100
                    with stats_lock:
                        print(f"   Прогресс: {pct:.0f}% | Отправлено: {stats['sent']:,} | "
                              f"Ошибок: {stats['errors']}")
            except:
                break
    
    running = False
    stats['end_time'] = time.time()
    monitor_thread.join(timeout=2)
    
    # ============================================================
    # ОТЧЁТ
    # ============================================================
    elapsed = stats['end_time'] - stats['start_time']
    pps = stats['sent'] / elapsed if elapsed > 0 else 0
    
    print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║                    📊 РЕЗУЛЬТАТЫ ТЕСТИРОВАНИЯ                      ║
╠══════════════════════════════════════════════════════════════════════╣
║  Время теста:          {elapsed:.1f}s                                          ║
║  Пакетов отправлено:   {stats['sent']:,}                                         ║
║  Трафика отправлено:   {stats['bytes_sent'] / 1024 / 1024:.1f} MB                                     ║
║  Скорость:             {pps:,.0f} пакетов/сек                                  ║
║  Ошибок:               {stats['errors']}                                              ║
║  Успешность:           {(1 - stats['errors'] / max(1, stats['sent'])) * 100:.1f}%                                          ║
╠══════════════════════════════════════════════════════════════════════╣
║  По портам:                                                         ║""")
    
    for port, count in sorted(stats['by_port'].items()):
        pct = count / max(1, stats['sent']) * 100
        print(f"║    {port:5d}: {count:6,} ({pct:4.1f}%)                                        ║")
    
    print(f"""╠══════════════════════════════════════════════════════════════════════╣
║  По типам трафика:                                                  ║
║    Normal:  {stats['by_type']['normal']:6,}                                              ║
║    Attack:  {stats['by_type']['attack']:6,}                                              ║
╠══════════════════════════════════════════════════════════════════════╣
║  Latency:                                                           ║""")
    
    if stats['latency_samples']:
        latencies = sorted(stats['latency_samples'])
        avg = sum(latencies) / len(latencies)
        p50 = latencies[len(latencies) // 2] * 1000
        p95 = latencies[int(len(latencies) * 0.95)] * 1000
        p99 = latencies[int(len(latencies) * 0.99)] * 1000
        print(f"║    Avg: {avg*1000:.2f}ms | P50: {p50:.2f}ms | P95: {p95:.2f}ms | P99: {p99:.2f}ms                  ║")
    
    print(f"""╚══════════════════════════════════════════════════════════════════════╝
""")
    
    # Сохраняем JSON-отчёт
    report = {
        'timestamp': datetime.now().isoformat(),
        'duration': elapsed,
        'packets_sent': stats['sent'],
        'bytes_sent': stats['bytes_sent'],
        'packets_per_second': pps,
        'errors': stats['errors'],
        'by_port': dict(stats['by_port']),
        'by_type': dict(stats['by_type']),
        'latency': {
            'avg_ms': sum(latencies) / len(latencies) * 1000 if latencies else 0,
            'p50_ms': p50 if 'p50' in dir() else 0,
            'p95_ms': p95 if 'p95' in dir() else 0,
            'p99_ms': p99 if 'p99' in dir() else 0,
        }
    }
    
    report_path = f'benchmark_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"📁 Отчёт сохранён: {report_path}")
    
    return report


def signal_handler(sig, frame):
    global running
    print("\n🛑 Прерывание теста...")
    running = False


if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    
    print("🔍 Проверка доступности SHARD...")
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((TARGET_HOST, 8080))
        s.close()
        print("✅ SHARD доступен на порту 8080")
    except:
        print("❌ SHARD не отвечает! Запусти SHARD сначала:")
        print("   docker run -d --name shard-enterprise ...")
        sys.exit(1)
    
    report = run_benchmark()
    
    # Проверим что SHARD обработал
    try:
        result = subprocess.run(
            ['docker', 'logs', 'shard-enterprise'], 
            capture_output=True, text=True, timeout=5
        )
        defense_count = result.stdout.count('🛡️ DEFENSE:')
        honeypot_count = result.stdout.count('🍯')
        rl_count = result.stdout.count('RL Decision')
        
        print(f"📊 SHARD за время теста:")
        print(f"   🛡️ Defence действий: {defense_count}")
        print(f"   🍯 Honeypot срабатываний: {honeypot_count}")
        print(f"   🤖 RL решений: {rl_count}")
    except:
        pass
