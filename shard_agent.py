#!/usr/bin/env python3
"""
SHARD Enterprise Agent v1.0
Лёгкий сборщик трафика для отправки на центральный сервер SHARD

Использование:
    python shard_agent.py --server https://your-shard.com --token YOUR_API_KEY
"""

import os
import sys
import time
import json
import hashlib
import threading
import argparse
import requests
from datetime import datetime
from collections import deque
from pathlib import Path

try:
    from scapy.all import sniff, IP, TCP, UDP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️ Scapy не установлен. Установите: pip install scapy")
    print("⚠️ Захват трафика отключён. Используется только отправка логов.")

class SHARDAgent:
    """Лёгкий агент SHARD для сбора и отправки данных"""
    
    def __init__(self, server_url: str, api_token: str, 
                 interface: str = None, batch_size: int = 50):
        self.server_url = server_url.rstrip('/')
        self.api_token = api_token
        self.interface = interface
        self.batch_size = batch_size
        
        self.buffer = deque(maxlen=1000)
        self.lock = threading.RLock()
        self.running = False
        
        self.stats = {
            'packets_captured': 0,
            'packets_sent': 0,
            'errors': 0,
            'start_time': time.time()
        }
        
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_token}',
            'Content-Type': 'application/json',
            'User-Agent': 'SHARD-Agent/1.0'
        })
    
    def start(self):
        """Запуск агента"""
        self.running = True
        print(f"🚀 SHARD Agent запущен")
        print(f"   Сервер: {self.server_url}")
        print(f"   Интерфейс: {self.interface or 'авто'}")
        
        # Поток отправки данных
        threading.Thread(target=self._sender_loop, daemon=True).start()
        
        # Захват трафика (если доступен)
        if SCAPY_AVAILABLE and self.interface:
            threading.Thread(target=self._capture_loop, daemon=True).start()
        else:
            print("⚠️ Захват трафика отключён")
        
        # Health check
        self._heartbeat_loop()
    
    def _capture_loop(self):
        """Захват сетевого трафика"""
        def packet_handler(packet):
            if not packet.haslayer(IP):
                return
            
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = 'TCP' if packet.haslayer(TCP) else 'UDP' if packet.haslayer(UDP) else 'OTHER'
            
            src_port = dst_port = 0
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            
            payload = bytes(packet[Raw].load)[:100] if packet.haslayer(Raw) else b''
            entropy = self._calculate_entropy(payload)
            
            data = {
                'timestamp': time.time(),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'size': len(packet),
                'entropy': round(entropy, 3),
                'payload_sample': payload[:50].hex() if payload else ''
            }
            
            with self.lock:
                self.buffer.append(data)
                self.stats['packets_captured'] += 1
        
        try:
            sniff(prn=packet_handler, iface=self.interface, 
                  store=False, filter='ip')
        except Exception as e:
            print(f"❌ Ошибка захвата: {e}")
            print("💡 Запустите от root: sudo python shard_agent.py ...")
    
    def _sender_loop(self):
        """Отправка накопленных данных на сервер"""
        while self.running:
            time.sleep(5)
            
            with self.lock:
                if len(self.buffer) >= self.batch_size:
                    batch = list(self.buffer)[:self.batch_size]
                    # Не очищаем пока не отправим
                else:
                    continue
            
            try:
                response = self.session.post(
                    f'{self.server_url}/api/agent/ingest',
                    json={'packets': batch, 'agent_version': '1.0'},
                    timeout=10
                )
                
                if response.status_code == 200:
                    with self.lock:
                        # Удаляем отправленное
                        for _ in range(len(batch)):
                            if self.buffer:
                                self.buffer.popleft()
                        self.stats['packets_sent'] += len(batch)
                else:
                    self.stats['errors'] += 1
                    
            except Exception as e:
                self.stats['errors'] += 1
    
    def _heartbeat_loop(self):
        """Health check агента"""
        while self.running:
            time.sleep(30)
            try:
                self.session.post(
                    f'{self.server_url}/api/agent/heartbeat',
                    json={'stats': self.stats},
                    timeout=5
                )
            except:
                pass
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Вычисление энтропии данных"""
        if not data:
            return 0.0
        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        entropy = -sum((c/len(data)) * (__import__('math').log2(c/len(data))) 
                      for c in freq.values())
        return min(8.0, entropy)
    
    def stop(self):
        """Остановка агента"""
        self.running = False
        print(f"\n👋 SHARD Agent остановлен")
        print(f"   Пакетов захвачено: {self.stats['packets_captured']}")
        print(f"   Пакетов отправлено: {self.stats['packets_sent']}")


def main():
    parser = argparse.ArgumentParser(description='SHARD Enterprise Agent')
    parser.add_argument('--server', '-s', required=True, 
                       help='URL сервера SHARD (например, https://shard.example.com)')
    parser.add_argument('--token', '-t', required=True,
                       help='API токен для аутентификации')
    parser.add_argument('--interface', '-i', default=None,
                       help='Сетевой интерфейс для захвата (например, eth0)')
    parser.add_argument('--batch-size', '-b', type=int, default=50,
                       help='Размер пакета для отправки')
    
    args = parser.parse_args()
    
    agent = SHARDAgent(
        server_url=args.server,
        api_token=args.token,
        interface=args.interface,
        batch_size=args.batch_size
    )
    
    try:
        agent.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        agent.stop()


if __name__ == '__main__':
    main()
