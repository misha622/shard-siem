#!/usr/bin/env python3

"""
SHARD Deception Technology Module
Полноценная honeypot-ферма с реалистичными сервисами
Обнаружение lateral movement, credential theft, и атак

Author: SHARD Enterprise
Version: 5.0.0
"""

import os
import joblib
import re
import json
import time
import socket
import threading
import random
import hashlib
import base64
import struct
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set, Union
from collections import deque, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor

import requests
import yaml



class DeceptionType(Enum):
    """Типы ловушек"""
    HONEYPOT = "honeypot"
    HONEYTOKEN = "honeytoken"
    HONEYNET = "honeynet"
    CANARY = "canary"
    BREADCRUMB = "breadcrumb"


class DeceptionSeverity(Enum):
    """Серьёзность срабатывания"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class DeceptionConfig:
    """Конфигурация Deception Technology"""

    enabled: bool = True
    mode: str = "realistic"

    network_honeypots: List[Dict] = field(default_factory=lambda: [
        {'name': 'SSH', 'port': 2222, 'protocol': 'tcp', 'banner': 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6'},
        {'name': 'HTTP', 'port': 8080, 'protocol': 'tcp', 'banner': 'Apache/2.4.52 (Ubuntu)'},
        {'name': 'HTTPS', 'port': 8443, 'protocol': 'tcp', 'banner': 'nginx/1.18.0'},
        {'name': 'MySQL', 'port': 3306, 'protocol': 'tcp', 'banner': '5.7.40-0ubuntu0.18.04.1'},
        {'name': 'PostgreSQL', 'port': 5432, 'protocol': 'tcp', 'banner': 'PostgreSQL 14.5'},
        {'name': 'Redis', 'port': 6379, 'protocol': 'tcp', 'banner': 'redis 6.0.16'},
        {'name': 'MongoDB', 'port': 27017, 'protocol': 'tcp', 'banner': 'MongoDB 5.0.14'},
        {'name': 'Elasticsearch', 'port': 9200, 'protocol': 'tcp', 'banner': 'Elasticsearch 7.17.6'},
        {'name': 'SMB', 'port': 445, 'protocol': 'tcp', 'banner': 'SMB 3.1.1'},
        {'name': 'RDP', 'port': 3389, 'protocol': 'tcp', 'banner': 'RDP 10.0'},
        {'name': 'VNC', 'port': 5900, 'protocol': 'tcp', 'banner': 'RFB 003.008'},
        {'name': 'Telnet', 'port': 23, 'protocol': 'tcp', 'banner': 'Ubuntu 22.04 LTS'},
        {'name': 'FTP', 'port': 21, 'protocol': 'tcp', 'banner': 'vsFTPd 3.0.5'},
    ])

    honeytokens: List[Dict] = field(default_factory=lambda: [
        {'name': 'passwords.txt', 'path': '/home/user/Documents/', 'content': 'admin:SuperSecret123\nroot:toor\n'},
        {'name': 'id_rsa', 'path': '/home/user/.ssh/',
         'content': '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----'},
        {'name': 'database.ini', 'path': '/var/www/html/',
         'content': '[mysql]\nhost=localhost\nuser=admin\npassword=DBPass123!'},
        {'name': '.env', 'path': '/var/www/app/', 'content': 'API_KEY=sk-1234567890abcdef\nSECRET=mysecretkey'},
        {'name': 'web.config', 'path': '/inetpub/wwwroot/',
         'content': '<configuration>\n  <connectionStrings>\n    <add name="Default" connectionString="Server=DB01;User=sa;Password=SAPass123!"/>\n  </connectionStrings>\n</configuration>'},
    ])

    breadcrumbs: List[Dict] = field(default_factory=lambda: [
        {'type': 'registry', 'key': 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', 'value': 'AdobeUpdate',
         'data': 'C:\\Program Files\\Adobe\\updater.exe'},
        {'type': 'history', 'file': '.bash_history',
         'content': 'ssh admin@10.0.0.5\nmysql -h db01 -u root -p\nsudo su -\n'},
        {'type': 'browser', 'file': 'Login Data',
         'content': 'https://vault.company.com\nhttps://admin-portal.internal'},
        {'type': 'rdp', 'file': 'default.rdp', 'content': 'full address:s:10.0.0.10:3389\nusername:s:administrator'},
    ])

    canary_tokens: List[Dict] = field(default_factory=lambda: [
        {'type': 'aws_key', 'value': 'AKIAIOSFODNN7EXAMPLE'},
        {'type': 'slack_webhook',
         'value': 'https://hooks.slack.com/services/TEST/FAKE/EXAMPLE'},
        {'type': 'http_endpoint', 'value': '/api/internal/health'},
        {'type': 'dns_entry', 'value': 'db-backup.internal.company.com'},
    ])

    auto_block: bool = True
    auto_isolate: bool = False
    alert_severity: str = "HIGH"
    data_dir: str = "./data/deception/"
    logs_dir: str = "./data/deception/logs/"
    emulate_vulnerabilities: bool = True
    record_sessions: bool = True
    max_session_size_mb: int = 10



class BaseHoneypot:
    """Базовый класс для всех ловушек"""

    def __init__(self, name: str, config: Dict, logger=None):
        self.name = name
        self.config = config
        self.logger = logger
        self.running = False
        self.connections: deque = deque(maxlen=1000)
        self.stats = {
            'total_connections': 0,
            'unique_sources': set(),
            'triggers': 0
        }
        self._lock = threading.RLock()

    def start(self):
        self.running = True

    def stop(self):
        self.running = False

    def get_stats(self) -> Dict:
        with self._lock:
            return {
                'name': self.name,
                'total_connections': self.stats['total_connections'],
                'unique_sources': len(self.stats['unique_sources']),
                'triggers': self.stats['triggers']
            }



class NetworkHoneypot(BaseHoneypot):
    """Сетевой honeypot с реалистичной эмуляцией сервиса"""

    def __init__(self, name: str, port: int, protocol: str, banner: str,
                 config: Dict, logger=None, callback=None):
        super().__init__(name, config, logger)
        self.port = port
        self.protocol = protocol
        self.banner = banner
        self.callback = callback
        self.event_bus = None
        self.socket: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None
        self.vulnerabilities = self._load_vulnerabilities()
        self._ai_model = None

    def _load_vulnerabilities(self) -> List[Dict]:
        vulns = {
            'SSH': [{'cve': 'CVE-2021-41617', 'exploit': 'ssh-auth-bypass'}],
            'HTTP': [{'cve': 'CVE-2021-41773', 'exploit': 'path-traversal'}],
            'MySQL': [{'cve': 'CVE-2012-2122', 'exploit': 'auth-bypass'}],
            'SMB': [{'cve': 'CVE-2020-0796', 'exploit': 'smb-ghost'}],
        }
        return vulns.get(self.name, [])

    def start(self):
        super().start()
        self.thread = threading.Thread(target=self._listen, daemon=True)
        self.thread.start()
        if self.logger:
            self.logger.info(f"🍯 Honeypot {self.name} started on port {self.port}")

    def stop(self):
        super().stop()
        if self.socket:
            try:
                self.socket.close()
            except:
                pass

    def _listen(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(('0.0.0.0', self.port))
            self.socket.listen(5)
            self.socket.settimeout(1.0)

            while self.running:
                try:
                    conn, addr = self.socket.accept()
                    threading.Thread(target=self._handle_connection, args=(conn, addr), daemon=True).start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running and self.logger:
                        self.logger.debug(f"Honeypot {self.name} accept error: {e}")

        except Exception as e:
            if self.logger:
                self.logger.error(f"Honeypot {self.name} error: {e}")

    def _handle_connection(self, conn: socket.socket, addr: Tuple[str, int]):
        src_ip = addr[0]
        src_port = addr[1]

        with self._lock:
            self.stats['total_connections'] += 1
            self.stats['unique_sources'].add(src_ip)

        if self.logger:
            self.logger.warning(f"🍯 [{self.name}] Connection from {src_ip}:{src_port}")
        
        try:
            alert = {
                'timestamp': time.time(),
                'attack_type': f'Honeypot - {self.name}',
                'severity': 'HIGH',
                'score': 0.9,
                'confidence': 0.95,
                'is_attack': True,
                'src_ip': src_ip,
                'dst_port': self.port,
                'explanation': f'ПОДКЛЮЧЕНИЕ К HONEYPOT {self.name} от {src_ip}'
            }
            if self.event_bus:
                self.event_bus.publish('honeypot.connection', alert)
                self.event_bus.publish('alert.detected', alert)
            if self.callback:
                self.callback(self.name, src_ip, self.port, None, None)
        except Exception as e:
            pass

        try:
            if self._ai_model is None:
                model_path = os.path.join(os.path.dirname(__file__), 'models', 'shard_real_alert_model.pkl')
                if os.path.exists(model_path):
                    self._ai_model = joblib.load(model_path)
            if self._ai_model is not None:
                alert = f"WARNING:SHARD.SHARD:🍯 Honeypot {self.name} triggered by {src_ip}"
                pred = self._ai_model.predict([alert])[0]
                print(f"🎯 [AI] {pred.upper()} from {src_ip}")
        except Exception as e:
            pass

        try:
            conn.send(self.banner.encode() + b'\r\n')
        except:
            pass

        data = b''
        try:
            conn.settimeout(5.0)
            while True:
                chunk = conn.recv(1024)
                if not chunk:
                    break
                data += chunk
                if len(data) > 10240:
                    break
        except socket.timeout:
            pass
        except:
            pass

        response = self._generate_response(data)
        if response:
            try:
                conn.send(response)
            except:
                pass

        session_data = {
            'timestamp': time.time(),
            'src_ip': src_ip,
            'src_port': src_port,
            'service': self.name,
            'port': self.port,
            'data_received': data[:1000].hex() if data else None,
            'data_sent': response[:1000].hex() if response else None
        }
        self.connections.append(session_data)

        if self.callback:
            self.callback(self.name, src_ip, self.port, data, response)

        self._check_triggers(src_ip, data)
        conn.close()

    def _generate_response(self, data: bytes) -> Optional[bytes]:
        if not data:
            return None

        data_str = data.decode('utf-8', errors='ignore')

        if self.name == 'SSH':
            return b'Protocol mismatch.\r\n'
        elif self.name == 'HTTP':
            if 'GET' in data_str:
                return b'HTTP/1.1 200 OK\r\nServer: Apache/2.4.52\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Welcome</h1></body></html>'
            elif 'POST' in data_str:
                return b'HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n'
            return b'HTTP/1.1 400 Bad Request\r\n\r\n'
        elif self.name == 'MySQL':
            if len(data) > 4:
                return b'\x4a\x00\x00\x00\x0a\x35\x2e\x37\x2e\x34\x30\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            return None
        elif self.name == 'SMB':
            if data[:4] == b'\x00\x00\x00\xa4':
                return b'\x00\x00\x00\x00'
            return None
        elif self.name == 'RDP':
            return b'\x03\x00\x00\x13\x0e\xd0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00'
        elif self.name == 'Redis':
            if b'PING' in data:
                return b'+PONG\r\n'
            elif b'INFO' in data:
                return b'$1024\r\nredis_version:6.0.0\r\nredis_mode:standalone\r\n' + b'*4\r\n$10\r\ncluster_\r\n$7\r\nenabled\r\n:0\r\n'
            return b'-ERR unknown command\r\n'
        return None

    def _check_triggers(self, src_ip: str, data: bytes):
        if not data:
            return

        data_str = data.decode('utf-8', errors='ignore').lower()
        triggers = {
            'SSH': ['root', 'admin', 'password', 'ssh-'],
            'HTTP': ['/admin', '/wp-admin', '/.env', '/config', '/phpmyadmin', 'union', 'select'],
            'MySQL': ['root', 'mysql', 'information_schema'],
            'Redis': ['config', 'set', 'slaveof', 'eval'],
        }

        service_triggers = triggers.get(self.name, [])
        detected = [t for t in service_triggers if t in data_str]

        if detected:
            with self._lock:
                self.stats['triggers'] += 1
            if self.logger:
                self.logger.warning(f"🚨 [{self.name}] Attack detected from {src_ip}: {', '.join(detected)}")



class HoneyToken(BaseHoneypot):
    """Файл-приманка с отслеживанием доступа"""

    def __init__(self, name: str, path: str, content: str, config: Dict, logger=None, callback=None):
        super().__init__(name, config, logger)
        self.path = Path(path)
        self.content = content
        self.callback = callback
        self.token_id = hashlib.md5(f"{name}{path}".encode()).hexdigest()[:8]
        self.watcher_thread: Optional[threading.Thread] = None
        self.last_modified: Optional[float] = None
        self._create_token()

    def _create_token(self):
        try:
            full_path = self.path / self.name
            full_path.parent.mkdir(parents=True, exist_ok=True)
            marked_content = f"{self.content}\n<!-- TOKEN_ID:{self.token_id} -->"
            with open(full_path, 'w') as f:
                f.write(marked_content)
            self.last_modified = full_path.stat().st_mtime
            if self.logger:
                self.logger.info(f"🍯 HoneyToken created: {full_path}")
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to create HoneyToken {self.name}: {e}")

    def start(self):
        super().start()
        self.watcher_thread = threading.Thread(target=self._watch, daemon=True)
        self.watcher_thread.start()

    def _watch(self):
        full_path = self.path / self.name
        while self.running:
            time.sleep(5)
            if not full_path.exists():
                with self._lock:
                    self.stats['triggers'] += 1
                if self.logger:
                    self.logger.critical(f"🚨 HoneyToken DELETED: {full_path}")
                if self.callback:
                    self.callback('honeytoken', 'deleted', str(full_path), None)
                self._create_token()
            else:
                current_mtime = full_path.stat().st_mtime
                if self.last_modified and abs(current_mtime - self.last_modified) > 1:
                    with self._lock:
                        self.stats['triggers'] += 1
                    try:
                        with open(full_path, 'r') as f:
                            content = f.read()
                            if f"TOKEN_ID:{self.token_id}" not in content:
                                if self.logger:
                                    self.logger.critical(f"🚨 HoneyToken MODIFIED: {full_path}")
                                if self.callback:
                                    self.callback('honeytoken', 'modified', str(full_path), content[:200])
                    except:
                        pass
                self.last_modified = current_mtime



class CanaryToken(BaseHoneypot):
    """Canary token - веб-триггер при обращении"""

    def __init__(self, token_type: str, value: str, config: Dict, logger=None, callback=None):
        super().__init__(f"Canary-{token_type}", config, logger)
        self.token_type = token_type
        self.value = value
        self.callback = callback
        self.token_id = hashlib.md5(value.encode()).hexdigest()[:12]

    def check_trigger(self, data: Dict) -> bool:
        triggered = False
        if self.token_type == 'aws_key' and data.get('aws_key') == self.value:
            triggered = True
        elif self.token_type == 'http_endpoint' and self.value in data.get('path', ''):
            triggered = True
        elif self.token_type == 'dns_entry' and self.value in data.get('query', ''):
            triggered = True
        elif self.token_type == 'slack_webhook' and self.value in data.get('url', ''):
            triggered = True

        if triggered:
            with self._lock:
                self.stats['triggers'] += 1
            if self.logger:
                self.logger.critical(f"🚨 CanaryToken TRIGGERED: {self.token_type}")
            if self.callback:
                self.callback('canary', self.token_type, self.value, data)
            return True
        return False



class DeceptionEngine:
    """Основной движок Deception Technology"""

    def __init__(self, config: DeceptionConfig = None, logger=None, event_bus=None):
        self.config = config or DeceptionConfig()
        self.logger = logger
        self.event_bus = event_bus
        self.honeypots: Dict[str, NetworkHoneypot] = {}
        self.honeytokens: Dict[str, HoneyToken] = {}
        self.canary_tokens: Dict[str, CanaryToken] = {}
        self.stats = {
            'total_triggers': 0,
            'total_connections': 0,
            'unique_attackers': set(),
            'triggers_by_type': defaultdict(int),
            'triggers_by_service': defaultdict(int)
        }
        self._lock = threading.RLock()
        self._running = False
        self._ai_model = None
        self._init_traps()

    def _init_traps(self):
        for hp_config in self.config.network_honeypots:
            hp = NetworkHoneypot(
                name=hp_config['name'],
                port=hp_config['port'],
                protocol=hp_config['protocol'],
                banner=hp_config['banner'],
                config=hp_config,
                logger=self.logger,
                callback=self._on_trap_triggered
            )
            hp.event_bus = self.event_bus
            self.honeypots[hp_config['name']] = hp

        for ht_config in self.config.honeytokens:
            ht = HoneyToken(
                name=ht_config['name'],
                path=ht_config['path'],
                content=ht_config['content'],
                config=ht_config,
                logger=self.logger,
                callback=self._on_trap_triggered
            )
            self.honeytokens[ht_config['name']] = ht

        for ct_config in self.config.canary_tokens:
            ct = CanaryToken(
                token_type=ct_config['type'],
                value=ct_config['value'],
                config=ct_config,
                logger=self.logger,
                callback=self._on_trap_triggered
            )
            self.canary_tokens[f"{ct_config['type']}_{hash(ct_config['value'])}"] = ct

    def start(self):
        self._running = True
        for hp in self.honeypots.values():
            hp.start()
        for ht in self.honeytokens.values():
            ht.start()
        if self.logger:
            self.logger.info(
                f"🚀 Deception Engine started with {len(self.honeypots)} honeypots, {len(self.honeytokens)} tokens")

    def stop(self):
        self._running = False
        for hp in self.honeypots.values():
            hp.stop()
        for ht in self.honeytokens.values():
            ht.stop()
        if self.logger:
            self.logger.info("🛑 Deception Engine stopped")

    def _on_trap_triggered(self, trap_type: str, *args):
        with self._lock:
            self.stats['total_triggers'] += 1
            self.stats['triggers_by_type'][trap_type] += 1

        if trap_type in self.honeypots:
            service = trap_type
            src_ip = args[0] if len(args) > 0 else 'unknown'

            if src_ip == "127.0.0.1" or src_ip == "::1":
                return

            self.stats['unique_attackers'].add(src_ip)
            self.stats['triggers_by_service'][service] += 1
            self.stats['total_connections'] += 1

            if self.logger:
                self.logger.warning(f"🍯 Honeypot {service} triggered by {src_ip}")

            try:
                if self._ai_model is None:
                    model_path = os.path.join(os.path.dirname(__file__), 'models', 'shard_real_alert_model.pkl')
                    if os.path.exists(model_path):
                        self._ai_model = joblib.load(model_path)
                if self._ai_model is not None:
                    alert = f"WARNING:SHARD.SHARD:🍯 Honeypot {service} triggered by {src_ip}"
                    pred = self._ai_model.predict([alert])[0]
                    print(f"🎯🎯🎯 [AI DETECTION] {pred.upper()} from {src_ip} ({service}) 🎯🎯🎯")
            except Exception as e:
                pass

        elif trap_type == 'honeytoken':
            action = args[0] if len(args) > 0 else 'unknown'
            path = args[1] if len(args) > 1 else 'unknown'
            self.stats['triggers_by_type']['honeytoken'] += 1
            if self.logger:
                self.logger.critical(f"🚨 HoneyToken {action}: {path}")

        elif trap_type == 'canary':
            token_type = args[0] if len(args) > 0 else 'unknown'
            self.stats['triggers_by_type']['canary'] += 1
            if self.logger:
                self.logger.critical(f"🚨 CanaryToken {token_type} triggered")

        self._generate_alert(trap_type, args)

    def _generate_alert(self, trap_type: str, args: tuple):
        alert = {
            'timestamp': time.time(),
            'attack_type': 'Deception Trigger',
            'severity': self.config.alert_severity,
            'score': 0.9,
            'confidence': 0.95,
            'is_attack': True,
            'explanation': f"Deception trap triggered: {trap_type}",
            'details': {
                'trap_type': trap_type,
                'args': list(args)[:5] if args else []
            }
        }

        if self.logger:
            self.logger.warning(f"🔔 ALERT: Deception trap {trap_type} triggered!")

            try:
                if self._ai_model is None:
                    model_path = os.path.join(os.path.dirname(__file__), 'models', 'shard_real_alert_model.pkl')
                    if os.path.exists(model_path):
                        self._ai_model = joblib.load(model_path)
                if self._ai_model is not None:
                    alert_msg = f"WARNING:SHARD.SHARD:🍯 Honeypot deception {trap_type} triggered"
                    pred = self._ai_model.predict([alert_msg])[0]
                    print(f"🎯 [AI] Deception {trap_type} → {pred.upper()}")
            except Exception as e:
                pass

    def check_canary_triggers(self, data: Dict) -> bool:
        triggered = False
        for ct in self.canary_tokens.values():
            if ct.check_trigger(data):
                triggered = True
        return triggered

    def get_stats(self) -> Dict:
        with self._lock:
            honeypot_stats = {name: hp.get_stats() for name, hp in self.honeypots.items()}
            honeytoken_stats = {name: ht.get_stats() for name, ht in self.honeytokens.items()}
            return {
                'total_triggers': self.stats['total_triggers'],
                'total_connections': self.stats['total_connections'],
                'unique_attackers': len(self.stats['unique_attackers']),
                'triggers_by_type': dict(self.stats['triggers_by_type']),
                'triggers_by_service': dict(self.stats['triggers_by_service']),
                'honeypots': honeypot_stats,
                'honeytokens': honeytoken_stats,
                'active_traps': len(self.honeypots) + len(self.honeytokens) + len(self.canary_tokens)
            }

    def deploy_breadcrumbs(self, target_path: str):
        deployed = []
        for bc in self.config.breadcrumbs:
            if bc['type'] == 'history':
                history_path = Path(target_path) / bc['file']
                try:
                    history_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(history_path, 'a') as f:
                        f.write(bc['content'])
                    deployed.append(str(history_path))
                except:
                    pass
            elif bc['type'] == 'browser':
                browser_path = Path(target_path) / bc['file']
                try:
                    browser_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(browser_path, 'w') as f:
                        f.write(bc['content'])
                    deployed.append(str(browser_path))
                except:
                    pass
        if self.logger:
            self.logger.info(f"🍯 Deployed {len(deployed)} breadcrumbs")
        return deployed



class ShardDeceptionIntegration:
    """Интеграция Deception Technology в SHARD"""

    def __init__(self, config: Dict = None):
        self.config = DeceptionConfig()
        self.engine: Optional[DeceptionEngine] = None
        self.event_bus = None
        self.logger = None

    def setup(self, event_bus, logger):
        self.event_bus = event_bus
        self.logger = logger
        self.engine = DeceptionEngine(self.config, logger, event_bus)

    def start(self):
        if self.engine:
            self.engine.start()
        if self.logger:
            self.logger.info("🚀 Deception Technology запущена")

    def stop(self):
        if self.engine:
            self.engine.stop()

    def get_stats(self) -> Dict:
        if self.engine:
            return self.engine.get_stats()
        return {}

    def check_canary(self, data: Dict) -> bool:
        if self.engine:
            return self.engine.check_canary_triggers(data)
        return False



def test_deception():
    """Тестирование Deception Technology"""
    print("=" * 60)
    print("🧪 ТЕСТИРОВАНИЕ DECEPTION TECHNOLOGY")
    print("=" * 60)

    config = DeceptionConfig()
    config.network_honeypots = config.network_honeypots[:3]
    config.honeytokens = config.honeytokens[:2]

    engine = DeceptionEngine(config)
    engine.start()

    print(f"\n📝 Тест 1: Активных ловушек")
    print(f"   Honeypots: {len(engine.honeypots)}")
    print(f"   HoneyTokens: {len(engine.honeytokens)}")
    print(f"   CanaryTokens: {len(engine.canary_tokens)}")

    print("\n📝 Тест 2: Симуляция подключения к SSH honeypot")
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex(('127.0.0.1', 2222))
        if result == 0:
            sock.send(b'SSH-2.0-OpenSSH_8.9\r\n')
            data = sock.recv(1024)
            print(f"   Получен ответ: {data[:50]}")
        sock.close()
    except Exception as e:
        print(f"   Ошибка подключения: {e}")

    time.sleep(1)

    print("\n📝 Тест 3: Статистика после теста")
    stats = engine.get_stats()
    print(f"   Всего триггеров: {stats['total_triggers']}")
    print(f"   Всего подключений: {stats['total_connections']}")
    print(f"   Уникальных атакующих: {stats['unique_attackers']}")

    engine.stop()

    print("\n" + "=" * 60)
    print("✅ ТЕСТИРОВАНИЕ ЗАВЕРШЕНО")
    print("=" * 60)


if __name__ == "__main__":
    test_deception()