#!/usr/bin/env python3
"""
SHARD Application-Level Firewall
Работает без root-прав — блокирует на уровне приложения.
Использует iptables через sudo (если доступен) как запасной вариант.
"""

import os
import time
import json
import threading
import logging
from pathlib import Path
from typing import Dict, Set, Optional
from datetime import datetime

logger = logging.getLogger("SHARD-AppFirewall")


class AppFirewall:
    """
    Файрвол прикладного уровня.
    
    Уровни блокировки:
    - Level 1: Блокировка в памяти (быстро, живёт пока запущен SHARD)
    - Level 2: Блокировка через hosts.deny (требует прав на запись)
    - Level 3: Блокировка через iptables с sudo (если настроен sudoers)
    """
    
    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        
        # Три уровня блокировки
        self.memory_blocks: Dict[str, float] = {}  # IP -> expires_at
        self.hosts_deny_blocks: Set[str] = set()
        self.iptables_blocks: Set[str] = set()
        
        # Whitelist
        self.whitelist: Set[str] = {
            '127.0.0.1', '::1', 'localhost',
            '192.168.1.0/24', '10.0.0.0/16'
        }
        
        # Статистика
        self.stats = {
            'total_blocks': 0,
            'memory_blocks': 0,
            'hosts_deny_blocks': 0,
            'iptables_blocks': 0,
            'active_blocks': 0,
            'unblocks': 0
        }
        
        self._lock = threading.RLock()
        self._running = False
        self._cleanup_thread = None
        
        # Проверяем доступные методы
        self.sudo_available = self._check_sudo()
        self.hosts_deny_available = self._check_hosts_deny()
        
        # Загружаем сохранённые блокировки
        self._load_state()
        
        logger.info(
            f"AppFirewall ready: sudo={self.sudo_available}, "
            f"hosts.deny={self.hosts_deny_available}"
        )
    
    def _check_sudo(self) -> bool:
        """Проверяет возможность использовать sudo iptables без пароля"""
        try:
            import subprocess
            result = subprocess.run(
                ['sudo', '-n', 'iptables', '-L', 'SHARD_BLOCK'],
                capture_output=True, timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def _check_hosts_deny(self) -> bool:
        """Проверяет возможность писать в hosts.deny"""
        try:
            path = Path('/etc/hosts.deny')
            if path.exists():
                return os.access(path, os.W_OK)
            return False
        except Exception:
            return False
    
    def start(self):
        """Запуск файрвола"""
        self._running = True
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop, daemon=True
        )
        self._cleanup_thread.start()
        logger.info("🛡️ AppFirewall started")
    
    def stop(self):
        """Остановка файрвола"""
        self._running = False
        self._save_state()
        self._flush_all()
        logger.info("🛡️ AppFirewall stopped")
    
    def block_ip(self, ip: str, duration: int = 3600, reason: str = "") -> Dict:
        """
        Заблокировать IP на всех доступных уровнях.
        
        Returns:
            Dict с результатом блокировки
        """
        # Проверка whitelist
        if not self._validate_ip(ip):
            return {'success': False, 'error': 'Invalid IP'}
        
        if self._is_whitelisted(ip):
            return {'success': False, 'error': 'IP is whitelisted'}
        
        with self._lock:
            expires = time.time() + duration
            result = {
                'ip': ip,
                'duration': duration,
                'expires_at': expires,
                'methods': [],
                'success': False
            }
            
            # Level 1: Memory block (всегда работает)
            self.memory_blocks[ip] = expires
            result['methods'].append('memory')
            self.stats['memory_blocks'] += 1
            
            # Level 2: hosts.deny
            if self.hosts_deny_available and ip not in self.hosts_deny_blocks:
                try:
                    with open('/etc/hosts.deny', 'a') as f:
                        f.write(f"\n# SHARD block {reason} - {datetime.now()}\n")
                        f.write(f"ALL: {ip}\n")
                    self.hosts_deny_blocks.add(ip)
                    result['methods'].append('hosts.deny')
                    self.stats['hosts_deny_blocks'] += 1
                except Exception as e:
                    logger.debug(f"hosts.deny block failed: {e}")
            
            # Level 3: iptables через sudo
            if self.sudo_available and ip not in self.iptables_blocks:
                try:
                    import subprocess
                    subprocess.run([
                        'sudo', '-n', 'iptables', '-A', 'SHARD_BLOCK',
                        '-s', ip, '-j', 'DROP',
                        '-m', 'comment', '--comment', f'SHARD:{reason[:50]}'
                    ], capture_output=True, timeout=5, check=True)
                    self.iptables_blocks.add(ip)
                    result['methods'].append('iptables')
                    self.stats['iptables_blocks'] += 1
                except Exception as e:
                    logger.debug(f"iptables block failed: {e}")
            
            if result['methods']:
                result['success'] = True
                self.stats['total_blocks'] += 1
                self.stats['active_blocks'] += 1
            
            self._audit_log('BLOCK', ip, duration, reason)
            
            return result
    
    def unblock_ip(self, ip: str) -> Dict:
        """Разблокировать IP на всех уровнях"""
        with self._lock:
            result = {'ip': ip, 'methods': [], 'success': False}
            
            # Memory
            if ip in self.memory_blocks:
                del self.memory_blocks[ip]
                result['methods'].append('memory')
                self.stats['active_blocks'] = max(0, self.stats['active_blocks'] - 1)
            
            # hosts.deny
            if ip in self.hosts_deny_blocks:
                try:
                    self._remove_from_hosts_deny(ip)
                    self.hosts_deny_blocks.discard(ip)
                    result['methods'].append('hosts.deny')
                except Exception:
                    logger.debug(f"Non-critical error: {e}") if "e" in dir() else logger.debug("Non-critical error")
            
            # iptables
            if ip in self.iptables_blocks:
                try:
                    import subprocess
                    subprocess.run([
                        'sudo', '-n', 'iptables', '-D', 'SHARD_BLOCK',
                        '-s', ip, '-j', 'DROP'
                    ], capture_output=True, timeout=5, check=True)
                    self.iptables_blocks.discard(ip)
                    result['methods'].append('iptables')
                except Exception:
                    logger.debug(f"Non-critical error: {e}") if "e" in dir() else logger.debug("Non-critical error")
            
            if result['methods']:
                result['success'] = True
                self.stats['unblocks'] += 1
            
            self._audit_log('UNBLOCK', ip, 0, 'manual')
            return result
    
    def is_blocked(self, ip: str) -> bool:
        """Проверить, заблокирован ли IP"""
        with self._lock:
            if ip in self.memory_blocks:
                if time.time() < self.memory_blocks[ip]:
                    return True
                del self.memory_blocks[ip]
            return False
    
    def get_blocked_ips(self) -> list:
        """Список заблокированных IP"""
        now = time.time()
        with self._lock:
            return [
                {'ip': ip, 'remaining': max(0, int(exp - now)), 'method': 'memory'}
                for ip, exp in self.memory_blocks.items()
                if exp > now
            ]
    
    def get_stats(self) -> Dict:
        """Статистика файрвола"""
        with self._lock:
            return {
                **self.stats,
                'active_blocks': len([e for e in self.memory_blocks.values() if e > time.time()]),
                'methods_available': {
                    'memory': True,
                    'hosts_deny': self.hosts_deny_available,
                    'iptables_sudo': self.sudo_available
                }
            }
    
    def add_whitelist(self, ip_or_network: str):
        """Добавить IP или сеть в whitelist"""
        self.whitelist.add(ip_or_network)
        self._audit_log('WHITELIST_ADD', ip_or_network, 0, 'manual')
    
    def _validate_ip(self, ip: str) -> bool:
        """Валидация IP"""
        import re
        return bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip)) and \
               all(0 <= int(o) <= 255 for o in ip.split('.'))
    
    def _is_whitelisted(self, ip: str) -> bool:
        """Проверка whitelist"""
        if ip in self.whitelist:
            return True
        
        try:
            import ipaddress
            addr = ipaddress.ip_address(ip)
            
            for entry in self.whitelist:
                try:
                    if '/' in entry:
                        if addr in ipaddress.ip_network(entry, strict=False):
                            return True
                except ValueError:
                    continue
        except Exception:
            logger.debug(f"Non-critical error: {e}") if "e" in dir() else logger.debug("Non-critical error")
        
        return False
    
    def _remove_from_hosts_deny(self, ip: str):
        """Удаление IP из hosts.deny"""
        path = Path('/etc/hosts.deny')
        if not path.exists():
            return
        
        lines = path.read_text().split('\n')
        new_lines = []
        skip = False
        
        for line in lines:
            if f'# SHARD block' in line:
                skip = True
                continue
            if skip and f'ALL: {ip}' in line:
                skip = False
                continue
            if skip and line.strip() == '':
                skip = False
            new_lines.append(line)
        
        path.write_text('\n'.join(new_lines))
    
    def _flush_all(self):
        """Сбросить все блокировки"""
        with self._lock:
            self.memory_blocks.clear()
            
            for ip in list(self.iptables_blocks):
                try:
                    import subprocess
                    subprocess.run([
                        'sudo', '-n', 'iptables', '-D', 'SHARD_BLOCK',
                        '-s', ip, '-j', 'DROP'
                    ], capture_output=True, timeout=5)
                except Exception:
                    logger.debug(f"Non-critical error: {e}") if "e" in dir() else logger.debug("Non-critical error")
            self.iptables_blocks.clear()
    
    def _cleanup_loop(self):
        """Очистка истёкших блокировок"""
        while self._running:
            time.sleep(30)
            now = time.time()
            with self._lock:
                expired = [ip for ip, exp in self.memory_blocks.items() if exp <= now]
                for ip in expired:
                    del self.memory_blocks[ip]
                    self.stats['active_blocks'] = max(0, self.stats['active_blocks'] - 1)
                    logger.debug(f"🧹 Expired block removed: {ip}")
    
    def _save_state(self):
        """Сохранить состояние"""
        try:
            state = {
                'memory_blocks': {ip: exp for ip, exp in self.memory_blocks.items() if exp > time.time()},
                'timestamp': time.time()
            }
            with open(self.data_dir / 'firewall_state.json', 'w') as f:
                json.dump(state, f)
        except Exception:
            logger.debug(f"Non-critical error: {e}") if "e" in dir() else logger.debug("Non-critical error")
    
    def _load_state(self):
        """Загрузить состояние"""
        try:
            path = self.data_dir / 'firewall_state.json'
            if path.exists():
                with open(path) as f:
                    state = json.load(f)
                    if time.time() - state.get('timestamp', 0) < 86400:
                        self.memory_blocks = state.get('memory_blocks', {})
                        logger.info(f"📂 Loaded {len(self.memory_blocks)} blocks from state")
        except Exception:
            logger.debug(f"Non-critical error: {e}") if "e" in dir() else logger.debug("Non-critical error")
    
    def _audit_log(self, action: str, ip: str, duration: int, reason: str):
        """Аудит-лог"""
        try:
            log_file = self.data_dir / 'firewall_audit.log'
            timestamp = datetime.now().isoformat()
            with open(log_file, 'a') as f:
                f.write(f"{timestamp} | {action} | {ip} | {duration}s | {reason}\n")
        except Exception:
            logger.debug(f"Non-critical error: {e}") if "e" in dir() else logger.debug("Non-critical error")


# Глобальный экземпляр
app_firewall = AppFirewall()
