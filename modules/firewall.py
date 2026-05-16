#!/usr/bin/env python3
"""SHARD SmartFirewall Module"""
from core.base import BaseModule, ConfigManager, EventBus, LoggingService
import os, time, threading, re, subprocess, json
from pathlib import Path
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Tuple
from collections import defaultdict, deque
from pathlib import Path

class SmartFirewall(BaseModule):
    """Умный файрвол с градацией ответа"""

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("Firewall", config, event_bus, logger)
        self.auto_block = config.get('protection.auto_block', False)
        self.block_duration = config.get('protection.block_duration', 3600)
        self.rate_threshold = config.get('protection.rate_limit.threshold', 100)
        self.rate_window = config.get('protection.rate_limit.window', 60)

        self.rate_limits: Dict[str, Dict[int, deque]] = defaultdict(lambda: defaultdict(lambda: deque(maxlen=1000)))
        self.blocked_ips: Dict[str, float] = {}
        self.blocked_ports: Dict[str, Set[int]] = defaultdict(set)
        self.action_levels: Dict[str, int] = defaultdict(int)
        self.action_history: Dict[str, List[Tuple[float, str]]] = defaultdict(list)
        self.whitelist: Set[str] = set()

        self.response_levels = {
            1: 'throttle',
            2: 'block_port',
            3: 'block_ip_temp',
            4: 'block_ip_perm'
        }

        # Отдельные блокировки для избежания deadlock
        self._lock = threading.RLock()
        self._history_lock = threading.RLock()
        self._cleanup_lock = threading.RLock()

        Path('data').mkdir(parents=True, exist_ok=True)
        Path('data').mkdir(parents=True, exist_ok=True)
        self.event_bus.subscribe('alert.detected', self.on_alert)
        self.event_bus.subscribe('exfiltration.detected', self.on_exfiltration)

    def start(self) -> None:
        self.running = True
        threading.Thread(target=self._cleanup_loop, daemon=True).start()
        self.logger.info(f"Запущен (auto_block: {self.auto_block}, умная градация)")

    def stop(self) -> None:
        self.running = False

    def add_to_whitelist(self, ip: str) -> None:
        """Добавить IP в белый список"""
        with self._lock:
            self.whitelist.add(ip)

    def remove_from_whitelist(self, ip: str) -> None:
        """Удалить IP из белого списка"""
        with self._lock:
            self.whitelist.discard(ip)

    def check_rate_limit(self, src_ip: str, dst_port: int) -> bool:
        """Проверка rate limit"""
        if src_ip in self.whitelist:
            return True

        with self._lock:
            now = time.time()
            entry = self.rate_limits[src_ip][dst_port]
            cutoff = now - self.rate_window

            # Очистка старых записей
            while entry and entry[0] < cutoff:
                entry.popleft()

            entry.append(now)

            if len(entry) >= self.rate_threshold:
                self._apply_action(src_ip, dst_port, 'throttle')
                return False
            return True

    def is_blocked(self, ip: str, port: int = None) -> bool:
        """Проверка, заблокирован ли IP/порт"""
        with self._lock:
            if ip in self.whitelist:
                return False

            if ip in self.blocked_ips:
                if time.time() < self.blocked_ips[ip]:
                    return True

            if port and ip in self.blocked_ports:
                return port in self.blocked_ports[ip]

            return False

    def on_alert(self, alert: Dict) -> None:
        """Обработка алерта"""
        if not self.auto_block:
            return

        src_ip = alert.get('src_ip', '')
        dst_port = alert.get('dst_port', 0)
        score = alert.get('score', 0)
        severity = alert.get('severity', 'LOW')

        if not src_ip or src_ip in self.whitelist:
            return

        with self._lock:
            # Увеличиваем уровень в зависимости от score и severity
            increment = 1
            if severity == 'CRITICAL':
                increment = 4
            elif severity == 'HIGH':
                increment = 3
            elif severity == 'MEDIUM':
                increment = 2
            elif score > 0.8:
                increment = 3
            elif score > 0.6:
                increment = 2

            self.action_levels[src_ip] += increment
            level = min(4, self.action_levels[src_ip])
            action = self.response_levels[level]

            self.action_history[src_ip].append((time.time(), action))

            # Очистка старых записей
            cutoff = time.time() - 3600
            self.action_history[src_ip] = [(t, a) for t, a in self.action_history[src_ip] if t > cutoff]

        self._apply_action(src_ip, dst_port, action, alert)

    def on_exfiltration(self, data: Dict) -> None:
        """Немедленная реакция на утечку данных"""
        if not self.auto_block:
            return

        src_ip = data.get('src_ip', '')
        if src_ip and src_ip not in self.whitelist:
            # Немедленная блокировка при утечке данных
            self._apply_action(src_ip, 0, 'block_ip_temp', data)
            self.logger.critical(f"🚨 НЕМЕДЛЕННАЯ БЛОКИРОВКА из-за утечки данных: {src_ip}")

    def _apply_action(self, src_ip: str, dst_port: int, action: str, context: Dict = None) -> None:
        """Применение действия"""
        if src_ip in self.whitelist:
            return

        if action == 'throttle':
            self.logger.info(f"🐢 Замедление {src_ip}:{dst_port}")
            # Здесь можно добавить реальное замедление через iptables/Windows Firewall

        elif action == 'block_port':
            with self._lock:
                self.blocked_ports[src_ip].add(dst_port)
            self.logger.warning(f"🔒 Блокировка порта {dst_port} для {src_ip}")
            self.event_bus.publish('firewall.port_blocked', {'ip': src_ip, 'port': dst_port})

        elif action == 'block_ip_temp':
            self.block_ip(src_ip, 1800)  # 30 минут
            self.event_bus.publish('firewall.blocked', {
                'ip': src_ip,
                'duration': 1800,
                'reason': context.get('attack_type') if context else 'unknown'
            })

        elif action == 'block_ip_perm':
            self.block_ip(src_ip, 86400)  # 24 часа
            self.event_bus.publish('firewall.blocked', {
                'ip': src_ip,
                'duration': 86400,
                'permanent': True,
                'reason': context.get('attack_type') if context else 'unknown'
            })

    def _validate_port(self, port: int) -> bool:
        """Валидация порта"""
        return isinstance(port, int) and 0 < port < 65536

    def _validate_ip(self, ip: str) -> bool:
        """Строгая валидация IP адреса"""
        if not ip:
            return False

        # Проверка формата
        if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
            return False

        # Проверка октетов
        try:
            octets = [int(x) for x in ip.split('.')]
            if any(o > 255 or o < 0 for o in octets):
                return False
        except ValueError:
            return False

        # Запрет опасных символов
        dangerous_chars = [';', '&', '|', '$', '`', '(', ')', '<', '>', '\'', '"', '\\', '\n', '\r', ' ']
        for char in dangerous_chars:
            if char in ip:
                return False

        return True

    def block_ip(self, ip: str, duration: int = 3600) -> bool:
        """Блокировка IP с проверкой существующей блокировки"""
        if not self._validate_ip(ip):
            self.logger.error(f"Некорректный IP адрес: {ip}")
            return False

        with self._lock:
            # Проверка whitelist
            if ip in self.whitelist:
                self.logger.debug(f"IP {ip} в белом списке, блокировка отменена")
                return False

            # Проверка существующей блокировки
            if ip in self.blocked_ips:
                existing_expiry = self.blocked_ips[ip]
                if time.time() < existing_expiry:
                    self.logger.debug(f"IP {ip} уже заблокирован до {datetime.fromtimestamp(existing_expiry)}")
                    return False

            # Устанавливаем блокировку
            self.blocked_ips[ip] = time.time() + duration
            # Аудит: логируем кто заблокировал IP
            self._audit_log(ip, duration, 'manual' if not hasattr(self, '_last_alert') else 'auto')

        # Проверяем существование правила в iptables
        if os.name != 'nt':
            try:
                check_result = subprocess.run(
                    ['iptables', '-C', 'SHARD_BLOCK', '-s', ip, '-j', 'DROP'],
                    capture_output=True,
                    timeout=5
                )
                if check_result.returncode == 0:
                    self.logger.debug(f"Правило iptables для {ip} уже существует")
                    return True
            except Exception:
                # -C не поддерживается, пробуем через grep
                try:
                    list_result = subprocess.run(
                        ['iptables', '-L', 'SHARD_BLOCK', '-n'],
                        capture_output=True, text=True, timeout=5
                    )
                    if ip in list_result.stdout:
                        self.logger.debug(f"Правило iptables для {ip} уже существует (проверка через list)")
                        return True
                except Exception:
                    pass

        # Добавляем правило
        try:
            if os.name == 'nt':
                rule_name = f"SHARD_Block_{ip.replace('.', '_')}"
                if not re.match(r'^[a-zA-Z0-9_]+$', rule_name):
                    return False

                result = subprocess.run(
                    ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                     f'name={rule_name}', 'dir=in', f'remoteip={ip}',
                     'action=block', 'enable=yes', 'profile=any'],
                    capture_output=True, text=True, timeout=10, check=False
                )

                if result.returncode == 0:
                    self.logger.warning(f"🚫 Заблокирован IP {ip} на {duration} сек (Windows Firewall)")
                    # Аудит
                    with open('data/audit.log', 'a') as audit:
                        audit.write(f"{time.time()} | BLOCK | {ip} | {duration}s | windows_firewall\n")
                    # Аудит
                    with open('data/audit.log', 'a') as audit:
                        audit.write(f"{time.time()} | BLOCK | {ip} | {duration}s | windows_firewall\n")
                    return True
            else:
                self.add_iptables_chain()
                result = subprocess.run(
                    ['iptables', '-A', 'SHARD_BLOCK', '-s', ip, '-j', 'DROP'],
                    capture_output=True, timeout=10, check=False
                )

                if result.returncode == 0:
                    self.logger.warning(f"🚫 Заблокирован IP {ip} на {duration} сек (iptables)")
                    # Аудит
                    with open('data/audit.log', 'a') as audit:
                        audit.write(f"{time.time()} | BLOCK | {ip} | {duration}s | iptables\n")
                    # Аудит
                    with open('data/audit.log', 'a') as audit:
                        audit.write(f"{time.time()} | BLOCK | {ip} | {duration}s | iptables\n")
                    return True

        except Exception as e:
            self.logger.error(f"Ошибка блокировки IP {ip}: {e}")

        # Откат при ошибке
        with self._lock:
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]
        return False

    def unblock_ip(self, ip: str) -> bool:
        """Разблокировка IP (безопасная версия)"""
        if not self._validate_ip(ip):
            return False

        with self._lock:
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]

        try:
            if os.name == 'nt':
                rule_name = f"SHARD_Block_{ip.replace('.', '_')}"
                if not re.match(r'^[a-zA-Z0-9_]+$', rule_name):
                    return False

                subprocess.run(
                    ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}'],
                    capture_output=True,
                    timeout=10,
                    check=False
                )
            else:
                # Удаляем все правила для этого IP
                while True:
                    result = subprocess.run(
                        ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
                        capture_output=True,
                        timeout=5
                    )
                    if result.returncode != 0:
                        break

            self.logger.info(f"✅ Разблокирован IP {ip}")
            return True

        except Exception as e:
            self.logger.error(f"Ошибка разблокировки IP {ip}: {e}")
            return False

    def block_port(self, ip: str, port: int) -> bool:
        """Блокировка порта для конкретного IP"""
        if not self._validate_ip(ip) or not self._validate_port(port):
            self.logger.error(f"Некорректный IP {ip} или порт {port}")
            return False

        if ip in self.whitelist:
            return False

        with self._lock:
            self.blocked_ports[ip].add(port)

        try:
            if os.name == 'nt':
                rule_name = f"SHARD_Block_{ip.replace('.', '_')}_port_{port}"
                result = subprocess.run(
                    [
                        'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                        f'name={rule_name}',
                        'dir=in',
                        f'remoteip={ip}',
                        f'localport={port}',
                        'protocol=TCP',
                        'action=block'
                    ],
                    capture_output=True,
                    timeout=10,
                    check=False
                )
                success = result.returncode == 0
            else:
                result = subprocess.run(
                    ['iptables', '-A', 'INPUT', '-s', ip, '-p', 'tcp', '--dport', str(port), '-j', 'DROP'],
                    capture_output=True,
                    timeout=10,
                    check=False
                )
                success = result.returncode == 0

            if success:
                self.logger.warning(f"🔒 Заблокирован порт {port} для {ip}")
            return success

        except Exception as e:
            self.logger.error(f"Ошибка блокировки порта {port} для {ip}: {e}")
            return False

    def _audit_log(self, ip: str, duration: int, source: str = 'auto') -> None:
        """Логирование аудита: кто, когда, кого заблокировал"""
        try:
            audit_file = Path('logs/audit_firewall.log')
            audit_file.parent.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().isoformat()
            with open(audit_file, 'a') as f:
                f.write(f"{timestamp} | BLOCK | {ip} | {duration}s | source={source}\n")
        except Exception:
            pass  # Аудит не должен блокировать работу

    def add_iptables_chain(self) -> bool:
        """Создание отдельной цепочки iptables для SHARD (однократно)"""
        if os.name == 'nt':
            return True

        # Проверяем кэш создания цепочки
        if hasattr(self, '_chain_created') and self._chain_created:
            return True

        try:
            # Проверяем существование цепочки
            check = subprocess.run(
                ['iptables', '-L', 'SHARD_BLOCK'],
                capture_output=True, timeout=5
            )

            if check.returncode != 0:
                # Создаём цепочку
                subprocess.run(
                    ['iptables', '-N', 'SHARD_BLOCK'],
                    capture_output=True, timeout=5, check=False
                )

            # Проверяем правило перехода
            check_jump = subprocess.run(
                ['iptables', '-C', 'INPUT', '-j', 'SHARD_BLOCK'],
                capture_output=True, timeout=5
            )

            if check_jump.returncode != 0:
                subprocess.run(
                    ['iptables', '-I', 'INPUT', '1', '-j', 'SHARD_BLOCK'],
                    capture_output=True, timeout=5, check=False
                )

            self._chain_created = True
            self.logger.debug("Цепочка SHARD_BLOCK в iptables создана")
            return True

        except Exception as e:
            self.logger.error(f"Ошибка создания цепочки iptables: {e}")
            return False

    def _cleanup_loop(self) -> None:
        """Очистка истёкших блокировок и снижение уровней угрозы (исправлен deadlock)"""
        while self.running:
            time.sleep(60)
            now = time.time()

            # Сначала собираем IP для разблокировки ВНЕ блокировки
            ips_to_unblock = []

            with self._lock:
                # Разблокировка истёкших IP
                expired = [ip for ip, exp in list(self.blocked_ips.items()) if exp <= now]
                ips_to_unblock.extend(expired)

                # Снижение уровней угрозы со временем
                for ip in list(self.action_levels.keys()):
                    if ip in self.action_history:
                        history = self.action_history[ip]
                        if history:
                            last_action_time = max(t for t, _ in history)
                            time_since_last = now - last_action_time

                            # Снижаем уровень каждые 30 минут бездействия
                            if time_since_last > 1800:
                                self.action_levels[ip] = max(0, self.action_levels[ip] - 1)

                                # Если уровень стал 0 - удаляем из истории
                                if self.action_levels[ip] == 0:
                                    del self.action_levels[ip]
                                    if ip in self.action_history:
                                        del self.action_history[ip]

                        # Очистка старых записей в истории
                        cutoff = now - 7200  # 2 часа
                        self.action_history[ip] = [(t, a) for t, a in history if t > cutoff]
                        if not self.action_history[ip]:
                            del self.action_history[ip]

            # Разблокируем IP ВНЕ блокировки
            for ip in ips_to_unblock:
                self._unblock_ip_internal(ip)
                try:
                    if os.name == 'nt':
                        rule_name = f"SHARD_Block_{ip.replace('.', '_')}"
                        subprocess.run(
                            ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}'],
                            capture_output=True,
                            timeout=5
                        )
                    else:
                        subprocess.run(
                            ['iptables', '-D', 'SHARD_BLOCK', '-s', ip, '-j', 'DROP'],
                            capture_output=True,
                            timeout=5
                        )
                except Exception as e:
                    self.logger.debug(f"Ошибка разблокировки {ip}: {e}")

    def _unblock_ip_internal(self, ip: str) -> None:
        """Внутренний метод разблокировки без дополнительных проверок"""
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]
        if ip in self.blocked_ports:
            del self.blocked_ports[ip]
        if ip in self.action_levels:
            del self.action_levels[ip]
        if ip in self.action_history:
            del self.action_history[ip]
        if ip in self.rate_limits:
            del self.rate_limits[ip]

    def flush_blocks(self) -> int:
        """Сброс всех блокировок"""
        count = 0

        try:
            if os.name == 'nt':
                # Удаление всех правил SHARD
                result = subprocess.run(
                    ['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                for line in result.stdout.split('\n'):
                    if 'SHARD_Block_' in line:
                        rule_name = line.split(':')[1].strip()
                        subprocess.run(
                            ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}'],
                            capture_output=True,
                            timeout=5
                        )
                        count += 1
            else:
                # Очистка цепочки SHARD
                subprocess.run(
                    ['iptables', '-F', 'SHARD_BLOCK'],
                    capture_output=True,
                    timeout=10
                )
                count = -1  # Неизвестно точное количество

            # Очистка внутренних структур
            with self._lock:
                self.blocked_ips.clear()
                self.blocked_ports.clear()
                self.action_levels.clear()
                self.action_history.clear()

            self.logger.info(f"Сброшено {count} правил блокировки")
            return count

        except Exception as e:
            self.logger.error(f"Ошибка сброса блокировок: {e}")
            return 0


# ============================================================
# ALERT EXPLAINER
# ============================================================

