#!/usr/bin/env python3
"""
SHARD Ethical Control System
Подтверждение критических действий перед выполнением.
Защита от Skynet-сценария — AI не может действовать без разрешения.
"""

import os
import re
import json
import time
import hashlib
import secrets
import threading
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Callable
from collections import deque, defaultdict
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger("SHARD-Ethics")


class ActionLevel(Enum):
    LEVEL_0 = 0
    LEVEL_1 = 1
    LEVEL_2 = 2
    LEVEL_3 = 3
    LEVEL_4 = 4
    LEVEL_5 = 5
    LEVEL_6 = 6
    
    def __ge__(self, other):
        if isinstance(other, ActionLevel):
            return self.value >= other.value
        return self.value >= other
    
    def __lt__(self, other):
        if isinstance(other, ActionLevel):
            return self.value < other.value
        return self.value < other


class ActionStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    EXECUTED = "executed"
    ROLLED_BACK = "rolled_back"


@dataclass
class EthicalAction:
    id: str
    level: ActionLevel
    description: str
    attack_info: Dict
    defense_code: Optional[str]
    status: ActionStatus = ActionStatus.PENDING
    created_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 300)
    approved_by: Optional[str] = None
    approved_at: Optional[float] = None
    confirmation_code: str = field(default_factory=lambda: secrets.token_hex(4).upper())
    rollback_code: Optional[str] = None
    execution_result: Optional[Dict] = None


class EthicalRules:

    INVINCIBLE_RULES = [
        "Запрещено атаковать в ответ (только защита)",
        "Запрещено блокировать критическую инфраструктуру без подтверждения",
        "Запрещено изменять системные файлы без подтверждения",
        "Запрещено отключать мониторинг и логирование",
        "Запрещено игнорировать команду отката",
    ]

    SACRED_IPS = {
        '127.0.0.1', '::1', 'localhost',
        '8.8.8.8', '8.8.4.4',
        '1.1.1.1', '1.0.0.1',
    }

    SACRED_SUBNETS = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '169.254.0.0/16',
        '224.0.0.0/4',
    ]

    SACRED_PORTS = {
        22: 'SSH (может заблокировать доступ администратора)',
        53: 'DNS (может сломать резолвинг)',
        67: 'DHCP Server',
        68: 'DHCP Client',
        123: 'NTP (синхронизация времени)',
        443: 'HTTPS (основной веб-трафик)',
        3306: 'MySQL (может быть production DB)',
        5432: 'PostgreSQL (может быть production DB)',
        6379: 'Redis (может быть production cache)',
        27017: 'MongoDB (может быть production DB)',
    }

    CONFIRMATION_CODE_ACTIONS = {
        ActionLevel.LEVEL_5: "Изоляция хоста",
        ActionLevel.LEVEL_6: "Активное противодействие",
    }

    @classmethod
    def is_sacred_ip(cls, ip: str) -> bool:
        return ip in cls.SACRED_IPS

    @classmethod
    def is_sacred_port(cls, port: int) -> bool:
        return port in cls.SACRED_PORTS

    @classmethod
    def get_port_warning(cls, port: int) -> Optional[str]:
        return cls.SACRED_PORTS.get(port)


class ActionAudit:

    def __init__(self, audit_dir: str = './audit_logs/'):
        self.audit_dir = Path(audit_dir)
        self.audit_dir.mkdir(exist_ok=True)
        self.actions: List[EthicalAction] = []
        self._lock = threading.RLock()

    def log_action(self, action: EthicalAction):
        with self._lock:
            self.actions.append(action)

            audit_file = self.audit_dir / f"audit_{datetime.now().strftime('%Y%m%d')}.json"

            audit_entry = {
                'id': action.id,
                'level': action.level.value,
                'description': action.description,
                'attack_type': action.attack_info.get('attack_type'),
                'src_ip': action.attack_info.get('src_ip'),
                'status': action.status.value,
                'approved_by': action.approved_by,
                'created_at': datetime.fromtimestamp(action.created_at).isoformat(),
                'approved_at': datetime.fromtimestamp(action.approved_at).isoformat() if action.approved_at else None,
            }

            try:
                existing = []
                if audit_file.exists():
                    with open(audit_file) as f:
                        existing = json.load(f)

                existing.append(audit_entry)

                with open(audit_file, 'w') as f:
                    json.dump(existing, f, indent=2, ensure_ascii=False)
            except:
                pass

    def get_daily_stats(self) -> Dict:
        today = datetime.now().strftime('%Y%m%d')
        audit_file = self.audit_dir / f"audit_{today}.json"

        if not audit_file.exists():
            return {'total': 0, 'approved': 0, 'rejected': 0}

        try:
            with open(audit_file) as f:
                actions = json.load(f)

            return {
                'total': len(actions),
                'approved': sum(1 for a in actions if a['status'] == 'approved'),
                'rejected': sum(1 for a in actions if a['status'] == 'rejected'),
            }
        except:
            return {'total': 0, 'approved': 0, 'rejected': 0}


class EthicalController:

    def __init__(self, event_bus=None, logger_instance=None):
        self.event_bus = event_bus
        self.logger = logger_instance or logger
        self.audit = ActionAudit()

        self.pending_actions: Dict[str, EthicalAction] = {}
        self.approval_callbacks: Dict[str, Callable] = {}

        self.stats = {
            'total_actions': 0,
            'approved': 0,
            'rejected': 0,
            'expired': 0,
            'auto_approved': 0,
            'rolled_back': 0,
        }

        self.hourly_limits: Dict[ActionLevel, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.max_per_hour = {
            ActionLevel.LEVEL_3: 10,
            ActionLevel.LEVEL_4: 5,
            ActionLevel.LEVEL_5: 2,
        }

        self.manual_mode = False
        self.auto_approve_enabled = False

        self._lock = threading.RLock()
        self._running = False

        self.trusted_operators = self._load_operators()

    def _load_operators(self) -> Dict[str, Dict]:
        operators_file = Path('./config/operators.json')

        if operators_file.exists():
            try:
                with open(operators_file) as f:
                    return json.load(f)
            except:
                pass

        return {
            'admin': {
                'name': 'Administrator',
                'role': 'admin',
                'can_approve_level': 6,
                'token': secrets.token_hex(16)
            }
        }

    def request_approval(
            self,
            action_level: ActionLevel,
            description: str,
            attack_info: Dict,
            defense_code: Optional[str] = None,
            callback: Optional[Callable] = None
    ) -> EthicalAction:
        with self._lock:
            self.stats['total_actions'] += 1

            src_ip = attack_info.get('src_ip', '')
            if EthicalRules.is_sacred_ip(src_ip):
                action = EthicalAction(
                    id=f"ETH-{int(time.time())}",
                    level=action_level,
                    description=f"ОТКЛОНЕНО: {description} (священный IP: {src_ip})",
                    attack_info=attack_info,
                    defense_code=defense_code,
                    status=ActionStatus.REJECTED
                )
                self.audit.log_action(action)
                self.stats['rejected'] += 1
                return action

            dst_port = attack_info.get('dst_port', 0)
            port_warning = EthicalRules.get_port_warning(dst_port)
            if port_warning and action_level.value >= ActionLevel.LEVEL_5.value:
                action = EthicalAction(
                    id=f"ETH-{int(time.time())}",
                    level=action_level,
                    description=f"ТРЕБУЕТ ПОДТВЕРЖДЕНИЯ: {description} ({port_warning})",
                    attack_info=attack_info,
                    defense_code=defense_code,
                )
            else:
                action = EthicalAction(
                    id=f"ETH-{int(time.time())}",
                    level=action_level,
                    description=description,
                    attack_info=attack_info,
                    defense_code=defense_code,
                )

            if not self._check_limits(action_level, attack_info.get('src_ip', '')):
                action.status = ActionStatus.REJECTED
                action.description += " (превышен лимит)"
                self.audit.log_action(action)
                self.stats['rejected'] += 1
                return action

            if action_level.value <= ActionLevel.LEVEL_2.value:
                if self.auto_approve_enabled:
                    action.status = ActionStatus.APPROVED
                    action.approved_at = time.time()
                    action.approved_by = "auto"
                    self.audit.log_action(action)
                    self.stats['approved'] += 1
                    self.stats['auto_approved'] += 1

                    if callback:
                        callback(action)

                    return action

            self.pending_actions[action.id] = action

            if callback:
                self.approval_callbacks[action.id] = callback

            self._log_approval_request(action)

            return action

    def _check_limits(self, level: ActionLevel, ip: str) -> bool:
        if level not in self.max_per_hour:
            return True

        now = time.time()
        hour_ago = now - 3600

        while self.hourly_limits[level] and self.hourly_limits[level][0] < hour_ago:
            self.hourly_limits[level].popleft()

        if len(self.hourly_limits[level]) >= self.max_per_hour[level]:
            self.logger.warning(
                f"⚠️ Превышен лимит {level.name}: "
                f"{len(self.hourly_limits[level])}/{self.max_per_hour[level]} за час"
            )
            return False

        self.hourly_limits[level].append(now)
        return True

    def approve_action(
            self,
            action_id: str,
            operator: str = "admin",
            confirmation_code: Optional[str] = None
    ) -> Dict:
        with self._lock:
            action = self.pending_actions.get(action_id)

            if not action:
                return {'error': 'Действие не найдено или уже обработано'}

            if action.status != ActionStatus.PENDING:
                return {'error': f'Действие уже {action.status.value}'}

            if time.time() > action.expires_at:
                action.status = ActionStatus.EXPIRED
                self.stats['expired'] += 1
                del self.pending_actions[action_id]
                return {'error': 'Время подтверждения истекло'}

            if operator not in self.trusted_operators:
                return {'error': 'Неизвестный оператор'}

            op = self.trusted_operators[operator]
            if op['can_approve_level'] < action.level.value:
                return {
                    'error': f"Оператор {operator} не может одобрить уровень {action.level.value}"
                }

            if action.level in EthicalRules.CONFIRMATION_CODE_ACTIONS:
                if not confirmation_code:
                    return {
                        'error': 'Требуется код подтверждения',
                        'confirmation_code': action.confirmation_code[:4] + '****'
                    }

                if confirmation_code.upper() != action.confirmation_code:
                    return {'error': 'Неверный код подтверждения'}

            action.status = ActionStatus.APPROVED
            action.approved_by = operator
            action.approved_at = time.time()

            self.stats['approved'] += 1
            self.audit.log_action(action)

            if action.id in self.approval_callbacks:
                try:
                    self.approval_callbacks[action.id](action)
                except Exception as e:
                    self.logger.error(f"Callback error: {e}")
                finally:
                    del self.approval_callbacks[action.id]

            del self.pending_actions[action_id]

            self.logger.info(f"✅ Действие {action_id} одобрено оператором {operator}")

            return {
                'success': True,
                'action_id': action_id,
                'status': 'approved',
                'approved_by': operator
            }

    def reject_action(self, action_id: str, operator: str = "admin", reason: str = "") -> Dict:
        with self._lock:
            action = self.pending_actions.get(action_id)

            if not action:
                return {'error': 'Действие не найдено'}

            action.status = ActionStatus.REJECTED
            self.stats['rejected'] += 1
            self.audit.log_action(action)

            if action.id in self.pending_actions:
                del self.pending_actions[action_id]

            if action.id in self.approval_callbacks:
                del self.approval_callbacks[action.id]

            self.logger.info(f"❌ Действие {action_id} отклонено: {reason}")

            return {'success': True, 'action_id': action_id, 'status': 'rejected'}

    def rollback_action(self, action_id: str) -> Dict:
        with self._lock:
            action = None

            for a in self.audit.actions:
                if a.id == action_id:
                    action = a
                    break

            if not action:
                return {'error': 'Действие не найдено'}

            if action.status != ActionStatus.EXECUTED:
                return {'error': f'Действие не выполнено (статус: {action.status.value})'}

            action.status = ActionStatus.ROLLED_BACK
            self.stats['rolled_back'] += 1

            src_ip = action.attack_info.get('src_ip', '')

            if src_ip:
                try:
                    import subprocess
                    subprocess.run(
                        ['iptables', '-D', 'INPUT', '-s', src_ip, '-j', 'DROP'],
                        capture_output=True, timeout=5
                    )
                    subprocess.run(
                        ['iptables', '-D', 'FORWARD', '-s', src_ip, '-j', 'DROP'],
                        capture_output=True, timeout=5
                    )
                except:
                    pass

            self.logger.info(f"↩️ Действие {action_id} откачено")

            return {'success': True, 'action_id': action_id, 'status': 'rolled_back'}

    def _log_approval_request(self, action: EthicalAction):
        level_name = action.level.name
        attack_type = action.attack_info.get('attack_type', 'Unknown')
        src_ip = action.attack_info.get('src_ip', 'unknown')

        self.logger.warning(f"""
╔══════════════════════════════════════════════════════════════════╗
║ 🔔 ТРЕБУЕТСЯ ПОДТВЕРЖДЕНИЕ                                      ║
╠══════════════════════════════════════════════════════════════════╣
║ ID:       {action.id}
║ Уровень:  {level_name} ({action.level.value})
║ Атака:    {attack_type}
║ Источник: {src_ip}
║ Описание: {action.description[:50]}
╠══════════════════════════════════════════════════════════════════╣
║ КОД ПОДТВЕРЖДЕНИЯ: {action.confirmation_code}
║ Действителен до: {datetime.fromtimestamp(action.expires_at).strftime('%H:%M:%S')}
╚══════════════════════════════════════════════════════════════════╝
""")

        if self.event_bus:
            self.event_bus.publish('ethics.approval_required', {
                'action_id': action.id,
                'level': action.level.value,
                'description': action.description,
                'confirmation_code': action.confirmation_code,
                'expires_at': action.expires_at
            })

    def get_pending_actions(self) -> List[Dict]:
        with self._lock:
            return [
                {
                    'id': a.id,
                    'level': a.level.value,
                    'description': a.description,
                    'attack_type': a.attack_info.get('attack_type'),
                    'src_ip': a.attack_info.get('src_ip'),
                    'created_at': datetime.fromtimestamp(a.created_at).isoformat(),
                    'expires_at': datetime.fromtimestamp(a.expires_at).isoformat(),
                    'requires_code': a.level in EthicalRules.CONFIRMATION_CODE_ACTIONS
                }
                for a in self.pending_actions.values()
                if a.status == ActionStatus.PENDING
            ]

    def get_stats(self) -> Dict:
        with self._lock:
            return {
                **self.stats,
                'pending': len(self.pending_actions),
                'daily_audit': self.audit.get_daily_stats(),
                'rules': {
                    'sacred_ips': len(EthicalRules.SACRED_IPS),
                    'sacred_ports': len(EthicalRules.SACRED_PORTS),
                    'invincible_rules': len(EthicalRules.INVINCIBLE_RULES)
                }
            }

    def set_mode(self, manual: bool = False, auto_approve: bool = False):
        self.manual_mode = manual
        self.auto_approve_enabled = auto_approve
        mode = "РУЧНОЙ" if manual else "АВТОМАТИЧЕСКИЙ"
        self.logger.warning(f"⚠️ Режим изменён: {mode}")


class ShardEthicalIntegration:

    def __init__(self, event_bus=None, logger_instance=None):
        self.controller = EthicalController(event_bus, logger_instance)
        self.event_bus = event_bus
        self.logger = logger_instance or logger
        self._running = False

    def setup(self, event_bus, logger_instance=None):
        self.event_bus = event_bus
        self.controller.event_bus = event_bus
        if logger_instance:
            self.logger = logger_instance
            self.controller.logger = logger_instance

        if event_bus:
            event_bus.subscribe('ethics.approve', self.on_approve)
            event_bus.subscribe('ethics.reject', self.on_reject)
            event_bus.subscribe('ethics.rollback', self.on_rollback)

    def start(self):
        self._running = True
        self.logger.info("⚖️ Этический контроль активирован")

    def stop(self):
        self._running = False

    def on_approve(self, data: Dict):
        action_id = data.get('action_id', '')
        operator = data.get('operator', 'admin')
        code = data.get('confirmation_code')

        result = self.controller.approve_action(action_id, operator, code)

        if self.event_bus:
            self.event_bus.publish('ethics.result', result)

    def on_reject(self, data: Dict):
        action_id = data.get('action_id', '')
        reason = data.get('reason', '')

        result = self.controller.reject_action(action_id, reason=reason)

        if self.event_bus:
            self.event_bus.publish('ethics.result', result)

    def on_rollback(self, data: Dict):
        action_id = data.get('action_id', '')

        result = self.controller.rollback_action(action_id)

        if self.event_bus:
            self.event_bus.publish('ethics.result', result)

    def get_stats(self) -> Dict:
        return self.controller.get_stats()


def test_ethical_control():
    print("=" * 60)
    print("⚖️ ТЕСТ ETHICAL CONTROL SYSTEM")
    print("=" * 60)

    controller = EthicalController()

    print("\n📝 Тест 1: Запрос на блокировку IP (LEVEL 4)")
    action1 = controller.request_approval(
        action_level=ActionLevel.LEVEL_4,
        description="Блокировка IP за множественные SQL инъекции",
        attack_info={
            'attack_type': 'SQL Injection',
            'src_ip': '185.142.53.101',
            'dst_port': 80,
            'severity': 'CRITICAL',
            'score': 0.95
        }
    )
    print(f"   Статус: {action1.status.value}")
    print(f"   Код подтверждения: {action1.confirmation_code}")

    print("\n📝 Тест 2: Запрос на изоляцию хоста (LEVEL 5)")
    action2 = controller.request_approval(
        action_level=ActionLevel.LEVEL_5,
        description="Изоляция хоста заражённого ботнетом",
        attack_info={
            'attack_type': 'Botnet',
            'src_ip': '89.248.163.1',
            'dst_ip': '192.168.1.50',
            'severity': 'CRITICAL',
            'score': 0.98
        }
    )
    print(f"   Статус: {action2.status.value}")
    print(f"   Требуется код: ДА")
    print(f"   Код подтверждения: {action2.confirmation_code}")

    print("\n📝 Тест 3: Подтверждение с правильным кодом")
    result = controller.approve_action(
        action2.id,
        operator="admin",
        confirmation_code=action2.confirmation_code
    )
    print(f"   Результат: {result.get('success')} - {result.get('status', result.get('error'))}")

    print("\n📝 Тест 4: Подтверждение с НЕправильным кодом")
    action3 = controller.request_approval(
        action_level=ActionLevel.LEVEL_5,
        description="Изоляция второго хоста",
        attack_info={
            'attack_type': 'Malware',
            'src_ip': '194.61.23.45',
            'dst_ip': '192.168.1.100',
            'severity': 'HIGH',
            'score': 0.88
        }
    )
    result = controller.approve_action(
        action3.id,
        confirmation_code="WRONG-CODE"
    )
    print(f"   Результат: {result.get('success')} - {result.get('error')}")

    print("\n📝 Тест 5: Блокировка священного IP (8.8.8.8)")
    action4 = controller.request_approval(
        action_level=ActionLevel.LEVEL_4,
        description="Блокировка DNS сервера",
        attack_info={
            'attack_type': 'DNS Attack',
            'src_ip': '8.8.8.8',
            'severity': 'HIGH'
        }
    )
    print(f"   Статус: {action4.status.value} (ожидаемо REJECTED)")

    print(f"\n📊 Статистика:")
    stats = controller.get_stats()
    print(f"   Всего действий: {stats['total_actions']}")
    print(f"   Одобрено: {stats['approved']}")
    print(f"   Отклонено: {stats['rejected']}")
    print(f"   На рассмотрении: {stats['pending']}")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    test_ethical_control()