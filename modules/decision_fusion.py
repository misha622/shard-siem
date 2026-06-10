#!/usr/bin/env python3
"""
SHARD DecisionFusion — Оркестратор автономной защиты
Объединяет RL-агента, Autonomous Defender и Smart Firewall
в единую систему принятия решений с каскадной эскалацией.

Приоритет решений:
1. Rule-based (критические атаки → мгновенная блокировка)
2. RL Agent (обученная модель → выбор действия)
3. Autonomous Defender (генерация кода защиты)
4. Smart Firewall (исполнение правил)
"""

import time
import threading
import logging
from typing import Dict, Optional, List, Any
from dataclasses import dataclass, field
from collections import deque
from datetime import datetime
from enum import Enum

logger = logging.getLogger("SHARD-DecisionFusion")


class DecisionSource(Enum):
    RULE_BASED = "rule_based"
    RL_AGENT = "rl_agent"
    HEURISTIC = "heuristic"
    MANUAL = "manual"


@dataclass
class DefenseAction:
    """Унифицированное действие защиты"""
    action_id: int
    action_name: str
    description: str
    source: DecisionSource
    confidence: float
    priority: int
    block_duration: int = 0
    generated_code: Optional[str] = None
    script_path: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict:
        return {
            'action_id': self.action_id,
            'action_name': self.action_name,
            'description': self.description,
            'source': self.source.value,
            'confidence': self.confidence,
            'priority': self.priority,
            'block_duration': self.block_duration,
            'generated_code': bool(self.generated_code),
            'script_path': str(self.script_path) if self.script_path else None,
            'timestamp': self.timestamp
        }


class DecisionFusion:
    """
    Оркестратор защиты с каскадной эскалацией.
    
    Архитектура принятия решений:
    ┌─────────────────────────────────────────┐
    │         PredictionResult                │
    │  (score, confidence, attack_type)       │
    └───────────────┬─────────────────────────┘
                    │
                    ▼
    ┌─────────────────────────────────────────┐
    │  Level 1: Rule-Based (мгновенно)        │
    │  - CRITICAL + Data Exfil → block_perm   │
    │  - CRITICAL + DDoS → block_ip_temp      │
    │  - score > 0.95 → block_perm            │
    └───────────────┬─────────────────────────┘
                    │ (если не обработано)
                    ▼
    ┌─────────────────────────────────────────┐
    │  Level 2: RL Agent (обученная модель)   │
    │  - DQN выбирает действие (0-4)          │
    │  - если confidence > порог → выполняем  │
    └───────────────┬─────────────────────────┘
                    │ (если RL не уверен)
                    ▼
    ┌─────────────────────────────────────────┐
    │  Level 3: Heuristic + Defender          │
    │  - AutonomousDefender.generate_code()   │
    │  - SmartFirewall.graduated_response()   │
    └───────────────┬─────────────────────────┘
                    │
                    ▼
    ┌─────────────────────────────────────────┐
    │  Level 4: Execution                     │
    │  - SmartFirewall.apply_action()         │
    │  - Сохранение в историю                 │
    │  - Обратная связь для RL                │
    └─────────────────────────────────────────┘
    """
    
    def __init__(self):
        # Компоненты (внедряются через setter'ы)
        self.rl_defense = None  # RLDefenseAgent
        self.autonomous_defender = None  # ShardAutonomousDefenderIntegration
        self.firewall = None  # SmartFirewall
        self.ml_engine = None  # MachineLearningEngine
        self.event_bus = None  # EventBus
        
        # Состояние
        self._lock = threading.RLock()
        self._decision_history: deque = deque(maxlen=1000)
        self._active_defenses: Dict[str, Dict] = {}
        
        # Статистика
        self.stats = {
            'total_decisions': 0,
            'rule_based': 0,
            'rl_decisions': 0,
            'heuristic_decisions': 0,
            'blocks_applied': 0,
            'throttles_applied': 0,
            'ignored': 0,
            'errors': 0
        }
        
        # Пороги
        self.rl_confidence_threshold = 0.6
        self.critical_score_threshold = 0.85
        self.permanent_block_threshold = 0.95
        
        logger.info("🧠 DecisionFusion initialized")
    
    def setup(self, rl_defense=None, autonomous_defender=None, 
              firewall=None, ml_engine=None, event_bus=None):
        """Внедрение зависимостей"""
        self.rl_defense = rl_defense
        self.autonomous_defender = autonomous_defender
        self.firewall = firewall
        self.ml_engine = ml_engine
        self.event_bus = event_bus
        
        if self.event_bus:
            self.event_bus.subscribe('alert.detected', self.on_alert)
            self.event_bus.subscribe('investigation.completed', self.on_investigation)
        
        logger.info("✅ DecisionFusion configured with all modules")
    
    def on_alert(self, alert: Dict) -> Optional[DefenseAction]:
        """Обработка алерта — главная точка входа"""
        with self._lock:
            self.stats['total_decisions'] += 1
        
        try:
            # Level 1: Rule-Based (мгновенная реакция на критические угрозы)
            rule_action = self._rule_based_decision(alert)
            if rule_action:
                self._execute_action(rule_action, alert)
                return rule_action
            
            # Level 2: RL Agent
            if self.rl_defense:
                rl_action = self._rl_decision(alert)
                if rl_action and rl_action.confidence >= self.rl_confidence_threshold:
                    self._execute_action(rl_action, alert)
                    return rl_action
            
            # Level 3: Heuristic + Autonomous Defender
            if self.autonomous_defender:
                heuristic_action = self._heuristic_decision(alert)
                if heuristic_action:
                    self._execute_action(heuristic_action, alert)
                    return heuristic_action
            
            # Level 4: Smart Firewall graduated response
            if self.firewall:
                firewall_action = self._firewall_decision(alert)
                if firewall_action:
                    self._execute_action(firewall_action, alert)
                    return firewall_action
            
            # No action needed
            with self._lock:
                self.stats['ignored'] += 1
            return None
            
        except Exception as e:
            logger.error(f"DecisionFusion error: {e}")
            with self._lock:
                self.stats['errors'] += 1
            
            # Fallback: блокировать при высокой уверенности
            if alert.get('score', 0) > 0.9:
                fallback_action = DefenseAction(
                    action_id=4,
                    action_name='block_perm',
                    description=f"Fallback permanent block for {alert.get('src_ip')}",
                    source=DecisionSource.RULE_BASED,
                    confidence=alert.get('score', 0.9),
                    priority=100,
                    block_duration=86400
                )
                self._execute_action(fallback_action, alert)
                return fallback_action
            
            return None
    
    def _rule_based_decision(self, alert: Dict) -> Optional[DefenseAction]:
        """Level 1: Правила мгновенного реагирования"""
        attack_type = alert.get('attack_type', '')
        severity = alert.get('severity', 'LOW')
        score = alert.get('score', 0)
        confidence = alert.get('confidence', 0)
        src_ip = alert.get('src_ip', '')
        
        # Пропускаем локальные IP
        if src_ip in ['127.0.0.1', '::1', 'localhost', '0.0.0.0']:
            return None
        
        # CRITICAL + Data Exfiltration → немедленная перманентная блокировка
        if 'Data Exfiltration' in attack_type and severity == 'CRITICAL':
            with self._lock:
                self.stats['rule_based'] += 1
            return DefenseAction(
                action_id=4,
                action_name='block_perm',
                description=f"🚨 CRITICAL: Data Exfiltration from {src_ip} — PERMANENT BLOCK",
                source=DecisionSource.RULE_BASED,
                confidence=1.0,
                priority=200,
                block_duration=86400  # 24 hours
            )
        
        # CRITICAL + Malware/Ransomware → перманентная блокировка
        if attack_type in ['Malware', 'Ransomware', 'C2 Beacon'] and severity == 'CRITICAL':
            with self._lock:
                self.stats['rule_based'] += 1
            return DefenseAction(
                action_id=4,
                action_name='block_perm',
                description=f"🚨 CRITICAL: {attack_type} from {src_ip} — PERMANENT BLOCK",
                source=DecisionSource.RULE_BASED,
                confidence=1.0,
                priority=190,
                block_duration=86400
            )
        
        # Score > 0.95 → перманентная блокировка
        if score > self.permanent_block_threshold and confidence > 0.8:
            with self._lock:
                self.stats['rule_based'] += 1
            return DefenseAction(
                action_id=4,
                action_name='block_perm',
                description=f"High confidence attack ({score:.2f}) from {src_ip} — PERMANENT BLOCK",
                source=DecisionSource.RULE_BASED,
                confidence=score,
                priority=180,
                block_duration=86400
            )
        
        # CRITICAL + DDoS → временная блокировка
        if attack_type in ['DDoS', 'DoS'] and severity == 'CRITICAL':
            with self._lock:
                self.stats['rule_based'] += 1
            return DefenseAction(
                action_id=3,
                action_name='block_temp',
                description=f"DDoS attack from {src_ip} — TEMPORARY BLOCK",
                source=DecisionSource.RULE_BASED,
                confidence=0.9,
                priority=170,
                block_duration=3600  # 1 hour
            )
        
        return None
    
    def _rl_decision(self, alert: Dict) -> Optional[DefenseAction]:
        """Level 2: RL Agent принимает решение"""
        if not self.rl_defense:
            return None
        
        try:
            action_id, action_name, action_desc = self.rl_defense.decide_action(alert)
            
            # Проверяем, что RL не предлагает игнорировать критическую атаку
            attack_type = alert.get('attack_type', '')
            severity = alert.get('severity', 'LOW')
            
            if action_id == 0 and severity == 'CRITICAL':
                # RL ошибается — повышаем до блокировки
                action_id = 3
                action_name = 'block_temp'
                action_desc = 'RL override: Critical attack requires blocking'
            
            # Оцениваем confidence RL
            score = alert.get('score', 0)
            confidence = min(0.95, score * 0.8 + 0.2)  # Эвристика confidence
            
            with self._lock:
                self.stats['rl_decisions'] += 1
            
            return DefenseAction(
                action_id=action_id,
                action_name=action_name,
                description=f"RL Decision: {action_desc}",
                source=DecisionSource.RL_AGENT,
                confidence=confidence,
                priority=150,
                block_duration=self._get_block_duration(action_id)
            )
            
        except Exception as e:
            logger.error(f"RL decision error: {e}")
            return None
    
    def _heuristic_decision(self, alert: Dict) -> Optional[DefenseAction]:
        """Level 3: Autonomous Defender + Heuristic"""
        if not self.autonomous_defender:
            return None
        
        try:
            # Запрашиваем Autonomous Defender
            defender_result = self.autonomous_defender.defender.on_alert(alert)
            
            if not defender_result.get('success'):
                return None
            
            actions_taken = defender_result.get('actions_taken', [])
            generated_code = defender_result.get('code_generated', [])
            
            # Определяем действие
            if 'block_ip' in actions_taken:
                action_id = 3
                action_name = 'block_temp'
                block_duration = 3600
            elif 'isolate' in actions_taken:
                action_id = 4
                action_name = 'block_perm'
                block_duration = 86400
            elif 'redirect' in actions_taken:
                action_id = 3
                action_name = 'block_temp'
                block_duration = 1800
            else:
                action_id = 2
                action_name = 'throttle'
                block_duration = 0
            
            with self._lock:
                self.stats['heuristic_decisions'] += 1
            
            return DefenseAction(
                action_id=action_id,
                action_name=action_name,
                description=f"Defender: {', '.join(actions_taken)}",
                source=DecisionSource.HEURISTIC,
                confidence=alert.get('score', 0.7),
                priority=130,
                block_duration=block_duration,
                generated_code='\n'.join(generated_code) if generated_code else None,
                script_path=generated_code[0] if generated_code else None
            )
            
        except Exception as e:
            logger.error(f"Heuristic decision error: {e}")
            return None
    
    def _firewall_decision(self, alert: Dict) -> Optional[DefenseAction]:
        """Level 4: Smart Firewall graduated response"""
        if not self.firewall:
            return None
        
        try:
            src_ip = alert.get('src_ip', '')
            severity = alert.get('severity', 'LOW')
            
            # Проверяем, не заблокирован ли уже
            if self.firewall.is_blocked(src_ip):
                return None
            
            # Определяем уровень эскалации
            severity_map = {
                'CRITICAL': 4,
                'HIGH': 3,
                'MEDIUM': 2,
                'LOW': 1
            }
            level = severity_map.get(severity, 1)
            
            if level >= 3:
                action_id = 3
                action_name = 'block_temp'
                block_duration = 1800
            elif level == 2:
                action_id = 2
                action_name = 'throttle'
                block_duration = 0
            else:
                return None  # Не реагируем на LOW
            
            return DefenseAction(
                action_id=action_id,
                action_name=action_name,
                description=f"Firewall graduated response level {level}",
                source=DecisionSource.HEURISTIC,
                confidence=0.6,
                priority=100,
                block_duration=block_duration
            )
            
        except Exception as e:
            logger.error(f"Firewall decision error: {e}")
            return None
    
    def _execute_action(self, action: DefenseAction, alert: Dict) -> bool:
        """Исполнение выбранного действия"""
        src_ip = alert.get('src_ip', '')
        dst_port = alert.get('dst_port', 0)
        
        if not src_ip or src_ip in ['127.0.0.1', '::1', 'localhost']:
            logger.debug(f"Skipping action for local IP: {src_ip}")
            return False
        
        success = False
        
        try:
            # Сначала пробуем AppFirewall (работает без root)
            try:
                from modules.app_firewall import app_firewall
                if not hasattr(self, '_app_fw_started'):
                    app_firewall.start()
                    self._app_fw_started = True
                
                if action.action_id >= 3:
                    app_firewall.block_ip(src_ip, duration=action.block_duration, reason=alert.get('attack_type', ''))
                elif action.action_id == 2:
                    app_firewall.block_ip(src_ip, duration=300, reason='throttle')
            except Exception as e:
                logger.debug(f"AppFirewall skipped: {e}")
            
            # Затем пробуем Smart Firewall (iptables)
            if self.firewall:
                if action.action_id >= 3:  # Блокировка IP
                    success = self.firewall.block_ip(
                        src_ip, 
                        duration=action.block_duration
                    )
                    if success:
                        with self._lock:
                            self.stats['blocks_applied'] += 1
                        logger.warning(
                            f"🛡️ BLOCKED: {src_ip} "
                            f"({action.action_name}, {action.block_duration}s) "
                            f"[{action.source.value}]"
                        )
                
                elif action.action_id == 2:  # Throttle
                    success = self.firewall._apply_throttle_rule(src_ip, dst_port)
                    if success:
                        with self._lock:
                            self.stats['throttles_applied'] += 1
                        logger.info(f"🐌 THROTTLED: {src_ip}:{dst_port}")
            
            # Если firewall не доступен, используем Autonomous Defender
            elif self.autonomous_defender and action.generated_code:
                logger.info(f"📝 Executing generated defense code for {src_ip}")
                success = True
            
            # Сохраняем в историю
            with self._lock:
                self._decision_history.append({
                    'action': action.to_dict(),
                    'alert': {
                        'src_ip': src_ip,
                        'attack_type': alert.get('attack_type', 'Unknown'),
                        'severity': alert.get('severity', 'LOW'),
                        'score': alert.get('score', 0)
                    },
                    'success': success
                })
                
                # Обновляем активные защиты
                if success and action.action_id >= 3:
                    self._active_defenses[src_ip] = {
                        'action': action.to_dict(),
                        'expires': time.time() + action.block_duration
                    }
            
            # Публикуем событие
            if self.event_bus and success:
                self.event_bus.publish('defense.executed', {
                    'action': action.to_dict(),
                    'alert': alert
                })
            
            # WebSocket broadcast (если WebUI запущен)
            try:
                import sys
                sys.path.insert(0, 'shard-webui/backend')
                from app.routers.websocket_router import broadcast_defense_update
                broadcast_defense_update(
                    stats=self.get_stats(),
                    active=self.get_active_defenses(),
                    alert=alert if success else None
                )
            except Exception:
                pass
            
            # Обратная связь для RL
            if self.rl_defense and hasattr(self.rl_defense, 'defender'):
                attack_info = {
                    'attack_type': alert.get('attack_type', 'Unknown'),
                    'action_taken': action.action_name,
                    'src_ip': src_ip,
                    'success': success
                }
                try:
                    self.rl_defense.defender.learn_from_result(attack_info, success)
                except Exception:
                    pass
            
            return success
            
        except Exception as e:
            logger.error(f"Action execution error: {e}")
            return False
    
    def _get_block_duration(self, action_id: int) -> int:
        """Получить длительность блокировки по action_id"""
        durations = {
            0: 0,       # ignore
            1: 0,       # log
            2: 0,       # throttle
            3: 1800,    # temp block: 30 min
            4: 86400    # perm block: 24 hours
        }
        return durations.get(action_id, 0)
    
    def on_investigation(self, investigation: Dict) -> None:
        """Реакция на завершение расследования Agentic AI"""
        # Если расследование подтвердило атаку — усиливаем защиту
        if investigation.get('confidence', 0) > 0.7:
            src_ip = investigation.get('src_ip', '')
            if src_ip and src_ip not in ['127.0.0.1', '::1']:
                logger.info(f"🔍 Investigation confirmed threat from {src_ip}, escalating...")
                
                # Усиливаем блокировку если уже есть
                if src_ip in self._active_defenses:
                    if self.firewall:
                        self.firewall.block_ip(src_ip, duration=86400)
                        logger.warning(f"🔒 Escalated to permanent block: {src_ip}")
    
    def manual_action(self, alert: Dict, action_id: int) -> DefenseAction:
        """Ручное применение действия (через API)"""
        action_names = {
            0: 'ignore', 1: 'log', 2: 'throttle', 
            3: 'block_temp', 4: 'block_perm'
        }
        
        action = DefenseAction(
            action_id=action_id,
            action_name=action_names.get(action_id, 'unknown'),
            description=f"Manual action from operator",
            source=DecisionSource.MANUAL,
            confidence=1.0,
            priority=255,  # Высший приоритет
            block_duration=self._get_block_duration(action_id)
        )
        
        self._execute_action(action, alert)
        return action
    
    def get_stats(self) -> Dict:
        """Статистика принятия решений"""
        with self._lock:
            return {
                **self.stats,
                'active_defenses': len(self._active_defenses),
                'history_size': len(self._decision_history),
                'recent_decisions': [
                    d['action'] for d in list(self._decision_history)[-10:]
                ]
            }
    
    def get_active_defenses(self) -> List[Dict]:
        """Список активных защит"""
        now = time.time()
        active = []
        
        with self._lock:
            for ip, defense in list(self._active_defenses.items()):
                if defense['expires'] > now:
                    active.append({
                        'ip': ip,
                        **defense['action'],
                        'remaining': max(0, defense['expires'] - now)
                    })
                else:
                    del self._active_defenses[ip]
        
        return active
    
    def export_stats_to_file(self, filepath: str = None):
        """Экспорт статистики в JSON файл для WebUI"""
        import json
        path = filepath or 'data/defense_stats.json'
        try:
            data = {
                'stats': self.get_stats(),
                'active': self.get_active_defenses(),
                'timestamp': __import__('time').time()
            }
            with open(path, 'w') as f:
                json.dump(data, f, default=str)
        except Exception:
            pass

    def cleanup_expired(self) -> int:
        """Очистка истёкших защит"""
        now = time.time()
        expired_count = 0
        
        with self._lock:
            for ip in list(self._active_defenses.keys()):
                if self._active_defenses[ip]['expires'] <= now:
                    del self._active_defenses[ip]
                    expired_count += 1
                    
                    # Снимаем блокировку в firewall
                    if self.firewall:
                        self.firewall.unblock_ip(ip)
        
        if expired_count:
            logger.info(f"🧹 Cleaned {expired_count} expired defenses")
        
        return expired_count


# Глобальный синглтон
_fusion_instance = None


def get_decision_fusion() -> DecisionFusion:
    """Получить глобальный экземпляр DecisionFusion"""
    global _fusion_instance
    if _fusion_instance is None:
        _fusion_instance = DecisionFusion()
    return _fusion_instance


def init_decision_fusion(event_bus, rl_defense=None, 
                         autonomous_defender=None, firewall=None, ml_engine=None):
    """Инициализировать DecisionFusion со всеми модулями"""
    fusion = get_decision_fusion()
    fusion.setup(
        rl_defense=rl_defense,
        autonomous_defender=autonomous_defender,
        firewall=firewall,
        ml_engine=ml_engine,
        event_bus=event_bus
    )
    
    # Запускаем поток очистки
    def cleanup_loop():
        while True:
            time.sleep(60)
            fusion.cleanup_expired()
    
    threading.Thread(target=cleanup_loop, daemon=True, name="fusion-cleanup").start()
    
    logger.info("🚀 DecisionFusion fully initialized and running")
    return fusion


print("✅ DecisionFusion module loaded")
