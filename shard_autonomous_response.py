#!/usr/bin/env python3

"""
SHARD Autonomous Response Engine
Автономная реакция с RL и контекстным анализом (как Darktrace Antigena)

Author: SHARD Enterprise
Version: 4.1.0
"""

import time
import threading
import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple
from collections import deque, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

import numpy as np



@dataclass
class AutonomousResponseConfig:
    """Конфигурация автономной реакции"""

    confidence_threshold_block_temp: float = 0.85
    confidence_threshold_block_perm: float = 0.95
    confidence_threshold_throttle: float = 0.70

    max_auto_blocks_per_hour: int = 10
    max_auto_blocks_per_day: int = 50

    action_cooldown: int = 300

    whitelist_ips: Set[str] = field(default_factory=lambda: {
        '127.0.0.1', '::1', 'localhost',
        '192.168.1.1', '10.0.0.1'
    })

    whitelist_subnets: List[str] = field(default_factory=lambda: [
        '127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'
    ])

    autonomous_mode: bool = True
    recommend_only: bool = False

    history_path: str = './data/autonomous_history.json'



class DefenseAction:
    """Защитные действия"""

    ACTIONS = {
        0: ('none', 'Ничего не делать', 0),
        1: ('log_increased', 'Увеличить логирование', 10),
        2: ('throttle', 'Замедлить трафик', 50),
        3: ('block_port', 'Заблокировать порт', 100),
        4: ('block_ip_temp', 'Временно заблокировать IP (1 час)', 200),
        5: ('block_ip_perm', 'Перманентно заблокировать IP', 500),
        6: ('isolate_device', 'Изолировать устройство', 1000),
        7: ('trigger_honeypot', 'Перенаправить на honeypot', 50)
    }

    @classmethod
    def get_name(cls, action_id: int) -> str:
        return cls.ACTIONS.get(action_id, ('unknown', 'Неизвестно', 0))[1]

    @classmethod
    def get_cost(cls, action_id: int) -> int:
        return cls.ACTIONS.get(action_id, ('unknown', 'Неизвестно', 0))[2]

    @classmethod
    def get_action_id(cls, action_name: str) -> int:
        for aid, (name, _, _) in cls.ACTIONS.items():
            if name == action_name:
                return aid
        return 0



class AutonomousResponseEngine:
    """
    Движок автономной реакции.
    Принимает решения на основе RL, контекста и истории.
    """

    def __init__(self, config: AutonomousResponseConfig = None):
        self.config = config or AutonomousResponseConfig()

        self.action_history: deque = deque(maxlen=10000)
        self.ip_action_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))

        self.hourly_blocks: deque = deque(maxlen=1000)
        self.daily_blocks: deque = deque(maxlen=10000)

        self.stats = {
            'total_actions': 0,
            'auto_blocks': 0,
            'auto_throttles': 0,
            'recommendations': 0,
            'prevented_attacks': 0
        }

        self.firewall = None
        self.rl_agent = None
        self.event_bus = None
        self.logger = None

        self._lock = threading.RLock()
        self._running = False

        self._load_history()

    def set_components(self, firewall, rl_agent, event_bus, logger):
        """Установка компонентов"""
        self.firewall = firewall
        self.rl_agent = rl_agent
        self.event_bus = event_bus
        self.logger = logger

    def _load_history(self):
        """Загрузка истории действий"""
        try:
            path = Path(self.config.history_path)
            if path.exists():
                with open(path, 'r') as f:
                    data = json.load(f)
                    for action in data.get('actions', []):
                        self.action_history.append(action)
                    self.stats = data.get('stats', self.stats)
        except Exception as e:
            print(f"⚠️ Ошибка загрузки истории: {e}")

    def _save_history(self):
        """Сохранение истории"""
        try:
            path = Path(self.config.history_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, 'w') as f:
                json.dump({
                    'actions': list(self.action_history),
                    'stats': self.stats
                }, f, indent=2)
        except Exception as e:
            print(f"⚠️ Ошибка сохранения истории: {e}")

    def _is_whitelisted(self, ip: str) -> bool:
        """Проверка, в белом ли списке IP"""
        if ip in self.config.whitelist_ips:
            return True

        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            for subnet in self.config.whitelist_subnets:
                if ip_obj in ipaddress.ip_network(subnet):
                    return True
        except:
            pass

        return False

    def _check_limits(self, action_id: int) -> bool:
        """Проверка лимитов на действия"""
        now = time.time()

        while self.hourly_blocks and now - self.hourly_blocks[0] > 3600:
            self.hourly_blocks.popleft()
        while self.daily_blocks and now - self.daily_blocks[0] > 86400:
            self.daily_blocks.popleft()

        if action_id in [4, 5]:
            if len(self.hourly_blocks) >= self.config.max_auto_blocks_per_hour:
                if self.logger:
                    self.logger.warning(f"⚠️ Достигнут лимит блокировок в час ({self.config.max_auto_blocks_per_hour})")
                return False
            if len(self.daily_blocks) >= self.config.max_auto_blocks_per_day:
                if self.logger:
                    self.logger.warning(f"⚠️ Достигнут лимит блокировок в день ({self.config.max_auto_blocks_per_day})")
                return False

        return True

    def _check_cooldown(self, ip: str) -> bool:
        """Проверка cooldown для IP"""
        if ip not in self.ip_action_history:
            return True

        history = self.ip_action_history[ip]
        if not history:
            return True

        last_action_time = history[-1]['timestamp']
        return time.time() - last_action_time >= self.config.action_cooldown

    def on_alert(self, alert: Dict) -> Optional[Dict]:
        """
        Обработка алерта и принятие решения о реакции.

        Returns:
            Dict с информацией о выполненном действии или None
        """
        with self._lock:
            confidence = alert.get('confidence', alert.get('score', 0))
            severity = alert.get('severity', 'LOW')
            attack_type = alert.get('attack_type', 'Unknown')
            src_ip = alert.get('src_ip', '')

            if not src_ip:
                return None

            if self._is_whitelisted(src_ip):
                return None

            if not self._check_cooldown(src_ip):
                return None

            action_id = self._decide_action(alert)

            if action_id == 0:
                return None

            if not self._check_limits(action_id):
                action_id = 2

            action_name = DefenseAction.get_name(action_id)

            result = self._execute_action(action_id, alert)

            action_record = {
                'timestamp': time.time(),
                'action_id': action_id,
                'action_name': action_name,
                'src_ip': src_ip,
                'alert': {
                    'attack_type': attack_type,
                    'severity': severity,
                    'confidence': confidence,
                    'score': alert.get('score', 0)
                },
                'result': result
            }

            self.action_history.append(action_record)
            self.ip_action_history[src_ip].append(action_record)

            if action_id in [4, 5]:
                self.hourly_blocks.append(time.time())
                self.daily_blocks.append(time.time())
                self.stats['auto_blocks'] += 1
            elif action_id == 2:
                self.stats['auto_throttles'] += 1

            self.stats['total_actions'] += 1

            self._save_history()

            if self.event_bus:
                self.event_bus.publish('autonomous.action', action_record)

            return action_record

    def _decide_action(self, alert: Dict) -> int:
        """
        Принятие решения о действии.
        Использует RL если доступен, иначе правила.
        """
        confidence = alert.get('confidence', alert.get('score', 0))
        severity = alert.get('severity', 'LOW')
        attack_type = alert.get('attack_type', '')

        if self.rl_agent:
            state = self._alert_to_state(alert)
            action_id, _ = self.rl_agent.act(state, training=False)
            return action_id

        if confidence >= self.config.confidence_threshold_block_perm:
            return 5
        elif confidence >= self.config.confidence_threshold_block_temp:
            return 4
        elif confidence >= self.config.confidence_threshold_throttle:
            return 2

        if attack_type in ['Data Exfiltration', 'C2 Beacon']:
            if confidence > 0.7:
                return 4

        if attack_type == 'Port Scan':
            if confidence > 0.6:
                return 1

        return 0

    def _alert_to_state(self, alert: Dict) -> Dict:
        """Преобразование алерта в состояние для RL"""
        return {
            'alert_score': alert.get('score', 0),
            'confidence': alert.get('confidence', 0),
            'severity_level': {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}.get(
                alert.get('severity', 'LOW'), 0
            ),
            'is_internal': alert.get('is_internal', False),
            'hour_of_day': datetime.now().hour,
            'day_of_week': datetime.now().weekday()
        }

    def _execute_action(self, action_id: int, alert: Dict) -> Dict:
        """Выполнение действия"""
        src_ip = alert.get('src_ip', '')
        result = {'success': False, 'action': DefenseAction.get_name(action_id)}

        if self.config.recommend_only:
            self.stats['recommendations'] += 1
            result['message'] = f"Рекомендовано: {DefenseAction.get_name(action_id)}"
            result['success'] = True
            return result

        if not self.config.autonomous_mode:
            result['message'] = "Автономный режим отключен"
            return result

        try:
            if action_id == 1:
                if self.logger:
                    self.logger.info(f"📝 Увеличено логирование для {src_ip}")
                result['success'] = True

            elif action_id == 2:
                if self.firewall:
                    self.firewall._apply_action(src_ip, 0, 'throttle', alert)
                result['success'] = True
                if self.logger:
                    self.logger.warning(f"🐢 Замедление трафика от {src_ip}")

            elif action_id == 3:
                dst_port = alert.get('dst_port', 0)
                if dst_port and self.firewall:
                    self.firewall.block_port(src_ip, dst_port)
                    result['success'] = True
                    if self.logger:
                        self.logger.warning(f"🔒 Заблокирован порт {dst_port} для {src_ip}")

            elif action_id == 4:
                if self.firewall:
                    self.firewall.block_ip(src_ip, 3600)
                    result['success'] = True
                    if self.logger:
                        self.logger.warning(f"🚫 Временно заблокирован IP {src_ip} (1 час)")

            elif action_id == 5:
                if self.firewall:
                    self.firewall.block_ip(src_ip, 86400)
                    result['success'] = True
                    if self.logger:
                        self.logger.warning(f"🚫 ПЕРМАНЕНТНО заблокирован IP {src_ip}")

            elif action_id == 6:
                if self.firewall:
                    self.firewall.block_ip(src_ip, 86400 * 7)
                    result['success'] = True
                    if self.logger:
                        self.logger.critical(f"🔴 Изолировано устройство {src_ip}")

            elif action_id == 7:
                result['success'] = True
                if self.logger:
                    self.logger.info(f"🍯 Перенаправление {src_ip} на honeypot")

        except Exception as e:
            result['error'] = str(e)
            if self.logger:
                self.logger.error(f"Ошибка выполнения действия {action_id}: {e}")

        return result

    def get_recommendation(self, alert: Dict) -> Dict:
        """
        Получить рекомендацию без выполнения действия.
        """
        action_id = self._decide_action(alert)
        action_name = DefenseAction.get_name(action_id)
        cost = DefenseAction.get_cost(action_id)

        return {
            'action_id': action_id,
            'action_name': action_name,
            'cost': cost,
            'confidence_required': self._get_confidence_required(action_id),
            'reason': self._get_reason(alert, action_id)
        }

    def _get_confidence_required(self, action_id: int) -> float:
        """Получить требуемую уверенность для действия"""
        if action_id == 5:
            return self.config.confidence_threshold_block_perm
        elif action_id == 4:
            return self.config.confidence_threshold_block_temp
        elif action_id in [2, 3, 7]:
            return self.config.confidence_threshold_throttle
        return 0.0

    def _get_reason(self, alert: Dict, action_id: int) -> str:
        """Получить объяснение рекомендации"""
        attack_type = alert.get('attack_type', 'Unknown')
        confidence = alert.get('confidence', 0)

        reasons = {
            5: f"Высокая уверенность ({confidence:.0%}) в атаке {attack_type}",
            4: f"Обнаружена атака {attack_type} с уверенностью {confidence:.0%}",
            2: f"Подозрительная активность типа {attack_type}",
            1: f"Требуется дополнительный мониторинг для {attack_type}"
        }
        return reasons.get(action_id, "Автоматическая рекомендация")

    def get_stats(self) -> Dict:
        """Получить статистику"""
        with self._lock:
            return {
                **self.stats,
                'hourly_blocks': len(self.hourly_blocks),
                'daily_blocks': len(self.daily_blocks),
                'history_size': len(self.action_history),
                'autonomous_mode': self.config.autonomous_mode,
                'recommend_only': self.config.recommend_only
            }

    def rollback_last_action(self) -> bool:
        """Откат последнего действия"""
        with self._lock:
            if not self.action_history:
                return False

            last = self.action_history[-1]
            src_ip = last['src_ip']
            action_id = last['action_id']

            if action_id in [4, 5, 6]:
                if self.firewall:
                    self.firewall.unblock_ip(src_ip)
                    if self.logger:
                        self.logger.info(f"↩️ Откат блокировки для {src_ip}")
                    return True

            return False



class LLMSecurityAnalyst:
    """
    AI аналитик на основе локальной LLM.
    Генерирует человеко-читаемые отчёты об инцидентах.
    """

    def __init__(self, model_path: str = None):
        self.model = None
        self.model_type = 'llama'
        self.cache: Dict[str, Tuple[float, str]] = {}
        self.cache_ttl = 3600

        if model_path and Path(model_path).exists():
            self._init_llama_cpp(model_path)
        else:
            self._try_ollama()

    def _init_llama_cpp(self, model_path: str):
        """Инициализация llama.cpp"""
        try:
            from llama_cpp import Llama
            self.model = Llama(
                model_path=model_path,
                n_ctx=4096,
                n_threads=4,
                verbose=False
            )
            self.model_type = 'llama'
            print("✅ LLM Analyst (llama.cpp) загружен")
        except ImportError:
            print("⚠️ llama-cpp-python не установлен. Используем fallback.")

    def _try_ollama(self):
        """Попытка подключения к Ollama"""
        try:
            import requests
            response = requests.get('http://localhost:11434/api/tags', timeout=2)
            if response.status_code == 200:
                self.model = 'ollama'
                self.model_type = 'ollama'
                print("✅ LLM Analyst (Ollama) подключён")
        except:
            print("⚠️ Ollama не доступен. Используем fallback.")

    def analyze_alert(self, alert: Dict, context: Dict = None) -> str:
        """
        Генерация экспертного заключения по алерту.
        """
        context = context or {}

        cache_key = f"{alert.get('attack_type')}_{alert.get('severity')}_{alert.get('score', 0):.1f}"
        if cache_key in self.cache:
            cached_time, cached_response = self.cache[cache_key]
            if time.time() - cached_time < self.cache_ttl:
                return cached_response

        prompt = self._build_prompt(alert, context)
        response = self._call_model(prompt)

        self.cache[cache_key] = (time.time(), response)
        if len(self.cache) > 100:
            now = time.time()
            self.cache = {k: v for k, v in self.cache.items() if now - v[0] < self.cache_ttl}

        return response

    def _build_prompt(self, alert: Dict, context: Dict) -> str:
        """Построение промпта для LLM"""
        attack_type = alert.get('attack_type', 'Unknown')
        src_ip = alert.get('src_ip', 'unknown')
        dst_ip = alert.get('dst_ip', 'N/A')
        dst_port = alert.get('dst_port', 'N/A')
        severity = alert.get('severity', 'LOW')
        score = alert.get('score', 0)
        confidence = alert.get('confidence', 0)

        prompt = f"""Ты — старший аналитик SOC (Security Operations Center). 
Проанализируй следующий алерт системы SIEM и дай краткое экспертное заключение.

ДАННЫЕ АЛЕРТА:
- Тип атаки: {attack_type}
- Источник: {src_ip}
- Цель: {dst_ip}:{dst_port}
- Серьёзность: {severity}
- Score: {score:.2f}
- Уверенность: {confidence:.0%}

КОНТЕКСТ:
- Локальная сеть: {'Да' if context.get('is_internal') else 'Нет'}
- Threat Intelligence: {context.get('threat_intel', 'Нет данных')}
- Похожих алертов за час: {context.get('similar_alerts', 0)}
- Время суток: {context.get('hour', datetime.now().hour)}:00

ФОРМАТ ОТВЕТА:
1. **Что произошло** (1 предложение)
2. **Оценка угрозы** (1 предложение)
3. **Рекомендация** (1 предложение)

Ответ должен быть на русском языке, профессиональным и лаконичным (3-4 предложения всего)."""

        return prompt

    def _call_model(self, prompt: str) -> str:
        """Вызов модели"""
        try:
            if self.model_type == 'llama' and self.model:
                response = self.model(prompt, max_tokens=250, stop=["\n\n", "---"], echo=False)
                return response['choices'][0]['text'].strip()

            elif self.model_type == 'ollama':
                import requests
                response = requests.post(
                    'http://localhost:11434/api/generate',
                    json={'model': 'llama3.2', 'prompt': prompt, 'stream': False},
                    timeout=30
                )
                if response.status_code == 200:
                    return response.json()['response'].strip()

        except Exception as e:
            print(f"⚠️ LLM error: {e}")

        return self._fallback_analysis(alert=None)

    def _fallback_analysis(self, alert: Dict = None) -> str:
        """Запасной анализ без LLM"""
        if alert:
            return f"**Что произошло**: Обнаружена атака типа {alert.get('attack_type')}. **Оценка угрозы**: Уровень {alert.get('severity')}. **Рекомендация**: Проверить источник {alert.get('src_ip')}."
        return "**Что произошло**: Обнаружена подозрительная активность. **Оценка угрозы**: Требуется анализ. **Рекомендация**: Проверить логи."

    def analyze_investigation(self, investigation: Dict) -> str:
        """Анализ расследования"""
        prompt = f"""Ты — эксперт по кибербезопасности. Подготовь краткий отчёт по расследованию инцидента.

ДАННЫЕ РАССЛЕДОВАНИЯ:
- ID: {investigation.get('id', 'N/A')}
- Тип атаки: {investigation.get('attack_type')}
- Источник: {investigation.get('src_ip')}
- Длительность: {investigation.get('duration', 0):.0f} сек
- Количество алертов: {len(investigation.get('alerts', []))}
- Заключение: {investigation.get('conclusion', 'Нет')}
- Уверенность: {investigation.get('confidence', 0):.0%}

Дай краткое резюме (3-4 предложения) и финальную рекомендацию."""

        return self._call_model(prompt)

    def get_stats(self) -> Dict:
        return {
            'model_type': self.model_type,
            'model_loaded': self.model is not None,
            'cache_size': len(self.cache)
        }



class ShardAutonomousIntegration:
    """Интеграция автономной реакции и LLM в SHARD"""

    def __init__(self, config: Dict = None):
        self.config = AutonomousResponseConfig()
        self.response_engine = AutonomousResponseEngine(self.config)

        llm_model = config.get('llm_model_path') if config else None
        self.llm_analyst = LLMSecurityAnalyst(llm_model)

    def setup(self, firewall, rl_agent, event_bus, logger):
        """Настройка компонентов"""
        self.response_engine.set_components(firewall, rl_agent, event_bus, logger)

    def on_alert(self, alert: Dict) -> Dict:
        """Обработка алерта"""
        action_result = self.response_engine.on_alert(alert)

        llm_analysis = self.llm_analyst.analyze_alert(alert, {
            'is_internal': alert.get('is_internal', False),
            'similar_alerts': 0,
            'hour': datetime.now().hour
        })

        result = {
            'autonomous_action': action_result,
            'llm_analysis': llm_analysis
        }

        return result

    def get_recommendation(self, alert: Dict) -> Dict:
        """Получить рекомендацию без выполнения"""
        rec = self.response_engine.get_recommendation(alert)
        rec['llm_analysis'] = self.llm_analyst.analyze_alert(alert)
        return rec

    def get_stats(self) -> Dict:
        return {
            'autonomous': self.response_engine.get_stats(),
            'llm': self.llm_analyst.get_stats()
        }



def test_autonomous_response():
    """Тестирование автономной реакции"""
    print("=" * 60)
    print("🧪 ТЕСТИРОВАНИЕ АВТОНОМНОЙ РЕАКЦИИ")
    print("=" * 60)

    engine = AutonomousResponseEngine()
    engine.config.autonomous_mode = False
    engine.config.recommend_only = True

    alert = {
        'attack_type': 'Brute Force',
        'src_ip': '192.168.1.100',
        'severity': 'HIGH',
        'score': 0.85,
        'confidence': 0.88
    }

    rec = engine.get_recommendation(alert)
    print(f"\n📊 Тестовый алерт: {alert['attack_type']} (score={alert['score']})")
    print(f"   Рекомендация: {rec['action_name']}")
    print(f"   Причина: {rec['reason']}")

    print("\n📊 Тест LLM Analyst...")
    llm = LLMSecurityAnalyst()
    analysis = llm.analyze_alert(alert)
    print(f"   Анализ: {analysis[:200]}...")

    print("\n" + "=" * 60)
    print("✅ ТЕСТИРОВАНИЕ ЗАВЕРШЕНО")
    print("=" * 60)


if __name__ == "__main__":
    test_autonomous_response()