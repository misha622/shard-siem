#!/usr/bin/env python3
"""SHARD UserBehaviorAnalytics Module"""
from core.base import BaseModule, ConfigManager, EventBus, LoggingService
import time, threading
from typing import Dict, List, Optional, Any, Set
from collections import defaultdict, deque
from datetime import datetime

class UserBehaviorAnalytics(BaseModule):
    """Анализ поведения пользователей и сущностей (UBA/UEBA)"""

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("UBA", config, event_bus, logger)

        self.users: Dict[str, Dict] = defaultdict(lambda: {
            'ips': set(),
            'login_times': defaultdict(int),  # час -> количество
            'login_days': defaultdict(int),  # день недели -> количество
            'accessed_resources': defaultdict(int),  # ресурс -> количество
            'bytes_downloaded': deque(maxlen=100),  # (timestamp, bytes)
            'bytes_uploaded': deque(maxlen=100),
            'sessions': deque(maxlen=200),  # (timestamp, type, details)
            'geo_locations': set(),
            'devices': set(),
            'risk_score': 0.0,
            'first_seen': time.time(),
            'last_seen': time.time(),
            'total_sessions': 0,
            'failed_logins': 0,
            'successful_logins': 0
        })

        self.ip_to_user: Dict[str, str] = {}
        self.user_peer_groups: Dict[str, List[str]] = defaultdict(list)  # Группы похожих пользователей

        # Пороги для аномалий
        self.thresholds = {
            'unusual_hour_threshold': 0.1,  # 10% от среднего
            'new_geo_score': 0.4,
            'volume_multiplier': 5,  # В 5 раз больше среднего
            'new_resource_score': 0.25,
            'failed_login_threshold': 5,  # 5 неудачных попыток
            'rapid_sessions_threshold': 10  # 10 сессий за минуту
        }

        self._lock = threading.RLock()
        self.event_bus.subscribe('auth.login', self.on_login)
        self.event_bus.subscribe('auth.logout', self.on_logout)
        self.event_bus.subscribe('auth.failed', self.on_failed_login)
        self.event_bus.subscribe('packet.received', self.on_traffic)
        self.event_bus.subscribe('alert.detected', self.on_alert)

    def start(self) -> None:
        self.running = True
        self.logger.info("UBA/UEBA запущен")

        # Поток обновления peer groups
        threading.Thread(target=self._peer_group_loop, daemon=True).start()
        # Поток снижения риска
        threading.Thread(target=self._risk_decay_loop, daemon=True).start()

    def stop(self) -> None:
        self.running = False

    def bind_ip_to_user(self, ip: str, username: str) -> None:
        """Привязка IP к пользователю"""
        with self._lock:
            self.ip_to_user[ip] = username
            self.users[username]['ips'].add(ip)

    def on_login(self, data: Dict) -> None:
        """Обработка успешного входа"""
        username = data.get('username', '')
        src_ip = data.get('src_ip', '')
        geo = data.get('geo', '')
        device = data.get('device', '')

        if not username:
            if src_ip:
                username = self.ip_to_user.get(src_ip, src_ip)
            else:
                return

        alert = self.record_event(
            src_ip=src_ip or username,
            event_type='login',
            details={
                'username': username,
                'success': True,
                'geo': geo,
                'device': device
            }
        )

        if alert:
            self.event_bus.publish('uba.anomaly', alert)

    def on_logout(self, data: Dict) -> None:
        """Обработка выхода"""
        username = data.get('username', '')
        src_ip = data.get('src_ip', '')

        if not username and src_ip:
            username = self.ip_to_user.get(src_ip, src_ip)

        if username:
            self.record_event(
                src_ip=src_ip or username,
                event_type='logout',
                details={'username': username}
            )

    def on_failed_login(self, data: Dict) -> None:
        """Обработка неудачного входа"""
        username = data.get('username', '')
        src_ip = data.get('src_ip', '')

        if not username:
            username = src_ip or 'unknown'

        alert = self.record_event(
            src_ip=src_ip or username,
            event_type='failed_login',
            details={'username': username, 'attempted_username': data.get('attempted_username', '')}
        )

        if alert:
            self.event_bus.publish('uba.anomaly', alert)

    def on_traffic(self, data: Dict) -> None:
        """Анализ трафика для UBA"""
        src_ip = data.get('src_ip', '')
        packet = data.get('packet')

        if not src_ip or not packet:
            return

        username = self.ip_to_user.get(src_ip, src_ip)
        bytes_count = len(packet)

        # Определяем направление
        local_networks = self.config.get('network.local_networks', ['192.168.', '10.', '172.16.'])
        dst_ip = data.get('dst_ip', '')
        is_download = any(dst_ip.startswith(net) for net in local_networks)

        with self._lock:
            user = self.users[username]
            now = time.time()

            if is_download:
                user['bytes_downloaded'].append((now, bytes_count))
            else:
                user['bytes_uploaded'].append((now, bytes_count))

    def on_alert(self, alert: Dict) -> None:
        """Обновление риска при алерте"""
        src_ip = alert.get('src_ip', '')
        if src_ip:
            username = self.ip_to_user.get(src_ip, src_ip)
            with self._lock:
                if username in self.users:
                    self.users[username]['risk_score'] = min(1.0, self.users[username]['risk_score'] + 0.1)

    def record_event(self, src_ip: str, event_type: str, details: Dict) -> Optional[Dict]:
        """Запись события и анализ аномалий (с копированием данных)"""
        username = self.ip_to_user.get(src_ip, src_ip)

        with self._lock:
            user = self.users[username]
            now = datetime.now()
            current_time = time.time()

            # Обновление статистики
            user['login_times'][now.hour] += 1
            user['login_days'][now.weekday()] += 1
            user['last_seen'] = current_time
            user['total_sessions'] += 1

            if event_type == 'login':
                user['successful_logins'] += 1
            elif event_type == 'failed_login':
                user['failed_logins'] += 1

            # СОЗДАЁМ КОПИЮ details для хранения
            details_copy = {}
            if details:
                for key, value in details.items():
                    if isinstance(value, (str, int, float, bool, type(None))):
                        details_copy[key] = value
                    elif isinstance(value, (list, tuple)):
                        details_copy[key] = list(value)[:10]  # Ограничиваем размер
                    elif isinstance(value, dict):
                        # Поверхностная копия словаря
                        details_copy[key] = dict(list(value.items())[:10])
                    else:
                        details_copy[key] = str(value)[:100]

            user['sessions'].append({
                'time': current_time,
                'type': event_type,
                'details': details_copy
            })

            if 'geo' in details_copy and details_copy['geo']:
                geo_value = str(details_copy['geo'])[:50]
                user['geo_locations'].add(geo_value)

            if 'device' in details_copy and details_copy['device']:
                device_value = str(details_copy['device'])[:100]
                user['devices'].add(device_value)

            if src_ip not in user['ips']:
                user['ips'].add(src_ip)

            # Анализ аномалий
            alert = self._analyze_anomalies(username, user, event_type, details_copy)

            if alert:
                user['risk_score'] = min(1.0, user['risk_score'] + alert['score'] * 0.3)
                alert['current_risk'] = user['risk_score']
            else:
                user['risk_score'] = max(0.0, user['risk_score'] - 0.01)

            # Проверка на высокий риск
            if user['risk_score'] > 0.7:
                risk_alert = {
                    'username': username,
                    'anomalies': ['high_risk_score'],
                    'score': user['risk_score'],
                    'severity': AlertSeverity.HIGH.value if user['risk_score'] > 0.85 else AlertSeverity.MEDIUM.value,
                    'details': {'risk_score': user['risk_score']}
                }
                self.event_bus.publish('uba.high_risk', risk_alert)

            return alert

    def _analyze_anomalies(self, username: str, user: Dict, event_type: str, details: Dict) -> Optional[Dict]:
        """Анализ аномалий в поведении (исправлена логика unusual time)"""
        alert = {
            'username': username,
            'anomalies': [],
            'score': 0.0,
            'severity': AlertSeverity.LOW.value,
            'timestamp': time.time()
        }

        now = datetime.now()
        current_hour = now.hour
        current_weekday = now.weekday()

        # 1. Необычное время входа (ИСПРАВЛЕНО)
        if event_type in ('login', 'failed_login'):
            # Получаем ИСТОРИЧЕСКУЮ активность (без текущего часа)
            historical_hours = {h: c for h, c in user['login_times'].items() if h != current_hour}

            if historical_hours:
                # Средняя активность по другим часам
                avg_activity = sum(historical_hours.values()) / len(historical_hours)

                # Текущая активность в этот час (уже с учётом нового события)
                current_hour_activity = user['login_times'].get(current_hour, 0)

                # Проверяем, является ли этот час необычным
                if avg_activity > 0:
                    # Если текущая активность значительно ниже средней - это необычное время
                    if current_hour_activity < avg_activity * 0.2:  # Меньше 20% от среднего
                        alert['anomalies'].append(f"unusual_time:{current_hour}:00")
                        alert['score'] += 0.3

                    # Если это ПЕРВЫЙ вход в этот час за всю историю
                    if current_hour_activity == 1 and len(historical_hours) > 10:
                        alert['anomalies'].append(f"first_time_this_hour:{current_hour}:00")
                        alert['score'] += 0.15

            # Необычный день недели (аналогичная логика)
            historical_days = {d: c for d, c in user['login_days'].items() if d != current_weekday}

            if len(historical_days) > 3:
                avg_daily = sum(historical_days.values()) / len(historical_days)
                current_day_activity = user['login_days'].get(current_weekday, 0)

                if avg_daily > 0 and current_day_activity < avg_daily * 0.2:
                    alert['anomalies'].append(f"unusual_day:{current_weekday}")
                    alert['score'] += 0.2

        # 2. Новая геолокация (без изменений)
        if 'geo' in details and details['geo']:
            if details['geo'] not in user['geo_locations'] and len(user['geo_locations']) > 0:
                alert['anomalies'].append(f"new_geo:{details['geo']}")
                alert['score'] += self.thresholds['new_geo_score']

        # 3. Новое устройство (без изменений)
        if 'device' in details and details['device']:
            if details['device'] not in user['devices'] and len(user['devices']) > 0:
                alert['anomalies'].append(f"new_device:{details['device']}")
                alert['score'] += 0.25

        # 4. Аномальный объём данных (без изменений)
        if event_type in ('login', 'traffic'):
            all_bytes = [b for _, b in user['bytes_downloaded']] + [b for _, b in user['bytes_uploaded']]
            if all_bytes:
                avg_bytes = sum(all_bytes) / len(all_bytes)
                recent_downloads = [b for t, b in user['bytes_downloaded'] if time.time() - t < 300]
                if recent_downloads:
                    recent_avg = sum(recent_downloads) / len(recent_downloads)
                    if recent_avg > avg_bytes * self.thresholds['volume_multiplier']:
                        alert['anomalies'].append(f"unusual_volume:{recent_avg / 1024:.1f}KB")
                        alert['score'] += 0.3

        # 5. Множественные неудачные попытки (без изменений)
        if event_type == 'failed_login':
            recent_failed = sum(1 for s in user['sessions']
                                if s.get('type') == 'failed_login' and time.time() - s.get('time', 0) < 300)
            if recent_failed >= self.thresholds['failed_login_threshold']:
                alert['anomalies'].append(f"multiple_failures:{recent_failed}")
                alert['score'] += 0.35

        # 6. Быстрые сессии (без изменений)
        recent_sessions = [s for s in user['sessions'] if time.time() - s.get('time', 0) < 60]
        if len(recent_sessions) >= self.thresholds['rapid_sessions_threshold']:
            alert['anomalies'].append(f"rapid_sessions:{len(recent_sessions)}")
            alert['score'] += 0.3

        # 7. Новый IP (без изменений)
        if 'src_ip' in details and details['src_ip'] not in user['ips']:
            if len(user['ips']) > 3:
                alert['anomalies'].append(f"new_ip:{details['src_ip']}")
                alert['score'] += 0.2

        # 8. Необычное соотношение успешных/неудачных входов (без изменений)
        total_logins = user['successful_logins'] + user['failed_logins']
        if total_logins > 10:
            fail_rate = user['failed_logins'] / total_logins
            if fail_rate > 0.5:
                alert['anomalies'].append(f"high_fail_rate:{fail_rate:.2f}")
                alert['score'] += 0.25

        alert['score'] = min(1.0, alert['score'])

        # Определение серьёзности
        if alert['score'] > 0.7:
            alert['severity'] = AlertSeverity.CRITICAL.value
        elif alert['score'] > 0.5:
            alert['severity'] = AlertSeverity.HIGH.value
        elif alert['score'] > 0.3:
            alert['severity'] = AlertSeverity.MEDIUM.value

        if alert['anomalies']:
            return alert
        return None

    def _peer_group_loop(self) -> None:
        """Обновление групп похожих пользователей"""
        while self.running:
            time.sleep(3600)  # Каждый час
            self._update_peer_groups()

    def _update_peer_groups(self) -> None:
        """Обновление peer groups на основе поведения"""
        with self._lock:
            # Простая кластеризация на основе активности
            user_activity = {}
            for username, data in self.users.items():
                activity = sum(data['login_times'].values())
                user_activity[username] = activity

            # Группировка по уровню активности
            if user_activity:
                avg_activity = sum(user_activity.values()) / len(user_activity)

                self.user_peer_groups.clear()
                for username, activity in user_activity.items():
                    if activity > avg_activity * 1.5:
                        self.user_peer_groups['high_activity'].append(username)
                    elif activity < avg_activity * 0.5:
                        self.user_peer_groups['low_activity'].append(username)
                    else:
                        self.user_peer_groups['normal_activity'].append(username)

    def _risk_decay_loop(self) -> None:
        """Постепенное снижение риска"""
        while self.running:
            time.sleep(60)  # Каждую минуту
            with self._lock:
                for user in self.users.values():
                    # Снижаем риск на 1% в минуту, если нет новых алертов
                    user['risk_score'] = max(0.0, user['risk_score'] * 0.99)

    def get_user_risk(self, username: str) -> float:
        """Получить текущий риск пользователя"""
        with self._lock:
            return self.users.get(username, {}).get('risk_score', 0.0)

    def get_user_profile(self, username: str) -> Optional[Dict]:
        """Получить профиль пользователя"""
        with self._lock:
            if username in self.users:
                user = self.users[username]
                return {
                    'username': username,
                    'ips': list(user['ips']),
                    'risk_score': user['risk_score'],
                    'total_sessions': user['total_sessions'],
                    'failed_logins': user['failed_logins'],
                    'successful_logins': user['successful_logins'],
                    'geo_locations': list(user['geo_locations']),
                    'devices': list(user['devices']),
                    'first_seen': user['first_seen'],
                    'last_seen': user['last_seen']
                }
        return None


# ============================================================
# 5️⃣ АВТОМАТИЧЕСКИЙ ОТЧЁТ ОБ ИНЦИДЕНТЕ
# ============================================================

from modules.report_generator import IncidentReportGenerator
