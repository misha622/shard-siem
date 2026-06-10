#!/usr/bin/env python3
"""
SHARD Telegram Bot v2.0 — Полная версия
- Инлайн-кнопки (Block IP, Details, False Positive, Dashboard)
- Live-алерты от SHARD Engine
- /mute, /unmute, /top5
- Ежедневный отчёт в 9:00
"""

import os, json, time, threading, logging, urllib.request, urllib.parse, urllib.error
from pathlib import Path
from typing import Dict, List, Optional, Set
from collections import deque, defaultdict
from datetime import datetime

logger = logging.getLogger("SHARD-Telegram")

class TelegramBot:
    """Полнофункциональный Telegram-бот для SHARD SIEM"""
    
    def __init__(self, token: str = None):
        self.token = token or os.getenv("TELEGRAM_BOT_TOKEN", "")
        self.base_url = f"https://api.telegram.org/bot{self.token}"
        
        # Chat IDs
        self.chat_ids: Set[str] = set()
        self._load_chat_ids()
        
        # Состояние
        self._running = False
        self._last_update_id = 0
        self._muted_until = 0
        
        # Очередь алертов (анти-спам)
        self._alert_cooldown: Dict[str, float] = {}
        self._alert_counts: Dict[str, int] = defaultdict(int)
        self._alert_lock = threading.Lock()
        
        # Статистика
        self.stats = {'sent': 0, 'errors': 0, 'commands': 0, 'blocks': 0}
        
        # SHARD модули
        self.event_bus = None
        self.decision_fusion = None
        self.firewall = None
        
        # Пути
        self.data_dir = Path('data/telegram')
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Telegram Bot v2.0 ready (token={'***' if self.token else 'MISSING'})")
    
    # ============================================================
    # API вызовы
    # ============================================================
    
    def _api_call(self, method: str, data: dict = None) -> Optional[dict]:
        """Вызов Telegram API"""
        import urllib.request, urllib.parse, urllib.error
        
        url = f"{self.base_url}/{method}"
        try:
            if data:
                params = urllib.parse.urlencode(data).encode('utf-8')
                req = urllib.request.Request(url, data=params)
            else:
                req = urllib.request.Request(url)
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
            
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read().decode())
                if result.get('ok'):
                    return result.get('result')
                else:
                    logger.error(f"API error: {result.get('description')}")
                    self.stats['errors'] += 1
        except Exception as e:
            logger.debug(f"API error: {e}")
            self.stats['errors'] += 1
        return None
    
    def send_message(self, text: str, chat_id: str = None, buttons: list = None, parse_mode: str = 'HTML') -> bool:
        """Отправить сообщение с кнопками"""
        targets = [chat_id] if chat_id else list(self.chat_ids)
        if not targets or not self.token:
            return False
        
        for cid in targets:
            data = {'chat_id': cid, 'text': text, 'parse_mode': parse_mode}
            if buttons:
                data['reply_markup'] = json.dumps({'inline_keyboard': buttons})
            self._api_call('sendMessage', data)
            self.stats['sent'] += 1
        return True
    
    def edit_message(self, text: str, chat_id: str, message_id: int, buttons: list = None):
        """Редактировать сообщение (для callback)"""
        data = {'chat_id': chat_id, 'message_id': message_id, 'text': text, 'parse_mode': 'HTML'}
        if buttons:
            data['reply_markup'] = json.dumps({'inline_keyboard': buttons})
        self._api_call('editMessageText', data)
    
    def answer_callback(self, callback_id: str, text: str = ""):
        """Ответ на нажатие кнопки"""
        self._api_call('answerCallbackQuery', {'callback_query_id': callback_id, 'text': text})
    
    # ============================================================
    # Команды
    # ============================================================
    
    def _handle_command(self, text: str, chat_id: str, msg_id: int = None):
        """Обработка команд"""
        self.stats['commands'] += 1
        parts = text.split()
        cmd = parts[0].lower().split('@')[0]  # убираем @botname
        
        if cmd == '/start':
            self._cmd_start(chat_id)
        elif cmd == '/help':
            self._cmd_help(chat_id)
        elif cmd == '/status':
            self._cmd_status(chat_id)
        elif cmd == '/stats':
            self._cmd_stats(chat_id)
        elif cmd == '/top5':
            self._cmd_top5(chat_id)
        elif cmd == '/block' and len(parts) > 1:
            self._cmd_block(chat_id, parts[1])
        elif cmd == '/unblock' and len(parts) > 1:
            self._cmd_unblock(chat_id, parts[1])
        elif cmd == '/mute':
            self._cmd_mute(chat_id, parts[1] if len(parts) > 1 else '30m')
        elif cmd == '/unmute':
            self._cmd_unmute(chat_id)
        elif cmd == '/report':
            self._send_daily_report(chat_id)
    
    def _cmd_start(self, chat_id):
        self.send_message(
            "🛡️ <b>SHARD Enterprise Security Bot v2.0</b>\n\n"
            "Я уведомляю о кибератаках в реальном времени.\n\n"
            "<b>📋 Команды:</b>\n"
            "/status — Текущий статус защиты\n"
            "/stats — Статистика за 24 часа\n"
            "/top5 — Топ-5 атакующих\n"
            "/block IP — Заблокировать IP\n"
            "/unblock IP — Разблокировать\n"
            "/mute 30m — Отключить алерты\n"
            "/unmute — Включить алерты\n"
            "/report — Отчёт за сегодня\n"
            "/help — Эта справка",
            chat_id
        )
    
    def _cmd_help(self, chat_id):
        self.send_message(
            "🛡️ <b>SHARD Bot — Справка</b>\n\n"
            "<b>Мониторинг:</b>\n"
            "/status — Блокировки и угрозы\n"
            "/stats — Статистика за 24ч\n"
            "/top5 — Топ атакующих\n\n"
            "<b>Защита:</b>\n"
            "/block 192.168.1.1 — Заблокировать\n"
            "/unblock 192.168.1.1 — Разблокировать\n\n"
            "<b>Уведомления:</b>\n"
            "/mute 30m — Тишина на 30 мин\n"
            "/mute 2h — На 2 часа\n"
            "/unmute — Включить\n\n"
            "<b>Отчёты:</b>\n"
            "/report — Сводка за сегодня",
            chat_id
        )
    
    def _cmd_status(self, chat_id):
        try:
            import sqlite3
            conn = sqlite3.connect('shard_siem.db')
            total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            recent = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE timestamp > ?", (time.time() - 3600,)
            ).fetchone()[0]
            critical = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL' AND timestamp > ?", (time.time() - 86400,)
            ).fetchone()[0]
            conn.close()
            
            muted = "🔕 Да" if time.time() < self._muted_until else "🔔 Нет"
            
            self.send_message(
                f"🛡️ <b>SHARD Status</b>\n\n"
                f"Всего алертов: <b>{total}</b>\n"
                f"За последний час: <b>{recent}</b>\n"
                f"CRITICAL за 24ч: <b>{critical}</b>\n"
                f"Отправлено в TG: <b>{self.stats['sent']}</b>\n"
                f"Заблокировано из TG: <b>{self.stats['blocks']}</b>\n"
                f"Режим тишины: {muted}",
                chat_id
            )
        except Exception as e:
            self.send_message(f"❌ Ошибка: {e}", chat_id)
    
    def _cmd_stats(self, chat_id):
        try:
            import sqlite3
            conn = sqlite3.connect('shard_siem.db')
            since = time.time() - 86400
            
            total = conn.execute("SELECT COUNT(*) FROM alerts WHERE timestamp > ?", (since,)).fetchone()[0]
            sev = conn.execute(
                "SELECT severity, COUNT(*) FROM alerts WHERE timestamp > ? GROUP BY severity", (since,)
            ).fetchall()
            top = conn.execute(
                "SELECT attack_type, COUNT(*) as c FROM alerts WHERE timestamp > ? GROUP BY attack_type ORDER BY c DESC LIMIT 5", (since,)
            ).fetchall()
            blocked = conn.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0]
            conn.close()
            
            msg = f"📊 <b>Статистика за 24 часа</b>\n\nВсего атак: <b>{total}</b>\nЗаблокировано IP: <b>{blocked}</b>\n\n"
            
            if sev:
                emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}
                msg += "<b>По severity:</b>\n"
                for s, c in sev:
                    msg += f"{emoji.get(s,'⚪')} {s}: {c}\n"
            
            if top:
                msg += "\n<b>Типы атак:</b>\n"
                for t, c in top:
                    msg += f"• {t}: {c}\n"
            
            self.send_message(msg, chat_id)
        except Exception as e:
            self.send_message(f"❌ Ошибка: {e}", chat_id)
    
    def _cmd_top5(self, chat_id):
        try:
            import sqlite3
            conn = sqlite3.connect('shard_siem.db')
            since = time.time() - 86400
            top = conn.execute(
                "SELECT src_ip, COUNT(*) as c, MAX(attack_type) FROM alerts WHERE timestamp > ? GROUP BY src_ip ORDER BY c DESC LIMIT 5", (since,)
            ).fetchall()
            conn.close()
            
            if top:
                msg = "🏆 <b>Топ-5 атакующих за 24 часа</b>\n\n"
                medals = ['🥇', '🥈', '🥉', '4️⃣', '5️⃣']
                for i, (ip, count, atype) in enumerate(top):
                    msg += f"{medals[i]} <code>{ip}</code> — {count} атак ({atype})\n"
                
                keyboard = [[{'text': f'🛡️ Block {top[0][0]}', 'callback_data': f'block_{top[0][0]}'}]]
                self.send_message(msg, chat_id, keyboard)
            else:
                self.send_message("📭 Нет атак за последние 24 часа", chat_id)
        except Exception as e:
            self.send_message(f"❌ Ошибка: {e}", chat_id)
    
    def _cmd_block(self, chat_id, ip):
        try:
            from modules.app_firewall import app_firewall
            result = app_firewall.block_ip(ip, duration=3600, reason=f"Telegram/{chat_id}")
            
            if result['success']:
                self.stats['blocks'] += 1
                methods = ', '.join(result['methods'])
                self.send_message(
                    f"🛡️ <b>IP заблокирован!</b>\n\n"
                    f"<code>{ip}</code>\n"
                    f"Длительность: 1 час\n"
                    f"Методы: {methods}",
                    chat_id,
                    [[{'text': '🔓 Разблокировать', 'callback_data': f'unblock_{ip}'}]]
                )
            else:
                self.send_message(f"❌ Не удалось заблокировать: {result.get('error')}", chat_id)
        except Exception as e:
            self.send_message(f"❌ Ошибка: {e}", chat_id)
    
    def _cmd_unblock(self, chat_id, ip):
        try:
            from modules.app_firewall import app_firewall
            result = app_firewall.unblock_ip(ip)
            if result['success']:
                self.send_message(f"🔓 <code>{ip}</code> разблокирован", chat_id)
            else:
                self.send_message(f"⚠️ <code>{ip}</code> не был заблокирован", chat_id)
        except Exception as e:
            self.send_message(f"❌ Ошибка: {e}", chat_id)
    
    def _cmd_mute(self, chat_id, duration_str: str):
        """Отключить уведомления на время"""
        multiplier = 1
        if duration_str.endswith('h'):
            multiplier = 3600
            duration_str = duration_str[:-1]
        elif duration_str.endswith('m'):
            multiplier = 60
            duration_str = duration_str[:-1]
        
        try:
            minutes = int(duration_str) * multiplier
        except ValueError:
            minutes = 1800  # default 30 min
        
        self._muted_until = time.time() + minutes
        until = datetime.fromtimestamp(self._muted_until).strftime('%H:%M')
        self.send_message(f"🔕 Алерты отключены до <b>{until}</b>", chat_id)
    
    def _cmd_unmute(self, chat_id):
        self._muted_until = 0
        self.send_message("🔔 Алерты включены!", chat_id)
    
    # ============================================================
    # Алерты
    # ============================================================
    
    def on_alert(self, alert: dict):
        """Получает алерт от SHARD Engine"""
        if time.time() < self._muted_until:
            return
        
        severity = alert.get('severity', 'MEDIUM')
        if severity not in ('HIGH', 'CRITICAL'):
            return
        
        src_ip = alert.get('src_ip', '?')
        attack_type = alert.get('attack_type', 'Unknown')
        
        # Анти-спам: группируем одинаковые алерты
        with self._alert_lock:
            key = f"{src_ip}:{attack_type}"
            now = time.time()
            
            if key in self._alert_cooldown and now - self._alert_cooldown[key] < 30:
                self._alert_counts[key] += 1
                if self._alert_counts[key] in [5, 10, 25, 50, 100]:
                    self._send_grouped_alert(key, src_ip, attack_type, severity)
                return
            
            self._alert_cooldown[key] = now
            self._alert_counts[key] = 1
        
        # Отправляем алерт
        self._send_single_alert(alert)
    
    def _send_single_alert(self, alert: dict):
        """Отправляет одиночный алерт с кнопками"""
        severity = alert.get('severity', 'MEDIUM')
        emoji = '🔴' if severity == 'CRITICAL' else '🟠'
        src_ip = alert.get('src_ip', '?')
        
        msg = (
            f"{emoji} <b>{severity} ALERT</b>\n\n"
            f"<b>Атака:</b> {alert.get('attack_type', 'Unknown')}\n"
            f"<b>Источник:</b> <code>{src_ip}</code>\n"
            f"<b>Цель:</b> {alert.get('dst_ip', '?')}:{alert.get('dst_port', '?')}\n"
            f"<b>Score:</b> {alert.get('score', 0):.2f}\n"
            f"<b>Confidence:</b> {alert.get('confidence', 0):.2f}\n"
        )
        if alert.get('explanation'):
            msg += f"\n📝 {alert['explanation'][:200]}\n"
        msg += f"\n🕐 {datetime.now().strftime('%H:%M:%S')}"
        
        # Инлайн-кнопки
        keyboard = [
            [
                {'text': '🛡️ Block IP', 'callback_data': f'block_{src_ip}'},
                {'text': '📋 Details', 'callback_data': f'details_{src_ip}'}
            ],
            [
                {'text': '❌ False Positive', 'callback_data': f'fp_{src_ip}'},
                {'text': '📊 Dashboard', 'url': 'http://localhost:5001/dashboard.html'}
            ]
        ]
        
        self.send_message(msg, buttons=keyboard)
    
    def _send_grouped_alert(self, key, src_ip, attack_type, severity):
        """Отправляет сгруппированный алерт"""
        count = self._alert_counts[key]
        emoji = '🔴' if severity == 'CRITICAL' else '🟠'
        
        msg = (
            f"{emoji} <b>Grouped Alert</b>\n\n"
            f"<b>Атака:</b> {attack_type}\n"
            f"<b>Источник:</b> <code>{src_ip}</code>\n"
            f"<b>Количество:</b> {count} за последние 30 сек\n"
        )
        
        keyboard = [[
            {'text': '🛡️ Block IP', 'callback_data': f'block_{src_ip}'},
            {'text': '❌ Dismiss', 'callback_data': 'dismiss'}
        ]]
        
        self.send_message(msg, buttons=keyboard)
    
    # ============================================================
    # Callback обработка (кнопки)
    # ============================================================
    
    def _handle_callback(self, callback: dict):
        """Обработка нажатий на инлайн-кнопки"""
        cid = callback.get('id', '')
        data = callback.get('data', '')
        msg = callback.get('message', {})
        chat_id = str(msg.get('chat', {}).get('id', ''))
        msg_id = msg.get('message_id', 0)
        
        if not data or not chat_id:
            return
        
        if data.startswith('block_'):
            ip = data.replace('block_', '')
            self._cmd_block(chat_id, ip)
            self.answer_callback(cid, f"IP {ip} заблокирован")
        
        elif data.startswith('unblock_'):
            ip = data.replace('unblock_', '')
            self._cmd_unblock(chat_id, ip)
            self.answer_callback(cid, f"IP {ip} разблокирован")
        
        elif data.startswith('details_'):
            ip = data.replace('details_', '')
            self._show_details(chat_id, ip)
            self.answer_callback(cid, "Загружаем детали...")
        
        elif data.startswith('fp_'):
            ip = data.replace('fp_', '')
            self.edit_message(
                f"✅ False Positive зафиксирован для <code>{ip}</code>\nСпасибо за обратную связь!",
                chat_id, msg_id
            )
            self.answer_callback(cid, "Спасибо!")
        
        elif data == 'dismiss':
            self.edit_message("✅ Алерты dismissed", chat_id, msg_id)
            self.answer_callback(cid, "OK")
    
    def _show_details(self, chat_id, ip):
        """Показать детальную информацию об IP"""
        try:
            import sqlite3
            conn = sqlite3.connect('shard_siem.db')
            alerts = conn.execute(
                "SELECT attack_type, severity, COUNT(*) FROM alerts WHERE src_ip=? GROUP BY attack_type, severity",
                (ip,)
            ).fetchall()
            total = conn.execute("SELECT COUNT(*) FROM alerts WHERE src_ip=?", (ip,)).fetchone()[0]
            last = conn.execute(
                "SELECT attack_type, severity, timestamp FROM alerts WHERE src_ip=? ORDER BY timestamp DESC LIMIT 3",
                (ip,)
            ).fetchall()
            conn.close()
            
            msg = f"📋 <b>Информация об IP:</b> <code>{ip}</code>\n\n"
            msg += f"Всего атак: <b>{total}</b>\n\n"
            
            if alerts:
                msg += "<b>По типам:</b>\n"
                for atype, sev, count in alerts:
                    emoji = '🔴' if sev == 'CRITICAL' else '🟠' if sev == 'HIGH' else '🟡'
                    msg += f"{emoji} {atype}: {count}\n"
            
            if last:
                msg += "\n<b>Последние алерты:</b>\n"
                for atype, sev, ts in last:
                    t = datetime.fromtimestamp(ts).strftime('%H:%M:%S')
                    msg += f"• {t} — {atype} ({sev})\n"
            
            keyboard = [[{'text': '🛡️ Block IP', 'callback_data': f'block_{ip}'}]]
            self.send_message(msg, chat_id, keyboard)
        except Exception as e:
            self.send_message(f"❌ Ошибка: {e}", chat_id)
    
    # ============================================================
    # Ежедневный отчёт
    # ============================================================
    
    def _send_daily_report(self, chat_id=None):
        """Отправляет ежедневный отчёт"""
        try:
            import sqlite3
            conn = sqlite3.connect('shard_siem.db')
            since = time.time() - 86400
            
            total = conn.execute("SELECT COUNT(*) FROM alerts WHERE timestamp > ?", (since,)).fetchone()[0]
            blocked = conn.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0]
            
            sev = conn.execute(
                "SELECT severity, COUNT(*) FROM alerts WHERE timestamp > ? GROUP BY severity", (since,)
            ).fetchall()
            
            top_type = conn.execute(
                "SELECT attack_type, COUNT(*) as c FROM alerts WHERE timestamp > ? GROUP BY attack_type ORDER BY c DESC LIMIT 3", (since,)
            ).fetchall()
            
            top_ip = conn.execute(
                "SELECT src_ip, COUNT(*) as c FROM alerts WHERE timestamp > ? GROUP BY src_ip ORDER BY c DESC LIMIT 3", (since,)
            ).fetchall()
            
            conn.close()
            
            msg = (
                f"📊 <b>Ежедневный отчёт SHARD</b>\n"
                f"📅 {datetime.now().strftime('%d.%m.%Y')}\n\n"
                f"━━━━━━━━━━━━━━━━━━\n\n"
                f"🚨 Всего атак: <b>{total}</b>\n"
                f"🛡️ Заблокировано IP: <b>{blocked}</b>\n\n"
            )
            
            if sev:
                msg += "<b>По severity:</b>\n"
                emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}
                for s, c in sev:
                    msg += f"{emoji.get(s,'⚪')} {s}: {c}\n"
            
            if top_type:
                msg += "\n<b>Топ-3 типа атак:</b>\n"
                for i, (t, c) in enumerate(top_type, 1):
                    msg += f"{i}. {t}: {c}\n"
            
            if top_ip:
                msg += "\n<b>Топ-3 атакующих:</b>\n"
                for i, (ip, c) in enumerate(top_ip, 1):
                    msg += f"{i}. <code>{ip}</code>: {c}\n"
            
            msg += f"\n━━━━━━━━━━━━━━━━━━\n🛡️ SHARD Enterprise SIEM"
            
            keyboard = [[{'text': '📊 Открыть дашборд', 'url': 'http://localhost:5001/dashboard.html'}]]
            self.send_message(msg, chat_id, keyboard)
            
        except Exception as e:
            self.send_message(f"❌ Ошибка отчёта: {e}", chat_id)
    
    # ============================================================
    # Polling
    # ============================================================
    
    def get_updates(self):
        """Получает новые сообщения"""
        data = {'offset': self._last_update_id + 1, 'timeout': 5, 'allowed_updates': ['message', 'callback_query']}
        updates = self._api_call('getUpdates', data)
        
        if updates:
            for update in updates:
                self._last_update_id = max(self._last_update_id, update['update_id'])
                
                # Сообщение
                if 'message' in update:
                    msg = update['message']
                    text = msg.get('text', '')
                    chat_id = str(msg.get('chat', {}).get('id', ''))
                    msg_id = msg.get('message_id')
                    
                    if chat_id:
                        self.chat_ids.add(chat_id)
                    
                    if text.startswith('/'):
                        self._handle_command(text, chat_id, msg_id)
                
                # Callback (кнопка)
                if 'callback_query' in update:
                    self._handle_callback(update['callback_query'])
    
    # ============================================================
    # Жизненный цикл
    # ============================================================
    
    def setup(self, event_bus=None, decision_fusion=None, firewall=None):
        if event_bus:
            self.event_bus = event_bus
            event_bus.subscribe('alert.detected', self.on_alert)
            logger.info("✅ Подписан на alert.detected")
        self.decision_fusion = decision_fusion
        self.firewall = firewall
    
    def start(self):
        self._running = True
        
        threading.Thread(target=self._polling_loop, daemon=True, name="TG-Poll").start()
        threading.Thread(target=self._daily_report_loop, daemon=True, name="TG-Report").start()
        
        self.send_message("🟢 <b>SHARD Bot v2.0 запущен!</b>\n\nДоступны команды: /start /help /status /stats /top5 /report")
        logger.info("🚀 Telegram Bot v2.0 started")
    
    def stop(self):
        self._running = False
        self._save_chat_ids()
    
    def _polling_loop(self):
        while self._running:
            try:
                self.get_updates()
            except Exception as e:
                logger.debug(f"Poll: {e}")
            time.sleep(1)
    
    def _daily_report_loop(self):
        """Отправляет отчёт каждый день в 9:00"""
        while self._running:
            now = datetime.now()
            # Вычисляем секунды до 9:00
            target = now.replace(hour=9, minute=0, second=0, microsecond=0)
            if now > target:
                target = target.replace(day=now.day + 1)
            
            wait = (target - now).total_seconds()
            time.sleep(min(wait, 3600))  # Проверяем каждый час
            
            if abs(wait) < 60:  # В течение минуты от 9:00
                self._send_daily_report()
    
    def _save_chat_ids(self):
        try:
            with open(self.data_dir / 'chats.json', 'w') as f:
                json.dump(list(self.chat_ids), f)
        except:
            pass
    
    def _load_chat_ids(self):
        try:
            path = self.data_dir / 'chats.json'
            if path.exists():
                with open(path) as f:
                    self.chat_ids.update(json.load(f))
        except:
            pass


telegram_bot = TelegramBot()
