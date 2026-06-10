#!/usr/bin/env python3
"""
SHARD Telegram Notifier — мгновенные уведомления об атаках
Поддерживает:
- Алерты в реальном времени (Telegram)
- Команды: /status, /block <IP>, /unblock <IP>, /stats
- Умную группировку (не спамит одинаковыми алертами)
- Разные уровни уведомлений (CRITICAL всегда, HIGH по выбору)

Требования: pip install python-telegram-bot
"""

import os
import sys
import json
import time
import asyncio
import threading
import logging
from pathlib import Path
from typing import Dict, List, Optional, Set
from collections import defaultdict, deque
from datetime import datetime, timedelta
from dataclasses import dataclass, field

logger = logging.getLogger("SHARD-TelegramNotifier")

try:
    from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, Bot
    from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes
    from telegram.constants import ParseMode
    TELEGRAM_AVAILABLE = True
except ImportError:
    TELEGRAM_AVAILABLE = False
    logger.warning("python-telegram-bot не установлен. pip install python-telegram-bot")


@dataclass
class AlertGroup:
    """Группировка алертов для избежания спама"""
    attack_type: str
    src_ip: str
    severity: str
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    count: int = 1
    sent: bool = False


class ShardTelegramNotifier:
    """
    Telegram-бот для SHARD Enterprise SIEM.
    
    Возможности:
    - Мгновенные уведомления об атаках
    - Группировка одинаковых алертов (анти-спам)
    - Интерактивные кнопки: Block IP, Details, False Positive
    - Команды: /status, /block, /unblock, /stats, /help
    - Настраиваемые уровни уведомлений
    """

    def __init__(
        self,
        token: str = None,
        chat_ids: List[str] = None,
        event_bus=None,
        min_severity: str = "HIGH",
        group_window: int = 60  # секунд для группировки
    ):
        """
        Args:
            token: Telegram Bot API token
            chat_ids: Список chat_id для уведомлений
            event_bus: EventBus SHARD для подписки на алерты
            min_severity: Минимальный уровень для уведомлений (LOW/MEDIUM/HIGH/CRITICAL)
            group_window: Окно группировки алертов в секундах
        """
        self.token = token or os.getenv("TELEGRAM_BOT_TOKEN", "")
        self.chat_ids = chat_ids or self._parse_chat_ids()
        self.event_bus = event_bus
        self.min_severity = min_severity
        self.group_window = group_window
        
        # Группировка алертов
        self._alert_groups: Dict[str, AlertGroup] = {}
        self._group_lock = threading.RLock()
        
        # Очередь алертов для отправки
        self._alert_queue: deque = deque(maxlen=500)
        
        # Кэш chat_id (автоматически добавляются при /start)
        self._known_chats: Set[str] = set(self.chat_ids)
        
        # Статистика
        self.stats = {
            'alerts_received': 0,
            'alerts_sent': 0,
            'alerts_grouped': 0,
            'commands_processed': 0,
            'blocks_from_telegram': 0
        }
        
        # Ссылки на модули SHARD
        self.decision_fusion = None
        self.firewall = None
        
        # Приложение Telegram
        self._app: Optional[Application] = None
        self._bot: Optional[Bot] = None
        self._running = False
        self._loop = None
        self._thread = None
        
        # Настройки
        self.settings = {
            'notify_critical': True,
            'notify_high': True,
            'notify_medium': False,
            'notify_low': False,
            'quiet_hours_start': 23,  # 23:00
            'quiet_hours_end': 7,     # 07:00
            'quiet_hours_enabled': False,
            'group_similar': True
        }
        
        # Пути
        self.data_dir = Path('data/telegram')
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Загружаем состояние
        self._load_state()
        
        logger.info(f"Telegram Notifier initialized (token={'***' if self.token else 'MISSING'})")
    
    def _parse_chat_ids(self) -> List[str]:
        """Парсит chat_ids из переменных окружения"""
        ids = os.getenv("TELEGRAM_CHAT_IDS", "")
        if ids:
            return [cid.strip() for cid in ids.split(",") if cid.strip()]
        return []
    
    def setup(self, event_bus=None, decision_fusion=None, firewall=None):
        """Подключение к модулям SHARD"""
        if event_bus:
            self.event_bus = event_bus
            event_bus.subscribe('alert.detected', self.on_alert)
            logger.info("✅ Подписан на alert.detected")
        
        self.decision_fusion = decision_fusion
        self.firewall = firewall
    
    def start(self):
        """Запуск бота"""
        if not TELEGRAM_AVAILABLE:
            logger.error("python-telegram-bot не установлен")
            return False
        
        if not self.token:
            logger.error("TELEGRAM_BOT_TOKEN не задан")
            return False
        
        self._running = True
        
        # Запускаем в отдельном потоке
        self._thread = threading.Thread(
            target=self._run_bot,
            daemon=True,
            name="TelegramBot"
        )
        self._thread.start()
        
        # Запускаем поток группировки алертов
        threading.Thread(
            target=self._grouping_loop,
            daemon=True,
            name="TelegramGrouping"
        ).start()
        
        logger.info("🚀 Telegram бот запущен")
        return True
    
    def stop(self):
        """Остановка бота"""
        self._running = False
        self._save_state()
        
        if self._app:
            try:
                asyncio.run_coroutine_threadsafe(
                    self._app.shutdown(), self._loop
                )
            except Exception:
                pass
        
        logger.info("🛑 Telegram бот остановлен")
    
    def _run_bot(self):
        """Запуск бота в отдельном потоке (синхронный режим)"""
        try:
            # Создаём приложение
            self._app = Application.builder().token(self.token).build()
            
            # Команды
            self._app.add_handler(CommandHandler("start", self._cmd_start))
            self._app.add_handler(CommandHandler("help", self._cmd_help))
            self._app.add_handler(CommandHandler("status", self._cmd_status))
            self._app.add_handler(CommandHandler("stats", self._cmd_stats))
            self._app.add_handler(CommandHandler("block", self._cmd_block))
            self._app.add_handler(CommandHandler("unblock", self._cmd_unblock))
            self._app.add_handler(CommandHandler("watch", self._cmd_watch))
            self._app.add_handler(CommandHandler("unwatch", self._cmd_unwatch))
            self._app.add_handler(CommandHandler("settings", self._cmd_settings))
            
            # Callback кнопок
            self._app.add_handler(CallbackQueryHandler(self._handle_callback))
            
            # Сохраняем loop главного потока
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            
            # Запускаем polling
            self._app.run_polling(allowed_updates=Update.ALL_TYPES, stop_signals=[])
            
        except Exception as e:
            logger.error(f"Ошибка бота: {e}")
    
    # ============================================================
    # Обработчики алертов
    # ============================================================
    
    def on_alert(self, alert: Dict):
        """Получает алерт из EventBus"""
        severity = alert.get('severity', 'MEDIUM')
        
        # Фильтр по severity
        severity_order = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
        min_level = severity_order.get(self.min_severity, 2)
        
        if severity_order.get(severity, 0) < min_level:
            return
        
        # Проверяем настройки
        sev_key = f'notify_{severity.lower()}'
        if not self.settings.get(sev_key, True):
            return
        
        # Quiet hours
        if self._is_quiet_hours():
            return
        
        self.stats['alerts_received'] += 1
        
        # Группировка
        if self.settings['group_similar']:
            group_key = f"{alert.get('attack_type','?')}:{alert.get('src_ip','?')}:{severity}"
            
            with self._group_lock:
                if group_key in self._alert_groups:
                    group = self._alert_groups[group_key]
                    group.last_seen = time.time()
                    group.count += 1
                    self.stats['alerts_grouped'] += 1
                    
                    # Отправляем если группа накопилась или прошло время
                    if group.count >= 10 or (time.time() - group.first_seen > 300):
                        if not group.sent:
                            self._send_grouped_alert(group)
                            group.sent = True
                    return
            
            # Новый алерт
            self._alert_groups[group_key] = AlertGroup(
                attack_type=alert.get('attack_type', 'Unknown'),
                src_ip=alert.get('src_ip', '0.0.0.0'),
                severity=severity
            )
        
        # Отправляем немедленно
        asyncio.run_coroutine_threadsafe(
            self._send_alert(alert),
            self._loop
        ) if self._loop else None
    
    async def _send_alert(self, alert: Dict):
        """Отправляет алерт в Telegram"""
        severity = alert.get('severity', 'MEDIUM')
        emoji_map = {
            'CRITICAL': '🔴', 'HIGH': '🟠',
            'MEDIUM': '🟡', 'LOW': '🔵', 'INFO': '⚪'
        }
        emoji = emoji_map.get(severity, '⚠️')
        
        # Формируем сообщение
        message = (
            f"{emoji} **{severity} ALERT**\n\n"
            f"**Тип атаки:** {alert.get('attack_type', 'Unknown')}\n"
            f"**Источник:** `{alert.get('src_ip', '?')}`\n"
            f"**Цель:** `{alert.get('dst_ip', '?')}:{alert.get('dst_port', '?')}`\n"
            f"**Score:** {alert.get('score', 0):.2f}\n"
            f"**Уверенность:** {alert.get('confidence', 0):.2f}\n"
        )
        
        if alert.get('explanation'):
            explanation = alert['explanation'][:200]
            message += f"\n📝 {explanation}\n"
        
        message += f"\n🕐 {datetime.now().strftime('%H:%M:%S')}"
        
        # Кнопки
        keyboard = [
            [
                InlineKeyboardButton("🛡️ Block IP", callback_data=f"block_{alert.get('src_ip')}"),
                InlineKeyboardButton("📋 Details", callback_data=f"details_{alert.get('id', 0)}")
            ],
            [
                InlineKeyboardButton("❌ False Positive", callback_data=f"fp_{alert.get('src_ip')}"),
                InlineKeyboardButton("📊 Dashboard", url="http://localhost:5001/dashboard.html")
            ]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        # Отправляем всем подписанным чатам
        for chat_id in list(self._known_chats):
            try:
                await self._app.bot.send_message(
                    chat_id=chat_id,
                    text=message,
                    parse_mode=ParseMode.MARKDOWN,
                    reply_markup=reply_markup
                )
            except Exception as e:
                logger.debug(f"Send error to {chat_id}: {e}")
        
        self.stats['alerts_sent'] += 1
    
    def _send_grouped_alert(self, group: AlertGroup):
        """Отправляет сгруппированный алерт"""
        message = (
            f"📊 **Grouped Alert**\n\n"
            f"**Тип:** {group.attack_type}\n"
            f"**Источник:** `{group.src_ip}`\n"
            f"**Количество:** {group.count} за "
            f"{int(time.time() - group.first_seen)} сек\n"
            f"**Severity:** {group.severity}\n"
        )
        
        keyboard = [[
            InlineKeyboardButton("🛡️ Block IP", callback_data=f"block_{group.src_ip}"),
            InlineKeyboardButton("❌ Dismiss", callback_data="dismiss")
        ]]
        
        for chat_id in list(self._known_chats):
            try:
                asyncio.run_coroutine_threadsafe(
                    self._app.bot.send_message(
                        chat_id=chat_id,
                        text=message,
                        parse_mode=ParseMode.MARKDOWN,
                        reply_markup=InlineKeyboardMarkup(keyboard)
                    ),
                    self._loop
                )
            except Exception:
                pass
    
    def _grouping_loop(self):
        """Периодическая отправка сгруппированных алертов"""
        while self._running:
            time.sleep(30)
            
            with self._group_lock:
                now = time.time()
                to_remove = []
                
                for key, group in self._alert_groups.items():
                    # Отправляем если прошло окно или накопилось много
                    if not group.sent and (
                        group.count >= 5 or
                        (now - group.first_seen) >= self.group_window
                    ):
                        self._send_grouped_alert(group)
                        group.sent = True
                    
                    # Удаляем старые (старше 10 минут)
                    if now - group.last_seen > 600:
                        to_remove.append(key)
                
                for key in to_remove:
                    del self._alert_groups[key]
    
    # ============================================================
    # Команды бота
    # ============================================================
    
    async def _cmd_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Команда /start"""
        chat_id = str(update.effective_chat.id)
        self._known_chats.add(chat_id)
        self._save_state()
        
        await update.message.reply_text(
            "🛡️ **SHARD Enterprise Security Bot**\n\n"
            "Я буду уведомлять вас о кибератаках в реальном времени.\n\n"
            "**Доступные команды:**\n"
            "/status — Текущий статус защиты\n"
            "/stats — Статистика атак\n"
            "/block <IP> — Заблокировать IP\n"
            "/unblock <IP> — Разблокировать IP\n"
            "/watch — Подписаться на алерты\n"
            "/unwatch — Отписаться\n"
            "/settings — Настройки уведомлений\n"
            "/help — Справка",
            parse_mode=ParseMode.MARKDOWN
        )
        self.stats['commands_processed'] += 1
    
    async def _cmd_help(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Команда /help"""
        await update.message.reply_text(
            "🛡️ **SHARD Security Bot — Справка**\n\n"
            "**Блокировка:**\n"
            "`/block 192.168.1.100` — заблокировать IP\n"
            "`/unblock 192.168.1.100` — разблокировать\n\n"
            "**Мониторинг:**\n"
            "`/status` — текущие блокировки и угрозы\n"
            "`/stats` — статистика за 24 часа\n\n"
            "**Уведомления:**\n"
            "`/watch` — подписаться на алерты\n"
            "`/unwatch` — отписаться\n"
            "`/settings` — настроить уровень уведомлений",
            parse_mode=ParseMode.MARKDOWN
        )
        self.stats['commands_processed'] += 1
    
    async def _cmd_status(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Команда /status — текущий статус"""
        # Получаем данные из DecisionFusion
        active_defenses = []
        if self.decision_fusion:
            active_defenses = self.decision_fusion.get_active_defenses()
        
        # Получаем статистику файрвола
        fw_stats = {}
        if self.firewall:
            try:
                fw_stats = self.firewall.get_stats()
            except Exception:
                pass
        
        message = "🛡️ **SHARD Status**\n\n"
        message += f"🔒 Активных блокировок: **{len(active_defenses)}**\n"
        message += f"📊 Алертов получено: **{self.stats['alerts_received']}**\n"
        message += f"📤 Отправлено в Telegram: **{self.stats['alerts_sent']}**\n"
        message += f"📦 Сгруппировано: **{self.stats['alerts_grouped']}**\n\n"
        
        if active_defenses:
            message += "**Топ-5 заблокированных IP:**\n"
            for d in active_defenses[:5]:
                remaining = int(d.get('remaining', 0))
                message += f"• `{d['ip']}` — {d['action_name']} ({remaining}с)\n"
        
        await update.message.reply_text(message, parse_mode=ParseMode.MARKDOWN)
        self.stats['commands_processed'] += 1
    
    async def _cmd_stats(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Команда /stats — статистика"""
        from collections import Counter
        
        # Собираем статистику из БД
        try:
            import sqlite3
            conn = sqlite3.connect('shard_siem.db')
            
            # За 24 часа
            since = time.time() - 86400
            total = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE timestamp > ?", (since,)
            ).fetchone()[0]
            
            # По severity
            sev = conn.execute(
                "SELECT severity, COUNT(*) FROM alerts WHERE timestamp > ? GROUP BY severity", (since,)
            ).fetchall()
            
            # Топ-5 атакующих
            top = conn.execute(
                "SELECT src_ip, COUNT(*) as c FROM alerts WHERE timestamp > ? GROUP BY src_ip ORDER BY c DESC LIMIT 5", (since,)
            ).fetchall()
            
            conn.close()
        except Exception:
            total = 0
            sev = []
            top = []
        
        message = "📊 **Статистика за 24 часа**\n\n"
        message += f"Всего атак: **{total}**\n\n"
        
        if sev:
            message += "**По severity:**\n"
            for s, c in sev:
                emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}.get(s, '⚪')
                message += f"{emoji} {s}: {c}\n"
        
        if top:
            message += "\n**Топ атакующих:**\n"
            for ip, c in top:
                message += f"• `{ip}`: {c} атак\n"
        
        await update.message.reply_text(message, parse_mode=ParseMode.MARKDOWN)
        self.stats['commands_processed'] += 1
    
    async def _cmd_block(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Команда /block <IP>"""
        if not context.args:
            await update.message.reply_text("❌ Укажите IP: `/block 192.168.1.100`")
            return
        
        ip = context.args[0]
        
        # Блокируем через DecisionFusion
        if self.decision_fusion:
            alert = {
                'src_ip': ip,
                'dst_port': 0,
                'attack_type': 'Manual (Telegram)',
                'severity': 'HIGH',
                'score': 1.0,
                'confidence': 1.0
            }
            action = self.decision_fusion.manual_action(alert, 3)  # block_temp
            self.stats['blocks_from_telegram'] += 1
            await update.message.reply_text(
                f"✅ IP `{ip}` заблокирован!\n"
                f"Действие: {action.description}\n"
                f"Длительность: {action.block_duration} сек",
                parse_mode=ParseMode.MARKDOWN
            )
        else:
            await update.message.reply_text("⚠️ Система защиты недоступна")
    
    async def _cmd_unblock(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Команда /unblock <IP>"""
        if not context.args:
            await update.message.reply_text("❌ Укажите IP: `/unblock 192.168.1.100`")
            return
        
        ip = context.args[0]
        
        if self.firewall:
            success = self.firewall.unblock_ip(ip)
            if success:
                await update.message.reply_text(f"🔓 IP `{ip}` разблокирован!")
            else:
                await update.message.reply_text(f"⚠️ IP `{ip}` не был заблокирован")
        else:
            await update.message.reply_text("⚠️ Файрвол недоступен")
    
    async def _cmd_watch(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Подписаться на алерты"""
        chat_id = str(update.effective_chat.id)
        self._known_chats.add(chat_id)
        self._save_state()
        await update.message.reply_text("✅ Вы подписаны на алерты SHARD!")
    
    async def _cmd_unwatch(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Отписаться"""
        chat_id = str(update.effective_chat.id)
        self._known_chats.discard(chat_id)
        self._save_state()
        await update.message.reply_text("🔕 Вы отписаны от алертов")
    
    async def _cmd_settings(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Настройки уведомлений"""
        keyboard = [
            [
                InlineKeyboardButton(
                    f"🔴 CRITICAL: {'✅' if self.settings['notify_critical'] else '❌'}",
                    callback_data="toggle_critical"
                )
            ],
            [
                InlineKeyboardButton(
                    f"🟠 HIGH: {'✅' if self.settings['notify_high'] else '❌'}",
                    callback_data="toggle_high"
                )
            ],
            [
                InlineKeyboardButton(
                    f"🟡 MEDIUM: {'✅' if self.settings['notify_medium'] else '❌'}",
                    callback_data="toggle_medium"
                )
            ],
            [
                InlineKeyboardButton(
                    f"📦 Grouping: {'✅' if self.settings['group_similar'] else '❌'}",
                    callback_data="toggle_grouping"
                )
            ],
        ]
        
        await update.message.reply_text(
            "⚙️ **Настройки уведомлений**\n"
            "Выберите какие алерты получать:",
            reply_markup=InlineKeyboardMarkup(keyboard),
            parse_mode=ParseMode.MARKDOWN
        )
    
    async def _handle_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Обработка кнопок"""
        query = update.callback_query
        await query.answer()
        data = query.data
        
        if data.startswith("block_"):
            ip = data.replace("block_", "")
            if self.decision_fusion:
                self.decision_fusion.manual_action(
                    {'src_ip': ip, 'severity': 'HIGH', 'score': 1.0}, 3
                )
                await query.edit_message_text(
                    f"🛡️ IP `{ip}` заблокирован!",
                    parse_mode=ParseMode.MARKDOWN
                )
                self.stats['blocks_from_telegram'] += 1
        
        elif data.startswith("fp_"):
            ip = data.replace("fp_", "")
            await query.edit_message_text(f"✅ False Positive для `{ip}` зафиксирован. Спасибо!")
        
        elif data == "dismiss":
            await query.edit_message_text("✅ Алерт dismissed")
        
        elif data.startswith("toggle_"):
            setting = data.replace("toggle_", "")
            key_map = {
                'critical': 'notify_critical',
                'high': 'notify_high',
                'medium': 'notify_medium',
                'grouping': 'group_similar'
            }
            if setting in key_map:
                key = key_map[setting]
                self.settings[key] = not self.settings[key]
                await self._cmd_settings(update, context)
    
    # ============================================================
    # Утилиты
    # ============================================================
    
    def _is_quiet_hours(self) -> bool:
        """Проверяет, активны ли тихие часы"""
        if not self.settings.get('quiet_hours_enabled'):
            return False
        
        hour = datetime.now().hour
        start = self.settings.get('quiet_hours_start', 23)
        end = self.settings.get('quiet_hours_end', 7)
        
        if start > end:
            return hour >= start or hour < end
        return hour >= start and hour < end
    
    def _save_state(self):
        """Сохраняет состояние в файл"""
        try:
            state = {
                'known_chats': list(self._known_chats),
                'settings': self.settings,
                'stats': self.stats
            }
            with open(self.data_dir / 'state.json', 'w') as f:
                json.dump(state, f, indent=2)
        except Exception:
            pass
    
    def _load_state(self):
        """Загружает состояние из файла"""
        try:
            path = self.data_dir / 'state.json'
            if path.exists():
                with open(path) as f:
                    state = json.load(f)
                    self._known_chats.update(state.get('known_chats', []))
                    self.settings.update(state.get('settings', {}))
        except Exception:
            pass
    
    def get_stats(self) -> Dict:
        """Возвращает статистику бота"""
        return {
            **self.stats,
            'known_chats': len(self._known_chats),
            'settings': self.settings
        }


# Глобальный экземпляр
telegram_notifier = ShardTelegramNotifier()
