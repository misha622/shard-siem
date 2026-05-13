#!/usr/bin/env python3
"""
SHARD Notifier — Telegram/Slack/Discord уведомления
Критические алерты, RL действия, статистика — прямо в мессенджер
"""

import requests
import json
import logging
import threading
from datetime import datetime
from typing import Dict, Optional

logger = logging.getLogger("SHARD-Notifier")

class ShardNotifier:
    """Мульти-канальный уведомитель"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self._load_config()
    
    def _load_config(self):
        """Загрузка токенов из переменных окружения или конфига"""
        import os
        self.telegram_token = os.environ.get('SHARD_TELEGRAM_TOKEN', '')
        self.telegram_chat_id = os.environ.get('SHARD_TELEGRAM_CHAT', '')
        self.slack_webhook = os.environ.get('SHARD_SLACK_WEBHOOK', '')
        self.discord_webhook = os.environ.get('SHARD_DISCORD_WEBHOOK', '')
        
        self.enabled = bool(self.telegram_token or self.slack_webhook or self.discord_webhook)
        
        if self.telegram_token:
            logger.info(f"📱 Telegram notifications enabled")
        if self.slack_webhook:
            logger.info(f"💼 Slack notifications enabled")
        if self.discord_webhook:
            logger.info(f"🎮 Discord notifications enabled")
    
    def _format_alert(self, alert: Dict) -> str:
        """Форматирование алерта в читаемый вид"""
        severity = alert.get('severity', 'LOW')
        attack_type = alert.get('attack_type', 'Unknown')
        src_ip = alert.get('src_ip', '?')
        dst_port = alert.get('dst_port', '?')
        confidence = alert.get('confidence', 0)
        timestamp = alert.get('timestamp', 0)
        
        emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(severity, '⚪')
        
        time_str = datetime.fromtimestamp(timestamp).strftime('%H:%M:%S') if timestamp else 'now'
        
        msg = f"{emoji} *{attack_type}* ({severity})\n"
        msg += f"📍 {src_ip}:{dst_port}\n"
        msg += f"🎯 Confidence: {confidence:.0%}\n"
        msg += f"🕐 {time_str}"
        
        rl = alert.get('rl_action')
        if rl:
            msg += f"\n🤖 RL: *{rl.get('action_name', '?')}*"
        
        code = alert.get('code', '')
        if code:
            first_line = code.split('\n')[0] if '\n' in code else code[:80]
            msg += f"\n🛡️ `{first_line[:60]}`"
        
        return msg
    
    def _format_defense(self, result: Dict) -> str:
        """Форматирование защитного действия"""
        atype = result.get('attack_type', '?')
        conf = result.get('confidence', 0)
        rl = result.get('rl_action', {})
        
        msg = f"🛡️ *DEFENSE: {atype}*\n"
        msg += f"Confidence: {conf:.0%}\n"
        
        if rl:
            msg += f"🤖 RL Decision: *{rl.get('action_name', '?')}* (cost: {rl.get('cost', 0)})\n"
        
        return msg
    
    def send_alert(self, alert: Dict):
        """Отправить алерт во все настроенные каналы"""
        if not self.enabled:
            return
        
        message = self._format_alert(alert)
        
        def _send():
            if self.telegram_token:
                self._send_telegram(message)
            if self.slack_webhook:
                self._send_slack(message)
            if self.discord_webhook:
                self._send_discord(message)
        
        threading.Thread(target=_send, daemon=True).start()
    
    def send_defense_action(self, result: Dict):
        """Отправить уведомление о защитном действии"""
        if not self.enabled:
            return
        
        message = self._format_defense(result)
        
        def _send():
            if self.telegram_token:
                self._send_telegram(message)
        
        threading.Thread(target=_send, daemon=True).start()
    
    def _send_telegram(self, message: str):
        """Отправка в Telegram"""
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            response = requests.post(url, json={
                'chat_id': self.telegram_chat_id,
                'text': message,
                'parse_mode': 'Markdown',
            }, timeout=5)
            if response.status_code != 200:
                logger.debug(f"Telegram error: {response.text[:100]}")
        except Exception as e:
            logger.debug(f"Telegram send error: {e}")
    
    def _send_slack(self, message: str):
        """Отправка в Slack"""
        try:
            requests.post(self.slack_webhook, json={
                'text': message.replace('*', '*'),
            }, timeout=5)
        except Exception as e:
            logger.debug(f"Slack send error: {e}")
    
    def _send_discord(self, message: str):
        """Отправка в Discord"""
        try:
            requests.post(self.discord_webhook, json={
                'content': message.replace('*', '**'),
            }, timeout=5)
        except Exception as e:
            logger.debug(f"Discord send error: {e}")

_notifier_instance = None

def get_notifier(config: Dict = None) -> ShardNotifier:
    global _notifier_instance
    if _notifier_instance is None:
        _notifier_instance = ShardNotifier(config)
    return _notifier_instance
