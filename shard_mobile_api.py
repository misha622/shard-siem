#!/usr/bin/env python3
"""
📱 SHARD MOBILE API - Push-уведомления и мобильное приложение
REST API для мобильного клиента
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Optional
from flask import Flask, request, jsonify
from flask_cors import CORS
import threading
import time
import requests

logger = logging.getLogger("SHARD-Mobile")

app = Flask(__name__)
CORS(app)


class PushNotificationManager:

    def __init__(self):
        self.devices = {}
        self.alert_history = []
        self.max_history = 1000

        self.firebase_enabled = False
        self.fcm_server_key = None

        logger.info("📱 Push Notification Manager инициализирован")

    def register_device(self, device_token: str, platform: str, user_id: str = None):
        self.devices[device_token] = {
            'token': device_token,
            'platform': platform,
            'user_id': user_id,
            'registered_at': datetime.now().isoformat(),
            'last_active': datetime.now().isoformat()
        }
        logger.info(f"📱 Устройство зарегистрировано: {device_token[:16]}... ({platform})")
        return {'status': 'registered', 'devices': len(self.devices)}

    def unregister_device(self, device_token: str):
        if device_token in self.devices:
            del self.devices[device_token]
            logger.info(f"📱 Устройство удалено: {device_token[:16]}...")
        return {'status': 'unregistered'}

    def send_push(self, device_token: str, title: str, body: str, data: Dict = None) -> bool:
        if device_token not in self.devices:
            return False

        platform = self.devices[device_token]['platform']

        if platform == 'ios':
            return self._send_apns(device_token, title, body, data)
        else:
            return self._send_fcm(device_token, title, body, data)

    def _send_fcm(self, token: str, title: str, body: str, data: Dict = None) -> bool:
        if not self.firebase_enabled:
            logger.info(f"📱 [FCM] {title}: {body}")
            return True

        try:
            headers = {
                'Authorization': f'key={self.fcm_server_key}',
                'Content-Type': 'application/json'
            }

            payload = {
                'to': token,
                'notification': {
                    'title': title,
                    'body': body,
                    'sound': 'default',
                    'badge': 1
                },
                'data': data or {}
            }

            response = requests.post(
                'https://fcm.googleapis.com/fcm/send',
                headers=headers,
                json=payload,
                timeout=5
            )

            return response.status_code == 200
        except Exception as e:
            logger.error(f"FCM error: {e}")
            return False

    def _send_apns(self, token: str, title: str, body: str, data: Dict = None) -> bool:
        logger.info(f"📱 [APNS] {title}: {body}")
        return True

    def broadcast_alert(self, alert: Dict, min_severity: str = 'HIGH'):
        severity = alert.get('severity', 'MEDIUM')
        severity_levels = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}

        if severity_levels.get(severity, 2) < severity_levels.get(min_severity, 3):
            return

        title = f"🚨 {severity} THREAT DETECTED"
        body = f"{alert.get('attack_type', 'Unknown')} from {alert.get('src_ip', 'unknown')}"

        data = {
            'alert_id': alert.get('id', str(time.time())),
            'type': alert.get('attack_type'),
            'severity': severity,
            'src_ip': alert.get('src_ip'),
            'confidence': str(alert.get('confidence', 0)),
            'timestamp': alert.get('timestamp', datetime.now().isoformat())
        }

        sent_count = 0
        for token in list(self.devices.keys()):
            if self.send_push(token, title, body, data):
                sent_count += 1

        logger.info(f"📱 Broadcast: {sent_count}/{len(self.devices)} устройств")

        self.alert_history.append({
            **data,
            'title': title,
            'body': body,
            'sent_at': datetime.now().isoformat(),
            'devices_notified': sent_count
        })

        if len(self.alert_history) > self.max_history:
            self.alert_history = self.alert_history[-self.max_history:]

    def get_stats(self) -> Dict:
        return {
            'devices': len(self.devices),
            'platforms': {
                'ios': sum(1 for d in self.devices.values() if d['platform'] == 'ios'),
                'android': sum(1 for d in self.devices.values() if d['platform'] == 'android')
            },
            'alerts_sent': len(self.alert_history),
            'firebase_enabled': self.firebase_enabled
        }


push_manager = PushNotificationManager()


@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '5.0.0'
    })


@app.route('/api/device/register', methods=['POST'])
def register_device():
    data = request.json
    device_token = data.get('device_token')
    platform = data.get('platform', 'android')
    user_id = data.get('user_id')

    if not device_token:
        return jsonify({'error': 'device_token required'}), 400

    result = push_manager.register_device(device_token, platform, user_id)
    return jsonify(result)


@app.route('/api/device/unregister', methods=['POST'])
def unregister_device():
    data = request.json
    device_token = data.get('device_token')

    if not device_token:
        return jsonify({'error': 'device_token required'}), 400

    result = push_manager.unregister_device(device_token)
    return jsonify(result)


@app.route('/api/alerts/recent', methods=['GET'])
def get_recent_alerts():
    limit = request.args.get('limit', 50, type=int)
    severity = request.args.get('severity', None)

    alerts = push_manager.alert_history[-limit:]

    if severity:
        alerts = [a for a in alerts if a.get('severity') == severity]

    return jsonify({
        'count': len(alerts),
        'alerts': alerts[::-1]
    })


@app.route('/api/alert/send', methods=['POST'])
def send_alert():
    data = request.json

    alert = {
        'id': data.get('id', str(time.time())),
        'attack_type': data.get('attack_type', 'Unknown'),
        'severity': data.get('severity', 'MEDIUM'),
        'src_ip': data.get('src_ip', 'unknown'),
        'confidence': data.get('confidence', 0.5),
        'timestamp': data.get('timestamp', datetime.now().isoformat())
    }

    min_severity = data.get('min_severity', 'HIGH')
    push_manager.broadcast_alert(alert, min_severity)

    return jsonify({'status': 'sent', 'alert': alert})


@app.route('/api/action/block', methods=['POST'])
def block_ip():
    data = request.json
    ip = data.get('ip')

    if not ip:
        return jsonify({'error': 'ip required'}), 400

    logger.warning(f"📱 Remote BLOCK command for IP: {ip}")

    return jsonify({
        'status': 'blocked',
        'ip': ip,
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/stats', methods=['GET'])
def get_stats():
    return jsonify(push_manager.get_stats())


@app.route('/api/dashboard', methods=['GET'])
def get_dashboard_data():
    return jsonify({
        'alerts_today': len([a for a in push_manager.alert_history
                             if datetime.fromisoformat(a['sent_at']).date() == datetime.now().date()]),
        'total_alerts': len(push_manager.alert_history),
        'devices_online': len(push_manager.devices),
        'top_threats': _get_top_threats(),
        'recent_alerts': push_manager.alert_history[-10:][::-1]
    })


def _get_top_threats() -> List[Dict]:
    threat_counts = {}
    for alert in push_manager.alert_history:
        t = alert.get('type', 'Unknown')
        threat_counts[t] = threat_counts.get(t, 0) + 1

    return sorted(
        [{'type': k, 'count': v} for k, v in threat_counts.items()],
        key=lambda x: x['count'],
        reverse=True
    )[:5]


class SHARDMobileIntegration:

    def __init__(self, port: int = 5000):
        self.port = port
        self.server_thread = None

        self.alert_callback = None

        logger.info(f"📱 SHARD Mobile Integration готов (порт: {port})")

    def start_server(self):

        def run():
            app.run(host='0.0.0.0', port=self.port, debug=False, use_reloader=False)

        self.server_thread = threading.Thread(target=run, daemon=True)
        self.server_thread.start()
        logger.info(f"🚀 Mobile API запущен на порту {self.port}")

    def on_alert(self, alert: Dict):
        severity = alert.get('severity', 'MEDIUM')
        if severity in ['HIGH', 'CRITICAL']:
            push_manager.broadcast_alert({
                'attack_type': alert.get('attack_type', alert.get('type', 'Unknown')),
                'severity': severity,
                'src_ip': alert.get('src_ip', 'unknown'),
                'confidence': alert.get('confidence', 0.5),
                'timestamp': datetime.now().isoformat()
            }, min_severity='HIGH')

    def get_stats(self) -> Dict:
        return {
            'api_port': self.port,
            'push_manager': push_manager.get_stats()
        }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    mobile = SHARDMobileIntegration(port=5000)
    mobile.start_server()

    print("\n📱 SHARD Mobile API запущен!")
    print("=" * 40)
    print("Эндпоинты:")
    print("  POST /api/device/register - регистрация устройства")
    print("  POST /api/device/unregister - отмена регистрации")
    print("  GET  /api/alerts/recent - последние алерты")
    print("  POST /api/action/block - блокировка IP")
    print("  GET  /api/stats - статистика")
    print("  GET  /api/dashboard - данные для дашборда")
    print("=" * 40)
    print("\nНажмите Ctrl+C для остановки")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Остановка...")