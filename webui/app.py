#!/usr/bin/env python3
"""SHARD WebUI Backend — Flask REST API"""
import sys, os, time, json, threading
from pathlib import Path
from flask import Flask, render_template, jsonify, request
from flask_cors import CORS

sys.path.insert(0, str(Path(__file__).parent.parent))

app = Flask(__name__)
CORS(app)

# Глобальное состояние дашборда
dashboard_state = {
    'total_packets': 0,
    'total_alerts': 0,
    'blocked_ips': 0,
    'active_threats': 0,
    'recent_alerts': [],
    'top_attackers': {},
    'top_targets': {},
    'attack_types': {},
    'system': {'cpu': 0, 'memory': 0, 'disk': 0},
    'modules': {},
    'uptime': '00:00:00',
    'start_time': time.time()
}
state_lock = threading.RLock()

# Подключение к SHARD EventBus (если запущен)
try:
    from core.base import EventBus
    event_bus = EventBus()
    
    def on_alert(alert):
        with state_lock:
            dashboard_state['total_alerts'] += 1
            dashboard_state['active_threats'] += 1
            src = alert.get('src_ip', 'unknown')
            dst = alert.get('dst_ip', 'unknown')
            atype = alert.get('attack_type', 'Unknown')
            dashboard_state['top_attackers'][src] = dashboard_state['top_attackers'].get(src, 0) + 1
            dashboard_state['top_targets'][dst] = dashboard_state['top_targets'].get(dst, 0) + 1
            dashboard_state['attack_types'][atype] = dashboard_state['attack_types'].get(atype, 0) + 1
            dashboard_state['recent_alerts'].insert(0, {
                'time': time.strftime('%H:%M:%S'),
                'src': src, 'dst': dst, 'type': atype,
                'score': alert.get('score', 0), 'severity': alert.get('severity', 'LOW')
            })
            if len(dashboard_state['recent_alerts']) > 100:
                dashboard_state['recent_alerts'] = dashboard_state['recent_alerts'][:100]
    
    def on_block(data):
        with state_lock:
            dashboard_state['blocked_ips'] += 1
    
    def on_packet(data):
        with state_lock:
            dashboard_state['total_packets'] += data.get('count', 1)
    
    event_bus.subscribe('alert.detected', on_alert)
    event_bus.subscribe('firewall.blocked', on_block)
    event_bus.subscribe('packet.processed', on_packet)
    print("✅ Connected to SHARD EventBus")
except Exception as e:
    print(f"⚠️ Standalone mode — EventBus not available: {e}")
    event_bus = None

# Системная статистика
def update_system_stats():
    while True:
        try:
            import psutil
            with state_lock:
                dashboard_state['system']['cpu'] = psutil.cpu_percent()
                dashboard_state['system']['memory'] = psutil.virtual_memory().percent
                dashboard_state['system']['disk'] = psutil.disk_usage('/').percent
                uptime = int(time.time() - dashboard_state['start_time'])
                h, m, s = uptime // 3600, (uptime % 3600) // 60, uptime % 60
                dashboard_state['uptime'] = f"{h:02d}:{m:02d}:{s:02d}"
        except:
            pass
        time.sleep(5)

threading.Thread(target=update_system_stats, daemon=True).start()

# API Endpoints
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def api_stats():
    with state_lock:
        return jsonify({
            'total_packets': dashboard_state['total_packets'],
            'total_alerts': dashboard_state['total_alerts'],
            'blocked_ips': dashboard_state['blocked_ips'],
            'active_threats': dashboard_state['active_threats'],
            'recent_alerts': dashboard_state['recent_alerts'][:20],
            'top_attackers': dict(sorted(dashboard_state['top_attackers'].items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_targets': dict(sorted(dashboard_state['top_targets'].items(), key=lambda x: x[1], reverse=True)[:10]),
            'attack_types': dict(sorted(dashboard_state['attack_types'].items(), key=lambda x: x[1], reverse=True)),
            'system': dashboard_state['system'],
            'uptime': dashboard_state['uptime']
        })

@app.route('/api/block', methods=['POST'])
def api_block():
    ip = request.json.get('ip', '')
    if event_bus:
        event_bus.publish('block.request', {'ip': ip})
        return jsonify({'status': 'ok', 'ip': ip})
    return jsonify({'status': 'error', 'message': 'EventBus not connected'})

@app.route('/api/health')
def api_health():
    return jsonify({'status': 'healthy', 'version': '5.2.0', 'timestamp': time.time()})

if __name__ == '__main__':
    print("🌐 SHARD WebUI starting on http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
