#!/usr/bin/env python3
"""Quick tests without ML dependencies"""
import sys, time
sys.path.insert(0, '.')

# Тест 1: EventBus напрямую (без импорта всего SHARD)
from core.base import EventBus

bus = EventBus()
received = []
bus.subscribe('test', lambda d: received.append(d))
bus.publish('test', {'msg': 'hello'})
time.sleep(0.1)
assert received[0]['msg'] == 'hello', f"Expected hello, got {received}"
print("✅ EventBus работает")

# Тест 2: ModuleRegistry
from core.base import ModuleRegistry
reg = ModuleRegistry()
reg.register('test', 42)
assert reg.get('test') == 42
print("✅ ModuleRegistry работает")

# Тест 3: ConfigManager
from core.base import ConfigManager
config = ConfigManager('config.yaml')
assert config.get('ml.online_learning') == True
print("✅ ConfigManager работает")

# Тест 4: Firewall IP validation (без iptables)
from modules.firewall import SmartFirewall
from core.base import LoggingService, EventBus
fw = SmartFirewall(ConfigManager('config.yaml'), EventBus(), LoggingService(ConfigManager('config.yaml'), EventBus()))
assert fw._validate_ip('192.168.1.1') == True
assert fw._validate_ip('127.0.0.1; rm -rf /') == False
print("✅ Firewall IP validation работает")

print("\n✅ Все 5 тестов пройдены!")
