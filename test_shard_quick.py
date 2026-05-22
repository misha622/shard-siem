#!/usr/bin/env python3
"""Quick tests without ML dependencies"""
import sys, os, time
sys.path.insert(0, '.')

from core.base import EventBus, ModuleRegistry, ConfigManager, LoggingService
from modules.firewall import SmartFirewall

print("Test 1: EventBus...")
bus = EventBus()
received = []
bus.subscribe('test', lambda d: received.append(d))
bus.publish('test', {'msg': 'hello'})
time.sleep(0.1)
assert received[0]['msg'] == 'hello'
print("   OK")

print("Test 2: ModuleRegistry...")
reg = ModuleRegistry()
reg.register('test', 42)
assert reg.get('test') == 42
print("   OK")

print("Test 3: ConfigManager...")
config = ConfigManager('config.yaml')
assert config.get('ml.online_learning') == True
print("   OK")

print("Test 4: Firewall...")
fw = SmartFirewall(config, EventBus(), LoggingService(config, EventBus()))
assert fw._validate_ip('192.168.1.1') == True
assert fw._validate_ip('127.0.0.1; rm -rf /') == False
print("   OK")

print("Test 5: SIEMStorage...")
config.set('storage.sqlite.path', ':memory:')
config.set('storage.timescaledb.enabled', False)
from modules.siem_storage import SIEMStorage
storage = SIEMStorage(config, EventBus(), LoggingService(config, EventBus()))
alerts = storage.query_alerts(limit=5)
assert isinstance(alerts, list)
print("   OK")

print("Test 6: ML Engine...")
from modules.ml_engine import MachineLearningEngine
ml = MachineLearningEngine(config, EventBus(), LoggingService(config, EventBus()))
assert ml is not None
print("   OK")


print("\nAll 6 tests passed!")
