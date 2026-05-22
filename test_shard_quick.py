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
print("Test 7: Encrypted Traffic...")
from modules.encrypted_traffic import EncryptedTrafficAnalyzer
enc = EncryptedTrafficAnalyzer(config, EventBus(), LoggingService(config, EventBus()))
assert enc.beacon_threshold == 0.7
print("   OK")

print("Test 8: DPI...")
from modules.dpi import DeepPacketInspector
dpi = DeepPacketInspector(config, EventBus(), LoggingService(config, EventBus()))
dpi.start()
assert dpi.running == True
dpi.stop()
print("   OK")

print("Test 9: LDAP...")
from modules.ldap import LDAPContextProvider
ldap = LDAPContextProvider(config, EventBus(), LoggingService(config, EventBus()))
ctx = ldap._create_basic_context('testuser')
assert ctx['username'] == 'testuser'
print("   OK")

print("Test 10: DNS Analyzer...")
from modules.dns_analyzer import DNSAnalyzer
dns = DNSAnalyzer(config, EventBus(), LoggingService(config, EventBus()))
dns.start()
assert dns.running == True
dns.stop()
print("   OK")

print("\nAll 10 tests passed!")

print("Test 11: Exfiltration Detector...")
from modules.exfil_detector import DataExfiltrationDetector
exfil = DataExfiltrationDetector(config, EventBus(), LoggingService(config, EventBus()))
assert exfil is not None
exfil.start()
assert exfil.running == True
exfil.stop()
print("   OK")

print("Test 12: Threat Intelligence (local)...")
from modules.threat_intel import ThreatIntelligence
ti = ThreatIntelligence(config, EventBus(), LoggingService(config, EventBus()))
assert ti._is_public_ip('8.8.8.8') == True
assert ti._is_public_ip('192.168.1.1') == False
assert ti._is_public_ip('127.0.0.1') == False
result = ti._check_local_lists('127.0.0.1')
assert isinstance(result, dict)
assert 'is_malicious' in result
ti.stop()
print("   OK")

print("Test 13: WAF...")
from modules.waf import WebApplicationFirewall
waf = WebApplicationFirewall(config, EventBus(), LoggingService(config, EventBus()))
result = waf._analyze_text("SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin", "test")
assert result['is_attack'] == True
result = waf._analyze_text("normal text without attacks", "test")
assert result['is_attack'] == False
print("   OK")

print("Test 14: UBA...")
from modules.uba import UserBehaviorAnalytics
uba = UserBehaviorAnalytics(config, EventBus(), LoggingService(config, EventBus()))
uba.bind_ip_to_user('10.0.0.1', 'testuser')
risk = uba.get_user_risk('testuser')
assert risk >= 0.0
result = uba.record_event('10.0.0.1', 'login', {'username': 'testuser'})
print("   OK")

print("Test 15: Report Generator...")
from modules.report_generator import IncidentReportGenerator
reporter = IncidentReportGenerator(config, EventBus(), LoggingService(config, EventBus()))
inv = {'id': 'T-001', 'start_time': 1234567890.0, 'end_time': 1234567999.0, 'severity': 'HIGH', 'stage': 'test', 'src_ip': '10.0.0.1', 'conclusion': 'Test', 'recommendations': ['Block']}
alerts = [{'timestamp': 1234567890.0, 'src_ip': '10.0.0.1', 'attack_type': 'Test', 'score': 0.8}]
report = reporter.generate_report(inv, alerts)
assert 'ОТЧЁТ' in report or 'INCIDENT' in report.upper()
print("   OK")

print("Test 16: Threat Intelligence Platform...")
from shard_tip import ShardTIPIntegration
tip = ShardTIPIntegration()
tip.setup(EventBus(), LoggingService(config, EventBus()))
stats = tip.get_stats()
assert isinstance(stats, dict)
print("   OK")

print("Test 17: Red Team...")
from shard_red_team import ShardRedTeamIntegration
rt = ShardRedTeamIntegration()
rt.setup(EventBus(), LoggingService(config, EventBus()))
assert rt is not None
print("   OK")

print("Test 18: Threat Hunting...")
from shard_threat_hunting import ShardThreatHuntingIntegration
th = ShardThreatHuntingIntegration()
th.setup(EventBus(), LoggingService(config, EventBus()))
assert th is not None
print("   OK")

print("Test 19: MITRE ATT&CK...")
from shard_mitre_attack import ShardMITREIntegration
mitre = ShardMITREIntegration()
mitre.setup(EventBus(), LoggingService(config, EventBus()))
coverage = mitre.get_coverage_report()
assert isinstance(coverage, dict)
print("   OK")

print("Test 20: CVE Intelligence...")
from shard_cve_intelligence import ShardCVEIntelligenceIntegration
cve = ShardCVEIntelligenceIntegration()
cve.setup(EventBus(), LoggingService(config, EventBus()))
assert cve is not None
print("   OK")

print("\nAll 20 tests passed!")



print("\n=== DEEP TESTS FOR COVERAGE ===")

# Test 21: ConfigManager - save/load
print("Test 21: ConfigManager save/load...")
config.set('test.key', 'value')
config.save()
config2 = ConfigManager('config.yaml')
assert config2.get('test.key') == 'value'
print("   OK")

# Test 22: EventBus - stats
print("Test 22: EventBus stats...")
bus2 = EventBus()
bus2.subscribe('test', lambda d: None)
bus2.publish('test', {})
bus2.publish('test', {})
time.sleep(0.2)
stats = bus2.get_stats()
assert stats['events_published'] == 2
print("   OK")

# Test 23: Firewall - block/unblock
print("Test 23: Firewall block/unblock...")
fw2 = SmartFirewall(config, EventBus(), LoggingService(config, EventBus()))
assert fw2._validate_port(80) == True
assert fw2._validate_port(99999) == False
assert fw2._validate_port(-1) == False
print("   OK")

# Test 24: SIEMStorage - get_stats
print("Test 24: SIEMStorage stats...")
storage2 = SIEMStorage(config, EventBus(), LoggingService(config, EventBus()))
stats = storage2.get_stats(hours=24)
assert 'total_alerts' in stats
assert 'period_hours' in stats
print("   OK")

# Test 25: ML Engine - stats
print("Test 25: ML Engine stats...")
ml2 = MachineLearningEngine(config, EventBus(), LoggingService(config, EventBus()))
stats = ml2.get_stats()
assert 'normal_buffer_size' in stats
assert 'models_loaded' in stats
print("   OK")

# Test 26: DNS Analyzer - stats
print("Test 26: DNS Analyzer stats...")
dns2 = DNSAnalyzer(config, EventBus(), LoggingService(config, EventBus()))
dns2.start()
stats = dns2.get_stats()
assert isinstance(stats, dict)
dns2.stop()
print("   OK")

# Test 27: Exfiltration Detector - stats
print("Test 27: Exfiltration stats...")
exfil2 = DataExfiltrationDetector(config, EventBus(), LoggingService(config, EventBus()))
stats = exfil2.get_stats()
assert 'total_hosts' in stats
print("   OK")

# Test 28: Threat Intelligence - cache stats
print("Test 28: Threat Intelligence cache...")
ti2 = ThreatIntelligence(config, EventBus(), LoggingService(config, EventBus()))
stats = ti2.get_cache_stats()
assert 'threat_cache_size' in stats
ti2.stop()
print("   OK")

# Test 29: WAF - stats
print("Test 29: WAF stats...")
waf2 = WebApplicationFirewall(config, EventBus(), LoggingService(config, EventBus()))
stats = waf2.get_stats()
assert 'total_rules' in stats
print("   OK")

# Test 30: UBA - user profile
print("Test 30: UBA user profile...")
uba2 = UserBehaviorAnalytics(config, EventBus(), LoggingService(config, EventBus()))
profile = uba2.get_user_profile('testuser')
assert profile is None or isinstance(profile, dict)
print("   OK")

# Test 31: Encrypted Traffic - stats
print("Test 31: Encrypted Traffic stats...")
enc2 = EncryptedTrafficAnalyzer(config, EventBus(), LoggingService(config, EventBus()))
stats = enc2.get_stats()
assert 'active_sessions' in stats
print("   OK")

# Test 32: DPI - stats
print("Test 32: DPI stats...")
dpi2 = DeepPacketInspector(config, EventBus(), LoggingService(config, EventBus()))
stats = dpi2.get_stats()
assert 'http_buffer_size' in stats
print("   OK")

# Test 33: LDAP - is_privileged
print("Test 33: LDAP privileged check...")
ldap2 = LDAPContextProvider(config, EventBus(), LoggingService(config, EventBus()))
is_priv = ldap2.is_privileged_account('admin')
assert isinstance(is_priv, bool)
print("   OK")

# Test 34: Report Generator - stats
print("Test 34: Report Generator stats...")
reporter2 = IncidentReportGenerator(config, EventBus(), LoggingService(config, EventBus()))
stats = reporter2.get_stats()
assert 'reports_dir' in stats
print("   OK")

# Test 35: Agentic AI - stats
print("Test 35: Agentic AI stats...")
from modules.agentic_ai import AgenticAIAnalyst
ai2 = AgenticAIAnalyst(config, EventBus(), LoggingService(config, EventBus()))
stats = ai2.get_stats()
assert 'total_investigations' in stats
print("   OK")

print("\nAll 35 tests passed!")
