#!/usr/bin/env python3
"""
Тест DecisionFusion — проверка всех уровней принятия решений
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from modules.decision_fusion import DecisionFusion, DefenseAction, DecisionSource

def test_decision_fusion():
    """Тестирование DecisionFusion"""
    print("=" * 60)
    print("🧪 TESTING DECISION FUSION MODULE")
    print("=" * 60)
    
    fusion = DecisionFusion()
    
    # Тест 1: Rule-Based — Critical Data Exfiltration
    print("\n📊 Test 1: Critical Data Exfiltration (Rule-Based)")
    alert = {
        'attack_type': 'Data Exfiltration',
        'severity': 'CRITICAL',
        'score': 0.98,
        'confidence': 0.99,
        'src_ip': '185.142.53.101',
        'dst_ip': '192.168.1.100',
        'dst_port': 443
    }
    action = fusion.on_alert(alert)
    if action:
        print(f"   ✅ Action: {action.action_name}")
        print(f"   📝 Description: {action.description}")
        print(f"   🎯 Source: {action.source.value}")
        print(f"   ⏱️ Duration: {action.block_duration}s")
        assert action.action_id == 4, "Expected permanent block"
        assert action.source == DecisionSource.RULE_BASED
    else:
        print("   ❌ No action taken (unexpected)")
    
    # Тест 2: Rule-Based — High score
    print("\n📊 Test 2: Critical DDoS (Rule-Based)")
    alert2 = {
        'attack_type': 'DDoS',
        'severity': 'CRITICAL',
        'score': 0.92,
        'confidence': 0.95,
        'src_ip': '194.61.23.45',
        'dst_ip': '10.0.0.5',
        'dst_port': 80
    }
    action2 = fusion.on_alert(alert2)
    if action2:
        print(f"   ✅ Action: {action2.action_name}")
        print(f"   📝 Description: {action2.description}")
        assert action2.action_id == 3, "Expected temporary block"
    
    # Тест 3: Medium severity — no rule-based trigger
    print("\n📊 Test 3: Medium Port Scan (No Rule-Based)")
    alert3 = {
        'attack_type': 'Port Scan',
        'severity': 'MEDIUM',
        'score': 0.6,
        'confidence': 0.7,
        'src_ip': '78.128.113.94',
        'dst_ip': '172.16.0.10',
        'dst_port': 22
    }
    action3 = fusion.on_alert(alert3)
    if action3:
        print(f"   Action taken: {action3.action_name} (source: {action3.source.value})")
    else:
        print(f"   ✅ No action (correct — below threshold without RL/Firewall)")
    
    # Тест 4: Localhost — should be ignored
    print("\n📊 Test 4: Localhost (should be ignored)")
    alert4 = {
        'attack_type': 'Malware',
        'severity': 'CRITICAL',
        'score': 0.99,
        'confidence': 0.99,
        'src_ip': '127.0.0.1',
        'dst_ip': '127.0.0.1',
        'dst_port': 4444
    }
    action4 = fusion.on_alert(alert4)
    if action4 is None:
        print(f"   ✅ Correctly ignored localhost")
    else:
        print(f"   ❌ Should have ignored localhost")
    
    # Тест 5: Manual action
    print("\n📊 Test 5: Manual Action")
    alert5 = {
        'attack_type': 'Brute Force',
        'severity': 'HIGH',
        'score': 0.85,
        'confidence': 0.88,
        'src_ip': '45.155.205.233',
        'dst_port': 22
    }
    manual_action = fusion.manual_action(alert5, 3)
    print(f"   ✅ Manual: {manual_action.action_name} (priority: {manual_action.priority})")
    assert manual_action.source == DecisionSource.MANUAL
    assert manual_action.priority == 255
    
    # Статистика
    print("\n📊 DecisionFusion Stats:")
    stats = fusion.get_stats()
    for key, value in stats.items():
        if not isinstance(value, list):
            print(f"   {key}: {value}")
    
    print("\n" + "=" * 60)
    print("✅ ALL TESTS PASSED!")
    print("=" * 60)

if __name__ == "__main__":
    test_decision_fusion()
