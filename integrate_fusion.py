#!/usr/bin/env python3
"""
Интеграция DecisionFusion в SHARD Core Engine.
Добавляет оркестратор защиты в основной пайплайн.
"""

import sys
from pathlib import Path

# Добавляем корень проекта в PYTHONPATH
sys.path.insert(0, str(Path(__file__).parent))

from modules.decision_fusion import init_decision_fusion

def integrate_fusion(shard_instance):
    """
    Интегрирует DecisionFusion в работающий экземпляр SHARD.
    
    Args:
        shard_instance: экземпляр основного движка SHARD
    """
    print("🔗 Integrating DecisionFusion into SHARD...")
    
    # Получаем модули из shard_instance
    event_bus = getattr(shard_instance, 'event_bus', None)
    ml_engine = getattr(shard_instance, 'ml_engine', None)
    
    # Ищем модули по имени
    rl_defense = None
    autonomous_defender = None
    firewall = None
    
    # Проверяем загруженные модули
    if hasattr(shard_instance, 'modules'):
        for module in shard_instance.modules:
            module_name = module.__class__.__name__
            if 'RL' in module_name or 'RLDefense' in module_name:
                rl_defense = module
                print(f"   ✅ Found RL Defense: {module_name}")
            elif 'AutonomousDefender' in module_name:
                autonomous_defender = module
                print(f"   ✅ Found Autonomous Defender: {module_name}")
            elif 'SmartFirewall' in module_name or 'Firewall' in module_name:
                firewall = module
                print(f"   ✅ Found Firewall: {module_name}")
    
    # Инициализируем DecisionFusion
    fusion = init_decision_fusion(
        event_bus=event_bus,
        rl_defense=rl_defense,
        autonomous_defender=autonomous_defender,
        firewall=firewall,
        ml_engine=ml_engine
    )
    
    # Сохраняем ссылку в shard_instance
    shard_instance.decision_fusion = fusion
    
    print("✅ DecisionFusion integrated successfully!")
    return fusion


if __name__ == "__main__":
    print("🔧 DecisionFusion Integration Script")
    print("=" * 50)
    print("\nДля интеграции в работающий SHARD, используйте:")
    print("  from integrate_fusion import integrate_fusion")
    print("  integrate_fusion(shard_instance)")
    print("\nИли добавьте в run_shard.py:")
    print("  from modules.decision_fusion import init_decision_fusion")
    print("  fusion = init_decision_fusion(event_bus, rl_defense, defender, firewall)")
