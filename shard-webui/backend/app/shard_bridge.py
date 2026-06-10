"""
SHARD Bridge — связывает WebUI с работающим SHARD Engine
"""
import sys
import os
from pathlib import Path

# Добавляем корень проекта
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

# Глобальная ссылка на DecisionFusion из SHARD Engine
_engine_fusion = None

def set_engine_fusion(fusion):
    """Установить ссылку на DecisionFusion из SHARD Engine"""
    global _engine_fusion
    _engine_fusion = fusion

def get_engine_fusion():
    """Получить DecisionFusion из SHARD Engine"""
    global _engine_fusion
    return _engine_fusion
