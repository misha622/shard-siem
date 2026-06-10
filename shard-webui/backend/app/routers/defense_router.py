
"""
SHARD Defense API Router — with SHARD Engine bridge
"""

import sys, json, logging
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent.parent))

from fastapi import APIRouter, HTTPException, Query
from typing import Dict, List, Optional
from pydantic import BaseModel, Field

logger = logging.getLogger("SHARD-DefenseAPI")
router = APIRouter(prefix="/api/defense", tags=["defense"])


class DefenseActionRequest(BaseModel):
    src_ip: str = Field(..., description="IP-адрес источника")
    action_id: int = Field(..., ge=0, le=4)
    reason: Optional[str] = Field(None)
    block_duration: Optional[int] = Field(None, ge=0, le=86400)


class DefenseActionResponse(BaseModel):
    success: bool
    action: str
    description: str
    source: str
    priority: int
    block_duration: int
    error: Optional[str] = None


class ActiveDefense(BaseModel):
    ip: str
    action_name: str
    description: str
    source: str
    confidence: float
    priority: int
    remaining: float
    block_duration: int
    timestamp: float


class DefenseStats(BaseModel):
    total_decisions: int
    rule_based: int
    rl_decisions: int
    heuristic_decisions: int
    blocks_applied: int
    throttles_applied: int
    ignored: int
    errors: int
    active_defenses: int
    history_size: int


class FileFusion:
    """Wrapper for reading stats from SHARD Engine JSON file"""
    def __init__(self, data):
        self._stats = data.get('stats', {})
        self._active = data.get('active', [])
        self.firewall = None
        self._lock = None
        self._decision_history = []
    
    def get_stats(self):
        return self._stats
    
    def get_active_defenses(self):
        return self._active


_cached_fusion = None

def get_fusion():
    """Get DecisionFusion — cached, first try SHARD Engine file, then local"""
    global _cached_fusion
    
    # Проверяем файл статистики от SHARD Engine
    try:
        stats_file = Path('data/defense_stats.json')
        if stats_file.exists():
            mtime = stats_file.stat().st_mtime
            if _cached_fusion is None or getattr(_cached_fusion, '_mtime', 0) != mtime:
                with open(stats_file) as f:
                    data = json.load(f)
                ff = FileFusion(data)
                ff._mtime = mtime
                return ff
    except Exception:
        pass
    
    # Возвращаем кешированный если есть
    if _cached_fusion is not None:
        return _cached_fusion
    
    # Ленивый импорт
    try:
        from modules.decision_fusion import get_decision_fusion
        _cached_fusion = get_decision_fusion()
        return _cached_fusion
    except Exception:
        return None


def validate_ip(ip: str) -> bool:
    import re
    return bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip)) and all(0 <= int(o) <= 255 for o in ip.split('.'))


@router.get("/stats", response_model=DefenseStats)
async def get_stats():
    fusion = get_fusion()
    stats = fusion.get_stats() if fusion else {}
    return DefenseStats(
        total_decisions=stats.get('total_decisions', 0),
        rule_based=stats.get('rule_based', 0),
        rl_decisions=stats.get('rl_decisions', 0),
        heuristic_decisions=stats.get('heuristic_decisions', 0),
        blocks_applied=stats.get('blocks_applied', 0),
        throttles_applied=stats.get('throttles_applied', 0),
        ignored=stats.get('ignored', 0),
        errors=stats.get('errors', 0),
        active_defenses=stats.get('active_defenses', 0),
        history_size=stats.get('history_size', 0)
    )


@router.get("/active", response_model=List[ActiveDefense])
async def get_active():
    fusion = get_fusion()
    return [ActiveDefense(**d) for d in (fusion.get_active_defenses() if fusion else [])]


@router.post("/test", response_model=DefenseActionResponse)
async def test_defense(request: DefenseActionRequest):
    if not validate_ip(request.src_ip):
        raise HTTPException(400, "Invalid IP")
    
    # Ленивый импорт — только при первом вызове
    try:
        from modules.decision_fusion import DecisionFusion, DecisionSource
    except ImportError:
        from modules.decision_fusion import DecisionFusion
        DecisionSource = None
    fusion = DecisionFusion()
    
    test_alerts = [
        {'attack_type': 'Data Exfiltration', 'severity': 'CRITICAL', 'score': 0.98, 'confidence': 0.99,
         'src_ip': request.src_ip, 'dst_port': 443},
        {'attack_type': 'DDoS', 'severity': 'CRITICAL', 'score': 0.92, 'confidence': 0.95,
         'src_ip': request.src_ip, 'dst_port': 80},
        {'attack_type': request.reason or 'Test', 'severity': 'CRITICAL', 'score': 0.9, 'confidence': 0.9,
         'src_ip': request.src_ip, 'dst_port': 443}
    ]
    
    for alert in test_alerts:
        action = fusion._rule_based_decision(alert)
        if action:
            return DefenseActionResponse(success=True, action=action.action_name,
                description=action.description, source=action.source.value,
                priority=action.priority, block_duration=action.block_duration)
    
    return DefenseActionResponse(success=False, action="none",
        description="Would escalate to RL/Heuristic/Firewall", source="rule_based",
        priority=0, block_duration=0)
