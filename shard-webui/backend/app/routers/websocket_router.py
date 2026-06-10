"""
SHARD WebSocket Router — Real-time updates
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import Dict, List
import json
import asyncio
import logging

logger = logging.getLogger("SHARD-WebSocket")

router = APIRouter()


class ConnectionManager:
    """Управление WebSocket соединениями"""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._lock = asyncio.Lock()
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            self.active_connections.append(websocket)
        logger.info(f"WebSocket connected (total: {len(self.active_connections)})")
    
    async def disconnect(self, websocket: WebSocket):
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
        logger.info(f"WebSocket disconnected (total: {len(self.active_connections)})")
    
    async def broadcast(self, message: Dict):
        """Отправить сообщение всем подключённым клиентам"""
        async with self._lock:
            dead = []
            for connection in self.active_connections:
                try:
                    await connection.send_json(message)
                except Exception:
                    dead.append(connection)
            
            for conn in dead:
                self.active_connections.remove(conn)


manager = ConnectionManager()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Отправляем приветственное сообщение
        await websocket.send_json({
            "type": "connected",
            "message": "SHARD Defense WebSocket connected",
            "timestamp": __import__('time').time()
        })
        
        # Держим соединение открытым, слушаем клиента
        while True:
            data = await websocket.receive_text()
            
            # Клиент может запросить обновление
            if data == "ping":
                await websocket.send_json({"type": "pong"})
            elif data == "get_stats":
                # Отправляем статистику защиты
                try:
                    from modules.decision_fusion import get_decision_fusion
                    fusion = get_decision_fusion()
                    stats = fusion.get_stats() if fusion else {}
                    active = fusion.get_active_defenses() if fusion else []
                    
                    await websocket.send_json({
                        "type": "defense_update",
                        "stats": stats,
                        "active_defenses": active,
                        "timestamp": __import__('time').time()
                    })
                except Exception as e:
                    # Fallback — пустая статистика
                    await websocket.send_json({
                        "type": "defense_update",
                        "stats": {
                            "total_decisions": 0, "rule_based": 0,
                            "rl_decisions": 0, "heuristic_decisions": 0,
                            "blocks_applied": 0, "throttles_applied": 0,
                            "ignored": 0, "errors": 0,
                            "active_defenses": 0, "history_size": 0
                        },
                        "active_defenses": [],
                        "timestamp": __import__('time').time()
                    })
    
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        await manager.disconnect(websocket)


def broadcast_defense_update(stats: Dict = None, active: List = None, alert: Dict = None):
    """Вызвать из SHARD Engine для отправки обновлений"""
    import asyncio
    
    async def _broadcast():
        message = {"type": "defense_update", "timestamp": __import__('time').time()}
        if stats:
            message["stats"] = stats
        if active is not None:
            message["active_defenses"] = active
        if alert:
            message["alert"] = alert
        await manager.broadcast(message)
    
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(_broadcast())
        else:
            asyncio.run(_broadcast())
    except Exception as e:
        logger.error(f"Broadcast error: {e}")


print("✅ WebSocket router loaded")
