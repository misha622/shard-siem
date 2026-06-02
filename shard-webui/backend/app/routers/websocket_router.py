from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Query
from typing import List, Dict
import json
import asyncio
from datetime import datetime
from app.eventbus import eventbus
from app.auth import decode_token
import logging

logger = logging.getLogger(__name__)
router = APIRouter()


class ConnectionManager:
    """WebSocket connection manager"""

    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}
        self.user_connections: Dict[WebSocket, str] = {}

    async def connect(self, websocket: WebSocket, user_id: str):
        await websocket.accept()
        if user_id not in self.active_connections:
            self.active_connections[user_id] = []
        self.active_connections[user_id].append(websocket)
        self.user_connections[websocket] = user_id
        logger.info(f"WebSocket connected for user {user_id}")

    def disconnect(self, websocket: WebSocket):
        user_id = self.user_connections.get(websocket)
        if user_id and user_id in self.active_connections:
            self.active_connections[user_id].remove(websocket)
            if not self.active_connections[user_id]:
                del self.active_connections[user_id]
        self.user_connections.pop(websocket, None)
        logger.info(f"WebSocket disconnected for user {user_id}")

    async def send_to_user(self, user_id: str, message: dict):
        if user_id in self.active_connections:
            dead_connections = []
            for ws in self.active_connections[user_id]:
                try:
                    await ws.send_json(message)
                except Exception as e:
                    logger.error(f"Error sending to websocket: {e}")
                    dead_connections.append(ws)

            # Clean up dead connections
            for ws in dead_connections:
                self.disconnect(ws)

    async def broadcast(self, message: dict):
        for user_id in self.active_connections:
            await self.send_to_user(user_id, message)

    async def broadcast_event(self, event_type: str, data: dict):
        """Broadcast an event to all connected clients"""
        message = {
            "type": event_type,
            "data": data,
            "timestamp": datetime.utcnow().isoformat()
        }
        await self.broadcast(message)


# Global connection manager
manager = ConnectionManager()


@router.websocket("/ws")
async def websocket_endpoint(
        websocket: WebSocket,
        token: str = Query(...)
):
    """
    WebSocket endpoint for real-time alerts
    """
    # Verify token
    payload = decode_token(token)
    if not payload:
        await websocket.close(code=4001, reason="Invalid token")
        return

    user_id = payload.get("sub")
    if not user_id:
        await websocket.close(code=4001, reason="Invalid token payload")
        return

    # Connect
    await manager.connect(websocket, user_id)

    # Subscribe to events
    async def handle_alert(data):
        await manager.send_to_user(user_id, {
            "type": "alert.detected",
            "data": data,
            "timestamp": datetime.utcnow().isoformat()
        })

    async def handle_block(data):
        await manager.send_to_user(user_id, {
            "type": "firewall.blocked",
            "data": data,
            "timestamp": datetime.utcnow().isoformat()
        })

    eventbus.subscribe("alert.detected", handle_alert)
    eventbus.subscribe("firewall.blocked", handle_block)

    try:
        # Keep connection alive
        while True:
            # Wait for messages (can be used for ping/pong)
            try:
                data = await websocket.receive_text()
                # Handle any client messages if needed
                message = json.loads(data)
                if message.get("type") == "ping":
                    await websocket.send_json({"type": "pong", "timestamp": datetime.utcnow().isoformat()})
            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error(f"WebSocket error: {e}")
                break
    except Exception as e:
        logger.error(f"WebSocket connection error: {e}")
    finally:
        manager.disconnect(websocket)