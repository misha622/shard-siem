from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from typing import Dict, List
import json, logging
from datetime import datetime
from app.eventbus import eventbus
from app.auth import decode_token

logger = logging.getLogger(__name__)
router = APIRouter()

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}
        self.user_connections: Dict[WebSocket, str] = {}

    async def connect(self, ws: WebSocket, user_id: str):
        await ws.accept()
        self.active_connections.setdefault(user_id, []).append(ws)
        self.user_connections[ws] = user_id

    def disconnect(self, ws: WebSocket):
        user_id = self.user_connections.pop(ws, None)
        if user_id and user_id in self.active_connections:
            self.active_connections[user_id].remove(ws)
            if not self.active_connections[user_id]:
                del self.active_connections[user_id]

    async def send_to_user(self, user_id: str, msg: dict):
        if user_id in self.active_connections:
            for ws in self.active_connections[user_id][:]:
                try: await ws.send_json(msg)
                except: self.disconnect(ws)

    async def broadcast(self, msg: dict):
        for uid in list(self.active_connections.keys()):
            await self.send_to_user(uid, msg)

manager = ConnectionManager()

@router.websocket("/ws")
async def ws_endpoint(websocket: WebSocket, token: str = Query(...)):
    payload = decode_token(token)
    if not payload: return await websocket.close(code=4001)
    user_id = payload.get("sub")
    if not user_id: return await websocket.close(code=4001)
    await manager.connect(websocket, user_id)
    try:
        while True:
            data = await websocket.receive_text()
            msg = json.loads(data)
            if msg.get("type") == "ping":
                await websocket.send_json({"type": "pong", "timestamp": datetime.utcnow().isoformat()})
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        manager.disconnect(websocket)
