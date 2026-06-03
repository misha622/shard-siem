from fastapi import APIRouter, WebSocket
router = APIRouter()

@router.websocket("/ws")
async def ws(websocket: WebSocket, token: str = ""):
    await websocket.accept()
    await websocket.send_json({"type": "connected"})
