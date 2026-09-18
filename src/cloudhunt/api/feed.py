"""Live case feed over WebSockets.

A minimal broadcast hub: each connected client gets a snapshot of current cases
on connect, then ``case_updated`` messages as actions are approved. Kept
deliberately small — no per-client backpressure or replay, which is fine for a
dashboard that can re-fetch on reconnect.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect

from cloudhunt.api.casestore import CaseService, get_case_service

router = APIRouter(tags=["feed"])


class ConnectionManager:
    def __init__(self) -> None:
        self.active: set[WebSocket] = set()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.active.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self.active.discard(ws)

    async def broadcast(self, message: dict) -> None:
        for ws in list(self.active):
            try:
                await ws.send_json(message)
            except Exception:
                self.disconnect(ws)


manager = ConnectionManager()


@router.websocket("/ws/cases")
async def ws_cases(ws: WebSocket, svc: CaseService = Depends(get_case_service)) -> None:
    await manager.connect(ws)
    try:
        await ws.send_json({"type": "snapshot", "cases": svc.list_cases()})
        while True:
            await ws.receive_text()          # keep-alive; ignore client chatter
    except WebSocketDisconnect:
        manager.disconnect(ws)
