from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import json
import uvicorn
from datetime import datetime
from typing import List, Optional
import sys
import os

# Path setup
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from brain.trust_engine import TrustEngine
from shared.models import SystemEvent, Severity

app = FastAPI()
engine = TrustEngine()
active_connections: List[WebSocket] = []

@app.get("/ping")
async def ping():
    return {"status": "alive", "time": datetime.now().isoformat()}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/status")
async def get_status():
    return {
        "trust_score": engine.trust_score,
        "events_count": len(engine.event_history),
        "actions_count": len(engine.action_history)
    }

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    print(f"[Brain] New Dashboard connected. Total: {len(active_connections)}")
    try:
        while True:
            # Send current state every 2 seconds
            data = {
                "score": engine.trust_score,
                "events": [{"time": e.timestamp.strftime("%H:%M:%S"), "msg": e.description, "severity": e.severity.name.lower(), "source": e.source} for e in reversed(engine.event_history[-20:])],
                "actions": [{"type": a.action_type.value, "target": a.target, "time": a.timestamp.strftime("%H:%M:%S")} for a in reversed(engine.action_history[-10:])],
                "heartbeat": datetime.now().isoformat()
            }
            await websocket.send_json(data)
            await asyncio.sleep(2)
    except Exception as e:
        print(f"[Brain] WebSocket disconnect or error: {e}")
    finally:
        if websocket in active_connections:
            active_connections.remove(websocket)
        print(f"[Brain] Dashboard disconnected. Total: {len(active_connections)}")
        try:
            await websocket.close()
        except:
            pass

@app.post("/inject")
async def receive_event(source: str, description: str, severity: str):
    sev_map = {
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL
    }
    sev = sev_map.get(severity.lower(), Severity.LOW)
    actions = inject_event(source, description, sev)
    return {
        "status": "event_received", 
        "actions": [{"type": a.action_type.value, "target": a.target} for a in actions]
    }

# Internal method to add events from the Agent
def inject_event(source: str, desc: str, sev: Severity):
    event = SystemEvent(
        id=str(len(engine.event_history)),
        timestamp=datetime.now(),
        source=source,
        description=desc,
        severity=sev
    )
    # The brain processes the event and automatically maps it to actions
    actions = engine.process_event(event)
    return actions

@app.on_event("startup")
async def startup_event():
    # Start the trust recovery background task
    asyncio.create_task(trust_recovery_loop())

async def trust_recovery_loop():
    """
    Background Task: Gradually restores trust when no threats are reported.
    """
    while True:
        await asyncio.sleep(5) # Pulse every 5 seconds
        engine.recover_trust()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
