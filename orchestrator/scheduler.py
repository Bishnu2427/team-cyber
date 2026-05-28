"""
Scheduler — task event publishing + agent health monitoring.
The orchestrator publishes scan lifecycle events to Redis channel 'scan:events'.
The backend subscribes and forwards them to WebSocket clients.
"""
import json
import os
import threading
import time

import httpx
import redis


REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

_AGENT_SERVICES = {
    "red-team":  os.getenv("RED_TEAM_URL",  "http://red-team:8001"),
    "blue-team": os.getenv("BLUE_TEAM_URL", "http://blue-team:8002"),
    "verifier":  os.getenv("VERIFIER_URL",  "http://verifier:8003"),
    "reporter":  os.getenv("REPORTER_URL",  "http://reporter:8004"),
}


# ── Event publishing ──────────────────────────────────────────────

def publish(event: str, data: dict) -> None:
    """Publish a structured event to Redis → backend WebSocket bridge."""
    try:
        r = redis.from_url(REDIS_URL)
        r.publish("scan:events", json.dumps({"event": event, "data": data}))
    except Exception as exc:
        print(f"[scheduler] Redis publish error: {exc}")


def progress(scan_id: str, pct: int, message: str) -> None:
    publish("scan_progress", {"scan_id": scan_id, "progress": pct, "message": message})


def complete(scan_id: str, counts: dict, score: float) -> None:
    publish("scan_complete", {
        "scan_id": scan_id,
        "findings_count": counts,
        "compliance_score": score,
    })


def error(scan_id: str, message: str) -> None:
    publish("scan_error", {"scan_id": scan_id, "error": message})


# ── Agent health monitor ──────────────────────────────────────────

def _monitor_loop() -> None:
    """Background thread: ping agent services every 60 s and log status."""
    while True:
        for name, url in _AGENT_SERVICES.items():
            try:
                r = httpx.get(f"{url}/health", timeout=5)
                status = "UP" if r.status_code == 200 else f"DEGRADED ({r.status_code})"
            except Exception:
                status = "DOWN"
            print(f"[monitor] {name}: {status}")
        time.sleep(60)


def start_monitor() -> None:
    t = threading.Thread(target=_monitor_loop, daemon=True)
    t.start()
