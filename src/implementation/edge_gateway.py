"""
SentinelOTA Edge Gateway — Backwards-Compatible Entry Point

This file preserves the original `uvicorn edge_gateway:app` usage.
The actual implementation now lives in the `gateway/` package.

Usage:
    uvicorn edge_gateway:app --host 0.0.0.0 --port 5000
    # OR
    uvicorn gateway:app --host 0.0.0.0 --port 5000
    # OR
    python edge_gateway.py
"""

from gateway import app  # noqa: F401
from gateway.config import HOST, PORT

if __name__ == '__main__':
    import uvicorn
    print(f"[*] Starting SentinelOTA FastAPI gateway on {HOST}:{PORT}...")
    uvicorn.run(app, host=HOST, port=PORT, reload=False)
