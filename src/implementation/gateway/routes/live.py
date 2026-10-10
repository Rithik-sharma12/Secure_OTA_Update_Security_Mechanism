"""
SentinelOTA Edge Gateway — Route: Live change stream (Server-Sent Events)

    GET /api/stream

Emits `event: state` whenever the gateway persists a change (heartbeat,
deployment, command result, release...), carrying the new revision number.
Dashboards refresh on that signal instead of polling every few seconds, so a
device's OTA phase or a command result shows up within about a second.

Deliberately content-free: the event says *that* something changed, and the
client fetches what it is allowed to see through its normal authenticated
routes. A comment line every 15 s keeps proxies (Cloudflare, nginx) from
closing an idle stream, and the stream ends after `max_seconds` so clients
reconnect periodically and a forgotten tab cannot hold a worker forever.
"""

from __future__ import annotations

import asyncio
import json
import time

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse

from ..state import state_revision
from ..utils import utc_now_iso

router = APIRouter()

POLL_SECONDS = 0.5
KEEPALIVE_SECONDS = 15.0


@router.get('/api/stream')
async def stream_changes(max_seconds: float = Query(default=300.0, ge=1.0, le=3600.0)) -> StreamingResponse:
    async def events():
        started = time.monotonic()
        last_revision = state_revision()
        last_sent = started
        # Tell the client where it starts; it can fetch once and then wait.
        yield f"retry: 3000\nevent: hello\ndata: {json.dumps({'revision': last_revision, 'at': utc_now_iso()})}\n\n"
        while time.monotonic() - started < max_seconds:
            await asyncio.sleep(POLL_SECONDS)
            revision = state_revision()
            now = time.monotonic()
            if revision != last_revision:
                last_revision = revision
                last_sent = now
                yield f"event: state\ndata: {json.dumps({'revision': revision, 'at': utc_now_iso()})}\n\n"
            elif now - last_sent >= KEEPALIVE_SECONDS:
                last_sent = now
                yield ': keepalive\n\n'
        yield 'event: bye\ndata: {}\n\n'

    return StreamingResponse(
        events(),
        media_type='text/event-stream',
        headers={'Cache-Control': 'no-store', 'X-Accel-Buffering': 'no'},
    )
