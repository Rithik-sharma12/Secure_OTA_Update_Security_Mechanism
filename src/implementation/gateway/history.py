"""
SentinelOTA Edge Gateway — Durable History (audit trail and telemetry)

gateway_state.json holds the *current* picture: latest heartbeat per device,
the newest 500 events. That is the wrong shape for two questions people ask
after something goes wrong:

  * who deployed / restarted / removed what, and when?      -> audit
  * how did this board's health, signal and memory trend?    -> telemetry

Both are append-only time series, so they live in SQLite next to the state
file instead of being rewritten wholesale on every heartbeat. SQLite ships with
Python, needs no server, and survives container restarts on the same volume as
the firmware cache.

Thread-safety: FastAPI runs sync endpoints in a thread pool, so one connection
is shared behind a lock (check_same_thread=False). Writes are tiny and the
lock is held for microseconds.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from typing import Any

from .config import FIRMWARE_CACHE_DIR

HISTORY_DB_PATH = FIRMWARE_CACHE_DIR / 'history.db'

TELEMETRY_RETENTION_DAYS = float(os.getenv('OTA_TELEMETRY_RETENTION_DAYS', '7'))
AUDIT_MAX_ROWS = int(os.getenv('OTA_AUDIT_MAX_ROWS', '50000'))
_PRUNE_EVERY = 500

_LOCK = threading.Lock()
_CONN: sqlite3.Connection | None = None
_WRITES_SINCE_PRUNE = 0

_SCHEMA = """
CREATE TABLE IF NOT EXISTS telemetry (
    device_id TEXT NOT NULL,
    ts        REAL NOT NULL,
    ash       INTEGER,
    rssi      INTEGER,
    memory    REAL,
    cpu       REAL,
    uptime    REAL,
    fw        TEXT
);
CREATE INDEX IF NOT EXISTS telemetry_device_ts ON telemetry(device_id, ts);

CREATE TABLE IF NOT EXISTS audit (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT NOT NULL,
    actor      TEXT NOT NULL,
    source_ip  TEXT,
    method     TEXT NOT NULL,
    path       TEXT NOT NULL,
    status     INTEGER NOT NULL,
    action     TEXT,
    detail     TEXT,
    device_id  TEXT
);
CREATE INDEX IF NOT EXISTS audit_ts ON audit(ts);
CREATE INDEX IF NOT EXISTS audit_device ON audit(device_id);
"""


def _connection() -> sqlite3.Connection:
    global _CONN
    if _CONN is None:
        HISTORY_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(HISTORY_DB_PATH), check_same_thread=False, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=NORMAL')
        conn.executescript(_SCHEMA)
        _CONN = conn
    return _CONN


def _maybe_prune_locked(conn: sqlite3.Connection) -> None:
    global _WRITES_SINCE_PRUNE
    _WRITES_SINCE_PRUNE += 1
    if _WRITES_SINCE_PRUNE < _PRUNE_EVERY:
        return
    _WRITES_SINCE_PRUNE = 0
    cutoff = time.time() - TELEMETRY_RETENTION_DAYS * 86400
    conn.execute('DELETE FROM telemetry WHERE ts < ?', (cutoff,))
    conn.execute(
        'DELETE FROM audit WHERE id <= (SELECT MAX(id) FROM audit) - ?',
        (AUDIT_MAX_ROWS,),
    )


# ── Telemetry ─────────────────────────────────────────────────

def record_telemetry(device_id: str, sample: dict[str, Any], ts: float | None = None) -> None:
    """Append one heartbeat sample. Never raises: history is best-effort."""
    try:
        with _LOCK:
            conn = _connection()
            conn.execute(
                'INSERT INTO telemetry(device_id, ts, ash, rssi, memory, cpu, uptime, fw) VALUES (?,?,?,?,?,?,?,?)',
                (
                    device_id,
                    ts if ts is not None else time.time(),
                    sample.get('ash'),
                    sample.get('rssi'),
                    sample.get('memory'),
                    sample.get('cpu'),
                    sample.get('uptime'),
                    sample.get('fw'),
                ),
            )
            _maybe_prune_locked(conn)
    except sqlite3.Error:
        pass


def telemetry_series(device_id: str, hours: float = 24.0, points: int = 240) -> dict[str, Any]:
    """Bucketed averages over the last `hours`, at most `points` buckets.

    Averaging keeps the response small for a 7-day window (40k raw samples at
    one per 15 s) while preserving the shape of the trend. Firmware version is
    the last value seen in each bucket so upgrades show as a step.
    """
    hours = max(0.25, min(hours, TELEMETRY_RETENTION_DAYS * 24))
    points = max(10, min(points, 1000))
    now = time.time()
    since = now - hours * 3600
    step = max(15.0, (hours * 3600) / points)

    with _LOCK:
        conn = _connection()
        rows = conn.execute(
            """
            SELECT CAST((ts - ?) / ? AS INTEGER) AS bucket,
                   MIN(ts) AS t0, COUNT(*) AS n,
                   AVG(ash) AS ash, MIN(ash) AS ash_min,
                   AVG(rssi) AS rssi, AVG(memory) AS memory, AVG(cpu) AS cpu,
                   MAX(uptime) AS uptime
            FROM telemetry
            WHERE device_id = ? AND ts >= ?
            GROUP BY bucket
            ORDER BY bucket
            """,
            (since, step, device_id, since),
        ).fetchall()
        # Last firmware version reported in each bucket, so an upgrade shows
        # as a step rather than an average of two version strings.
        last_fw: dict[int, str] = {}
        for fw_row in conn.execute(
            'SELECT CAST((ts - ?) / ? AS INTEGER) AS bucket, fw FROM telemetry '
            'WHERE device_id = ? AND ts >= ? ORDER BY ts',
            (since, step, device_id, since),
        ):
            last_fw[fw_row['bucket']] = fw_row['fw']
        total = conn.execute(
            'SELECT COUNT(*) FROM telemetry WHERE device_id = ? AND ts >= ?', (device_id, since)
        ).fetchone()[0]

    def _round(value: Any, digits: int = 1) -> Any:
        return None if value is None else round(float(value), digits)

    series = [
        {
            't': datetime.fromtimestamp(since + row['bucket'] * step, timezone.utc).replace(microsecond=0).isoformat(),
            'samples': row['n'],
            'ash': _round(row['ash']),
            'ashMin': row['ash_min'],
            'rssi': _round(row['rssi']),
            'memory': _round(row['memory']),
            'cpu': _round(row['cpu']),
            'uptime': _round(row['uptime'], 0),
            'fw': last_fw.get(row['bucket']),
        }
        for row in rows
    ]
    return {
        'deviceId': device_id,
        'hours': hours,
        'bucketSeconds': round(step),
        'rawSamples': total,
        'points': series,
        'retentionDays': TELEMETRY_RETENTION_DAYS,
    }


# ── Audit ─────────────────────────────────────────────────────

def record_audit(
    *,
    actor: str,
    source_ip: str | None,
    method: str,
    path: str,
    status: int,
    action: str | None = None,
    detail: str | None = None,
    device_id: str | None = None,
) -> None:
    try:
        with _LOCK:
            conn = _connection()
            conn.execute(
                'INSERT INTO audit(ts, actor, source_ip, method, path, status, action, detail, device_id) '
                'VALUES (?,?,?,?,?,?,?,?,?)',
                (
                    datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
                    actor[:128],
                    (source_ip or '')[:64],
                    method,
                    path[:256],
                    status,
                    (action or '')[:64] or None,
                    (detail or '')[:500] or None,
                    (device_id or '')[:64] or None,
                ),
            )
            _maybe_prune_locked(conn)
    except sqlite3.Error:
        pass


def audit_entries(
    limit: int = 200,
    before_id: int | None = None,
    device_id: str | None = None,
    actor: str | None = None,
    action: str | None = None,
) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 1000))
    clauses, args = [], []
    if before_id:
        clauses.append('id < ?')
        args.append(before_id)
    if device_id:
        clauses.append('device_id = ?')
        args.append(device_id)
    if actor:
        clauses.append('actor LIKE ?')
        args.append(f'%{actor}%')
    if action:
        clauses.append('action = ?')
        args.append(action)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ''
    with _LOCK:
        rows = _connection().execute(
            f'SELECT * FROM audit {where} ORDER BY id DESC LIMIT ?', (*args, limit)
        ).fetchall()
    return [
        {
            'id': row['id'],
            'timestamp': row['ts'],
            'actor': row['actor'],
            'sourceIp': row['source_ip'],
            'method': row['method'],
            'path': row['path'],
            'status': row['status'],
            'action': row['action'],
            'detail': row['detail'],
            'deviceId': row['device_id'],
        }
        for row in rows
    ]


def reset_for_tests() -> None:
    """Close the connection so a test can point HISTORY_DB_PATH elsewhere."""
    global _CONN
    with _LOCK:
        if _CONN is not None:
            _CONN.close()
            _CONN = None
