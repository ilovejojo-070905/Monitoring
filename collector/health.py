"""InfraSight's own self-health tracking (directive section 9/27).

Records when the scheduler last successfully ran a poll job, so
GET /api/system/health can report whether the collector itself is alive --
independent of whether any individual monitored device is up or down.
"""
import threading
import time

import storage
from applog import app_logger, safe_log_value

_lock = threading.Lock()
_last_tick_ok = None     # epoch seconds of the last fully-successful scheduler pass
_last_tick_error = None  # (epoch seconds, message) of the last job error, if any


def record_tick_success():
    global _last_tick_ok
    with _lock:
        _last_tick_ok = time.time()


def record_tick_error(message):
    """Also writes to logs/app.log (Phase F) -- before this, a collector
    exception only ever overwrote the single in-memory _last_tick_error slot,
    so anything wrong between two /api/system/health checks left no trace at
    all once the next tick (successful or not) came in."""
    global _last_tick_error
    with _lock:
        _last_tick_error = (time.time(), str(message))
    app_logger.error('collector tick error: %s', safe_log_value(message))


def get_health(stale_after_sec=30):
    with _lock:
        last_ok = _last_tick_ok
        last_error = _last_tick_error
    now = time.time()
    collector_up = last_ok is not None and (now - last_ok) <= stale_after_sec
    db_up = True
    try:
        conn = storage.get_db()
        conn.execute('SELECT 1')
        conn.close()
    except Exception:
        db_up = False
    return {
        'web': 'up',
        'database': 'up' if db_up else 'down',
        'collector': 'up' if collector_up else 'down',
        'collectorLastTick': last_ok,
        'collectorLastError': {'ts': last_error[0], 'message': last_error[1]} if last_error else None,
    }
