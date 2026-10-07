"""Phase 5: persists the same numbers that already go into each entity's
in-memory hist[] arrays into metrics_raw, so history survives a server
restart. Deliberately mirrors what each collector already pushes into
hist{} (collector.state.push_cap) rather than inventing a new metric set:
  cpu / mem / disk   -- local & agent devices
  latency            -- ping & snmp devices
  net                -- local & agent (netIn+netOut combined, matches hist.net)
  traffic            -- snmp 'net' category devices (trafficIn+trafficOut, matches hist.traffic)

record_entity_metrics() is called from every device's own poll-tick thread
(collector/scheduler.py's per-device interval job) PLUS every agent report
(server.py's /api/agent/report) -- on a deployment with enough devices, that
can be dozens of independent threads each wanting to INSERT+commit roughly
every couple seconds. SQLite only ever allows one writer at a time no matter
how many connections ask (WAL mode makes that fast, not concurrent), so each
of those used to open its own short-lived connection and race every other
one for that single writer slot. Confirmed live on a deployment with enough
registered devices: frequent 'database is locked' errors in the collector
tick log, and -- because an admin action (bulk-delete) competes for that
exact same lock -- occasional outright request failures too.
Funneling every write through one background thread via a thread-safe
Queue fixes the actual contention (many writers -> one), not just a
symptom of it: producers (the poll-tick threads) just enqueue and return
immediately, and this one thread does the real INSERT, batching whatever
arrived together into a single transaction when a burst lands at once.
"""
import queue
import threading
import time

import storage

_queue = queue.Queue()
_writer_thread = None
_writer_lock = threading.Lock()


def _writer_loop():
    while True:
        batch = [_queue.get()]
        try:
            while True:
                batch.append(_queue.get_nowait())
        except queue.Empty:
            pass
        rows = [r for rows in batch for r in rows]
        try:
            storage.record_metrics(rows)
        except Exception:
            pass  # never let one bad batch take down the only writer thread


def _ensure_writer_started():
    global _writer_thread
    if _writer_thread is not None:
        return
    with _writer_lock:
        if _writer_thread is not None:
            return
        _writer_thread = threading.Thread(target=_writer_loop, name='metrics-writer', daemon=True)
        _writer_thread.start()


def record_entity_metrics(device_id, entity):
    now = int(time.time() * 1000)
    rows = []

    def add(metric, value):
        if value is not None:
            rows.append((device_id, metric, now, float(value)))

    add('cpu', entity.get('cpu'))
    add('mem', entity.get('mem'))
    add('disk', entity.get('disk'))
    add('latency', entity.get('latencyMs'))
    if entity.get('netIn') is not None and entity.get('netOut') is not None:
        add('net', entity['netIn'] + entity['netOut'])
    if entity.get('trafficIn') is not None and entity.get('trafficOut') is not None:
        add('traffic', entity['trafficIn'] + entity['trafficOut'])

    if not rows:
        return
    _ensure_writer_started()
    _queue.put(rows)
