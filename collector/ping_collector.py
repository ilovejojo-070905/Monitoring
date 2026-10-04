"""Ping/TCP-reachability sampler. Logic moved from server.py's sample_ping()
(plus ping_host/tcp_check/DB_PORTS) with two Phase 1 additions:
  - per-device timeout_sec / retry_count (falls back to the old hardcoded
    1.0s / 0 retries when a device doesn't set them, so behavior for existing
    devices is unchanged)
  - status now comes from collector.state.evaluate_status() instead of
    flipping straight to 'crit' on the very first failed poll
"""
import socket
import subprocess
import time

import storage
import validation
from collector import state
from collector.state import push_cap, evaluate_status

IS_WINDOWS = storage.IS_WINDOWS

DB_PORTS = {'Oracle': 1521, 'MySQL': 3306, 'PostgreSQL': 5432, 'MS-SQL': 1433, 'MongoDB': 27017, 'Redis': 6379}

DEFAULT_TIMEOUT_SEC = 1.0
DEFAULT_RETRY_COUNT = 0


def ping_host(ip, timeout_s=1.0):
    if not ip:
        return False, None
    # Defense in depth on top of the registration-time check in
    # api_register_device: refuse to build a ping command from anything that
    # isn't a plain IPv4/hostname. Without this, a value starting with '-'
    # would be read as a ping flag rather than a target (argument injection)
    # -- this only ever matters for a device whose IP predates that
    # validation, or was written directly to the DB.
    if not validation.is_valid_host(ip):
        return False, None
    try:
        if IS_WINDOWS:
            cmd = ['ping', '-n', '1', '-w', str(int(timeout_s * 1000)), ip]
        else:
            cmd = ['ping', '-c', '1', '-W', str(int(max(timeout_s, 1))), ip]
        start = time.time()
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 timeout=timeout_s + 1.5)
        elapsed = round((time.time() - start) * 1000, 1)
        return result.returncode == 0, elapsed
    except Exception:
        return False, None


def tcp_check(ip, port, timeout_s=1.0):
    try:
        start = time.time()
        with socket.create_connection((ip, port), timeout=timeout_s):
            return True, round((time.time() - start) * 1000, 1)
    except Exception:
        return False, None


def _attempt(ip, port, timeout_s):
    if port:
        reachable, latency = tcp_check(ip, int(port), timeout_s)
        if not reachable:
            reachable, latency = ping_host(ip, timeout_s)
    else:
        reachable, latency = ping_host(ip, timeout_s)
    return reachable, latency


def sample_ping(entity, device_row):
    ip = device_row['ip']
    fields = device_row['fields']
    port = DB_PORTS.get(fields.get('engine')) if device_row['category'] == 'db' else fields.get('port')
    timeout_s = device_row.get('timeout_sec') or DEFAULT_TIMEOUT_SEC
    retry_count = device_row.get('retry_count')
    try:
        retry_count = DEFAULT_RETRY_COUNT if retry_count is None else int(retry_count)
    except (TypeError, ValueError):
        retry_count = DEFAULT_RETRY_COUNT

    reachable, latency = _attempt(ip, port, timeout_s)
    tries = 1
    while not reachable and tries <= retry_count:
        reachable, latency = _attempt(ip, port, timeout_s)
        tries += 1

    prev_failures = device_row.get('consecutive_failures') or 0
    failures = 0 if reachable else prev_failures + 1
    status = evaluate_status(failures)
    # Code review pass, finding #5: the network I/O above (ping/TCP attempts,
    # up to retry_count+1 of them) deliberately stays outside this lock --
    # that's the whole point of each device getting its own worker thread.
    # Only the actual shared-dict read-then-write is a real race with
    # /api/state reading the same entity concurrently, so only this part
    # needs to be atomic.
    with state.LOCK:
        prev_status = entity.get('status', 'good')
        entity.update(mode='ping', online=True, reachable=reachable, latencyMs=latency, status=status)
        push_cap(entity['hist']['latency'], latency if latency is not None else 0)

    now_ms = int(time.time() * 1000)
    storage.update_failure_state(
        device_row['id'], failures,
        None if reachable else 'PING_TIMEOUT',
        now_ms if reachable else device_row.get('last_success_at'),
        now_ms,
        device_row.get('last_failure_at') if reachable else now_ms)

    rank = {'good': 0, 'warn': 1, 'crit': 2}
    maint = storage.in_maintenance(device_row)
    if rank[status] > rank[prev_status]:
        storage.add_incident(status, device_row['name'], storage.category_label(device_row['category']),
                              f"{device_row['name']} 응답 없음 (Ping/포트 확인 실패, 연속 {failures}회)",
                              device_id=device_row['id'], event_type='REACHABILITY', maintenance=maint)
    elif prev_status != 'good' and status == 'good':
        storage.add_incident('info', device_row['name'], storage.category_label(device_row['category']),
                              f"{device_row['name']} 응답 정상 복구",
                              device_id=device_row['id'], event_type='REACHABILITY', maintenance=maint)
