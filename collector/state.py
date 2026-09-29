"""
In-memory live state shared by every collector module and read by server.py's
API routes. This is exactly the LIVE/LOCK/LAST_REPORT/hist/push_cap/ensure_entity
set that used to live at the top of server.py -- only the location changed
(server.py:0-3 in the Phase 1 analysis noted these were already reusable
as-is), so entity/hist shapes are byte-for-byte identical to before.
"""
import threading

HIST_LEN = 30

LOCK = threading.Lock()
LIVE = {}          # device_id -> metrics dict (see shapes below)
LAST_REPORT = {}   # device_id -> epoch seconds of last agent report


def hist(v=0):
    return [v] * HIST_LEN


def push_cap(arr, v):
    arr.append(v)
    if len(arr) > HIST_LEN:
        arr.pop(0)


def level_of(pct, warn_at, crit_at):
    return 'crit' if pct >= crit_at else 'warn' if pct >= warn_at else 'good'


def evaluate_status(consecutive_failures, warn_at=1, down_at=2):
    """Turns a run of consecutive reachability failures into a status.

    Replaces the old pattern (repeated in sample_ping/sample_snmp/sample_agent)
    of going straight from 'good' to 'crit' on a single failed poll -- which is
    exactly what produced a false DOWN alarm during a transient network change
    observed earlier in this project. One failure now reads as 'warn'; it only
    escalates to 'crit' once it persists across `down_at` consecutive polls.
    """
    if consecutive_failures <= 0:
        return 'good'
    if consecutive_failures >= down_at:
        return 'crit'
    if consecutive_failures >= warn_at:
        return 'warn'
    return 'good'


def ensure_entity(device):
    did = device['id']
    if did not in LIVE:
        if device['mode'] == 'ping':
            LIVE[did] = {'status': 'good', 'reachable': True, 'latencyMs': None, 'hist': {'latency': hist(0)}}
        elif device['mode'] == 'snmp':
            LIVE[did] = {'status': 'good', 'reachable': True, 'latencyMs': None, 'hist': {'latency': hist(0)}}
        elif device['mode'] == 'agent':
            LIVE[did] = {'status': 'warn', 'online': False, 'reachable': False, 'cpu': 0, 'mem': 0, 'disk': 0,
                         'netIn': 0, 'netOut': 0, 'load': 0, 'uptime': 0, 'procs': [],
                         'hist': {'cpu': hist(0), 'mem': hist(0), 'net': hist(0)}}
        else:
            LIVE[did] = {'status': 'good', 'cpu': 0, 'mem': 0, 'disk': 0, 'netIn': 0, 'netOut': 0, 'load': 0,
                         'uptime': 0, 'procs': [], 'hist': {'cpu': hist(0), 'mem': hist(0), 'net': hist(0)}}
    return LIVE[did]
