"""Local-PC sampler (psutil). Logic moved from server.py's sample_local()
unchanged -- resource-threshold status stays immediate by default (not the
Phase 1 consecutive-failure smoothing in collector.state.evaluate_status,
which is a reachability-only concept), but 2-2 makes "immediate" a
configurable default rather than the only option -- see
collector/thresholds.py's sustainedSec."""
import os
import time

import psutil

from collector import state, thresholds
from collector.state import push_cap
import storage

IS_WINDOWS = storage.IS_WINDOWS

_last_net = None
_last_net_t = 0.0
_last_nics = {}


def prime_psutil():
    global _last_net, _last_net_t, _last_nics
    psutil.cpu_percent(interval=None)
    for p in psutil.process_iter(['name']):
        try:
            p.cpu_percent(None)
        except Exception:
            pass
    _last_net = psutil.net_io_counters()
    _last_net_t = time.time()
    try:
        _last_nics = psutil.net_io_counters(pernic=True)
    except Exception:
        _last_nics = {}


def sample_disks():
    out = []
    try:
        parts = psutil.disk_partitions(all=False)
    except Exception:
        parts = []
    for p in parts:
        try:
            u = psutil.disk_usage(p.mountpoint)
        except Exception:
            continue
        out.append({
            'mount': p.mountpoint, 'total': round(u.total / 1_073_741_824, 1),
            'used': round(u.used / 1_073_741_824, 1), 'pct': round(u.percent, 1),
        })
    return out[:12]


def sample_nics(dt):
    global _last_nics
    out = []
    try:
        current = psutil.net_io_counters(pernic=True)
    except Exception:
        current = {}
    for name, c in current.items():
        prev = _last_nics.get(name)
        if prev is None:
            in_mbps = out_mbps = 0.0
        else:
            in_mbps = max((c.bytes_recv - prev.bytes_recv) * 8 / dt / 1_000_000, 0)
            out_mbps = max((c.bytes_sent - prev.bytes_sent) * 8 / dt / 1_000_000, 0)
        if c.bytes_recv or c.bytes_sent:
            out.append({'name': name, 'inMbps': round(in_mbps, 2), 'outMbps': round(out_mbps, 2)})
    out.sort(key=lambda x: x['inMbps'] + x['outMbps'], reverse=True)
    _last_nics = current
    return out[:10]


def sample_services():
    if not IS_WINDOWS:
        return {'running': 0, 'total': 0, 'stoppedAutoStart': []}
    running = 0
    total = 0
    anomalies = []
    try:
        for svc in psutil.win_service_iter():
            try:
                info = svc.as_dict()
            except Exception:
                continue
            total += 1
            if info.get('status') == 'running':
                running += 1
            elif info.get('start_type') == 'automatic':
                anomalies.append({'name': info.get('display_name') or info.get('name'), 'status': info.get('status')})
    except Exception:
        pass
    return {'running': running, 'total': total, 'stoppedAutoStart': anomalies[:30]}


def sample_local(entity, device_row):
    global _last_net, _last_net_t
    if _last_net is None:
        prime_psutil()
    cpu = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory().percent
    try:
        disk = psutil.disk_usage('C:\\' if IS_WINDOWS else '/').percent
    except Exception:
        disk = 0.0
    now = time.time()
    net = psutil.net_io_counters()
    dt = max(now - _last_net_t, 0.5)
    net_in = max((net.bytes_recv - _last_net.bytes_recv) * 8 / dt / 1_000_000, 0)
    net_out = max((net.bytes_sent - _last_net.bytes_sent) * 8 / dt / 1_000_000, 0)
    nics = sample_nics(dt)
    _last_net, _last_net_t = net, now
    try:
        load = os.getloadavg()[0]
    except Exception:
        load = round(cpu / 25, 2)
    uptime_days = round((time.time() - psutil.boot_time()) / 86400, 1)
    ncpu = psutil.cpu_count() or 1
    procs = []
    for p in psutil.process_iter(['name', 'cpu_percent', 'memory_percent']):
        try:
            info = p.info
            procs.append({
                'name': info.get('name') or '-',
                'pct': round((info.get('cpu_percent') or 0.0) / ncpu, 1),
                'memPct': round(info.get('memory_percent') or 0.0, 1),
            })
        except Exception:
            pass
    procs.sort(key=lambda x: x['pct'], reverse=True)
    disks = sample_disks()
    services = sample_services()
    device_thresholds = thresholds.resolve_thresholds(device_row)
    status, incident_event = thresholds.evaluate_resource(device_row['id'], cpu, mem, disk, device_thresholds)
    # Code review pass, finding #5: psutil gathering above stays unlocked
    # (it's the slow part, and this is the only device that ever runs on
    # this collector so there's no cross-device parallelism to lose
    # anyway) -- only the dict mutation itself needs to be atomic against
    # /api/state reading the same entity concurrently.
    with state.LOCK:
        entity.update(mode='local', online=True, reachable=True, latencyMs=0,
                      cpu=round(cpu, 1), mem=round(mem, 1), disk=round(disk, 1),
                      netIn=round(net_in, 2), netOut=round(net_out, 2), load=round(load, 2),
                      uptime=uptime_days, status=status, procs=procs[:12],
                      disks=disks, nics=nics, services=services)
        push_cap(entity['hist']['cpu'], entity['cpu'])
        push_cap(entity['hist']['mem'], entity['mem'])
        push_cap(entity['hist']['net'], round(net_in + net_out, 2))
    # This PC is always "reachable" to itself -- there's no reachability
    # failure mode here -- but it still needs last_collected_at/
    # last_success_at populated, otherwise the device-status view would show
    # "미수집" forever for the one device that's actually the most reliable.
    now_ms = int(time.time() * 1000)
    storage.update_failure_state(device_row['id'], 0, None, now_ms, now_ms, device_row.get('last_failure_at'))
    if incident_event:
        maint = storage.in_maintenance(device_row)
        kind, new_status = incident_event
        if kind == 'escalate':
            storage.add_incident(new_status, device_row['name'], 'SMS',
                                  f"리소스 사용률 {'임계치 초과' if new_status=='crit' else '주의 구간 진입'} (CPU {cpu:.0f}% / MEM {mem:.0f}%)",
                                  device_id=device_row['id'], event_type='RESOURCE', maintenance=maint)
        else:
            storage.add_incident('info', device_row['name'], 'SMS',
                                  f"{device_row['name']} 리소스 사용률 정상 범위로 복구",
                                  device_id=device_row['id'], event_type='RESOURCE', maintenance=maint)
