"""Local-PC sampler (psutil). Logic moved from server.py's sample_local()
unchanged -- only the CPU/mem/disk threshold status stays "immediate" (this
is a resource-threshold check, not a reachability check, so the Phase 1
consecutive-failure smoothing in collector.state.evaluate_status doesn't
apply here)."""
import os
import time

import psutil

from collector.state import push_cap
import storage

IS_WINDOWS = storage.IS_WINDOWS

_last_net = None
_last_net_t = 0.0


def prime_psutil():
    global _last_net, _last_net_t
    psutil.cpu_percent(interval=None)
    for p in psutil.process_iter(['name']):
        try:
            p.cpu_percent(None)
        except Exception:
            pass
    _last_net = psutil.net_io_counters()
    _last_net_t = time.time()


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
    _last_net, _last_net_t = net, now
    try:
        load = os.getloadavg()[0]
    except Exception:
        load = round(cpu / 25, 2)
    uptime_days = round((time.time() - psutil.boot_time()) / 86400, 1)
    ncpu = psutil.cpu_count() or 1
    procs = []
    for p in psutil.process_iter(['name', 'cpu_percent']):
        try:
            info = p.info
            procs.append({'name': info.get('name') or '-', 'pct': round((info.get('cpu_percent') or 0.0) / ncpu, 1)})
        except Exception:
            pass
    procs.sort(key=lambda x: x['pct'], reverse=True)
    status = 'crit' if (cpu >= 90 or mem >= 92 or disk >= 92) else 'warn' if (cpu >= 75 or mem >= 80 or disk >= 80) else 'good'
    prev_status = entity.get('status', 'good')
    entity.update(mode='local', online=True, reachable=True, latencyMs=0,
                  cpu=round(cpu, 1), mem=round(mem, 1), disk=round(disk, 1),
                  netIn=round(net_in, 2), netOut=round(net_out, 2), load=round(load, 2),
                  uptime=uptime_days, status=status, procs=procs[:6])
    push_cap(entity['hist']['cpu'], entity['cpu'])
    push_cap(entity['hist']['mem'], entity['mem'])
    push_cap(entity['hist']['net'], round(net_in + net_out, 2))
    if storage.in_maintenance(device_row):
        return
    rank = {'good': 0, 'warn': 1, 'crit': 2}
    if rank[status] > rank[prev_status]:
        storage.add_incident(status, device_row['name'], 'SMS',
                              f"리소스 사용률 {'임계치 초과' if status=='crit' else '주의 구간 진입'} (CPU {cpu:.0f}% / MEM {mem:.0f}%)",
                              device_id=device_row['id'], event_type='RESOURCE')
    elif status == 'good' and prev_status != 'good':
        storage.add_incident('info', device_row['name'], 'SMS',
                              f"{device_row['name']} 리소스 사용률 정상 범위로 복구",
                              device_id=device_row['id'], event_type='RESOURCE')
