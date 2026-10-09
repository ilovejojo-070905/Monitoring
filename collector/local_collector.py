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

if IS_WINDOWS:
    import winreg
    try:
        import win32evtlog
        WIN32EVTLOG_AVAILABLE = True
    except Exception:
        WIN32EVTLOG_AVAILABLE = False
else:
    WIN32EVTLOG_AVAILABLE = False

_last_net = None
_last_net_t = 0.0
_last_nics = {}
_last_disk_io = {}


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


def sample_disk_io(dt):
    """Same cumulative-counter-to-rate shape as sample_nics() above, just
    read_bytes/write_bytes (-> MB/s) and read_count/write_count (-> IOPS)
    instead of bytes_recv/bytes_sent. perdisk=True keys are physical-device
    names (e.g. 'PhysicalDrive0' on Windows), not mountpoints -- this is
    deliberately a separate list from sample_disks()'s per-partition
    capacity breakdown rather than merged into it, since one physical disk
    can back multiple partitions (or vice versa with striping)."""
    global _last_disk_io
    out = []
    try:
        current = psutil.disk_io_counters(perdisk=True) or {}
    except Exception:
        current = {}
    for name, c in current.items():
        prev = _last_disk_io.get(name)
        if prev is None:
            read_mbps = write_mbps = read_iops = write_iops = 0.0
        else:
            read_mbps = max((c.read_bytes - prev.read_bytes) / dt / 1_048_576, 0)
            write_mbps = max((c.write_bytes - prev.write_bytes) / dt / 1_048_576, 0)
            read_iops = max((c.read_count - prev.read_count) / dt, 0)
            write_iops = max((c.write_count - prev.write_count) / dt, 0)
        out.append({
            'name': name, 'readMBps': round(read_mbps, 2), 'writeMBps': round(write_mbps, 2),
            'readIOPS': round(read_iops, 1), 'writeIOPS': round(write_iops, 1),
        })
    out.sort(key=lambda x: x['readMBps'] + x['writeMBps'], reverse=True)
    _last_disk_io = current
    return out[:12]


def sample_users():
    out = []
    try:
        for u in psutil.users():
            out.append({'name': u.name, 'terminal': u.terminal or '-', 'host': u.host or '',
                        'startedAt': int(u.started * 1000)})
    except Exception:
        pass
    return out[:20]


def sample_mem_detail():
    """virtual_memory()'s cached/buffers fields are Linux-only (0/absent on
    Windows) -- reported as None there rather than a misleading 0, so the UI
    can tell "no cache to report" apart from "this platform doesn't expose
    it". available and swap are cross-platform and the actually-useful
    numbers on Windows."""
    try:
        vm = psutil.virtual_memory()
        sw = psutil.swap_memory()
    except Exception:
        return None
    return {
        'totalGB': round(vm.total / 1_073_741_824, 2),
        'availableGB': round(vm.available / 1_073_741_824, 2),
        'cachedGB': round(vm.cached / 1_073_741_824, 2) if hasattr(vm, 'cached') and not IS_WINDOWS else None,
        'buffersGB': round(vm.buffers / 1_073_741_824, 2) if hasattr(vm, 'buffers') and not IS_WINDOWS else None,
        'swapUsedGB': round(sw.used / 1_073_741_824, 2),
        'swapTotalGB': round(sw.total / 1_073_741_824, 2),
        'swapPct': round(sw.percent, 1),
    }


_UNINSTALL_KEYS = [
    (r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', False),
    (r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall', False),
    (r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', True),
] if IS_WINDOWS else []


_last_programs_scan_t = 0.0
_cached_programs = []
PROGRAMS_SCAN_INTERVAL_SEC = 300  # installed-programs list barely changes tick to tick


def sample_installed_programs():
    """Cached wrapper around _scan_installed_programs() -- a ~100-300 key
    registry walk every 2s poll tick for a list that changes maybe a few
    times a month is pure waste, so this only actually rescans every
    PROGRAMS_SCAN_INTERVAL_SEC and returns the cached list otherwise (same
    throttle-cache shape as snmp_collector.py's extended_due pattern)."""
    global _last_programs_scan_t, _cached_programs
    now = time.time()
    if now - _last_programs_scan_t >= PROGRAMS_SCAN_INTERVAL_SEC:
        _cached_programs = _scan_installed_programs()
        _last_programs_scan_t = now
    return _cached_programs


def _scan_installed_programs():
    """Registry-based (stdlib winreg, no extra dependency): every installed-
    program's uninstall entry lives under one of these three keys --
    HKLM\\...\\Uninstall for 64-bit apps, the WOW6432Node mirror for 32-bit
    apps on a 64-bit OS (a separate physical key, not something registry
    redirection merges for a direct winreg.OpenKey call the way it would for
    a 32-bit *process*), and HKCU\\...\\Uninstall for per-user installs.
    SystemComponent=1 entries are hidden from Add/Remove Programs on
    purpose (runtime redistributables, update packages, etc.) and skipped
    here for the same reason. Sorted by InstallDate (registry's own
    YYYYMMDD string -- already chronologically sortable as plain text) so
    the most recently installed/updated things surface first."""
    if not IS_WINDOWS:
        return []
    out = []
    seen = set()
    for path, is_hkcu in _UNINSTALL_KEYS:
        hive = winreg.HKEY_CURRENT_USER if is_hkcu else winreg.HKEY_LOCAL_MACHINE
        try:
            key = winreg.OpenKey(hive, path)
        except Exception:
            continue
        try:
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                except OSError:
                    break
                i += 1
                try:
                    sub = winreg.OpenKey(key, subkey_name)
                except Exception:
                    continue
                try:
                    try:
                        name = winreg.QueryValueEx(sub, 'DisplayName')[0]
                    except Exception:
                        continue
                    if not name or name in seen:
                        continue
                    try:
                        if winreg.QueryValueEx(sub, 'SystemComponent')[0]:
                            continue
                    except Exception:
                        pass
                    try:
                        version = winreg.QueryValueEx(sub, 'DisplayVersion')[0]
                    except Exception:
                        version = ''
                    try:
                        publisher = winreg.QueryValueEx(sub, 'Publisher')[0]
                    except Exception:
                        publisher = ''
                    try:
                        install_date = winreg.QueryValueEx(sub, 'InstallDate')[0]
                    except Exception:
                        install_date = ''
                    seen.add(name)
                    out.append({'name': name, 'version': version, 'publisher': publisher, 'installDate': install_date})
                finally:
                    sub.Close()
        finally:
            key.Close()
    out.sort(key=lambda x: x['installDate'] or '', reverse=True)
    return out[:200]


# Windows-only (same guard every other Windows-specific sampler here uses --
# see IS_WINDOWS checks above). The legacy OpenEventLog/ReadEventLog API
# (still fully supported, not deprecated) is simpler and more robust for
# "give me the last N error/warning records" than the newer XML-query
# EvtQuery API -- no formatted message lookup (FormatMessage DLL resolution
# is the slow, failure-prone part of event log reading) is attempted here on
# purpose; source+eventId+level+time is enough to tell someone "go look at
# this in Event Viewer" without the overhead.
_EVENT_LOGS = ('System', 'Application')
_MAX_RECORDS_SCANNED_PER_LOG = 300
_MAX_EVENT_ERRORS_RETURNED = 20
_last_eventlog_scan_t = 0.0
_cached_event_errors = []
EVENTLOG_SCAN_INTERVAL_SEC = 30


def sample_event_errors():
    """Cached wrapper around _scan_event_errors() -- same throttle shape as
    sample_installed_programs() above, just a shorter interval since event
    log errors are more time-sensitive than an installed-programs list."""
    global _last_eventlog_scan_t, _cached_event_errors
    now = time.time()
    if now - _last_eventlog_scan_t >= EVENTLOG_SCAN_INTERVAL_SEC:
        _cached_event_errors = _scan_event_errors()
        _last_eventlog_scan_t = now
    return _cached_event_errors


def _scan_event_errors():
    if not IS_WINDOWS or not WIN32EVTLOG_AVAILABLE:
        return []
    out = []
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    for log_name in _EVENT_LOGS:
        try:
            h = win32evtlog.OpenEventLog(None, log_name)
        except Exception:
            continue
        scanned = 0
        try:
            while scanned < _MAX_RECORDS_SCANNED_PER_LOG:
                events = win32evtlog.ReadEventLog(h, flags, 0)
                if not events:
                    break
                for ev in events:
                    scanned += 1
                    if ev.EventType not in (win32evtlog.EVENTLOG_ERROR_TYPE, win32evtlog.EVENTLOG_WARNING_TYPE):
                        continue
                    out.append({
                        'log': log_name,
                        'level': 'error' if ev.EventType == win32evtlog.EVENTLOG_ERROR_TYPE else 'warning',
                        'source': ev.SourceName,
                        'eventId': ev.EventID & 0xFFFF,
                        'time': int(ev.TimeGenerated.timestamp() * 1000),
                    })
                if scanned >= _MAX_RECORDS_SCANNED_PER_LOG:
                    break
        except Exception:
            pass
        finally:
            try:
                win32evtlog.CloseEventLog(h)
            except Exception:
                pass
    out.sort(key=lambda x: x['time'], reverse=True)
    return out[:_MAX_EVENT_ERRORS_RETURNED]


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
    disk_io = sample_disk_io(dt)
    users = sample_users()
    mem_detail = sample_mem_detail()
    services = sample_services()
    installed_programs = sample_installed_programs()
    event_errors = sample_event_errors()
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
                      disks=disks, nics=nics, services=services,
                      diskIO=disk_io, users=users, memDetail=mem_detail,
                      installedPrograms=installed_programs, eventErrors=event_errors)
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
