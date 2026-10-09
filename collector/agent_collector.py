"""Agent (push-based) sampler. Logic moved from server.py's sample_agent()
plus the metrics-update block that used to live inline in the
/api/agent/report route handler.

Phase 1 addition: last_success_at is now persisted to the devices table (not
just kept in the in-memory LAST_REPORT dict), and seed_last_report_from_db()
reloads it at startup. This is a direct fix for the "server restart makes
every agent look offline" case noted in the Phase 1 analysis (0-4): the
freshness window now survives a restart instead of resetting to None.
"""
import time

from collector import state, thresholds
from collector.state import LAST_REPORT, push_cap
import storage

ONLINE_WINDOW_SEC = 15
WARN_WINDOW_SEC = 60


def seed_last_report_from_db(device_row):
    last_success_at = device_row.get('last_success_at')
    if last_success_at and device_row['id'] not in LAST_REPORT:
        LAST_REPORT[device_row['id']] = last_success_at / 1000.0


def check_freshness(entity, device_row):
    device_id = device_row['id']
    last = LAST_REPORT.get(device_id)
    now = time.time()
    # Code review pass, finding #5: no slow I/O anywhere in this function
    # (this is push-based -- the network wait already happened on the HTTP
    # request thread that called record_report below), so the whole
    # mutation can just be one lock scope with no parallelism cost.
    with state.LOCK:
        was_online = entity.get('online', False)
        if last is None:
            entity.update(mode='agent', online=False, reachable=False, status='warn')
        else:
            age = now - last
            entity['online'] = age <= ONLINE_WINDOW_SEC
            if not entity['online']:
                entity['status'] = 'crit' if age > WARN_WINDOW_SEC else 'warn'
                entity['reachable'] = False
        is_online_now = entity['online']
    if was_online and not is_online_now:
        storage.add_incident('warn', device_row['name'], 'SMS', f"{device_row['name']} 에이전트 응답 없음 (통신 두절)",
                              device_id=device_id, event_type='REACHABILITY', maintenance=storage.in_maintenance(device_row))
    # Bookkeeping for the 5-state collection status (연속 실패 횟수/마지막 수집
    # 시간 등): the actual online/offline classification above is unchanged
    # (still time-window based, since agent mode is push- not poll-based),
    # this just records that a freshness *check* happened and what it found.
    # A success is already recorded by record_report() when the report
    # itself arrives, so there's nothing to do here on the online branch.
    if not entity['online']:
        now_ms = int(now * 1000)
        prev_failures = device_row.get('consecutive_failures') or 0
        storage.update_failure_state(
            device_id, prev_failures + 1, 'AGENT_OFFLINE',
            device_row.get('last_success_at'), now_ms, now_ms)


def record_report(entity, device_row, body, remote_addr=None):
    cpu = float(body.get('cpu', 0)); mem = float(body.get('mem', 0)); disk = float(body.get('disk', 0))
    # 2-2: resolved per-device (falls back through group -> global -> the
    # same 75/90/80/92/80/92 this used to have hardcoded right here).
    device_thresholds = thresholds.resolve_thresholds(device_row)
    status, incident_event = thresholds.evaluate_resource(
        device_row['id'], cpu, mem, disk, device_thresholds)
    with state.LOCK:
        was_online = entity.get('online', True)
        entity.update(mode='agent', online=True, reachable=True, latencyMs=0,
                      cpu=round(cpu, 1), mem=round(mem, 1), disk=round(disk, 1),
                      netIn=round(float(body.get('netIn', 0)), 2), netOut=round(float(body.get('netOut', 0)), 2),
                      load=round(float(body.get('load', 0)), 2), uptime=round(float(body.get('uptime', 0)), 1),
                      status=status, procs=(body.get('procs') or [])[:12],
                      # More-detail pass: disks/nics/services are already capped and
                      # shaped by the agent itself (sample_disks/sample_nics/
                      # sample_services in agent.py) -- stored as-is, display-only.
                      disks=(body.get('disks') or [])[:12], nics=(body.get('nics') or [])[:10],
                      services=body.get('services') or {'running': 0, 'total': 0, 'stoppedAutoStart': []},
                      diskIO=(body.get('diskIO') or [])[:12], users=(body.get('users') or [])[:20],
                      memDetail=body.get('memDetail'))
        push_cap(entity['hist']['cpu'], entity['cpu'])
        push_cap(entity['hist']['mem'], entity['mem'])
        push_cap(entity['hist']['net'], round(entity['netIn'] + entity['netOut'], 2))
    now = time.time()
    LAST_REPORT[device_row['id']] = now
    now_ms = int(now * 1000)
    storage.update_failure_state(device_row['id'], 0, None, now_ms, now_ms, device_row.get('last_failure_at'))
    # Agent management pass: what the agent process itself says about
    # itself. These are display-only fields (already escaped on the
    # frontend), but capped here regardless as a sanity bound against an
    # absurd payload -- same convention as the free-text device fields in
    # server.py's api_register_device.
    started_at = body.get('startedAt')
    storage.update_agent_info(
        device_row['id'],
        str(body.get('version') or '')[:40] or None,
        str(body.get('os') or '')[:200] or None,
        int(started_at) if isinstance(started_at, (int, float)) else None,
        remote_addr,
        str(body.get('lastError') or '')[:300] or None,
    )
    maint = storage.in_maintenance(device_row)
    if not was_online:
        storage.add_incident('info', device_row['name'], 'SMS', f"{device_row['name']} 에이전트 통신 정상 복구",
                              device_id=device_row['id'], event_type='REACHABILITY', maintenance=maint)
    if incident_event:
        kind, new_status = incident_event
        if kind == 'escalate':
            storage.add_incident(new_status, device_row['name'], 'SMS',
                                  f"리소스 사용률 {'임계치 초과' if new_status=='crit' else '주의 구간 진입'} (CPU {cpu:.0f}% / MEM {mem:.0f}%)",
                                  device_id=device_row['id'], event_type='RESOURCE', maintenance=maint)
        else:
            storage.add_incident('info', device_row['name'], 'SMS',
                                  f"{device_row['name']} 리소스 사용률 정상 범위로 복구",
                                  device_id=device_row['id'], event_type='RESOURCE', maintenance=maint)
