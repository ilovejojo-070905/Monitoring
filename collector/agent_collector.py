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
    was_online = entity.get('online', False)
    if last is None:
        entity.update(mode='agent', online=False, reachable=False, status='warn')
    else:
        age = now - last
        entity['online'] = age <= ONLINE_WINDOW_SEC
        if not entity['online']:
            entity['status'] = 'crit' if age > WARN_WINDOW_SEC else 'warn'
            entity['reachable'] = False
    if was_online and not entity['online'] and not storage.in_maintenance(device_row):
        storage.add_incident('warn', device_row['name'], 'SMS', f"{device_row['name']} 에이전트 응답 없음 (통신 두절)",
                              device_id=device_id, event_type='REACHABILITY')


def record_report(entity, device_row, body):
    cpu = float(body.get('cpu', 0)); mem = float(body.get('mem', 0)); disk = float(body.get('disk', 0))
    status = 'crit' if (cpu >= 90 or mem >= 92 or disk >= 92) else 'warn' if (cpu >= 75 or mem >= 80 or disk >= 80) else 'good'
    prev_status = entity.get('status', 'good')
    was_online = entity.get('online', True)
    entity.update(mode='agent', online=True, reachable=True, latencyMs=0,
                  cpu=round(cpu, 1), mem=round(mem, 1), disk=round(disk, 1),
                  netIn=round(float(body.get('netIn', 0)), 2), netOut=round(float(body.get('netOut', 0)), 2),
                  load=round(float(body.get('load', 0)), 2), uptime=round(float(body.get('uptime', 0)), 1),
                  status=status, procs=(body.get('procs') or [])[:6])
    push_cap(entity['hist']['cpu'], entity['cpu'])
    push_cap(entity['hist']['mem'], entity['mem'])
    push_cap(entity['hist']['net'], round(entity['netIn'] + entity['netOut'], 2))
    now = time.time()
    LAST_REPORT[device_row['id']] = now
    storage.update_failure_state(device_row['id'], 0, None, int(now * 1000))
    if storage.in_maintenance(device_row):
        return
    if not was_online:
        storage.add_incident('info', device_row['name'], 'SMS', f"{device_row['name']} 에이전트 통신 정상 복구",
                              device_id=device_row['id'], event_type='REACHABILITY')
    rank = {'good': 0, 'warn': 1, 'crit': 2}
    if rank[status] > rank[prev_status]:
        storage.add_incident(status, device_row['name'], 'SMS',
                              f"리소스 사용률 {'임계치 초과' if status=='crit' else '주의 구간 진입'} (CPU {cpu:.0f}% / MEM {mem:.0f}%)",
                              device_id=device_row['id'], event_type='RESOURCE')
    elif status == 'good' and prev_status != 'good':
        storage.add_incident('info', device_row['name'], 'SMS',
                              f"{device_row['name']} 리소스 사용률 정상 범위로 복구",
                              device_id=device_row['id'], event_type='RESOURCE')
