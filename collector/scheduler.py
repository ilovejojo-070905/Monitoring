"""Per-device APScheduler-based scheduling. Replaces server.py's old
monitor_loop() (a single sequential while-True loop): each device now gets
its own interval job, run on a bounded thread pool, so one slow/unreachable
device's timeout no longer delays every other device's poll (Phase 1
analysis 0-3).

server.py should only call start()/add_device_job()/remove_device_job() from
here -- it must not reach into collector internals directly, matching the
original directive's "server.py becomes routes + collector.state reads only"
layout.
"""
from datetime import datetime

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.executors.pool import ThreadPoolExecutor
from apscheduler.jobstores.base import JobLookupError

import storage
from collector import state, health, metrics
from collector import local_collector, ping_collector, snmp_collector, agent_collector
from collector import flow_listener
from collector import maintenance
from collector import escalation
from collector import alert_retry
from collector import report_delivery
from collector import cert_check

def _compute_max_workers():
    """Code review pass, finding #4: this was a flat, hardcoded 10
    regardless of how many devices were actually registered -- fine at
    small scale, but a handful of slow/unreachable devices can occupy every
    worker for their full timeout and delay healthy devices' polls once
    registered-device count grows well past it. Scales with however many
    devices exist right now, within a floor (today's old default, so small
    deployments are unaffected) and a ceiling (so a huge device count can't
    spawn an unreasonable number of threads).

    Computed once at import time, so a count that grows a lot later is
    picked up on the next restart rather than instantly -- rebuilding a
    running thread pool isn't worth it for something that only needs to
    keep pace with slow, deliberate growth. Falls back to the old default
    if the DB isn't ready yet (this module loads before storage.init_db()
    runs on a brand-new install) or on any other error.
    """
    try:
        n = len(storage.load_devices())
    except Exception:
        n = 0
    return max(10, min(50, int(n * 1.5)))


MAX_WORKERS = _compute_max_workers()

# NULL polling_interval on a device falls back to this per-mode default.
# Values match the old global TICK_SECONDS (2.0s) exactly, so devices that
# don't opt into a custom interval behave exactly as before.
TICK_SECONDS = 2.0
DEFAULT_INTERVALS = {'local': TICK_SECONDS, 'ping': TICK_SECONDS, 'snmp': TICK_SECONDS, 'agent': TICK_SECONDS}

_scheduler = BackgroundScheduler(
    executors={'default': ThreadPoolExecutor(MAX_WORKERS)},
    job_defaults={'coalesce': True, 'max_instances': 1, 'misfire_grace_time': 10},
)


def _job_id(device_id):
    return f"poll_{device_id}"


def _run_job(device_id):
    device_row = storage.load_device(device_id)
    if not device_row:
        # device was deleted since this job was scheduled
        remove_device_job(device_id)
        return
    if device_row.get('monitoring_enabled') == 0:
        return
    try:
        with state.LOCK:
            entity = state.ensure_entity(device_row)
        if device_id == storage.LOCAL_ID:
            local_collector.sample_local(entity, device_row)
            metrics.record_entity_metrics(device_id, entity)
        elif device_row['mode'] == 'agent':
            agent_collector.check_freshness(entity, device_row)
        elif device_row['mode'] == 'ping':
            ping_collector.sample_ping(entity, device_row)
            metrics.record_entity_metrics(device_id, entity)
        elif device_row['mode'] == 'snmp':
            snmp_collector.sample_snmp(entity, device_row)
            metrics.record_entity_metrics(device_id, entity)
        # 네트워크 장비 목록의 SSH/Telnet 버튼을 실제 열린 포트만 보이게
        # (요청 사항) -- ping/snmp 둘 중 어느 모드든 네트워크 장비면 같이
        # 확인한다. 자체 쓰로틀(REMOTE_PORT_RECHECK_SEC)이 있어 매 틱마다
        # 실제로 포트를 열어보진 않는다.
        if device_row['category'] == 'net':
            ping_collector.check_remote_ports(entity, device_row['ip'])
        health.record_tick_success('collector')
        # Alert design section [4]/[5]: a device that was mid-outage due to a
        # collector-internal error (not a clean reachability failure) just
        # collected successfully again -- close out that alert the same way
        # the samplers close out a reachability alert (device_id+event_type
        # dedup in add_incident folds this into a recovery of the same
        # open incident, never a flood of new rows).
        if entity.get('_collectorError'):
            entity['_collectorError'] = False
            storage.add_incident(
                'info', device_row['name'], storage.category_label(device_row['category']),
                f"{device_row['name']} 수집 오류 복구", device_id=device_id, event_type='COLLECTION_ERROR',
                maintenance=storage.in_maintenance(device_row))
    except Exception as e:
        health.record_tick_error('collector', f"{device_id}: {e}")
        # Distinct from a clean "no response" result (that's the sampler's
        # own job, above): this is the collector *itself* blowing up --
        # a bug, a crashed library, etc. -- which storage.compute_
        # collection_state() surfaces as '알 수 없음' rather than folding it
        # into the normal 정상/주의/장애 reachability ladder. Alert design
        # section [1]: this is the "서버/DB 수집 오류" alert type -- the one
        # case that had no incident at all before (the sampler never even
        # ran, so none of its own add_incident calls could fire).
        try:
            now_ms = int(datetime.now().timestamp() * 1000)
            prev_failures = device_row.get('consecutive_failures') or 0
            storage.update_failure_state(
                device_id, prev_failures + 1, f'COLLECTOR_ERROR: {str(e)[:180]}',
                device_row.get('last_success_at'), now_ms, now_ms)
            with state.LOCK:
                err_entity = state.LIVE.get(device_id)
                if err_entity is not None:
                    err_entity['_collectorError'] = True
            storage.add_incident(
                'crit', device_row['name'], storage.category_label(device_row['category']),
                f"{device_row['name']} 수집 중 오류가 발생했습니다 ({str(e)[:120]})",
                device_id=device_id, event_type='COLLECTION_ERROR', maintenance=storage.in_maintenance(device_row))
        except Exception:
            pass  # never let bookkeeping itself take down the scheduler job


def add_device_job(device_row):
    interval = device_row.get('polling_interval') or DEFAULT_INTERVALS.get(device_row['mode'], TICK_SECONDS)
    _scheduler.add_job(
        _run_job, 'interval', seconds=interval, id=_job_id(device_row['id']),
        args=[device_row['id']], replace_existing=True, next_run_time=datetime.now(),
        max_instances=1,
    )


def remove_device_job(device_id):
    try:
        _scheduler.remove_job(_job_id(device_id))
    except JobLookupError:
        pass


# 신규(2026-10-17, "Flask, 스케줄러, 수집기, 알림 엔진, DB, Caddy, 디스크
# 상태를 구분한다"): 이 밑의 일/주/월 단위 배치 작업들은 전부 'scheduler'
# 서브시스템으로 기록한다 -- 이전엔 health.record_tick_success()/error()를
# 인자 없이 호출해서, 2초마다 도는 장비 polling(collector 서브시스템)과
# 같은 슬롯에 몰려 있었다. 그래서 백업이 며칠째 실패해도 polling만
# 계속 성공하면 전체 상태가 "정상"으로 보이던 사각지대가 있었음.
def _run_retention_job():
    try:
        storage.run_metrics_retention()
        storage.run_incident_retention()
        storage.run_flow_retention()
        storage.run_discovery_retention()
        storage.run_api_token_usage_retention()
        health.record_tick_success('scheduler')
    except Exception as e:
        health.record_tick_error('scheduler', f"retention: {e}")


def _run_backup_job():
    import os
    backup_dir = os.path.join(storage.BASE_DIR, 'backups')
    try:
        storage.backup_database(backup_dir, keep_days=storage.BACKUP_RETENTION_DAYS)
        # 버그 수정: 성공했을 때 health에 전혀 기록을 안 남겼었음(실패만
        # 기록) -- "마지막 백업 성공 시각"을 알 방법이 없었던 것도 그래서.
        health.record_tick_success('scheduler')
    except Exception as e:
        health.record_tick_error('scheduler', f"backup: {e}")
        storage.add_incident('warn', 'InfraSight', 'SYSTEM', f"DB 백업 실패: {e}")


def _run_cert_check_job():
    try:
        cert_check.check_certificate()
        health.record_tick_success('scheduler')
    except Exception as e:
        health.record_tick_error('scheduler', f"cert_check: {e}")


def _run_weekly_report_job():
    try:
        report_delivery.run_due_schedules('weekly')
        health.record_tick_success('scheduler')
    except Exception as e:
        health.record_tick_error('scheduler', f"weekly_report: {e}")


def _run_monthly_report_job():
    try:
        report_delivery.run_due_schedules('monthly')
        health.record_tick_success('scheduler')
    except Exception as e:
        health.record_tick_error('scheduler', f"monthly_report: {e}")


# 신규(2026-10-17): escalation.tick/alert_retry.tick/maintenance.tick은
# 이전에 APScheduler 작업으로 직접 등록돼서(아래 add_job에 함수 자체를
# 바로 넘김), 그 안에서 예외가 나면 APScheduler 자체 로그에만 남고
# InfraSight의 health에는 전혀 안 드러났다 -- 즉 "알림 엔진"(에스컬레이션
# +재시도 큐)이 완전히 멈춰도 /api/system/health는 모르는 상태였음. 다른
# 배치 작업들과 같은 try/except+health.record_tick_* 패턴으로 감싼다.
# escalation/alert_retry는 'alerts'(알림 엔진), maintenance는 그 자체가
# 알림을 보내는 게 아니라 "지금 점검 중인지" 판정만 하는 주기 작업이라
# 'scheduler'로 분류한다.
def _run_escalation_tick():
    try:
        escalation.tick()
        health.record_tick_success('alerts')
    except Exception as e:
        health.record_tick_error('alerts', f"escalation: {e}")


def _run_alert_retry_tick():
    try:
        alert_retry.tick()
        health.record_tick_success('alerts')
    except Exception as e:
        health.record_tick_error('alerts', f"alert_retry: {e}")


def _run_maintenance_tick():
    try:
        maintenance.tick()
        health.record_tick_success('scheduler')
    except Exception as e:
        health.record_tick_error('scheduler', f"maintenance: {e}")


def start():
    local_collector.prime_psutil()
    for d in storage.load_devices():
        if d['mode'] == 'agent':
            agent_collector.seed_last_report_from_db(d)
    _scheduler.start()
    for d in storage.load_devices():
        add_device_job(d)
    # Phase 5: daily metrics rollup/purge and DB backup, both at low-traffic
    # hours. Times are staggered so the backup doesn't run mid-aggregation.
    _scheduler.add_job(_run_retention_job, 'cron', hour=3, minute=10, id='metrics_retention', replace_existing=True)
    _scheduler.add_job(_run_backup_job, 'cron', hour=3, minute=0, id='db_backup', replace_existing=True)
    # 신규(2026-10-17, "HTTPS 인증서 만료 및 갱신 실패를 감지한다") --
    # 백업/보존 작업과 같은 매일 새벽 주기. next_run_time=now로 즉시 한 번
    # 돌려서 재시작 직후에도 지금 상태를 바로 알 수 있게 한다(maintenance.
    # tick/escalation.tick과 같은 이유).
    _scheduler.add_job(_run_cert_check_job, 'cron', hour=3, minute=20, id='cert_check',
                        replace_existing=True, next_run_time=datetime.now())
    # 4-3: flush flow_listener's in-memory NetFlow/sFlow aggregates to
    # storage once a minute -- this scheduler's thread pool, not a new one,
    # same reasoning as every other periodic job here.
    _scheduler.add_job(flow_listener.flush, 'interval', seconds=60, id='flow_flush', replace_existing=True)
    # 2-3: evaluate maintenance_windows against the clock every 60s, with an
    # immediate first run (next_run_time=now) so a window that should already
    # be active takes effect right after a restart instead of waiting a full
    # minute -- same reasoning as add_device_job's own next_run_time.
    _scheduler.add_job(_run_maintenance_tick, 'interval', seconds=60, id='maintenance_tick',
                        replace_existing=True, next_run_time=datetime.now())
    # 2-5: same cadence/pattern as maintenance.tick -- checks every open
    # incident against the configured escalation chain each run.
    _scheduler.add_job(_run_escalation_tick, 'interval', seconds=60, id='escalation_tick',
                        replace_existing=True, next_run_time=datetime.now())
    # 알림 재시도 큐 (버그 수정, 2026-10-16) -- 같은 60초 주기/즉시 첫 실행
    # 패턴. pending_alert_retries에 쌓인, 처음 시도가 실패한 알림들을
    # 백오프를 두고 재시도한다 (storage.py의 enqueue_alert_retry/
    # _dispatch_one_channel 쪽 주석 참고).
    _scheduler.add_job(_run_alert_retry_tick, 'interval', seconds=60, id='alert_retry_tick',
                        replace_existing=True, next_run_time=datetime.now())
    # 3-3: 주간 보고서는 매주 월요일, 월간 보고서는 매월 1일 아침에 생성+발송.
    # collector/report_delivery.period_for_frequency()가 "오늘 자정까지의
    # 완전한 한 주/한 달"을 계산하므로, 월요일 06:00에 발송되는 주간 보고서는
    # 바로 지난 일~월요일이 아니라 지난주 월~일(완전한 한 주)을 담는다.
    _scheduler.add_job(_run_weekly_report_job, 'cron', day_of_week='mon', hour=6, minute=0,
                        id='weekly_report', replace_existing=True)
    _scheduler.add_job(_run_monthly_report_job, 'cron', day=1, hour=6, minute=30,
                        id='monthly_report', replace_existing=True)


def shutdown():
    _scheduler.shutdown(wait=False)
