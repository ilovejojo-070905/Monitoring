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
        health.record_tick_success()
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
        health.record_tick_error(f"{device_id}: {e}")
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


def _run_retention_job():
    try:
        storage.run_metrics_retention()
        storage.run_incident_retention()
        storage.run_flow_retention()
        storage.run_discovery_retention()
        health.record_tick_success()
    except Exception as e:
        health.record_tick_error(f"retention: {e}")


def _run_backup_job():
    import os
    backup_dir = os.path.join(storage.BASE_DIR, 'backups')
    try:
        storage.backup_database(backup_dir, keep_days=storage.BACKUP_RETENTION_DAYS)
    except Exception as e:
        health.record_tick_error(f"backup: {e}")
        storage.add_incident('warn', 'InfraSight', 'SYSTEM', f"DB 백업 실패: {e}")


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
    # 4-3: flush flow_listener's in-memory NetFlow/sFlow aggregates to
    # storage once a minute -- this scheduler's thread pool, not a new one,
    # same reasoning as every other periodic job here.
    _scheduler.add_job(flow_listener.flush, 'interval', seconds=60, id='flow_flush', replace_existing=True)
    # 2-3: evaluate maintenance_windows against the clock every 60s, with an
    # immediate first run (next_run_time=now) so a window that should already
    # be active takes effect right after a restart instead of waiting a full
    # minute -- same reasoning as add_device_job's own next_run_time.
    _scheduler.add_job(maintenance.tick, 'interval', seconds=60, id='maintenance_tick',
                        replace_existing=True, next_run_time=datetime.now())


def shutdown():
    _scheduler.shutdown(wait=False)
