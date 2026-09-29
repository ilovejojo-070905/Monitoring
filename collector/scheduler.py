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

MAX_WORKERS = 10

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
    except Exception as e:
        health.record_tick_error(f"{device_id}: {e}")


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
        health.record_tick_success()
    except Exception as e:
        health.record_tick_error(f"retention: {e}")


def _run_backup_job():
    import os
    backup_dir = os.path.join(storage.BASE_DIR, 'backups')
    try:
        storage.backup_database(backup_dir, keep=14)
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


def shutdown():
    _scheduler.shutdown(wait=False)
