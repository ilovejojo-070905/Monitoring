"""InfraSight's own self-health tracking (directive section 9/27).

Records when each of InfraSight's own internal subsystems last ran
successfully, so GET /api/system/health can report whether THIS app itself
is alive -- independent of whether any individual monitored device is up or
down.

버그 수정(2026-10-17, "Flask, 스케줄러, 수집기, 알림 엔진, DB, Caddy,
디스크 상태를 구분한다"): 이전엔 record_tick_success()/record_tick_error()가
인자 없이 딱 하나의 전역 _last_tick_ok/_last_tick_error만 갱신해서, 전혀
다른 6가지 작업(장비별 polling, 일 단위 retention/backup/cert_check,
주/월간 보고서)이 전부 같은 슬롯에 몰아 썼다. 실제로 생기던 문제: 2초마다
도는 장비 polling이 계속 성공하면, 매일 새벽 도는 백업 작업이 며칠째
조용히 실패하고 있어도 전체 상태는 계속 "정상"으로 보였다 -- 가장 자주
도는 작업이 가장 드물게 도는(그리고 더 중요할 수 있는) 작업의 실패를
가려버리는 구조. 게다가 collector/escalation.py(알림 에스컬레이션)와
collector/alert_retry.py(알림 재시도 큐)는 애초에 이 모듈을 호출조차
안 해서, 그 둘이 완전히 멈춰도 health 어디에도 안 드러났다.

이제 서브시스템별로 따로 추적한다:
  collector  -- 장비별 polling (collector/scheduler.py의 _run_job, 매 poll tick)
  scheduler  -- 일/주/월 단위 배치 작업(retention/backup/cert_check/report)
  alerts     -- 알림 엔진(에스컬레이션 + 알림 재시도 큐)
  (database/caddy/disk는 틱을 기록하는 게 아니라 get_health() 호출 시점에
  직접 확인하는 방식이라 아래 _check_* 함수들이 따로 있음 -- "마지막으로
  성공한 시각"이라는 개념 자체가 없는 상태 확인이기 때문.)
"""
import os
import threading
import time

import storage
from applog import app_logger, safe_log_value

_lock = threading.Lock()
# subsystem -> {'last_ok': epoch_sec_or_None, 'last_error': (epoch_sec, message)_or_None}
_subsystems = {}

# 수집기(매 poll tick, 기본 2초)와 스케줄러 배치 작업(가장 잦은 게 분
# 단위)은 "정상"으로 볼 수 있는 공백 기간이 아예 다르다 -- 수집기가 30초
# 넘게 조용하면 확실히 문제지만, 배치 작업은 원래 몇 분~하루 간격이라
# 같은 30초 기준을 적용하면 항상 "지연"으로 잘못 뜬다. 서브시스템별로
# 다른 기본 기준을 둔다 (get_health의 stale_after_sec 인자로도 개별
# 오버라이드 가능, 과거 호출부와의 하위 호환용).
_DEFAULT_STALE_SEC = {
    'collector': 30,
    'scheduler': 24 * 3600 + 3600,  # 가장 느린 배치(일 단위)보다 1시간 여유
    'alerts': 300,  # escalation.tick/alert_retry.tick 둘 다 60초 주기
}


def record_tick_success(subsystem='collector'):
    with _lock:
        entry = _subsystems.setdefault(subsystem, {})
        entry['last_ok'] = time.time()


def record_tick_error(subsystem, message=None):
    """하위 호환: record_tick_error(message) 한 개짜리 호출(과거 코드)도
    여전히 동작하게, 첫 인자가 알려진 서브시스템 이름이 아니면 그 값
    자체를 메시지로, 서브시스템은 'collector'로 간주한다."""
    if message is None:
        message, subsystem = subsystem, 'collector'
    with _lock:
        entry = _subsystems.setdefault(subsystem, {})
        entry['last_error'] = (time.time(), str(message))
    app_logger.error('%s tick error: %s', subsystem, safe_log_value(message))


def _check_database():
    try:
        conn = storage.get_db()
        conn.execute('SELECT 1')
        conn.close()
        return True
    except Exception:
        return False


def _read_supervisor_status():
    """run\\status.json은 ops\\supervisor.ps1이 5초마다 직접 쓴다(Caddy는
    별도 프로세스라 Python 쪽에서 직접 살았는지 확인할 방법이 없음 --
    supervisor가 이미 확인한 결과를 그대로 읽어오는 게 유일한 방법).
    supervisor 자체가 없으면(수동 start.bat 실행 등) 이 파일도 없으므로
    그 경우엔 None을 돌려준다 -- 없다고 바로 'down'으로 단정하면
    supervisor 없이 수동 실행 중인 정상적인 경우까지 오탐이 된다."""
    status_path = os.path.join(storage.BASE_DIR, 'run', 'status.json')
    try:
        if not os.path.exists(status_path):
            return None
        import json
        with open(status_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        updated_at = data.get('updatedAt')
        if updated_at:
            import datetime
            age = (datetime.datetime.now() - datetime.datetime.fromisoformat(updated_at)).total_seconds()
            if age > 60:  # supervisor 자체가 멈췄으면 이 파일도 더 이상 갱신 안 됨
                return None
        return data
    except Exception:
        return None


def _check_caddy(supervisor_status):
    if supervisor_status is None:
        return None
    return bool(supervisor_status.get('caddy', {}).get('alive'))


def _restart_history(supervisor_status):
    """신규(2026-10-17, "Supervisor의 재시작 횟수와 실패 원인을 기록한다")
    -- ops\\supervisor.ps1이 누적해서 쓰는 값을 그대로 노출. supervisor
    자체가 없으면(위와 같은 이유) 둘 다 비워서 돌려준다."""
    empty = {'totalRestarts': 0, 'lastReason': None, 'lastAt': None}
    if supervisor_status is None:
        return {'backend': dict(empty), 'caddy': dict(empty)}
    out = {}
    for name in ('backend', 'caddy'):
        entry = supervisor_status.get(name, {}) or {}
        out[name] = {
            'totalRestarts': entry.get('totalRestarts', 0),
            'lastReason': entry.get('lastRestartReason'),
            'lastAt': entry.get('lastRestartAt'),
        }
    return out


DISK_WARN_FREE_GB = 5
DISK_CRIT_FREE_GB = 1


def _check_disk():
    """설치 폴더가 있는 드라이브의 남은 용량 -- storage.get_db()가 쓰기
    실패를 던지기 전에 미리 경고할 수 있는 유일한 선행 지표(디스크가
    꽉 차면 SQLite 쓰기 자체가 막히므로, 그때는 이미 늦음)."""
    try:
        import shutil
        usage = shutil.disk_usage(storage.BASE_DIR)
        free_gb = usage.free / (1024 ** 3)
        if free_gb < DISK_CRIT_FREE_GB:
            return 'crit', free_gb
        if free_gb < DISK_WARN_FREE_GB:
            return 'warn', free_gb
        return 'ok', free_gb
    except Exception:
        return 'unknown', None


def get_health(stale_after_sec=None):
    """stale_after_sec: 과거 호출부(서버 시작 초기 등)와의 하위 호환을
    위해 남겨둔 전역 오버라이드 -- 넘기면 모든 틱-기반 서브시스템에
    똑같이 적용되고(과거 동작), 안 넘기면(기본) 서브시스템별
    _DEFAULT_STALE_SEC를 각자 쓴다."""
    now = time.time()
    with _lock:
        snapshot = {k: dict(v) for k, v in _subsystems.items()}

    def _tick_status(name):
        entry = snapshot.get(name, {})
        last_ok = entry.get('last_ok')
        last_error = entry.get('last_error')
        threshold = stale_after_sec if stale_after_sec is not None else _DEFAULT_STALE_SEC.get(name, 60)
        up = last_ok is not None and (now - last_ok) <= threshold
        return {
            'status': 'up' if up else 'down',
            'lastOkAt': int(last_ok * 1000) if last_ok else None,
            'lastError': {'ts': int(last_error[0] * 1000), 'message': last_error[1]} if last_error else None,
        }

    db_up = _check_database()
    supervisor_status = _read_supervisor_status()
    caddy_up = _check_caddy(supervisor_status)
    disk_status, disk_free_gb = _check_disk()

    collector_tick = _tick_status('collector')
    scheduler_tick = _tick_status('scheduler')
    alerts_tick = _tick_status('alerts')

    result = {
        'web': 'up',  # 이 코드가 실행되고 있다는 것 자체가 Flask가 응답 중이라는 뜻
        'database': 'up' if db_up else 'down',
        'caddy': 'up' if caddy_up is True else 'down' if caddy_up is False else 'unknown',
        'disk': disk_status, 'diskFreeGb': round(disk_free_gb, 1) if disk_free_gb is not None else None,
        'collector': collector_tick['status'], 'collectorLastTick': collector_tick['lastOkAt'],
        'collectorLastError': collector_tick['lastError'],
        'scheduler': scheduler_tick['status'], 'schedulerLastTick': scheduler_tick['lastOkAt'],
        'schedulerLastError': scheduler_tick['lastError'],
        'alerts': alerts_tick['status'], 'alertsLastTick': alerts_tick['lastOkAt'],
        'alertsLastError': alerts_tick['lastError'],
        'supervisorRestarts': _restart_history(supervisor_status),
    }
    return result
