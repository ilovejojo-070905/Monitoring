"""3-4: 외부 공개 상태 페이지 -- computes the public-safe status
representation for each public_services row.

공개 정보와 내부 정보 분리 (보안 원칙 -- enforced here, not just assumed):
  이 모듈이 반환하는 모든 dict는 이 파일 안에서 키를 하나씩 직접 나열해
  만든다 (device_row나 entity를 통째로 넘기거나 **dict로 펼치지 않음) --
  그래서 내부 필드가 나중에 추가되어도 "실수로" 공개 응답에 섞여 들어갈 수
  없다. 지금 공개되는 값은 딱 이것뿐이다:
    - admin이 직접 입력한 label/description (장비명이 아님)
    - 파생된 상태 하나 ('operational'|'degraded'|'down'|'unknown')
    - 가동률 숫자와 일별 상태 막대 (collector/sla.py 재사용 -- 수치만,
      장애 메시지 텍스트는 전혀 없음)
  다음은 어떤 경우에도 반환값에 들어가지 않는다: device_id, 장비명,
  IP/호스트명, category, SNMP 관련 모든 정보(sysDescr 등), CPU/메모리/
  디스크 등 상세 자원 수치, 포트/인터페이스 정보, incidents 테이블의
  원문 메시지. device_id는 상태를 조회하기 위해서만 내부적으로 쓰이고
  반환되지 않는다.

내부 로그인 세션과 분리: 이 모듈과 이를 호출하는 server.py의 /api/public/*
라우트는 flask.session을 절대 읽지 않는다 -- 인증 여부와 무관하게 항상
동일한 (공개) 데이터만 내려준다. 관리(생성/수정/공지 작성) 쪽은 기존
@require_role('OPERATOR')가 걸린 별도 라우트(/api/public-status/*)에서만
가능하고, 그 라우트들은 공개 페이지가 호출하는 라우트와 코드상 완전히
분리되어 있다.
"""
import time

import storage
from collector import sla, state

_STATUS_MAP = {'good': 'operational', 'warn': 'degraded', 'crit': 'down'}
HISTORY_DAYS = 90


def _live_status(device_id):
    with state.LOCK:
        entity = state.LIVE.get(device_id) or {}
        raw = entity.get('status', 'good')
    return _STATUS_MAP.get(raw, 'unknown')


def _daily_history(device_row, end_ms):
    start_ms = end_ms - HISTORY_DAYS * 86400 * 1000
    buckets = sla.bucketed_device_report(device_row, start_ms, end_ms, 'day')
    out = []
    for b in buckets:
        pct = b['uptimePct']
        bar = 'operational' if pct >= 99.9 else 'degraded' if pct >= 99 else 'down'
        out.append({'date': time.strftime('%Y-%m-%d', time.localtime(b['periodStart'] / 1000)), 'status': bar})
    return out, buckets


def public_service_view(service):
    """service: one row from storage.load_public_services() (has
    device_id). Returns the public-safe dict, or None if the linked device
    no longer exists (a deleted device shouldn't surface as a dangling
    'unknown' service on the public page)."""
    device_row = storage.load_device(service['device_id'])
    if not device_row:
        return None
    now_ms = int(time.time() * 1000)
    history, buckets = _daily_history(device_row, now_ms)
    total_measured = sum(b['measuredMs'] for b in buckets)
    total_downtime = sum(b['downtimeMs'] for b in buckets)
    uptime_pct = 100.0 if total_measured <= 0 else round(max(0.0, min(100.0, (total_measured - total_downtime) / total_measured * 100)), 2)
    return {
        'id': service['id'],
        'label': service['label'],
        'description': service.get('description'),
        'status': _live_status(service['device_id']),
        'uptimePct90d': uptime_pct,
        'history': history,
    }


def public_services_view():
    return [v for v in (public_service_view(s) for s in storage.load_public_services() if s['enabled']) if v]


def public_announcements_view(limit=20):
    """Strips internal-only columns (created_by -- an internal username is
    itself internal information) from each row before returning."""
    rows = storage.load_public_announcements(limit=limit)
    return [{
        'id': r['id'], 'serviceId': r['service_id'], 'title': r['title'], 'body': r['body'],
        'status': r['status'], 'createdAt': r['created_at'], 'resolvedAt': r['resolved_at'],
    } for r in rows]
