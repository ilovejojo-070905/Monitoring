"""Periodic network-device running-config backup. Reuses device_control.py's
SSH/Telnet connection logic (vendor profiles, stored credentials) -- see its
own module docstring for why netmiko is used.

사용자 요청("네트워크 등록 된 장비들 일정 기간을 지정해서 config 를
자동으로 받을 수 있게 할수 있어?"): 전역 설정(기본 꺼짐, storage.
get_config_backup_settings)으로 활성화하면, 지정한 주기(시간 단위)마다
등록된 모든 네트워크 장비의 설정을 가져와 이전 백업과 다르면 새 버전으로
저장하고 알림(incident)을 남긴다. 같으면 저장하지 않고(용량 절약)
"마지막 확인 시각"만 갱신한다.
"""
import time
import hashlib
import difflib

import storage
from collector import device_control, snmp_profiles, state


def _content_hash(text):
    return hashlib.sha256(text.encode('utf-8', errors='replace')).hexdigest()


def diff_configs(old_text, new_text, context=3):
    """두 설정 텍스트의 줄 단위 비교 -- 사용자 요청("백업 파일도 서로 비교해서
    변경된 부분도 확인하고 싶어").

    반환: {'added': 추가된 줄 수, 'removed': 삭제된 줄 수,
           'hunks': [[{'t': ' '|'+'|'-', 'o': 이전 줄번호|None, 'n': 새 줄번호|None, 's': 내용}, ...], ...]}
    context=None이면 변경 없는 줄까지 전체를 한 덩어리로(전체 보기).

    autojunk=False: 설정 파일은 "!", "#", "exit" 같은 같은 줄이 수백 번
    반복되는데, difflib 기본값(autojunk)은 200줄 넘는 입력에서 자주 나오는
    줄을 "무시할 줄"로 취급해 엉뚱한 위치끼리 짝지은 비교 결과를 낸다."""
    old = (old_text or '').splitlines()
    new = (new_text or '').splitlines()
    sm = difflib.SequenceMatcher(None, old, new, autojunk=False)
    groups = [sm.get_opcodes()] if context is None else list(sm.get_grouped_opcodes(context))
    added = removed = 0
    hunks = []
    for group in groups:
        lines = []
        for tag, i1, i2, j1, j2 in group:
            if tag == 'equal':
                for k in range(i2 - i1):
                    lines.append({'t': ' ', 'o': i1 + k + 1, 'n': j1 + k + 1, 's': old[i1 + k]})
                continue
            for i in range(i1, i2):
                lines.append({'t': '-', 'o': i + 1, 'n': None, 's': old[i]})
                removed += 1
            for j in range(j1, j2):
                lines.append({'t': '+', 'o': None, 'n': j + 1, 's': new[j]})
                added += 1
        hunks.append(lines)
    if not added and not removed and context is not None:
        hunks = []
    return {'added': added, 'removed': removed, 'hunks': hunks}


def _resolve_vendor_profile(device_row):
    entity = state.LIVE.get(device_row['id']) or {}
    return snmp_profiles.resolve_profile_name(device_row.get('vendor_profile'), entity.get('sysDescr'))


def backup_one_device(device_row):
    """한 장비를 백업 시도 -- 성공/실패, 변경 여부와 무관하게 항상
    storage.save_config_backup()으로 결과를 기록한다(스케줄러가 "다음에
    언제 다시 시도할지" 판단할 기준이 바로 이 기록이므로)."""
    device_id = device_row['id']
    vendor_profile = _resolve_vendor_profile(device_row)
    try:
        content = device_control.fetch_running_config(device_row, vendor_profile)
    except device_control.DeviceControlError as e:
        storage.save_config_backup(device_id, success=False, changed=False, content=None, content_hash=None, error=str(e))
        return
    except Exception as e:
        storage.save_config_backup(device_id, success=False, changed=False, content=None, content_hash=None, error=str(e)[:300])
        return

    new_hash = _content_hash(content)
    prev = storage.get_latest_config_backup_content(device_id)
    changed = prev is None or prev.get('content_hash') != new_hash
    storage.save_config_backup(
        device_id, success=True, changed=changed, content=content if changed else None,
        content_hash=new_hash, error=None)
    if changed:
        is_first = prev is None
        if is_first:
            message = f"{device_row['name']} 설정이 최초로 백업되었습니다"
        else:
            # 알림만 보고도 변경 규모를 알 수 있게 추가/삭제 줄 수를 붙인다
            # (실제 내용은 장비 상세의 config 백업 "이전과 비교"로 확인).
            try:
                d = diff_configs(prev.get('content'), content)
                size = f", +{d['added']}줄 / -{d['removed']}줄"
            except Exception:
                size = ''
            message = f"{device_row['name']} 설정이 변경되었습니다 (이전 백업과 다름{size})"
        storage.add_incident(
            'info' if is_first else 'warn', device_row['name'], storage.category_label(device_row['category']),
            message, device_id=device_id, event_type='CONFIG_CHANGED', maintenance=storage.in_maintenance(device_row))


def run_due_backups():
    """스케줄러에서 주기적으로(예: 10분마다) 호출 -- 실제로 "지금 백업할
    때가 된" 장비만 골라서 접속을 시도한다(전역 intervalHours 기준,
    장비별 마지막 시도 시각과 비교)."""
    settings = storage.get_config_backup_settings()
    if not settings['enabled']:
        return
    interval_ms = settings['intervalHours'] * 3600 * 1000
    now_ms = int(time.time() * 1000)
    for device_row in storage.load_devices():
        if device_row.get('category') != 'net':
            continue
        if device_row.get('monitoring_enabled') == 0:
            continue
        try:
            last_attempt = storage.get_last_config_backup_attempt_at(device_row['id'])
            if last_attempt is not None and now_ms - last_attempt < interval_ms:
                continue
            backup_one_device(device_row)
        except Exception:
            # 한 장비 처리 중 예상 못 한 오류가 나머지 장비 백업까지 막지
            # 않게 -- 이 함수 자체의 성공/실패는 호출부(scheduler.py)가
            # health.record_tick_error로 별도 기록한다.
            continue
