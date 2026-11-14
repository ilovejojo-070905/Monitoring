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

import storage
from collector import device_control, snmp_profiles, state


def _content_hash(text):
    return hashlib.sha256(text.encode('utf-8', errors='replace')).hexdigest()


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
        message = (f"{device_row['name']} 설정이 최초로 백업되었습니다" if is_first
                   else f"{device_row['name']} 설정이 변경되었습니다 (이전 백업과 다름)")
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
