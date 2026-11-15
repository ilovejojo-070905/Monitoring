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
import os
import re
import time
import hashlib
import difflib
import logging
from datetime import datetime

import storage
from collector import device_control, snmp_profiles, state

log = logging.getLogger(__name__)

# 사용자 요청("config 파일로 남기고 싶어"): DB 저장과 별개로, 내용이 저장되는
# 백업(최초 + 실제 변경분)마다 설치 폴더 아래 장비별 폴더에 .cfg 파일로도
# 남긴다 -- 예: C:\InfraSight\config-backups\Arbua\Arbua_20261115-211019.cfg.
# DB가 원본이고 파일은 사본이라, 파일 쓰기가 실패해도 백업 자체는 실패로
# 치지 않는다. 장비를 삭제해도 파일은 지우지 않는다(지난 설정 보관용).
CONFIG_FILES_DIR = os.path.join(storage.BASE_DIR, 'config-backups')
_FS_UNSAFE_RE = re.compile(r'[\\/:*?"<>|\x00-\x1f]')
_WIN_RESERVED = {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1, 10)), *(f'LPT{i}' for i in range(1, 10))}


def safe_file_part(name):
    """장비 이름을 Windows 폴더/파일 이름으로 안전하게 -- 금지 문자는 _로,
    끝의 점/공백 제거, 예약어(CON/NUL 등)는 앞에 _를 붙인다."""
    s = _FS_UNSAFE_RE.sub('_', str(name or '')).strip().rstrip('. ')
    if not s or set(s) <= {'.'}:
        s = 'device'
    if s.upper().split('.')[0] in _WIN_RESERVED:
        s = '_' + s
    return s[:80]


def backup_file_dir(device_name):
    return os.path.join(CONFIG_FILES_DIR, safe_file_part(device_name))


def backup_file_path(device_name, captured_at_ms):
    part = safe_file_part(device_name)
    ts = datetime.fromtimestamp(captured_at_ms / 1000).strftime('%Y%m%d-%H%M%S')
    return os.path.join(CONFIG_FILES_DIR, part, f'{part}_{ts}.cfg')


def write_backup_file(device_name, captured_at_ms, content):
    """이미 있으면 그대로 두고(같은 시각 = 같은 백업) 경로만 돌려준다.
    임시 파일에 다 쓴 뒤 바꿔치기해서 쓰다 만 .cfg가 남지 않게 한다.
    장비가 보낸 줄바꿈을 그대로 보존(newline='')."""
    path = backup_file_path(device_name, captured_at_ms)
    if os.path.exists(path):
        return path
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8', newline='') as f:
        f.write(content)
    os.replace(tmp, path)
    return path


def build_backups_zip(device_id=None):
    """사용자 요청("전체 백업 한번에 zip으로"): 내용이 저장된 모든 백업
    버전을 장비별 폴더로 묶은 zip(bytes). device_id를 주면 그 장비 것만.
    zip 안 경로/이름은 서버의 .cfg 사본과 같다(<장비명>/<장비명>_날짜-시각.cfg).
    삭제된 장비의 옛 백업은 이름을 알 수 없어 장비 id 폴더로 넣는다.
    반환: (zip bytes, 파일 수)."""
    import io
    import zipfile
    names = {d['id']: d['name'] for d in storage.load_devices()}
    buf = io.BytesIO()
    count = 0
    used = set()
    with zipfile.ZipFile(buf, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        for r in storage.list_config_backup_contents():
            if device_id is not None and r['device_id'] != device_id:
                continue
            name = names.get(r['device_id']) or r['device_id']
            path = os.path.relpath(backup_file_path(name, r['captured_at']), CONFIG_FILES_DIR).replace(os.sep, '/')
            # 같은 이름 장비 2대가 같은 초에 백업된 드문 경우에도 덮어쓰지 않게
            base, n = path, 2
            while path in used:
                path = base[:-4] + f'_{n}.cfg'
                n += 1
            used.add(path)
            zf.writestr(path, r['content'])
            count += 1
    return buf.getvalue(), count


def export_missing_backup_files():
    """DB에는 있는데 파일로 안 남은 백업(이 기능 전에 받은 것, 또는 파일
    쓰기가 실패했던 것)을 채운다. 서버 시작 때 한 번 -- 이미 있는 파일은
    건너뛰므로 몇 번 돌려도 안전. 반환: 새로 쓴 파일 수."""
    names = {d['id']: d['name'] for d in storage.load_devices()}
    written = 0
    for r in storage.list_config_backup_contents():
        name = names.get(r['device_id'])
        if not name:
            continue  # 삭제된 장비 -- 이름을 알 수 없어 건너뜀
        if os.path.exists(backup_file_path(name, r['captured_at'])):
            continue
        try:
            write_backup_file(name, r['captured_at'], r['content'])
            written += 1
        except OSError as e:
            log.warning('config backup file export failed for %s: %s', r['device_id'], e)
    return written


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
    captured_at = storage.save_config_backup(
        device_id, success=True, changed=changed, content=content if changed else None,
        content_hash=new_hash, error=None)
    if changed:
        try:
            write_backup_file(device_row['name'], captured_at, content)
        except OSError as e:
            # DB에는 이미 저장됐으니 백업은 성공 -- 파일은 다음 서버 시작 때
            # export_missing_backup_files()가 다시 채운다.
            log.warning('config backup file write failed for %s: %s', device_id, e)
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
