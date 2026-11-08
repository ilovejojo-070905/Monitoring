"""Ping/TCP-reachability sampler. Logic moved from server.py's sample_ping()
(plus ping_host/tcp_check/DB_PORTS) with two Phase 1 additions:
  - per-device timeout_sec / retry_count (falls back to the old hardcoded
    1.0s / 0 retries when a device doesn't set them, so behavior for existing
    devices is unchanged)
  - status now comes from collector.state.evaluate_status() instead of
    flipping straight to 'crit' on the very first failed poll
"""
import socket
import subprocess
import time

import storage
import validation
from collector import state
from collector.state import push_cap, evaluate_status

IS_WINDOWS = storage.IS_WINDOWS

DB_PORTS = {'Oracle': 1521, 'MySQL': 3306, 'PostgreSQL': 5432, 'MS-SQL': 1433, 'MongoDB': 27017, 'Redis': 6379}

DEFAULT_TIMEOUT_SEC = 1.0
DEFAULT_RETRY_COUNT = 0


def ping_host(ip, timeout_s=1.0):
    if not ip:
        return False, None
    # Defense in depth on top of the registration-time check in
    # api_register_device: refuse to build a ping command from anything that
    # isn't a plain IPv4/hostname. Without this, a value starting with '-'
    # would be read as a ping flag rather than a target (argument injection)
    # -- this only ever matters for a device whose IP predates that
    # validation, or was written directly to the DB.
    if not validation.is_valid_host(ip):
        return False, None
    try:
        if IS_WINDOWS:
            cmd = ['ping', '-n', '1', '-w', str(int(timeout_s * 1000)), ip]
        else:
            cmd = ['ping', '-c', '1', '-W', str(int(max(timeout_s, 1))), ip]
        start = time.time()
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 timeout=timeout_s + 1.5)
        elapsed = round((time.time() - start) * 1000, 1)
        return result.returncode == 0, elapsed
    except Exception:
        return False, None


def tcp_check(ip, port, timeout_s=1.0):
    try:
        start = time.time()
        with socket.create_connection((ip, port), timeout=timeout_s):
            return True, round((time.time() - start) * 1000, 1)
    except Exception:
        return False, None


def _attempt(ip, port, timeout_s):
    if port:
        reachable, latency = tcp_check(ip, int(port), timeout_s)
        if not reachable:
            reachable, latency = ping_host(ip, timeout_s)
    else:
        reachable, latency = ping_host(ip, timeout_s)
    return reachable, latency


def sample_ping(entity, device_row):
    ip = device_row['ip']
    fields = device_row['fields']
    port = DB_PORTS.get(fields.get('engine')) if device_row['category'] == 'db' else fields.get('port')
    timeout_s = device_row.get('timeout_sec') or DEFAULT_TIMEOUT_SEC
    retry_count = device_row.get('retry_count')
    try:
        retry_count = DEFAULT_RETRY_COUNT if retry_count is None else int(retry_count)
    except (TypeError, ValueError):
        retry_count = DEFAULT_RETRY_COUNT

    reachable, latency = _attempt(ip, port, timeout_s)
    tries = 1
    while not reachable and tries <= retry_count:
        reachable, latency = _attempt(ip, port, timeout_s)
        tries += 1

    prev_failures = device_row.get('consecutive_failures') or 0
    failures = 0 if reachable else prev_failures + 1
    status = evaluate_status(failures)
    # Code review pass, finding #5: the network I/O above (ping/TCP attempts,
    # up to retry_count+1 of them) deliberately stays outside this lock --
    # that's the whole point of each device getting its own worker thread.
    # Only the actual shared-dict read-then-write is a real race with
    # /api/state reading the same entity concurrently, so only this part
    # needs to be atomic.
    with state.LOCK:
        prev_status = entity.get('status', 'good')
        entity.update(mode='ping', online=True, reachable=reachable, latencyMs=latency, status=status)
        push_cap(entity['hist']['latency'], latency if latency is not None else 0)

    now_ms = int(time.time() * 1000)
    storage.update_failure_state(
        device_row['id'], failures,
        None if reachable else 'PING_TIMEOUT',
        now_ms if reachable else device_row.get('last_success_at'),
        now_ms,
        device_row.get('last_failure_at') if reachable else now_ms)

    rank = {'good': 0, 'warn': 1, 'crit': 2}
    maint = storage.in_maintenance(device_row)
    if rank[status] > rank[prev_status]:
        storage.add_incident(status, device_row['name'], storage.category_label(device_row['category']),
                              f"{device_row['name']} 응답 없음 (Ping/포트 확인 실패, 연속 {failures}회)",
                              device_id=device_row['id'], event_type='REACHABILITY', maintenance=maint)
    elif prev_status != 'good' and status == 'good':
        storage.add_incident('info', device_row['name'], storage.category_label(device_row['category']),
                              f"{device_row['name']} 응답 정상 복구",
                              device_id=device_row['id'], event_type='REACHABILITY', maintenance=maint)


REMOTE_PORT_RECHECK_SEC = 20

# 버그 수정(2026-11-08, "HPE Arbua는 접속 하지도 않았는데 왜 로그인성공,
# 로그인실패, 로그아웃 이력이 남아"): 이 포트 체크가 20초마다 23번
# (Telnet)에 실제 TCP 연결을 여는데, Cisco와 달리 Comware/ArubaOS-Switch는
# 완전한 로그인 절차(아이디/비밀번호 입력)가 끝나기도 전에 "연결이 열렸다"
# 자체를 syslog로 남긴다(Comware는 입력 없이 연결이 끊기면
# LOGINAUTHFAIL+LOGOUT, ArubaOS-Switch는 연결이 열리자마자 LOGIN_SUCCESS)
# -- 실제 운영 DB에서 두 장비 모두 이 20초 주기와 정확히 맞물려 밤새
# 수천 건씩 쌓인 것으로 확인됨. Cisco의 %SEC_LOGIN은 AAA 인증이 실제로
# 끝나야만 찍혀서 이 문제가 없었다(그래서 Cisco는 그대로 라이브로 확인).
# 이 두 벤더는 Telnet이 항상 열려 있는 게 이미 실측 확인돼 있으므로
# (collector/device_control.py PROFILES 주석: Comware는 "Telnet만 응답",
# ArubaOS-Switch는 "실제 검증은 Telnet으로만 함") 매번 다시 열어보는 대신
# 고정값을 쓴다 -- SSH(22)는 이 문제가 관찰되지 않아 그대로 라이브 확인.
_STATIC_TELNET_OPEN_VENDOR_PROFILES = {'hp-comware', 'hp'}


def check_remote_ports(entity, ip, vendor_profile=None):
    """네트워크 장비 목록의 SSH/Telnet 버튼을 실제로 열려 있는 포트만
    보이게 하려고(요청: "텔넷 포트만 열려 있으면 텔넷만 표시") 22/23번을
    직접 TCP 연결해본다. 포트 상태는 거의 안 바뀌므로 매 틱(기본 2초)마다
    다시 열지 않고 REMOTE_PORT_RECHECK_SEC마다만 갱신 -- sshOpen/telnetOpen은
    밑줄로 시작하지 않는 일반 entity 필드라 sysDescr와 같은 경로로
    serialize_device()의 base.update(entity)를 거쳐 그대로 /api/state에
    실린다(서버 쪽 추가 배선 불필요)."""
    if not ip:
        return
    now = time.time()
    last = entity.get('_remotePortCheckedAt') or 0
    if now - last < REMOTE_PORT_RECHECK_SEC:
        return
    ssh_open, _ = tcp_check(ip, 22, 0.5)
    # 버그 수정(2026-11-09, "스위치 다 응답없음인데 HPE만 원격 telnet이
    # 보여"): 위 고정값 처리가 장비의 실제 생존 여부(entity['reachable'],
    # sample_ping/sample_snmp가 매 틱 갱신)와 상관없이 무조건 True였다 --
    # HPE 장비가 응답없음(다운)이어도 Telnet 버튼이 계속 떠 있었음. 장비가
    # 다운일 때는 고정값을 쓰지 말고 다른 벤더처럼 실제 포트를 열어봐서
    # (당연히 실패해 False) 버튼이 사라지게 한다.
    if vendor_profile in _STATIC_TELNET_OPEN_VENDOR_PROFILES and entity.get('reachable'):
        telnet_open = True
    else:
        telnet_open, _ = tcp_check(ip, 23, 0.5)
    with state.LOCK:
        entity['sshOpen'] = ssh_open
        entity['telnetOpen'] = telnet_open
        entity['_remotePortCheckedAt'] = now
