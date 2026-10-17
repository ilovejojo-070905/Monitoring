"""Functional regression tests covering InfraSight's implemented features
end-to-end, as a companion to security_tests.py (which covers the section
40/41 security checklist, not general functionality).

Run against an already-running InfraSight instance:

    INFRASIGHT_TEST_ADMIN_USER=admin INFRASIGHT_TEST_ADMIN_PASS='...' \
        python functional_tests.py [base_url]

Credentials are read from environment variables ONLY -- never hardcode a
real password in this file, since it's meant to be committed alongside the
rest of the source.

Safety contract (same spirit as security_tests.py):
  - Every device/group/user/token/maintenance window/escalation tier/report
    schedule/public service & announcement this script creates is named with
    a "functest_" prefix and deleted again at the end of the run. It never
    touches your real registered devices, groups, users, or schedules.
  - It NEVER writes to a singleton setting that your real environment
    already depends on -- global thresholds, escalation on/off, or any
    notification channel's credentials (SMTP/Slack/Kakao/KakaoBiz/SMS).
    Those are GET-only here (verify the endpoint responds with the expected
    shape) specifically so this script can't silently overwrite the Kakao
    REST API key or SMTP password you've already configured. Actually
    *sending* a real notification (email/Slack/Kakao/SMS) also needs a live
    external account this script doesn't have, so those stay untested here
    by design -- test them by hand via each channel's "테스트 발송" button.
  - Needs a reachable network stack to pass the two ping-mode device tests
    (pings 127.0.0.1, which should always succeed) -- no external device
    required.
  - SNMP-mode *registration* needs a real SNMP-speaking device to succeed,
    which this script has no way to assume exists, so only the validation
    (rejection) path is tested for SNMP, not a successful registration.
"""
import io
import json
import os
import secrets as _secrets
import sys
import time

import requests
import urllib3

try:
    import openpyxl
except ImportError:
    openpyxl = None

# The session cookie is Secure-flagged (HTTPS-only, by design -- see
# server.py's login route), so it's only ever sent back on a follow-up
# request if that request itself is HTTPS too: hitting the plain-HTTP
# backend port (5057) makes `requests` silently drop the cookie on every
# request after login, and every authenticated call then 401s even though
# the login itself returned 200 -- confirmed directly (login succeeds,
# session.cookies has it, but the next request's outgoing Cookie header is
# empty). So this must go through Caddy's HTTPS port (8443), the same path
# a real user's browser takes, not the backend's own plain-HTTP port.
# Caddy's cert is issued by mkcert's local CA, which isn't in the
# `requests`/certifi trust bundle (importing it onto this machine's own
# Windows cert store via `mkcert -install` doesn't help, since `requests`
# doesn't consult the OS store) -- verify=False below is the normal way to
# point this kind of local test script at a self-signed/local-CA HTTPS
# endpoint without wiring in a separate trust bundle for it. Testing against
# a plain dev server instead of the real Caddy? ops\devtest-https.ps1 puts a
# throwaway HTTPS front-end on any dev backend port in one command.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
BASE_URL = sys.argv[1] if len(sys.argv) > 1 else 'https://localhost:8443'
ADMIN_USER = os.environ.get('INFRASIGHT_TEST_ADMIN_USER')
ADMIN_PASS = os.environ.get('INFRASIGHT_TEST_ADMIN_PASS')
PREFIX = f"functest_{_secrets.token_hex(3)}"

results = []  # (name, 'PASS'|'FAIL'|'SKIP', detail)
cleanup = {'devices': [], 'groups': [], 'users': [], 'tokens': [], 'windows': [],
           'tiers': [], 'schedules': [], 'services': [], 'announcements': []}


def check(name, condition, detail=''):
    results.append((name, 'PASS' if condition else 'FAIL', detail))
    print(f"[{'PASS' if condition else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not condition else ''))
    return condition


def skip(name, reason):
    results.append((name, 'SKIP', reason))
    print(f"[SKIP] {name} -- {reason}")


def admin_session():
    s = requests.Session()
    s.verify = False
    r = s.post(f'{BASE_URL}/api/auth/login', json={'username': ADMIN_USER, 'password': ADMIN_PASS}, timeout=10)
    r.raise_for_status()
    csrf = r.json()['csrfToken']
    return s, csrf


def main():
    print(f"Target: {BASE_URL}\nPrefix: {PREFIX}\n")

    # ------------------------------------------------- A. 비로그인 공개 엔드포인트 --
    r = requests.get(f'{BASE_URL}/api/public/status', timeout=10, verify=False)
    check('A1 GET /api/public/status (no login) -> 200', r.status_code == 200, f'got {r.status_code}')

    r = requests.get(f'{BASE_URL}/api/public/announcements', timeout=10, verify=False)
    check('A2 GET /api/public/announcements (no login) -> 200', r.status_code == 200, f'got {r.status_code}')

    r = requests.get(f'{BASE_URL}/status', timeout=10, verify=False)
    check('A3 GET /status (public status page) -> 200', r.status_code == 200, f'got {r.status_code}')

    if not (ADMIN_USER and ADMIN_PASS):
        skip('(all remaining sections B-P)', 'INFRASIGHT_TEST_ADMIN_USER/PASS not set')
        print_summary()
        return

    try:
        s, csrf = admin_session()
    except Exception as e:
        skip('(all remaining sections B-P)',
             f'admin login failed ({e}) -- possibly rate-limited from a recent run; wait 5 min or restart the server')
        print_summary()
        return
    h = {'X-CSRF-Token': csrf}

    try:
        run_logged_in_sections(s, h)
    finally:
        do_cleanup(s, h)

    print_summary()


def run_logged_in_sections(s, h):
    # --------------------------------------------------------- B. 인증/세션 --
    r = s.get(f'{BASE_URL}/api/auth/me', timeout=10)
    check('B1 GET /api/auth/me -> 200, role present', r.status_code == 200 and r.json().get('role'), f'got {r.status_code}')

    r = s.get(f'{BASE_URL}/api/auth/totp/status', timeout=10)
    check('B2 GET /api/auth/totp/status -> 200', r.status_code == 200, f'got {r.status_code}')

    r = s.get(f'{BASE_URL}/api/system/health', timeout=10)
    check('B3 GET /api/system/health -> 200 (VIEWER+ only, not public)', r.status_code == 200, f'got {r.status_code}')

    # ------------------------------------------------------- C. API 토큰 --
    r = s.post(f'{BASE_URL}/api/tokens', json={'name': f'{PREFIX}_token', 'scope': 'VIEWER'}, headers=h, timeout=10)
    token_created = check('C1 POST /api/tokens (VIEWER scope) -> 200 + plaintext token',
                           r.status_code == 200 and bool(r.json().get('token')), f'got {r.status_code}')
    token_id = r.json().get('id') if token_created else None
    raw_token = r.json().get('token') if token_created else None
    if token_id:
        cleanup['tokens'].append(token_id)

    r = s.get(f'{BASE_URL}/api/tokens', timeout=10)
    check('C2 GET /api/tokens -> 200, includes the new token', r.status_code == 200 and
          any(t['id'] == token_id for t in r.json().get('tokens', [])), f'got {r.status_code}')

    if raw_token:
        tr = requests.get(f'{BASE_URL}/api/state', headers={'Authorization': f'Bearer {raw_token}'}, timeout=10, verify=False)
        check('C3 Bearer token auth works on a real route -> 200', tr.status_code == 200, f'got {tr.status_code}')
    else:
        skip('C3 Bearer token auth works on a real route -> 200', 'token creation failed (C1)')

    if token_id:
        r = s.get(f'{BASE_URL}/api/tokens/{token_id}/usage', timeout=10)
        check('C4 GET /api/tokens/<id>/usage -> 200', r.status_code == 200, f'got {r.status_code}')
        r = s.post(f'{BASE_URL}/api/tokens/{token_id}/rotate', headers=h, timeout=10)
        check('C5 POST /api/tokens/<id>/rotate -> 200, new token issued',
              r.status_code == 200 and bool(r.json().get('token')), f'got {r.status_code}')
    else:
        skip('C4 GET /api/tokens/<id>/usage -> 200', 'token creation failed (C1)')
        skip('C5 POST /api/tokens/<id>/rotate -> 200', 'token creation failed (C1)')

    # ------------------------------------------------- D. 장비 등록 (ping 모드) --
    r = s.post(f'{BASE_URL}/api/devices', json={
        'category': 'net', 'name': f'{PREFIX}_ping', 'mode': 'ping', 'ip': '127.0.0.1', 'fields': {}},
        headers=h, timeout=15)
    ping_ok = check('D1 register ping device (127.0.0.1, always reachable) -> 200', r.status_code == 200, f'got {r.status_code}: {r.text[:200]}')
    ping_id = r.json().get('id') if ping_ok else None
    if ping_id:
        cleanup['devices'].append(ping_id)

    if ping_id:
        r = s.get(f'{BASE_URL}/api/state', timeout=10)
        # /api/state keys its category buckets 'servers'/'dbs'/'nets'/'facs'
        # (server.py's key_map) -- a 'net'-category device lands in 'nets'.
        found = any(d['id'] == ping_id for d in r.json().get('nets', [])) if r.status_code == 200 else False
        check('D2 registered ping device appears in /api/state', found, f'state status={r.status_code}')

        r = s.put(f'{BASE_URL}/api/devices/{ping_id}', json={'name': f'{PREFIX}_ping_renamed', 'ip': '127.0.0.1', 'fields': {}},
                  headers=h, timeout=10)
        check('D3 PUT /api/devices/<id> (rename) -> 200', r.status_code == 200, f'got {r.status_code}')

        r = s.put(f'{BASE_URL}/api/devices/{ping_id}/maintenance',
                   json={'enabled': True, 'reason': 'functional test'}, headers=h, timeout=10)
        check('D4 PUT /api/devices/<id>/maintenance (enable) -> 200', r.status_code == 200, f'got {r.status_code}')
        r = s.put(f'{BASE_URL}/api/devices/{ping_id}/maintenance', json={'enabled': False}, headers=h, timeout=10)
        check('D5 PUT /api/devices/<id>/maintenance (disable) -> 200', r.status_code == 200, f'got {r.status_code}')

        r = s.get(f'{BASE_URL}/api/devices/{ping_id}/metrics?metric=cpu', timeout=10)
        check('D6 GET /api/devices/<id>/metrics -> 200', r.status_code == 200, f'got {r.status_code}')
    else:
        for n in ('D2 registered ping device appears in /api/state', 'D3 PUT /api/devices/<id> (rename) -> 200',
                  'D4 PUT /api/devices/<id>/maintenance (enable) -> 200', 'D5 PUT /api/devices/<id>/maintenance (disable) -> 200',
                  'D6 GET /api/devices/<id>/metrics -> 200'):
            skip(n, 'ping device registration failed (D1)')

    # --------------------------------------------- E. 중복 등록 차단 (신규 기능) --
    r = s.post(f'{BASE_URL}/api/devices', json={
        'category': 'net', 'name': f'{PREFIX}_dup_name', 'mode': 'agent', 'ip': None, 'fields': {}},
        headers=h, timeout=10)
    dup1_ok = r.status_code == 200
    dup1_id = r.json().get('id') if dup1_ok else None
    if dup1_id:
        cleanup['devices'].append(dup1_id)
    if dup1_ok:
        r2 = s.post(f'{BASE_URL}/api/devices', json={
            'category': 'net', 'name': f'{PREFIX}_dup_name', 'mode': 'agent', 'ip': None, 'fields': {}},
            headers=h, timeout=10)
        check('E1 duplicate name registration -> 409', r2.status_code == 409, f'got {r2.status_code}')
    else:
        skip('E1 duplicate name registration -> 409', 'first registration failed')

    r = s.post(f'{BASE_URL}/api/devices', json={
        'category': 'net', 'name': f'{PREFIX}_dup_ip_a', 'mode': 'agent', 'ip': '203.0.113.5', 'fields': {}},
        headers=h, timeout=10)
    dup_ip_ok = r.status_code == 200
    dup_ip_id = r.json().get('id') if dup_ip_ok else None
    if dup_ip_id:
        cleanup['devices'].append(dup_ip_id)
    if dup_ip_ok:
        r2 = s.post(f'{BASE_URL}/api/devices', json={
            'category': 'net', 'name': f'{PREFIX}_dup_ip_b', 'mode': 'agent', 'ip': '203.0.113.5', 'fields': {}},
            headers=h, timeout=10)
        check('E2 duplicate IP (different name) -> 409', r2.status_code == 409, f'got {r2.status_code}')
    else:
        skip('E2 duplicate IP (different name) -> 409', 'first registration failed')

    # ------------------------------------------------- F. 장비 등록 (agent 모드) --
    r = s.post(f'{BASE_URL}/api/devices', json={
        'category': 'server', 'name': f'{PREFIX}_agent', 'mode': 'agent', 'ip': None, 'fields': {}},
        headers=h, timeout=10)
    agent_ok = check('F1 register agent device (no IP, no connectivity check) -> 200', r.status_code == 200, f'got {r.status_code}: {r.text[:200]}')
    agent_id = r.json().get('id') if agent_ok else None
    agent_token = r.json().get('token') if agent_ok else None
    if agent_id:
        cleanup['devices'].append(agent_id)

    if agent_token:
        rr = requests.post(f'{BASE_URL}/api/agent/report', json={'token': agent_token, 'cpu': 12.5, 'mem': 40.0, 'disk': 55.0}, timeout=10, verify=False)
        check('F2 agent report with valid token -> 200 ok', rr.status_code == 200 and rr.json().get('ok'), f'got {rr.status_code}')

        r = s.post(f'{BASE_URL}/api/devices/{agent_id}/token/reissue', headers=h, timeout=10)
        reissue_ok = check('F3 POST token/reissue -> 200, new token differs', r.status_code == 200 and r.json().get('token') and r.json()['token'] != agent_token,
                            f'got {r.status_code}')
        new_token = r.json().get('token') if reissue_ok else None

        if new_token:
            rr_old = requests.post(f'{BASE_URL}/api/agent/report', json={'token': agent_token, 'cpu': 1, 'mem': 1, 'disk': 1}, timeout=10, verify=False)
            check('F4 old token rejected after reissue -> 404 unknown token', rr_old.status_code == 404, f'got {rr_old.status_code}')
            rr_new = requests.post(f'{BASE_URL}/api/agent/report', json={'token': new_token, 'cpu': 1, 'mem': 1, 'disk': 1}, timeout=10, verify=False)
            check('F5 new token accepted -> 200 ok', rr_new.status_code == 200 and rr_new.json().get('ok'), f'got {rr_new.status_code}')

            r = s.post(f'{BASE_URL}/api/devices/{agent_id}/token/revoke', headers=h, timeout=10)
            check('F6 POST token/revoke -> 200', r.status_code == 200, f'got {r.status_code}')
            rr_revoked = requests.post(f'{BASE_URL}/api/agent/report', json={'token': new_token, 'cpu': 1, 'mem': 1, 'disk': 1}, timeout=10, verify=False)
            check('F7 revoked token rejected -> 404 unknown token', rr_revoked.status_code == 404, f'got {rr_revoked.status_code}')
        else:
            for n in ('F4 old token rejected after reissue -> 404 unknown token', 'F5 new token accepted -> 200 ok',
                      'F6 POST token/revoke -> 200', 'F7 revoked token rejected -> 404 unknown token'):
                skip(n, 'token reissue failed (F3)')
    else:
        for n in ('F2 agent report with valid token -> 200 ok', 'F3 POST token/reissue -> 200, new token differs',
                  'F4 old token rejected after reissue -> 404 unknown token', 'F5 new token accepted -> 200 ok',
                  'F6 POST token/revoke -> 200', 'F7 revoked token rejected -> 404 unknown token'):
            skip(n, 'agent device registration failed (F1)')

    # --------------------------------------------- G. SNMP 모드 (검증 경로만) --
    r = s.post(f'{BASE_URL}/api/devices', json={
        'category': 'net', 'name': f'{PREFIX}_snmp_badport', 'mode': 'snmp', 'ip': '203.0.113.9', 'fields': {'snmpPort': 999999}},
        headers=h, timeout=10)
    check('G1 SNMP device with invalid port -> 400', r.status_code == 400, f'got {r.status_code}')
    skip('G2 SNMP device with valid connectivity -> 200', '실제 SNMP 에이전트가 있는 장비가 필요해 일반 환경에서는 건너뜀')

    # ------------------------------------------------------- H. 일괄 등록/내보내기 --
    # D1's ping device already occupies 127.0.0.1 -- the new duplicate-IP
    # check (section E) would correctly reject a second device there, so
    # free that IP first by deleting D's device now (nothing after this
    # point needs `ping_id` itself; K/M/O below use `bulk_device_id`
    # instead, once it exists).
    if ping_id:
        s.delete(f'{BASE_URL}/api/devices/{ping_id}', headers=h, timeout=10)
        if ping_id in cleanup['devices']:
            cleanup['devices'].remove(ping_id)

    r = s.get(f'{BASE_URL}/download/network-bulk-template', timeout=10)
    template_ok = check('H1 GET bulk-import template (.xlsx) -> 200', r.status_code == 200 and len(r.content) > 100, f'got {r.status_code}')

    bulk_device_id = None
    if template_ok and openpyxl:
        wb = openpyxl.load_workbook(io.BytesIO(r.content))
        ws = wb.active
        # The downloaded template ships with 2 illustrative example rows
        # (network_bulk_import.TEMPLATE_EXAMPLE_ROWS) meant to be deleted
        # before real data goes in -- leaving them in would try to register
        # them too (one SNMP, one ping, neither a real reachable device
        # here), throwing off successCount. Strip everything below the
        # header row first.
        if ws.max_row > 1:
            ws.delete_rows(2, ws.max_row - 1)
        ws.append([f'{PREFIX}_bulk1', '127.0.0.1', '기타', '', 'ping', '', '', ''])
        buf = io.BytesIO()
        wb.save(buf)
        buf.seek(0)
        files = {'file': ('bulk.xlsx', buf, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')}
        r = s.post(f'{BASE_URL}/api/devices/bulk-import/network', files=files, headers=h, timeout=30)
        bulk_ok = check('H2 bulk-import one ping row (127.0.0.1) -> 200, successCount=1',
                         r.status_code == 200 and r.json().get('successCount') == 1, f'got {r.status_code}: {r.text[:200]}')
        bulk_device_id = (r.json().get('results') or [{}])[0].get('id') if bulk_ok else None
        if bulk_device_id:
            cleanup['devices'].append(bulk_device_id)
    elif template_ok:
        skip('H2 bulk-import one ping row (127.0.0.1) -> 200', 'openpyxl이 설치되어 있지 않음')
    else:
        skip('H2 bulk-import one ping row (127.0.0.1) -> 200', '템플릿 다운로드 실패 (H1)')

    r = s.get(f'{BASE_URL}/api/devices/export/network', timeout=15)
    check('H3 GET /api/devices/export/network -> 200, non-empty xlsx', r.status_code == 200 and len(r.content) > 100, f'got {r.status_code}')

    # ------------------------------------------------------------- I. 그룹 --
    group_name = f'{PREFIX}_group'
    r = s.post(f'{BASE_URL}/api/groups', json={'name': group_name, 'description': 'functional test group'}, headers=h, timeout=10)
    group_ok = check('I1 POST /api/groups -> 200', r.status_code == 200, f'got {r.status_code}')
    if group_ok:
        cleanup['groups'].append(group_name)
        r = s.get(f'{BASE_URL}/api/groups', timeout=10)
        check('I2 GET /api/groups -> includes new group', r.status_code == 200 and
              any(g['name'] == group_name for g in r.json().get('groups', [])), f'got {r.status_code}')
        r = s.put(f'{BASE_URL}/api/groups/{group_name}', json={'description': 'updated'}, headers=h, timeout=10)
        check('I3 PUT /api/groups/<name> (description) -> 200', r.status_code == 200, f'got {r.status_code}')
        r = s.put(f'{BASE_URL}/api/groups/{group_name}/thresholds', json={'cpu': {'warn': 70, 'crit': 90}}, headers=h, timeout=10)
        check('I4 PUT /api/groups/<name>/thresholds -> 200', r.status_code == 200, f'got {r.status_code}')
    else:
        for n in ('I2 GET /api/groups -> includes new group', 'I3 PUT /api/groups/<name> (description) -> 200',
                  'I4 PUT /api/groups/<name>/thresholds -> 200'):
            skip(n, 'group creation failed (I1)')

    # --------------------------------------------- J. 전역 임계값 (읽기 전용) --
    r = s.get(f'{BASE_URL}/api/thresholds/global', timeout=10)
    check('J1 GET /api/thresholds/global -> 200', r.status_code == 200, f'got {r.status_code}')
    skip('J2 PUT /api/thresholds/global', '모든 장비에 영향을 주는 실제 운영 설정이라 쓰기 테스트는 건너뜀 (조회만 확인)')

    r = s.get(f'{BASE_URL}/api/thresholds/history', timeout=10)
    check('J3 GET /api/thresholds/history -> 200', r.status_code == 200, f'got {r.status_code}')

    # ------------------------------------------------------- K. 유지보수 창 --
    # D's ping device was deleted already (see section H) to free up
    # 127.0.0.1 -- reuse H's bulk-imported device (also a real ping-mode
    # device, same IP) as the reference device for the rest of the run.
    ref_device_id = bulk_device_id
    if ref_device_id:
        r = s.post(f'{BASE_URL}/api/maintenance/windows', json={
            'scope': 'device', 'scopeId': ref_device_id, 'kind': 'once',
            'startAt': int(time.time() * 1000) + 3600_000, 'endAt': int(time.time() * 1000) + 7200_000,
            'reason': 'functional test'}, headers=h, timeout=10)
        win_ok = check('K1 POST /api/maintenance/windows (once) -> 200', r.status_code == 200, f'got {r.status_code}: {r.text[:200]}')
        window_id = r.json().get('id') if win_ok else None
        if window_id:
            cleanup['windows'].append(window_id)
            r = s.put(f'{BASE_URL}/api/maintenance/windows/{window_id}/enabled', json={'enabled': False}, headers=h, timeout=10)
            check('K2 PUT .../enabled (disable) -> 200', r.status_code == 200, f'got {r.status_code}')
            r = s.get(f'{BASE_URL}/api/maintenance/log', timeout=10)
            check('K3 GET /api/maintenance/log -> 200', r.status_code == 200, f'got {r.status_code}')
        else:
            skip('K2 PUT .../enabled (disable) -> 200', 'window creation failed (K1)')
            skip('K3 GET /api/maintenance/log -> 200', 'window creation failed (K1)')
    else:
        for n in ('K1 POST /api/maintenance/windows (once) -> 200', 'K2 PUT .../enabled (disable) -> 200', 'K3 GET /api/maintenance/log -> 200'):
            skip(n, 'no reference device available (H2 bulk-import failed)')

    # ----------------------------------------------------- L. 알림 에스컬레이션 --
    r = s.get(f'{BASE_URL}/api/escalation/settings', timeout=10)
    check('L1 GET /api/escalation/settings -> 200', r.status_code == 200, f'got {r.status_code}')
    skip('L2 PUT /api/escalation/settings', '전역 on/off 싱글톤 설정이라 쓰기 테스트는 건너뜀 (조회만 확인)')

    r = s.post(f'{BASE_URL}/api/escalation/tiers', json={
        'name': f'{PREFIX}_tier', 'email': 'functest@example.com', 'timeoutMinutes': 15}, headers=h, timeout=10)
    tier_ok = check('L3 POST /api/escalation/tiers -> 200', r.status_code == 200, f'got {r.status_code}')
    tier_id = r.json().get('id') if tier_ok else None
    if tier_id:
        cleanup['tiers'].append(tier_id)
        r = s.put(f'{BASE_URL}/api/escalation/tiers/{tier_id}', json={
            'name': f'{PREFIX}_tier2', 'email': 'functest2@example.com', 'timeoutMinutes': 30, 'enabled': True}, headers=h, timeout=10)
        check('L4 PUT /api/escalation/tiers/<id> -> 200', r.status_code == 200, f'got {r.status_code}')
    else:
        skip('L4 PUT /api/escalation/tiers/<id> -> 200', 'tier creation failed (L3)')

    r = s.get(f'{BASE_URL}/api/escalation/log', timeout=10)
    check('L5 GET /api/escalation/log -> 200', r.status_code == 200, f'got {r.status_code}')

    # ------------------------------------------------------------- M. SLA --
    r = s.get(f'{BASE_URL}/api/sla/overview', timeout=10)
    check('M1 GET /api/sla/overview -> 200', r.status_code == 200, f'got {r.status_code}')
    r = s.get(f'{BASE_URL}/api/sla/settings', timeout=10)
    check('M2 GET /api/sla/settings -> 200', r.status_code == 200, f'got {r.status_code}')
    if ref_device_id:
        r = s.get(f'{BASE_URL}/api/sla/device/{ref_device_id}', timeout=10)
        check('M3 GET /api/sla/device/<id> -> 200', r.status_code == 200, f'got {r.status_code}')
    else:
        skip('M3 GET /api/sla/device/<id> -> 200', 'no reference device available (H2 bulk-import failed)')

    # ------------------------------------------------------------- N. 보고서 --
    r = s.get(f'{BASE_URL}/api/reports/export?type=incident&format=pdf', timeout=20)
    check('N1 GET /api/reports/export (incident/pdf) -> 200, non-empty', r.status_code == 200 and len(r.content) > 100, f'got {r.status_code}')
    r = s.get(f'{BASE_URL}/api/reports/export?type=resource&format=excel', timeout=20)
    check('N2 GET /api/reports/export (resource/excel) -> 200, non-empty', r.status_code == 200 and len(r.content) > 100, f'got {r.status_code}')

    r = s.post(f'{BASE_URL}/api/reports/schedules', json={
        'name': f'{PREFIX}_schedule', 'frequency': 'weekly', 'reportType': 'incident', 'format': 'pdf',
        'recipients': ['functest@example.com']}, headers=h, timeout=10)
    sched_ok = check('N3 POST /api/reports/schedules -> 200', r.status_code == 200, f'got {r.status_code}: {r.text[:200]}')
    schedule_id = r.json().get('id') if sched_ok else None
    if schedule_id:
        cleanup['schedules'].append(schedule_id)
        r = s.put(f'{BASE_URL}/api/reports/schedules/{schedule_id}/enabled', json={'enabled': False}, headers=h, timeout=10)
        check('N4 PUT .../enabled (disable) -> 200', r.status_code == 200, f'got {r.status_code}')
    else:
        skip('N4 PUT .../enabled (disable) -> 200', 'schedule creation failed (N3)')

    r = s.get(f'{BASE_URL}/api/reports/delivery-log', timeout=10)
    check('N5 GET /api/reports/delivery-log -> 200', r.status_code == 200, f'got {r.status_code}')

    # --------------------------------------------------------- O. 공개 상태 페이지 --
    if ref_device_id:
        r = s.post(f'{BASE_URL}/api/public-status/services', json={
            'label': f'{PREFIX}_service', 'deviceId': ref_device_id, 'description': 'functional test'}, headers=h, timeout=10)
        svc_ok = check('O1 POST /api/public-status/services -> 200', r.status_code == 200, f'got {r.status_code}')
        service_id = r.json().get('id') if svc_ok else None
        if service_id:
            cleanup['services'].append(service_id)
            r = s.put(f'{BASE_URL}/api/public-status/services/{service_id}', json={'enabled': False}, headers=h, timeout=10)
            check('O2 PUT /api/public-status/services/<id> -> 200', r.status_code == 200, f'got {r.status_code}')

            r = s.post(f'{BASE_URL}/api/public-status/announcements', json={
                'title': f'{PREFIX}_announcement', 'body': 'functional test', 'status': 'investigating',
                'serviceId': service_id}, headers=h, timeout=10)
            ann_ok = check('O3 POST /api/public-status/announcements -> 200', r.status_code == 200, f'got {r.status_code}')
            ann_id = r.json().get('id') if ann_ok else None
            if ann_id:
                cleanup['announcements'].append(ann_id)
                r = s.put(f'{BASE_URL}/api/public-status/announcements/{ann_id}', json={'status': 'resolved'}, headers=h, timeout=10)
                check('O4 PUT /api/public-status/announcements/<id> (resolve) -> 200', r.status_code == 200, f'got {r.status_code}')
            else:
                skip('O4 PUT /api/public-status/announcements/<id> (resolve) -> 200', 'announcement creation failed (O3)')
        else:
            for n in ('O2 PUT /api/public-status/services/<id> -> 200', 'O3 POST /api/public-status/announcements -> 200',
                      'O4 PUT /api/public-status/announcements/<id> (resolve) -> 200'):
                skip(n, 'service creation failed (O1)')
    else:
        for n in ('O1 POST /api/public-status/services -> 200', 'O2 PUT /api/public-status/services/<id> -> 200',
                  'O3 POST /api/public-status/announcements -> 200', 'O4 PUT /api/public-status/announcements/<id> (resolve) -> 200'):
            skip(n, 'no reference device available (H2 bulk-import failed)')

    # ------------------------------------------- P. 알림 채널 설정 (조회 전용) --
    for prefix, label in (('smtp', 'SMTP'), ('slack', 'Slack'), ('kakao', 'Kakao'), ('kakaobiz', 'KakaoBiz'), ('sms', 'SMS')):
        r = s.get(f'{BASE_URL}/api/settings/{prefix}', timeout=10)
        check(f'P GET /api/settings/{prefix} -> 200 ({label})', r.status_code == 200, f'got {r.status_code}')
    skip('P (write/test-send for every channel)', '실제 운영 중인 알림 채널 자격증명을 덮어쓰지 않기 위해 건너뜀 -- 각 채널의 "테스트 발송" 버튼으로 수동 확인')

    r = s.get(f'{BASE_URL}/api/kakaobiz/recipients', timeout=10)
    check('P GET /api/kakaobiz/recipients -> 200', r.status_code == 200, f'got {r.status_code}')

    # --------------------------------------------------------- Q. 토폴로지 --
    r = s.get(f'{BASE_URL}/api/topology/links', timeout=10)
    check('Q1 GET /api/topology/links -> 200', r.status_code == 200, f'got {r.status_code}')

    # --------------------------------------------------------- R. NetFlow/sFlow --
    for path in ('status', 'summary', 'timeseries', 'protocols', 'top-talkers'):
        r = s.get(f'{BASE_URL}/api/flow/{path}', timeout=10)
        check(f'R GET /api/flow/{path} -> 200', r.status_code == 200, f'got {r.status_code}')

    # --------------------------------------------------------- S. 사용자 관리 --
    tmp_user = f"{PREFIX}_user"
    tmp_pass = _secrets.token_hex(12)
    r = s.post(f'{BASE_URL}/api/users', json={'username': tmp_user, 'password': tmp_pass, 'role': 'VIEWER'}, headers=h, timeout=10)
    user_ok = check('S1 POST /api/users (VIEWER) -> 200', r.status_code == 200, f'got {r.status_code}')
    if user_ok:
        users = s.get(f'{BASE_URL}/api/users', timeout=10).json().get('users', [])
        uid = next((u['id'] for u in users if u['username'] == tmp_user), None)
        if uid:
            cleanup['users'].append(uid)
            r = s.put(f'{BASE_URL}/api/users/{uid}', json={'role': 'OPERATOR'}, headers=h, timeout=10)
            check('S2 PUT /api/users/<id> (role change) -> 200', r.status_code == 200, f'got {r.status_code}')
            vs = requests.Session()
            vs.verify = False
            vr = vs.post(f'{BASE_URL}/api/auth/login', json={'username': tmp_user, 'password': tmp_pass}, timeout=10)
            check('S3 new user can log in -> 200', vr.status_code == 200, f'got {vr.status_code}')
        else:
            skip('S2 PUT /api/users/<id> (role change) -> 200', 'could not find created user id')
            skip('S3 new user can log in -> 200', 'could not find created user id')
    else:
        skip('S2 PUT /api/users/<id> (role change) -> 200', 'user creation failed (S1)')
        skip('S3 new user can log in -> 200', 'user creation failed (S1)')

    # --------------------------------------------------------- T. 일괄 삭제 --
    bulk_del_targets = [d for d in (dup1_id, dup_ip_id) if d]
    if bulk_del_targets:
        r = s.post(f'{BASE_URL}/api/devices/bulk-delete', json={'ids': bulk_del_targets}, headers=h, timeout=10)
        if check('T1 POST /api/devices/bulk-delete -> 200', r.status_code == 200, f'got {r.status_code}'):
            for d in bulk_del_targets:
                if d in cleanup['devices']:
                    cleanup['devices'].remove(d)  # already deleted by bulk-delete, skip in final cleanup
    else:
        skip('T1 POST /api/devices/bulk-delete -> 200', 'no devices available to bulk-delete (E1/E2 failed)')


def do_cleanup(s, h):
    print('\n--- cleanup ---')
    for did in cleanup['devices']:
        s.delete(f'{BASE_URL}/api/devices/{did}', headers=h, timeout=10)
    for sid in cleanup['services']:
        s.delete(f'{BASE_URL}/api/public-status/services/{sid}', headers=h, timeout=10)
    for aid in cleanup['announcements']:
        s.delete(f'{BASE_URL}/api/public-status/announcements/{aid}', headers=h, timeout=10)
    for wid in cleanup['windows']:
        s.delete(f'{BASE_URL}/api/maintenance/windows/{wid}', headers=h, timeout=10)
    for tid in cleanup['tiers']:
        s.delete(f'{BASE_URL}/api/escalation/tiers/{tid}', headers=h, timeout=10)
    for sid in cleanup['schedules']:
        s.delete(f'{BASE_URL}/api/reports/schedules/{sid}', headers=h, timeout=10)
    for tok in cleanup['tokens']:
        s.delete(f'{BASE_URL}/api/tokens/{tok}', headers=h, timeout=10)
    for uid in cleanup['users']:
        s.delete(f'{BASE_URL}/api/users/{uid}', headers=h, timeout=10)
    for gname in cleanup['groups']:
        s.delete(f'{BASE_URL}/api/groups/{gname}', headers=h, timeout=10)
    print(f"cleaned up: {sum(len(v) for v in cleanup.values())} temp record(s)")


def print_summary():
    print()
    passed = sum(1 for _, st, _ in results if st == 'PASS')
    failed = sum(1 for _, st, _ in results if st == 'FAIL')
    skipped = sum(1 for _, st, _ in results if st == 'SKIP')
    print(f"=== {passed} passed, {failed} failed, {skipped} skipped (of {len(results)}) ===")
    if failed:
        sys.exit(1)


if __name__ == '__main__':
    main()
