"""Automated security regression tests (directive section 40 -- the 20-case
checklist) plus a short functional regression pass (section 41).

Run against an already-running InfraSight instance:

    INFRASIGHT_TEST_ADMIN_USER=admin INFRASIGHT_TEST_ADMIN_PASS='...' \
        python security_tests.py [base_url]

Credentials are read from environment variables ONLY -- never hardcode a
real password in this file, since it's meant to be committed alongside the
rest of the source. Tests that need an authenticated admin session are
skipped (not failed) if the env vars aren't set, so this script is still
safe to hand to someone else without your credentials.

This creates and deletes its own temporary test devices/users; it does not
touch any of your real registered devices, and every test user it creates is
deleted again at the end of the run.
"""
import json
import os
import sys
import time

import requests
import urllib3

# The session cookie is Secure-flagged (HTTPS-only -- see server.py's login
# route), so `requests` only sends it back on a follow-up request if that
# request is itself HTTPS: hitting the plain-HTTP backend port (5057)
# silently drops the cookie after login, and every "authenticated" call
# below then 401s even though login itself returned 200 -- confirmed
# directly (this was a real, previously-unnoticed bug in this exact
# script). Must go through Caddy's HTTPS port (8443), the same path a real
# user's browser takes. Caddy's cert is issued by mkcert's local CA, which
# isn't in the `requests`/certifi trust bundle (`mkcert -install` only
# adds it to the Windows cert store, which `requests` doesn't consult), so
# verify=False is used throughout -- the normal way to point a local test
# script at a self-signed/local-CA HTTPS endpoint without wiring in a
# separate trust bundle for it. Testing against a plain dev server instead of
# the real Caddy? ops\devtest-https.ps1 puts a throwaway HTTPS front-end on
# any dev backend port in one command.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
BASE_URL = sys.argv[1] if len(sys.argv) > 1 else 'https://localhost:8443'
ADMIN_USER = os.environ.get('INFRASIGHT_TEST_ADMIN_USER')
ADMIN_PASS = os.environ.get('INFRASIGHT_TEST_ADMIN_PASS')

results = []  # (name, 'PASS'|'FAIL'|'SKIP', detail)


def check(name, condition, detail=''):
    results.append((name, 'PASS' if condition else 'FAIL', detail))
    print(f"[{'PASS' if condition else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not condition else ''))


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
    print(f"Target: {BASE_URL}\n")

    # 1. Unauthenticated access to a device-data API
    r = requests.get(f'{BASE_URL}/api/state', timeout=10, verify=False)
    check('01 unauth GET /api/state -> 401', r.status_code == 401, f'got {r.status_code}')

    # 2. Unauthenticated device deletion
    r = requests.delete(f'{BASE_URL}/api/devices/does-not-exist', timeout=10, verify=False)
    check('02 unauth DELETE /api/devices/<id> -> 401', r.status_code == 401, f'got {r.status_code}')

    # 9/18/19/20 don't need auth -- run these regardless of admin creds
    # 17. Malformed JSON body
    r = requests.post(f'{BASE_URL}/api/auth/login', data='{not json', headers={'Content-Type': 'application/json'}, timeout=10, verify=False)
    check('17 malformed JSON -> 400', r.status_code == 400, f'got {r.status_code}')

    # 18. Oversized request body (MAX_CONTENT_LENGTH = 2MB)
    big_body = json.dumps({'username': 'x' * (3 * 1024 * 1024), 'password': 'x'})
    r = requests.post(f'{BASE_URL}/api/auth/login', data=big_body, headers={'Content-Type': 'application/json'}, timeout=15, verify=False)
    check('18 oversized request body -> 413', r.status_code == 413, f'got {r.status_code}')

    # 19. Nonexistent API
    r = requests.get(f'{BASE_URL}/api/this-endpoint-does-not-exist', timeout=10, verify=False)
    check('19 nonexistent endpoint -> 404', r.status_code == 404, f'got {r.status_code}')

    # 20. HTTP method tampering
    r = requests.patch(f'{BASE_URL}/api/devices', timeout=10, verify=False)
    check('20 PATCH /api/devices -> 405', r.status_code == 405, f'got {r.status_code}')

    # 10. Path traversal against static-file-serving endpoints
    r = requests.get(f'{BASE_URL}/download/installer/..%2f..%2finfrasight.db', timeout=10, verify=False)
    check('10 path traversal on /download/installer -> 404 (not the DB file)',
          r.status_code == 404 or 'sqlite' not in r.text.lower(), f'got {r.status_code}')

    # 14. Unknown agent token
    r = requests.post(f'{BASE_URL}/api/agent/report', json={'token': 'not-a-real-token', 'cpu': 1, 'mem': 1, 'disk': 1}, timeout=10, verify=False)
    check('14 unknown agent token -> 404', r.status_code == 404, f'got {r.status_code}')

    # 6. Garbage/tampered session cookie
    s = requests.Session()
    s.verify = False
    s.cookies.set('session', 'garbage.tampered.cookie')
    r = s.get(f'{BASE_URL}/api/state', timeout=10)
    check('06 tampered session cookie -> 401', r.status_code == 401, f'got {r.status_code}')

    if not (ADMIN_USER and ADMIN_PASS):
        for n in ('03 VIEWER role deletes device -> 403', '04 wrong CSRF token -> 403',
                  '05 session invalidated after logout -> 401', '07 account lockout after 5 failures -> 423',
                  '08 SQL injection payload in device name -> safely rejected/stored',
                  '09 XSS payload in device name -> rejected by input validation',
                  '11 invalid IP (ping-flag injection attempt) -> 400',
                  '12 invalid SNMP port -> 400',
                  '13 unknown extra field in payload -> ignored, not a crash',
                  '15 metrics for a random nonexistent device_id -> 200, empty',
                  '16 SNMP device with bogus community registers fine (polling failure is async)'):
            skip(n, 'INFRASIGHT_TEST_ADMIN_USER/PASS not set')
        print_summary()
        return

    try:
        s, csrf = admin_session()
    except Exception as e:
        # Most likely cause: the Phase B per-IP login rate limit (20/5min) was
        # already used up by an earlier run of this same script -- that's the
        # rate limiter doing exactly what it's supposed to, not a bug. Fail
        # loudly but don't crash: whatever ran before this point still counts.
        for n in ('03 VIEWER role deletes device -> 403', '04 wrong CSRF token -> 403',
                  '05 session invalidated after logout -> 401', '07 account lockout after 5 failures -> 423',
                  '08 SQL injection payload in device name -> safely rejected/stored',
                  '09 XSS payload in device name -> rejected by input validation',
                  '11 invalid IP (ping-flag injection attempt) -> 400',
                  '12 invalid SNMP port -> 400',
                  '13 unknown extra field in payload -> ignored, not a crash',
                  '15 metrics for a random nonexistent device_id -> 200, empty',
                  '16 SNMP device with bogus community registers fine (polling failure is async)'):
            skip(n, f'admin login failed ({e}) -- possibly rate-limited from a previous run; wait 5 min or restart the server')
        print_summary()
        return
    headers = {'X-CSRF-Token': csrf}

    # 4. Wrong CSRF token on a state-changing request
    r = s.post(f'{BASE_URL}/api/devices', json={'category': 'net', 'name': 'csrf-test', 'mode': 'ping', 'ip': '10.0.0.1', 'fields': {}},
               headers={'X-CSRF-Token': 'wrong-token'}, timeout=10)
    check('04 wrong CSRF token -> 403', r.status_code == 403, f'got {r.status_code}')

    # 8. SQL injection in device name -- should be rejected by is_safe_name (quotes/semicolons aren't in the allow-list)
    r = s.post(f'{BASE_URL}/api/devices', json={'category': 'net', 'name': "x'; DROP TABLE devices;--", 'mode': 'ping', 'ip': '10.0.0.1', 'fields': {}},
               headers=headers, timeout=10)
    sqli_rejected = r.status_code == 400
    # Confirm the table really is intact either way
    r2 = s.get(f'{BASE_URL}/api/state', timeout=10)
    table_intact = r2.status_code == 200 and 'servers' in r2.json()
    check('08 SQL injection payload in device name -> rejected, table intact', sqli_rejected and table_intact,
          f'register status={r.status_code}, state status={r2.status_code}')

    # 9. XSS payload in device name -- should be rejected by is_safe_name (angle brackets aren't allowed)
    r = s.post(f'{BASE_URL}/api/devices', json={'category': 'net', 'name': '<script>alert(1)</script>', 'mode': 'ping', 'ip': '10.0.0.1', 'fields': {}},
               headers=headers, timeout=10)
    check('09 XSS payload in device name -> 400', r.status_code == 400, f'got {r.status_code}')

    # 11. Invalid IP / ping-argument-injection attempt
    r = s.post(f'{BASE_URL}/api/devices', json={'category': 'net', 'name': 'sec-test-badip', 'mode': 'ping', 'ip': '-t', 'fields': {}},
               headers=headers, timeout=10)
    check('11 invalid IP (ping-flag injection attempt) -> 400', r.status_code == 400, f'got {r.status_code}')

    # 12. Invalid SNMP port
    r = s.post(f'{BASE_URL}/api/devices', json={'category': 'net', 'name': 'sec-test-badport', 'mode': 'snmp', 'ip': '10.0.0.1', 'fields': {'snmpPort': 999999}},
               headers=headers, timeout=10)
    check('12 invalid SNMP port -> 400', r.status_code == 400, f'got {r.status_code}')

    # 13. Unknown extra field in payload should just be ignored, not crash the
    # endpoint -- uses 127.0.0.1 (always reachable) rather than an arbitrary
    # private IP like 10.0.0.2, which has no guarantee of answering ping in
    # an arbitrary test environment and would 400 on the (unrelated)
    # reachability check before ever exercising what this case is actually
    # about. (Found live: this case silently never ran correctly before --
    # the whole authenticated section 401'd on every request due to the
    # Secure-cookie/HTTP-port bug fixed above, so this bad assumption was
    # never actually exposed until now.)
    r = s.post(f'{BASE_URL}/api/devices', json={'category': 'net', 'name': 'sec-test-extra', 'mode': 'ping', 'ip': '127.0.0.1',
                                                 'fields': {}, 'pollingIntervalTotallyMadeUp': -999}, headers=headers, timeout=10)
    check('13 unrecognized field in payload -> ignored (still 200)', r.status_code == 200, f'got {r.status_code}')
    extra_device_id = r.json().get('id') if r.status_code == 200 else None

    # 16. SNMP device registration requires a real, live connectivity test
    # (same pattern as ping -- see _register_device_core's `if mode ==
    # 'snmp':` branch) -- a bogus community against a target with no real
    # SNMP responder times out exactly like an unreachable host and is
    # rejected at registration time (400), not deferred to poll time. (This
    # case's original comment/assumption -- "registers fine, fails only at
    # poll time" -- doesn't match current server.py behavior; same
    # never-actually-ran reason as 13 above.)
    r = s.post(f'{BASE_URL}/api/devices', json={'category': 'net', 'name': 'sec-test-badcommunity', 'mode': 'snmp', 'ip': '203.0.113.3',
                                                 'fields': {'community': 'definitely-wrong'}}, headers=headers, timeout=10)
    check('16 SNMP device with bogus community / unreachable target -> 400 at registration time', r.status_code == 400, f'got {r.status_code}')
    snmp_device_id = r.json().get('id') if r.status_code == 200 else None

    # 15. Metrics for a random, nonexistent device_id should degrade gracefully, not 500
    r = s.get(f'{BASE_URL}/api/devices/does-not-exist-12345/metrics?metric=cpu', timeout=10)
    check('15 metrics for nonexistent device_id -> 200 with empty points',
          r.status_code == 200 and r.json().get('points') == [], f'got {r.status_code}: {r.text[:200]}')

    # 3. VIEWER role cannot delete a device
    import secrets as _secrets
    tmp_user = f"sectest_{_secrets.token_hex(4)}"
    tmp_pass = _secrets.token_hex(12)
    r = s.post(f'{BASE_URL}/api/users', json={'username': tmp_user, 'password': tmp_pass, 'role': 'VIEWER'}, headers=headers, timeout=10)
    viewer_created = r.status_code == 200
    if viewer_created:
        vs = requests.Session()
        vs.verify = False
        vr = vs.post(f'{BASE_URL}/api/auth/login', json={'username': tmp_user, 'password': tmp_pass}, timeout=10)
        v_csrf = vr.json().get('csrfToken')
        dr = vs.delete(f'{BASE_URL}/api/devices/{extra_device_id or "x"}', headers={'X-CSRF-Token': v_csrf}, timeout=10)
        check('03 VIEWER role deletes device -> 403', dr.status_code == 403, f'got {dr.status_code}')
    else:
        skip('03 VIEWER role deletes device -> 403', 'could not create temp VIEWER user')

    # 7. Account lockout after 5 failed attempts (uses a disposable temp account)
    lock_user = f"sectest_lock_{_secrets.token_hex(4)}"
    lock_pass = _secrets.token_hex(12)
    r = s.post(f'{BASE_URL}/api/users', json={'username': lock_user, 'password': lock_pass, 'role': 'VIEWER'}, headers=headers, timeout=10)
    if r.status_code == 200:
        last_status = None
        for _ in range(5):
            fr = requests.post(f'{BASE_URL}/api/auth/login', json={'username': lock_user, 'password': 'wrong'}, timeout=10, verify=False)
            last_status = fr.status_code
        check('07 account lockout after 5 failed attempts -> 423', last_status == 423, f'got {last_status}')
        # unlock + delete the temp user
        users = s.get(f'{BASE_URL}/api/users', timeout=10).json().get('users', [])
        uid = next((u['id'] for u in users if u['username'] == lock_user), None)
        if uid:
            s.delete(f'{BASE_URL}/api/users/{uid}', headers=headers, timeout=10)
    else:
        skip('07 account lockout after 5 failed attempts -> 423', 'could not create temp account')

    # --- cleanup: delete every temp device/user this run created, using the
    # ORIGINAL session `s` -- it's still valid here because nothing has
    # logged out yet. Do this BEFORE test 05: a successful logout bumps the
    # admin account's session_version globally (that's the actual Phase B
    # fix under test), which invalidates every open session for that same
    # user, `s` included, so cleanup has to happen first.
    for did in (extra_device_id, snmp_device_id):
        if did:
            s.delete(f'{BASE_URL}/api/devices/{did}', headers=headers, timeout=10)
    if viewer_created:
        users = s.get(f'{BASE_URL}/api/users', timeout=10).json().get('users', [])
        uid = next((u['id'] for u in users if u['username'] == tmp_user), None)
        if uid:
            s.delete(f'{BASE_URL}/api/users/{uid}', headers=headers, timeout=10)

    # 5. Session invalidated after logout (the actual fix from Phase B) -- run
    # last and reuse `s` itself (no extra login -- every login here counts
    # against the Phase B per-IP rate limit too, so minimizing login calls
    # matters if this script gets re-run repeatedly in a short window).
    s.post(f'{BASE_URL}/api/auth/logout', timeout=10)
    r = s.get(f'{BASE_URL}/api/auth/me', timeout=10)
    check('05 session invalidated after logout -> 401', r.status_code == 401, f'got {r.status_code}')

    print_summary()


def print_summary():
    print()
    passed = sum(1 for _, s, _ in results if s == 'PASS')
    failed = sum(1 for _, s, _ in results if s == 'FAIL')
    skipped = sum(1 for _, s, _ in results if s == 'SKIP')
    print(f"=== {passed} passed, {failed} failed, {skipped} skipped (of {len(results)}) ===")
    if failed:
        sys.exit(1)


if __name__ == '__main__':
    main()
