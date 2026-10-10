"""
InfraSight local monitoring service.

Serves the dashboard and a small JSON API. Actual monitoring (local psutil,
agent reports, ping/TCP reachability, SNMP) is done by the collector/
package on a per-device APScheduler schedule; this file only wires up Flask
routes and reads/writes the shared state in collector.state / storage.

Run:  python server.py   (see start.bat for a one-click launcher)
"""
import json
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import defaultdict, deque
from datetime import timedelta, datetime
from functools import wraps

import psutil
from flask import Flask, Response, g, jsonify, redirect, request, send_file, send_from_directory, session
from waitress import serve
from werkzeug.middleware.proxy_fix import ProxyFix

import storage
import validation
import totp
from applog import app_logger, safe_log_value
from collector import state, scheduler, health, metrics, thresholds, maintenance, sla, report_delivery, public_status
import reports
import network_bulk_import
from collector import agent_collector, ping_collector
from collector.snmp_collector import SNMP_AVAILABLE
from collector import snmp_collector
from collector import discovery
from collector import flow_listener

BASE_DIR = storage.BASE_DIR
PORT = storage.PORT
LOCAL_ID = storage.LOCAL_ID

app = Flask(__name__, static_folder=None)


class _TrustedProxyFix:
    """Like werkzeug's ProxyFix, but only honors X-Forwarded-* headers when
    the request's actual TCP peer is this machine itself -- i.e. it really
    did come through the local Caddy reverse proxy (Caddyfile points
    reverse_proxy at 127.0.0.1:5057). Without this guard, plain ProxyFix
    would trust X-Forwarded-For on *every* request, including one sent
    directly to waitress's 0.0.0.0:5057 listener (still open for
    not-yet-migrated agents/browsers -- see the Caddyfile's comments on the
    transition period): a remote client could forge its own X-Forwarded-For
    and corrupt every audit_log row's source_ip. Once 5057 is firewalled to
    localhost-only, that direct path goes away and this reduces to plain
    ProxyFix behavior."""
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app
        self._proxied = ProxyFix(wsgi_app, x_for=1, x_proto=1, x_host=0, x_port=0, x_prefix=0)

    def __call__(self, environ, start_response):
        if environ.get('REMOTE_ADDR') in ('127.0.0.1', '::1'):
            return self._proxied(environ, start_response)
        return self.wsgi_app(environ, start_response)


# Security hardening Phase E: see _TrustedProxyFix above for why this isn't
# just werkzeug's ProxyFix directly. This is what makes request.remote_addr
# (used everywhere audit_log records source_ip) show the real browser/agent
# IP again instead of always "127.0.0.1" once Caddy is in front.
app.wsgi_app = _TrustedProxyFix(app.wsgi_app)


# ------------------------------------------------------------------ auth --
def _load_or_create_secret_key():
    # A dotfile next to the DB, outside anything Flask ever serves (static_folder
    # is None and send_from_directory only ever names index.html/agent.py/dist/*
    # explicitly) -- so sessions survive a server restart without the signing
    # key living in source code.
    path = os.path.join(BASE_DIR, '.infrasight_secret_key')
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(key)
    return key


app.secret_key = _load_or_create_secret_key()
# Security hardening Phase B section 2/23: idle-timeout the session. The
# *sliding* part (a dashboard tab left open and actively polling never
# idles out, but a closed/forgotten one does after 30 min) depends on
# session.permanent=True at every login site below -- Flask's
# should_set_cookie() only re-signs (refreshes) the cookie on a response
# when session.modified is True OR (session.permanent AND
# SESSION_REFRESH_EACH_REQUEST). A plain polling request that doesn't touch
# the session dict leaves session.modified False, so without
# session.permanent the second condition is always False too: the cookie
# is never resent, its embedded timestamp never advances, and the session
# hard-expires exactly PERMANENT_SESSION_LIFETIME after login no matter how
# continuously the dashboard is being used right then. Confirmed as the
# cause of a real "로그인 중에 갑자기 로그아웃됨" report after a few days of
# this *not* being set (see the reboot-cookie history below for why it was
# removed in the first place) -- restored here, sliding-idle-timeout is the
# actual intent.
#
# SameSite=Lax stops the cookie being sent on cross-site POST/PUT/DELETE,
# which is most of what CSRF relies on; the explicit CSRF token below
# covers the rest.
#
# Reboot-cookie history (why session.permanent being on does NOT bring back
# the original "still logged in after a reboot" bug): a permanent cookie
# carries its own Expires/Max-Age, so the browser persists it to disk and
# it survives the browser (and the whole PC) restarting -- and separately,
# even a non-permanent "session cookie" isn't reliably gone after a restart
# either, since Chrome/Edge's "continue where you left off" (and Firefox's
# "restore previous session") deliberately keep those alive too, so neither
# cookie flavor can be trusted to enforce "logged out after reboot" on its
# own. What actually fixed that report is BOOT_TIME below, independent of
# any cookie attribute: captured once when this process starts, every
# session carries the BOOT_TIME it was issued under (session['boot'] at
# each login site) and require_role() rejects a mismatch exactly like a
# session_version mismatch. A reboot restarts this process too (the
# supervisor scheduled task), so the freshly-imported BOOT_TIME is new and
# every pre-reboot session -- however the browser preserved its cookie --
# stops validating immediately, regardless of session.permanent. A plain
# backend crash/auto-restart with no real reboot leaves BOOT_TIME
# unchanged, so that case still doesn't force everyone to re-login.
#
# Bug found the hard way: psutil.boot_time() is NOT bit-for-bit identical
# across separate process launches on the same, never-rebooted machine --
# confirmed directly (three separate `python -c` calls returned
# 1791284431.2269921 / .226992 / .2269921, a few ULPs apart, likely from
# how it derives boot time as time.time() minus uptime internally). With
# exact float equality, that jitter alone made *every* plain backend
# restart (several a day while iterating on this app -- nothing to do with
# an actual reboot) silently invalidate every logged-in session. Rounded
# to whole seconds: a real reboot still differs by minutes at the very
# least, so this loses none of the real detection while absorbing noise
# many orders of magnitude smaller than what it's meant to catch.
BOOT_TIME = round(psutil.boot_time())
#
# Security review pass: SESSION_COOKIE_SECURE was left off through Phase E
# (HTTPS via Caddy) landing -- the comment here used to say "revisit once
# HTTPS is in place" and then nobody did, so the login session cookie was
# still being sent over plain HTTP too. Now that Caddy is the supervised,
# always-on way this app is accessed, Secure is on: the browser will refuse
# to store or send this cookie over anything but HTTPS. This is a deliberate
# breaking change for the *old* http://<ip>:5057-direct login path (see
# start.bat, updated to open the HTTPS address) -- accepted intentionally
# rather than leaving the session cookie interceptable on the LAN.
# api_agent_report is unaffected either way: it was never cookie-based (the
# device token travels in the request body, not a cookie).
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
# Security hardening Phase G (audit item #17, "요청 크기 제한 없음"): without
# this, waitress's own default (1GB) is the only limit on a request body --
# a device-registration or SMTP-settings payload has no legitimate reason to
# be anywhere near this large. 2MB comfortably fits the largest real payload
# (a metrics query response is a GET, not bounded by this at all) with
# headroom, while still refusing a deliberately oversized POST.
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024

CSRF_METHODS = ('POST', 'PUT', 'DELETE', 'PATCH')

# Security hardening Phase B section 3: per-IP login rate limit, on top of the
# per-account lockout in storage.verify_login. In-memory only (a restart
# clears it) -- this is a coarse net-abuse guard, not the primary defense.
_login_attempts_by_ip = defaultdict(deque)
IP_WINDOW_SEC = 300
IP_MAX_ATTEMPTS = 20


def _ip_rate_limited(ip):
    now = time.time()
    # Code review pass, finding #2: an IP's own deque emptying out (the loop
    # below) only ever gets noticed if that same IP shows up again later --
    # one attempt from an IP that never returns left a permanent, never-
    # collected dict entry. This endpoint is low-traffic (login attempts
    # only), so sweeping every known IP here each call is cheap, and it's
    # the only reliable way to actually bound the dict's size over time.
    stale = [k for k, dq in _login_attempts_by_ip.items() if not dq or now - dq[-1] > IP_WINDOW_SEC]
    for k in stale:
        del _login_attempts_by_ip[k]
    dq = _login_attempts_by_ip[ip]
    while dq and now - dq[0] > IP_WINDOW_SEC:
        dq.popleft()
    if len(dq) >= IP_MAX_ATTEMPTS:
        return True
    dq.append(now)
    return False


# 3-4 "외부 접근을 위한 ... 접근 제어 검토": the public status page has no
# login to rate-limit attempts against, but it's still an unauthenticated
# endpoint reachable by anyone on the internet once exposed -- a separate,
# more generous limiter (page views legitimately fire several API calls at
# once) than the login one, so a scraping/DoS-ish burst from one IP can't
# peg the collector thread pool that's also serving the real monitoring
# workload.
_public_requests_by_ip = defaultdict(deque)
PUBLIC_IP_WINDOW_SEC = 60
PUBLIC_IP_MAX_REQUESTS = 120


def _public_rate_limited(ip):
    now = time.time()
    stale = [k for k, dq in _public_requests_by_ip.items() if not dq or now - dq[-1] > PUBLIC_IP_WINDOW_SEC]
    for k in stale:
        del _public_requests_by_ip[k]
    dq = _public_requests_by_ip[ip]
    while dq and now - dq[0] > PUBLIC_IP_WINDOW_SEC:
        dq.popleft()
    if len(dq) >= PUBLIC_IP_MAX_REQUESTS:
        return True
    dq.append(now)
    return False


def _current_username():
    """The acting identity for this request, regardless of auth method --
    a browser session's username, or (5-2) an API token's owning user when
    this request authenticated via Authorization: Bearer instead. Every
    call site that used to read session.get('user')/session['user'] purely
    to answer "who did this" (audit attribution, ownership checks) should
    go through this instead, so those fields/checks stay correct for a
    token-authenticated request rather than silently seeing None or
    crashing on a direct session['user'] subscript."""
    return session.get('user') or getattr(g, 'api_token_row', {}).get('owner_username')


def _current_role():
    """Same idea as _current_username() but for the acting role/scope --
    an API token's scope is rank-compared via the exact same storage.
    ROLE_RANK table a session role is, so this is the one place code that
    needs "what rank is this request allowed to act as" should read from."""
    return session.get('role') or getattr(g, 'api_token_row', {}).get('scope')


def audit(action, target=None, details=None):
    storage.write_audit(_current_username(), action, target, details, request.remote_addr)


def _diff_str(before, after, keys):
    """Short 'field: old->new' summary for an audit log `details` string,
    listing only fields that actually changed (2nd dev pass, finding #2:
    edits used to log just the target id/name, with no record of what
    changed). Never pass a dict containing a password/token/SNMP credential
    here -- those stay out of every audit call by design (see the Security
    Hardening Phase review)."""
    parts = []
    for k in keys:
        b, a = before.get(k), after.get(k)
        if b != a:
            parts.append(f"{k}: {b!r}->{a!r}")
    return ', '.join(parts)


def _handle_token_auth(fn, token, min_role, args, kwargs):
    """5-2: the Authorization: Bearer branch of require_role() -- a
    completely separate code path from the session branch below (per
    "관리자 세션과 API 토큰 인증을 분리"), with its own scope check instead of
    session['role'], no CSRF check (a bearer token carries no ambient
    browser credential for a forged cross-site request to ride along on,
    unlike a cookie), and its own usage log instead of the CSRF/session
    audit events."""
    token_row = storage.find_api_token(token)
    if not token_row:
        return jsonify({'error': 'invalid_token'}), 401
    if storage.ROLE_RANK.get(token_row['scope'], -1) < storage.ROLE_RANK.get(min_role, 0):
        storage.write_audit(token_row['owner_username'], 'API_TOKEN_FORBIDDEN', target=request.path,
                             details=f"scope={token_row['scope']} needs {min_role}", source_ip=request.remote_addr)
        return jsonify({'error': 'forbidden'}), 403
    g.api_token_row = token_row
    storage.touch_api_token_last_used(token_row['id'])
    resp = fn(*args, **kwargs)
    status_code = resp[1] if isinstance(resp, tuple) else getattr(resp, 'status_code', 200)
    storage.record_api_token_usage(token_row['id'], request.method, request.path, status_code, request.remote_addr)
    return resp


def require_role(min_role='VIEWER'):
    """Replaces the old login_required for every protected route: checks the
    user is logged in, that their session hasn't been invalidated by a
    logout/password-change elsewhere (session_version), that their role meets
    the route's minimum, and -- for state-changing methods -- that a valid
    CSRF token was sent. Also accepts an Authorization: Bearer <api-token>
    in place of a session entirely (5-2) -- see _handle_token_auth above."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                return _handle_token_auth(fn, auth_header[7:].strip(), min_role, args, kwargs)
            username = session.get('user')
            if not username:
                return jsonify({'error': 'unauthorized'}), 401
            current_sv = storage.get_session_version(username)
            if current_sv is None or session.get('sv') != current_sv:
                session.clear()
                return jsonify({'error': 'session_expired'}), 401
            if session.get('boot') != BOOT_TIME:
                session.clear()
                return jsonify({'error': 'session_expired'}), 401
            if storage.ROLE_RANK.get(session.get('role'), -1) < storage.ROLE_RANK.get(min_role, 0):
                audit('AUTHORIZATION_FAILURE', target=request.path, details=f"role={session.get('role')} needs {min_role}")
                return jsonify({'error': 'forbidden'}), 403
            # 5-1 "관리자 계정 2FA 적용 정책" 강제 게이트: 2026-10-05 사용자
            # 요청으로 비활성화 -- 2FA 자체(등록/로그인 시 검증/관리자의 타
            # 계정 초기화)는 전부 그대로 동작하고, ADMIN 계정이 원하면 언제든
            # 자발적으로 켤 수 있다. 다만 "2FA 안 켜면 OPERATOR+ 작업을 전부
            # 막는다"는 강제성만 뺐다. 다시 켜려면 아래 블록의 주석을 풀면
            # 된다 (원래 동작: ADMIN 세션인데 2FA 미설정이면 VIEWER급을 뺀
            # 모든 요청을 totp_enrollment_required 403으로 거부).
            #
            # if session.get('role') == 'ADMIN' and min_role != 'VIEWER':
            #     user_row = storage.get_user_by_username(username)
            #     if user_row and not user_row['totp_enabled']:
            #         return jsonify({'error': 'totp_enrollment_required'}), 403
            if request.method in CSRF_METHODS:
                token = request.headers.get('X-CSRF-Token')
                if not token or token != session.get('csrf'):
                    audit('CSRF_FAILURE', target=request.path)
                    return jsonify({'error': 'csrf_failed'}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


@app.post('/api/auth/login')
def api_login():
    ip = request.remote_addr
    if _ip_rate_limited(ip):
        return jsonify({'error': '요청이 너무 많습니다. 잠시 후 다시 시도해주세요'}), 429
    body = request.get_json(force=True)
    username = (body.get('username') or '').strip()
    password = body.get('password') or ''
    result = storage.verify_login(username, password)
    if result['status'] == 'locked':
        storage.write_audit(username or None, 'ACCOUNT_LOCKED', source_ip=ip)
        return jsonify({'error': '로그인 실패 횟수를 초과해 계정이 잠겼습니다. 10분 후 다시 시도해주세요'}), 423
    if result['status'] == 'disabled':
        storage.write_audit(username or None, 'LOGIN_DISABLED_ACCOUNT', source_ip=ip)
        return jsonify({'error': '비활성화된 계정입니다. 관리자에게 문의해주세요'}), 403
    if result['status'] != 'ok':
        storage.write_audit(username or None, 'LOGIN_FAILED', source_ip=ip)
        return jsonify({'error': '아이디 또는 비밀번호가 올바르지 않습니다'}), 401
    session.clear()  # session-fixation defense: never reuse whatever session existed pre-login
    if result['totp_enabled']:
        # 5-1: password is correct, but the real session (session['user'],
        # ['role'], the CSRF token) is NOT established yet -- require_role
        # keys entirely off session['user'] being set, so leaving it unset
        # here is what actually blocks every protected route until the
        # second factor is verified, not just a frontend-side gate. A
        # short-lived 'pending' marker is all the session carries in the
        # meantime; /api/auth/totp-verify is the only thing that can turn
        # it into a real login.
        session['pending_2fa_user_id'] = result['user_id']
        session['pending_2fa_username'] = result['username']
        session['pending_2fa_exp'] = int(time.time()) + 300
        return jsonify({'ok': True, 'needsTotp': True})
    csrf_token = secrets.token_hex(16)
    session['user'] = result['username']
    session['role'] = result['role']
    session['sv'] = result['session_version']
    session['csrf'] = csrf_token
    session['boot'] = BOOT_TIME
    session.permanent = True
    storage.write_audit(result['username'], 'LOGIN', source_ip=ip)
    return jsonify({'ok': True, 'username': result['username'], 'role': result['role'], 'csrfToken': csrf_token,
                     'mustChangePassword': result.get('must_change_password', False)})


@app.post('/api/auth/totp-verify')
def api_totp_verify():
    """Completes a login that /api/auth/login left pending because the
    account has 2FA enabled (see above) -- the ONLY path that can turn a
    'pending_2fa_*' session into session['user'] actually being set."""
    ip = request.remote_addr
    pending_id = session.get('pending_2fa_user_id')
    pending_exp = session.get('pending_2fa_exp')
    if not pending_id or not pending_exp or time.time() > pending_exp:
        session.clear()
        return jsonify({'error': '로그인 세션이 만료되었습니다. 다시 로그인해주세요'}), 401
    user = storage.get_user_by_id(pending_id)
    if not user or not user['is_active']:
        session.clear()
        return jsonify({'error': '로그인할 수 없는 계정입니다'}), 401
    lockout = storage.totp_lockout_state(pending_id)
    now_ms = int(time.time() * 1000)
    if lockout['totp_locked_until'] and lockout['totp_locked_until'] > now_ms:
        return jsonify({'error': '인증 코드 입력 횟수를 초과했습니다. 10분 후 다시 시도해주세요'}), 423
    body = request.get_json(force=True)
    code = (body.get('code') or '').strip()
    recovery_code = (body.get('recoveryCode') or '').strip()
    ok = False
    used_recovery = False
    if recovery_code:
        ok = storage.consume_recovery_code(pending_id, recovery_code)
        used_recovery = ok
    elif code:
        secret = storage.get_credential(f'user:{pending_id}', 'totp_secret')
        ok = bool(secret) and totp.verify_totp(secret, code)
    if not ok:
        locked_until = storage.record_totp_failure(pending_id)
        storage.write_audit(user['username'], 'TOTP_FAILED', source_ip=ip)
        if locked_until:
            return jsonify({'error': '인증 코드 입력 횟수를 초과했습니다. 10분 후 다시 시도해주세요'}), 423
        return jsonify({'error': '인증 코드가 올바르지 않습니다'}), 401
    storage.clear_totp_failures(pending_id)
    session.clear()
    csrf_token = secrets.token_hex(16)
    session['user'] = user['username']
    session['role'] = user['role']
    session['sv'] = user['session_version']
    session['csrf'] = csrf_token
    session['boot'] = BOOT_TIME
    session.permanent = True
    storage.write_audit(user['username'], 'LOGIN (TOTP)' if not used_recovery else 'LOGIN (recovery code)', source_ip=ip)
    resp = {'ok': True, 'username': user['username'], 'role': user['role'], 'csrfToken': csrf_token,
            'mustChangePassword': bool(user['must_change_password'])}
    if used_recovery:
        storage.write_audit(user['username'], 'RECOVERY_CODE_USED', source_ip=ip)
        resp['recoveryCodesRemaining'] = storage.count_unused_recovery_codes(pending_id)
    return jsonify(resp)


@app.post('/api/auth/logout')
def api_logout():
    if session.get('user'):
        storage.bump_session_version(session['user'])  # invalidates this cookie and any other copy of it
        storage.write_audit(session['user'], 'LOGOUT', source_ip=request.remote_addr)
    session.clear()
    return jsonify({'ok': True})


@app.get('/api/auth/me')
@require_role('VIEWER')
def api_me():
    # A session created before this CSRF token existed (or one that
    # survived a server restart) won't have session['csrf'] yet -- issue one
    # now rather than forcing a re-login just to get a token.
    if not session.get('csrf'):
        session['csrf'] = secrets.token_hex(16)
    return jsonify({'username': session.get('user'), 'role': session.get('role'), 'csrfToken': session['csrf'],
                     'mustChangePassword': storage.get_must_change_password(session.get('user'))})


@app.post('/api/auth/change-password')
@require_role('VIEWER')
def api_change_password():
    body = request.get_json(force=True)
    current_password = body.get('currentPassword') or ''
    new_password = body.get('newPassword') or ''
    if len(new_password) < 8:
        return jsonify({'error': '새 비밀번호는 8자 이상이어야 합니다'}), 400
    if not storage.change_password(_current_username(), current_password, new_password):
        return jsonify({'error': '현재 비밀번호가 올바르지 않습니다'}), 401
    audit('CHANGE_PASSWORD')
    session.clear()  # the password change already bumped session_version; drop our own copy too
    return jsonify({'ok': True})


# --------------------------------------------------------- 5-1 2FA (self) --
def _qr_svg(data):
    import qrcode
    import qrcode.image.svg
    img = qrcode.make(data, image_factory=qrcode.image.svg.SvgPathImage)
    import io
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode('utf-8')


@app.post('/api/auth/totp/enroll/start')
@require_role('VIEWER')
def api_totp_enroll_start():
    """Any logged-in user can enroll themselves (2FA is opt-in for VIEWER/
    OPERATOR, mandatory in effect for ADMIN via the require_role gate
    above). Generates a NEW secret and stages it under a distinct
    credential key ('totp_secret_pending', not 'totp_secret') -- it only
    becomes the account's real secret once /confirm verifies a live code
    against it, so a QR nobody ever scanned can't half-enable 2FA."""
    user = storage.get_user_by_username(_current_username())
    secret = totp.generate_secret()
    storage.set_credential(f"user:{user['id']}", 'totp_secret_pending', secret)
    uri = totp.provisioning_uri(secret, user['username'])
    return jsonify({'secret': secret, 'otpauthUri': uri, 'qrSvg': _qr_svg(uri)})


@app.post('/api/auth/totp/enroll/confirm')
@require_role('VIEWER')
def api_totp_enroll_confirm():
    body = request.get_json(force=True)
    code = (body.get('code') or '').strip()
    user = storage.get_user_by_username(_current_username())
    pending_secret = storage.get_credential(f"user:{user['id']}", 'totp_secret_pending')
    if not pending_secret:
        return jsonify({'error': '먼저 QR 코드를 등록해주세요'}), 400
    if not totp.verify_totp(pending_secret, code):
        return jsonify({'error': '인증 코드가 올바르지 않습니다. 앱의 시간이 정확한지 확인해주세요'}), 400
    storage.set_credential(f"user:{user['id']}", 'totp_secret', pending_secret)
    storage.delete_credential(f"user:{user['id']}", 'totp_secret_pending')
    storage.set_user_totp_enabled(user['id'], True)
    recovery_codes = storage.generate_recovery_codes(user['id'])
    audit('TOTP_ENROLLED')
    # recovery_codes is returned exactly this once -- storage only ever
    # keeps their hash, same one-time-reveal contract as an API token.
    return jsonify({'ok': True, 'recoveryCodes': recovery_codes})


@app.post('/api/auth/totp/disable')
@require_role('VIEWER')
def api_totp_disable():
    """Self-service disable requires a live code, not just an active
    session -- otherwise a hijacked session (the exact threat 2FA exists to
    reduce) could silently turn its own protection back off."""
    body = request.get_json(force=True)
    code = (body.get('code') or '').strip()
    user = storage.get_user_by_username(_current_username())
    secret = storage.get_credential(f"user:{user['id']}", 'totp_secret')
    if not secret or not totp.verify_totp(secret, code):
        return jsonify({'error': '인증 코드가 올바르지 않습니다'}), 400
    storage.disable_totp(user['id'])
    audit('TOTP_DISABLED')
    return jsonify({'ok': True})


@app.post('/api/auth/totp/recovery-codes/regenerate')
@require_role('VIEWER')
def api_totp_regenerate_recovery_codes():
    """Invalidates every existing recovery code and issues a fresh set --
    for when a user has used most of theirs, or suspects a written-down
    copy was exposed. Requires a live code for the same reason /disable
    does."""
    body = request.get_json(force=True)
    code = (body.get('code') or '').strip()
    user = storage.get_user_by_username(_current_username())
    secret = storage.get_credential(f"user:{user['id']}", 'totp_secret')
    if not user['totp_enabled'] or not secret:
        return jsonify({'error': '2FA가 활성화되어 있지 않습니다'}), 400
    if not totp.verify_totp(secret, code):
        return jsonify({'error': '인증 코드가 올바르지 않습니다'}), 400
    codes = storage.generate_recovery_codes(user['id'])
    audit('TOTP_RECOVERY_CODES_REGENERATED')
    return jsonify({'ok': True, 'recoveryCodes': codes})


@app.get('/api/auth/totp/status')
@require_role('VIEWER')
def api_totp_status():
    user = storage.get_user_by_username(_current_username())
    return jsonify({'enabled': bool(user['totp_enabled']),
                     'recoveryCodesRemaining': storage.count_unused_recovery_codes(user['id']) if user['totp_enabled'] else 0})


def _operator_blocked_on_admin_target(target_role):
    """1-4 policy: OPERATOR gets user management, but scoped to OPERATOR/
    VIEWER accounts only -- an ADMIN account (existing or being created) can
    only be touched by an ADMIN. Without this, "operators can manage users"
    would let a non-admin delete/demote the admin or promote themselves,
    which is a straight privilege-escalation path, not a convenience."""
    return _current_role() != 'ADMIN' and target_role == 'ADMIN'


@app.get('/api/users')
@require_role('OPERATOR')
def api_list_users():
    return jsonify({'users': storage.list_users()})


@app.post('/api/users')
@require_role('OPERATOR')
def api_create_user():
    body = request.get_json(force=True)
    username = (body.get('username') or '').strip()
    password = body.get('password') or ''
    role = (body.get('role') or 'VIEWER').upper()
    if not username or len(password) < 8:
        return jsonify({'error': '아이디와 8자 이상의 비밀번호가 필요합니다'}), 400
    if role not in storage.ROLES:
        return jsonify({'error': 'role은 ADMIN, OPERATOR, VIEWER 중 하나여야 합니다'}), 400
    if _operator_blocked_on_admin_target(role):
        return jsonify({'error': '운영자는 관리자(ADMIN) 계정을 만들 수 없습니다'}), 403
    try:
        storage.create_user(username, password, role)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    audit('CREATE_USER', target=username, details=role)
    return jsonify({'ok': True})


@app.delete('/api/users/<int:user_id>')
@require_role('OPERATOR')
def api_delete_user(user_id):
    target = storage.get_user_by_id(user_id)
    if not target:
        return jsonify({'error': 'not found'}), 404
    if target['username'] == _current_username():
        return jsonify({'error': '자기 자신은 삭제할 수 없습니다'}), 400
    if _operator_blocked_on_admin_target(target['role']):
        return jsonify({'error': '운영자는 관리자(ADMIN) 계정을 변경할 수 없습니다'}), 403
    if target['role'] == 'ADMIN' and storage.count_admins() <= 1:
        return jsonify({'error': '마지막 관리자 계정은 삭제할 수 없습니다'}), 400
    storage.delete_user(user_id)
    audit('DELETE_USER', target=target['username'])
    return jsonify({'ok': True})


@app.put('/api/users/<int:user_id>')
@require_role('OPERATOR')
def api_update_user(user_id):
    target = storage.get_user_by_id(user_id)
    if not target:
        return jsonify({'error': 'not found'}), 404
    if _operator_blocked_on_admin_target(target['role']):
        return jsonify({'error': '운영자는 관리자(ADMIN) 계정을 변경할 수 없습니다'}), 403
    body = request.get_json(force=True)
    role = (body.get('role') or '').upper() or None
    new_password = body.get('password') or ''
    # 1-4: account activation -- None means "not included in this request"
    # (left unchanged), as opposed to False (explicitly turn off).
    active = body.get('active')
    if active is not None:
        active = bool(active)
    if role and role not in storage.ROLES:
        return jsonify({'error': 'role은 ADMIN, OPERATOR, VIEWER 중 하나여야 합니다'}), 400
    if role and _operator_blocked_on_admin_target(role):
        return jsonify({'error': '운영자는 계정을 관리자(ADMIN)로 지정할 수 없습니다'}), 403
    if role and target['role'] == 'ADMIN' and role != 'ADMIN' and storage.count_admins() <= 1:
        return jsonify({'error': '마지막 관리자 계정의 권한은 변경할 수 없습니다'}), 400
    if new_password and len(new_password) < 8:
        return jsonify({'error': '새 비밀번호는 8자 이상이어야 합니다'}), 400
    if active is False:
        if target['username'] == _current_username():
            return jsonify({'error': '자기 자신은 비활성화할 수 없습니다'}), 400
        if target['role'] == 'ADMIN' and storage.count_active_admins() <= 1:
            return jsonify({'error': '마지막 활성 관리자 계정은 비활성화할 수 없습니다'}), 400
    if role is None and not new_password and active is None:
        return jsonify({'error': '변경할 내용이 없습니다'}), 400
    if role is not None or new_password:
        storage.update_user(user_id, role=role, new_password=new_password or None)
    if active is not None:
        storage.set_user_active(user_id, active)
    detail_parts = []
    if role and role != target['role']:
        detail_parts.append(f"role: {target['role']}->{role}")
    if new_password:
        detail_parts.append('password_reset')
    if active is not None:
        detail_parts.append('activated' if active else 'deactivated')
    audit('UPDATE_USER', target=target['username'], details=', '.join(detail_parts) or None)
    return jsonify({'ok': True})


@app.post('/api/users/<int:user_id>/unlock')
@require_role('OPERATOR')
def api_unlock_user(user_id):
    target = storage.get_user_by_id(user_id)
    if not target:
        return jsonify({'error': 'not found'}), 404
    if _operator_blocked_on_admin_target(target['role']):
        return jsonify({'error': '운영자는 관리자(ADMIN) 계정을 변경할 수 없습니다'}), 403
    storage.unlock_user(target['username'])
    audit('ACCOUNT_UNLOCKED', target=target['username'])
    return jsonify({'ok': True})


@app.post('/api/users/<int:user_id>/totp/reset')
@require_role('OPERATOR')
def api_admin_reset_totp(user_id):
    """5-1 "인증 초기화 절차": for a lost/wiped device, not a routine
    toggle -- wipes the target's secret and recovery codes entirely (they
    re-enroll from scratch next login) and bumps session_version to kick
    any session that might already be compromised right along with it,
    same reasoning as a forced password reset. Same admin-protection rule
    as every other per-user action here: an OPERATOR can reset a VIEWER/
    OPERATOR's 2FA, only an ADMIN can reset another ADMIN's."""
    target = storage.get_user_by_id(user_id)
    if not target:
        return jsonify({'error': 'not found'}), 404
    if _operator_blocked_on_admin_target(target['role']):
        return jsonify({'error': '운영자는 관리자(ADMIN) 계정을 변경할 수 없습니다'}), 403
    storage.disable_totp(user_id)
    storage.bump_session_version(target['username'])
    audit('TOTP_RESET', target=target['username'])
    return jsonify({'ok': True})


# ------------------------------------------------------- 5-2 API 토큰 --
@app.get('/api/tokens')
@require_role('VIEWER')
def api_list_tokens():
    # Each user manages their own tokens; an ADMIN can additionally pass
    # ?all=1 for an account-wide view (oversight, matching how /api/users
    # is itself OPERATOR+-only) -- an ordinary user never sees another
    # user's tokens (not even their names), only their own.
    if _current_role() == 'ADMIN' and request.args.get('all') == '1':
        return jsonify({'tokens': storage.list_api_tokens()})
    user = storage.get_user_by_username(_current_username())
    return jsonify({'tokens': storage.list_api_tokens(user['id'])})


@app.post('/api/tokens')
@require_role('VIEWER')
def api_create_token():
    body = request.get_json(force=True)
    name = (body.get('name') or '').strip()
    scope = (body.get('scope') or 'VIEWER').upper()
    if not name or len(name) > 80:
        return jsonify({'error': '토큰 이름을 입력해주세요 (80자 이하)'}), 400
    # 최소 권한 원칙: a token's scope can never exceed ADMIN (tokens are for
    # programmatic/API access, not full account administration -- see this
    # route's module comment) nor exceed the creating user's own current
    # role, so a VIEWER can't mint themselves an OPERATOR-scoped token.
    if scope not in ('VIEWER', 'OPERATOR'):
        return jsonify({'error': '토큰 권한 범위는 VIEWER 또는 OPERATOR여야 합니다 (ADMIN 범위 토큰은 발급할 수 없습니다)'}), 400
    if storage.ROLE_RANK.get(scope, 0) > storage.ROLE_RANK.get(_current_role(), 0):
        return jsonify({'error': '자신의 권한보다 높은 범위의 토큰은 발급할 수 없습니다'}), 403
    expires_days = body.get('expiresDays')
    expires_at = None
    if expires_days not in (None, ''):
        expires_days = validation.clamp_int(expires_days, 1, 3650, None)
        if expires_days is None:
            return jsonify({'error': '만료일은 1~3650일 사이여야 합니다'}), 400
        expires_at = int(time.time() * 1000) + expires_days * 86400 * 1000
    user = storage.get_user_by_username(_current_username())
    token_id, token = storage.create_api_token(user['id'], name, scope, expires_at)
    audit('API_TOKEN_CREATED', target=str(token_id), details=f"{name} scope={scope}")
    # The plaintext token is returned exactly once, here -- storage only
    # ever keeps hash_token(token). There is no endpoint that can show it
    # again; losing it means revoking and issuing a new one.
    return jsonify({'ok': True, 'id': token_id, 'token': token})


@app.delete('/api/tokens/<int:token_id>')
@require_role('VIEWER')
def api_revoke_api_token(token_id):
    row = storage.get_api_token(token_id)
    if not row:
        return jsonify({'error': 'not found'}), 404
    user = storage.get_user_by_username(_current_username())
    if row['user_id'] != user['id'] and _current_role() != 'ADMIN':
        return jsonify({'error': 'forbidden'}), 403
    storage.revoke_api_token(token_id)
    audit('API_TOKEN_REVOKED', target=str(token_id), details=row['name'])
    return jsonify({'ok': True})


@app.post('/api/tokens/<int:token_id>/rotate')
@require_role('VIEWER')
def api_rotate_token(token_id):
    """토큰 재발급 및 회전 정책: revokes the old token and issues a brand-new
    one under the same name/scope/expiry-from-now -- the standard "rotate"
    UX (old one stops working the instant the new one is shown), rather
    than a window where both are simultaneously valid."""
    row = storage.get_api_token(token_id)
    if not row:
        return jsonify({'error': 'not found'}), 404
    user = storage.get_user_by_username(_current_username())
    if row['user_id'] != user['id'] and _current_role() != 'ADMIN':
        return jsonify({'error': 'forbidden'}), 403
    if row['revoked_at']:
        return jsonify({'error': '이미 폐기된 토큰입니다'}), 400
    storage.revoke_api_token(token_id)
    new_expires_at = None
    if row['expires_at']:
        new_expires_at = int(time.time() * 1000) + (row['expires_at'] - row['created_at'])
    new_id, new_token = storage.create_api_token(row['user_id'], row['name'], row['scope'], new_expires_at)
    audit('API_TOKEN_ROTATED', target=f"{token_id}->{new_id}", details=row['name'])
    return jsonify({'ok': True, 'id': new_id, 'token': new_token})


@app.get('/api/tokens/<int:token_id>/usage')
@require_role('VIEWER')
def api_token_usage(token_id):
    row = storage.get_api_token(token_id)
    if not row:
        return jsonify({'error': 'not found'}), 404
    user = storage.get_user_by_username(_current_username())
    if row['user_id'] != user['id'] and _current_role() != 'ADMIN':
        return jsonify({'error': 'forbidden'}), 403
    limit = validation.clamp_int(request.args.get('limit'), 1, 200, 50)
    return jsonify({'usage': storage.load_api_token_usage(token_id, limit)})


# ------------------------------------------------------------------ API --
def serialize_device(d, global_thresholds=None, groups_cache=None):
    entity = {k: v for k, v in state.LIVE.get(d['id'], {}).items() if not k.startswith('_')}
    f = {k: v for k, v in d['fields'].items() if k != 'community'}
    base = {
        'id': d['id'], 'category': d['category'], 'name': d['name'], 'mode': d['mode'],
        'ip': d['ip'], 'origin': 'local' if d['id'] == LOCAL_ID else 'user',
        'createdAt': d['created_at'],
    }
    base.update(f)
    base.update(entity)
    base['maintenance'] = {
        'enabled': bool(d.get('maintenance_enabled')),
        'start': d.get('maintenance_start'),
        'end': d.get('maintenance_end'),
        'reason': d.get('maintenance_reason'),
    }
    # Device status management pass: a persisted, always-consistent 5-value
    # collection-health status (정상/주의/장애/미수집/알 수 없음) plus the
    # timestamps/counters it's derived from -- separate from `status` above
    # (which stays exactly as it was: the existing resource/reachability
    # severity that topology colors, KPI counts, etc. already depend on).
    base['collectionState'] = storage.compute_collection_state(d)
    base['lastSuccessAt'] = d.get('last_success_at')
    base['lastCollectedAt'] = d.get('last_collected_at')
    base['lastFailureAt'] = d.get('last_failure_at')
    base['consecutiveFailures'] = d.get('consecutive_failures') or 0
    base['lastFailureReason'] = d.get('last_failure_reason')
    # Agent management pass: only meaningful for mode=='agent' devices, but
    # harmless (just null) to include for every other mode.
    if d['mode'] == 'agent':
        base['agentVersion'] = d.get('agent_version')
        base['agentOs'] = d.get('agent_os')
        base['agentStartedAt'] = d.get('agent_started_at')
        base['agentReportedIp'] = d.get('agent_reported_ip')
        base['agentLastError'] = d.get('agent_last_error')
        base['agentLatestVersion'] = storage.AGENT_VERSION
    # 2-2: the fully-resolved (device > group > global > fallback) thresholds
    # this device is actually being evaluated against right now -- so the
    # frontend's status bars/gauges can color by the same numbers the
    # backend's incidents fire on, instead of each duplicating the old
    # hardcoded 75/90/80/92/80/92 independently of whatever's configured.
    base['resolvedThresholds'] = thresholds.resolve_thresholds(d, global_thresholds, groups_cache)
    return base


@app.get('/api/state')
@require_role('VIEWER')
def api_state():
    global_thresholds = thresholds.get_global_thresholds()
    groups_cache = {g['name']: g for g in storage.load_device_groups()}
    with state.LOCK:
        devices = storage.load_devices()
        out = {'servers': [], 'dbs': [], 'nets': [], 'facs': []}
        key_map = {'server': 'servers', 'db': 'dbs', 'net': 'nets', 'fac': 'facs'}
        for d in devices:
            out[key_map[d['category']]].append(serialize_device(d, global_thresholds, groups_cache))
    conn = storage.get_db()
    incidents = conn.execute('SELECT * FROM incidents ORDER BY id DESC LIMIT 200').fetchall()
    conn.close()
    out['incidents'] = [dict(r) for r in incidents]
    out['serverInfo'] = {'lanIp': storage.get_lan_ip(), 'port': PORT}
    # Phase 7 LLDP groundwork (collector/lldp.py) has been populating this
    # table every 300s for any registered 'net' device all along; this is the
    # first thing that actually reads it back out, for the topology map to
    # draw those auto-discovered links alongside the manually-drawn ones.
    out['deviceLinks'] = storage.load_device_links()
    return jsonify(out)


@app.get('/api/system/health')
@require_role('VIEWER')
def api_system_health():
    return jsonify(health.get_health())


@app.post('/api/discovery/scan')
@require_role('OPERATOR')
def api_discovery_scan():
    body = request.get_json(force=True)
    range_text = (body.get('range') or '').strip()
    started_at = int(time.time() * 1000)
    try:
        host_count = len(discovery.parse_range(range_text))
        results = discovery.scan(range_text)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        app_logger.exception('network scan failed')
        return jsonify({'error': f'스캔 중 오류가 발생했습니다: {e}'}), 500
    existing_ips = {d['ip'] for d in storage.load_devices() if d.get('ip')}
    for r in results:
        r['alreadyRegistered'] = r['ip'] in existing_ips
    finished_at = int(time.time() * 1000)
    scan_id = storage.save_discovery_scan(range_text, _current_username(), started_at, finished_at,
                                           host_count, results)
    audit('NETWORK_SCAN', target=range_text, details=f'{len(results)}대 발견')
    return jsonify({'scanId': scan_id, 'results': results})


@app.get('/api/discovery/scans')
@require_role('OPERATOR')
def api_discovery_scans():
    return jsonify({'scans': storage.load_discovery_scans()})


@app.get('/api/discovery/scans/<int:scan_id>')
@require_role('OPERATOR')
def api_discovery_scan_detail(scan_id):
    detail = storage.load_discovery_scan_detail(scan_id)
    if not detail:
        return jsonify({'error': 'not found'}), 404
    return jsonify(detail)


@app.post('/api/devices/test-snmp')
@require_role('OPERATOR')
def api_test_snmp():
    """Standalone SNMP connectivity test for the registration form's "연결
    테스트" button -- lets the user confirm credentials/reachability before
    committing to registration, using the exact same majority-vote probe
    (and the exact same SNMPv3 validation) that registration itself gates
    on below, so a passing test reliably predicts a passing registration.
    Nothing is persisted here -- this never touches the devices table.
    """
    if not SNMP_AVAILABLE:
        return jsonify({'error': 'SNMP 라이브러리(pysnmp)가 서버에 설치되어 있지 않습니다'}), 400
    body = request.get_json(force=True)
    ip = (body.get('ip') or '').strip()
    if not ip or not validation.is_valid_host(ip):
        return jsonify({'error': 'IP 주소 또는 호스트명 형식이 올바르지 않습니다'}), 400
    version = body.get('snmpVersion') or 'v2c'
    port = body.get('snmpPort') or 161
    if not validation.is_valid_port(port):
        return jsonify({'error': 'port는 1~65535 사이의 숫자여야 합니다'}), 400
    community = (body.get('community') or '').strip() or 'public'
    v3_username = body.get('snmpv3Username')
    v3_auth_protocol = body.get('snmpv3AuthProtocol')
    v3_auth_password = body.get('snmpv3AuthPassword')
    v3_priv_protocol = body.get('snmpv3PrivProtocol')
    v3_priv_password = body.get('snmpv3PrivPassword')
    if version == 'v3':
        v3_err = validation.validate_snmpv3_params(
            v3_username, v3_auth_protocol, v3_auth_password, v3_priv_protocol, v3_priv_password,
            require_username=True)
        if v3_err:
            return jsonify({'error': v3_err}), 400
    ok, successes, attempts = snmp_collector.test_connection(
        ip, version, community, port, v3_username,
        v3_auth_protocol, v3_auth_password, v3_priv_protocol, v3_priv_password)
    # Logged, but deliberately without any secret -- ip and pass/fail only.
    audit('TEST_SNMP', target=ip, details=f'{"성공" if ok else "실패"} ({successes}/{attempts})')
    if not ok:
        cred_hint = '사용자명/인증·개인정보 보호 정보' if version == 'v3' else 'Community 문자열'
        return jsonify({'ok': False, 'error': f'"{ip}"에서 SNMP 응답을 받지 못했습니다 ({attempts}회 중 {successes}회만 응답). {cred_hint}/버전/포트를 확인해주세요.'})
    return jsonify({'ok': True, 'message': f'"{ip}"에서 SNMP 응답을 확인했습니다 ({successes}/{attempts}회 성공).'})


def _register_device_core(category, name, mode, ip, fields):
    """All the validation/connectivity-check/creation logic for registering
    one device, shared by the single-device route (api_register_device)
    below and the network bulk-import route (api_bulk_import_network
    devices) -- extracted so the Excel-upload path gets exactly the same
    safety checks (name/IP validation, live ping/SNMP connectivity test,
    credential handling, scheduler wiring, audit log) as registering one
    device by hand, instead of a second, drifting copy of them.

    Returns (status_code, resp_dict) -- the route wrappers just
    jsonify(resp_dict), status_code. 200/resp with an 'id' means success;
    any other code means resp['error'] is the reason, same shape the
    frontend's register form has always handled."""
    name = (name or '').strip()
    ip = (ip or '').strip() or None
    fields = dict(fields or {})
    if category not in ('server', 'db', 'net', 'fac') or mode not in ('agent', 'ping', 'snmp') or not name:
        return 400, {'error': 'invalid payload'}
    # Security hardening Phase C sections 12/18: name is used verbatim in a
    # per-device installer filename and title -- validating the character set
    # here is what actually prevents any downstream injection through it, not
    # escaping on the display side alone.
    if not validation.is_safe_name(name):
        return 400, {'error': '장비 이름에 사용할 수 없는 문자가 포함되어 있습니다 (특수문자 &|<>^%"\'` 등 제외, 80자 이하)'}
    if mode in ('ping', 'snmp') and not ip:
        return 400, {'error': 'ip required for this mode'}
    # Also closes the ping-argument-injection gap (collector/ping_collector.py
    # passes ip straight into a subprocess arg list; a leading '-' would
    # otherwise be read as a ping flag rather than a target).
    if ip and not validation.is_valid_host(ip):
        return 400, {'error': 'IP 주소 또는 호스트명 형식이 올바르지 않습니다'}
    if mode == 'snmp' and not SNMP_AVAILABLE:
        return 400, {'error': 'SNMP 라이브러리(pysnmp)가 서버에 설치되어 있지 않습니다'}
    port_field = fields.get('port')
    if port_field not in (None, '') and not validation.is_valid_port(port_field):
        return 400, {'error': 'port는 1~65535 사이의 숫자여야 합니다'}
    snmp_port = fields.get('snmpPort')
    if snmp_port not in (None, '') and not validation.is_valid_port(snmp_port):
        return 400, {'error': 'snmpPort는 1~65535 사이의 숫자여야 합니다'}
    # 2-1: group is still just a free-text fields.group string (see
    # storage.py's device_groups docstring for why), but it's rendered and
    # matched the same way a device name is, so it gets the same charset/
    # length validation here rather than accepting literally anything.
    group_field = (fields.get('group') or '').strip()
    if group_field:
        if len(group_field) > 60 or not validation.is_safe_name(group_field):
            return 400, {'error': '그룹 이름에 사용할 수 없는 문자가 포함되어 있습니다 (60자 이하)'}
        fields['group'] = group_field
    if 'tags' in fields:
        try:
            fields['tags'] = validation.validate_tags(fields['tags'])
        except ValueError as e:
            return 400, {'error': str(e)}
        if not fields['tags']:
            del fields['tags']
    if 'thresholds' in fields:
        try:
            fields['thresholds'] = validation.validate_thresholds(fields['thresholds'])
        except ValueError as e:
            return 400, {'error': str(e)}
        if not fields['thresholds']:
            del fields['thresholds']
    if mode == 'ping':
        # Registering a device that's already unreachable just guarantees an
        # immediate "위험" incident with nothing anyone can do about it from
        # here -- almost always a typo'd IP. Check reachability up front with
        # the exact same port-or-ICMP logic the ongoing monitor uses (a DB
        # engine's known port, or fields['port'] if the form set one -- both
        # already validated above -- falling back to plain ping).
        #
        # A single attempt isn't enough: a flaky/intermittent device (weak
        # wifi, power-saving network mode, etc.) can easily win one ping out
        # of several tries, which let one straight through here despite it
        # failing almost every real poll afterward. Require the majority of
        # a few quick attempts to succeed instead of just one.
        check_port = ping_collector.DB_PORTS.get(fields.get('engine')) if category == 'db' else port_field
        attempts, needed = 3, 2
        successes = sum(1 for _ in range(attempts) if ping_collector._attempt(ip, check_port or None, timeout_s=1.5)[0])
        if successes < needed:
            return 400, {'error': f'"{ip}"에 연결할 수 없습니다 ({attempts}회 중 {successes}회만 응답). IP 주소를 확인해주세요. 응답이 불안정해도 꼭 등록해야 한다면 SNMP나 Agent 방식을 이용해주세요.'}
    # Generic length cap on every free-text field value -- these are all
    # display-only (already HTML-escaped on the frontend) so this is just a
    # sanity bound against absurd payloads, not itself an XSS control.
    for k, v in list(fields.items()):
        if isinstance(v, str) and len(v) > 200:
            fields[k] = v[:200]
    # Phase 3: the community string is a credential, so it goes to the
    # credentials table, not into this device's fields JSON blob.
    community = fields.pop('community', None)
    # Phase 7: SNMPv3 secrets (username stays informational, but is still a
    # credential -- kept out of fields alongside the auth/priv passwords).
    v3_username = fields.pop('snmpv3Username', None)
    v3_auth_protocol = fields.pop('snmpv3AuthProtocol', None)
    v3_auth_password = fields.pop('snmpv3AuthPassword', None)
    v3_priv_protocol = fields.pop('snmpv3PrivProtocol', None)
    v3_priv_password = fields.pop('snmpv3PrivPassword', None)
    vendor_profile = fields.pop('vendorProfile', None)
    if mode == 'snmp':
        snmp_version = fields.get('snmpVersion') or 'v2c'
        snmp_port_val = fields.get('snmpPort') or 161
        if snmp_version == 'v3':
            v3_err = validation.validate_snmpv3_params(
                v3_username, v3_auth_protocol, v3_auth_password, v3_priv_protocol, v3_priv_password,
                require_username=True)
            if v3_err:
                return 400, {'error': v3_err}
        # Same reasoning as the ping check above: one lucky reply out of a
        # flaky device isn't good enough evidence to register on.
        ok, successes, attempts = snmp_collector.test_connection(
            ip, snmp_version, community or 'public', snmp_port_val, v3_username,
            v3_auth_protocol, v3_auth_password, v3_priv_protocol, v3_priv_password)
        if not ok:
            cred_hint = '사용자명/인증·개인정보 보호 정보' if snmp_version == 'v3' else 'Community 문자열'
            return 400, {'error': f'"{ip}"에서 SNMP 응답을 받지 못했습니다 ({attempts}회 중 {successes}회만 응답). {cred_hint}/버전/포트를 확인해주세요. 응답이 없어도 꼭 등록해야 한다면 Ping이나 Agent 방식을 이용해주세요.'}
    device_id = uuid.uuid4().hex[:10]
    token = secrets.token_hex(16) if mode == 'agent' else None
    conn = storage.get_db()
    created_at = int(time.time() * 1000)
    # Security hardening Phase C section 10: the token is never written to
    # the devices.token column -- only its SHA-256 hash. The plaintext exists
    # for exactly as long as this one response body, then it's gone from the
    # server for good (the agent's own config.json is the only place it's
    # kept from here on).
    conn.execute('INSERT INTO devices(id,category,name,mode,ip,token,fields,created_at) VALUES (?,?,?,?,?,?,?,?)',
                 (device_id, category, name, mode, ip, None, json.dumps(fields), created_at))
    conn.commit()
    conn.close()
    if token:
        storage.set_device_token_hash(device_id, token)
    if community:
        storage.set_credential(device_id, 'snmp_community', community)
    storage.set_credential(device_id, 'snmpv3_username', v3_username)
    storage.set_credential(device_id, 'snmpv3_auth_protocol', v3_auth_protocol)
    storage.set_credential(device_id, 'snmpv3_auth_password', v3_auth_password)
    storage.set_credential(device_id, 'snmpv3_priv_protocol', v3_priv_protocol)
    storage.set_credential(device_id, 'snmpv3_priv_password', v3_priv_password)
    if vendor_profile:
        storage.set_vendor_profile(device_id, vendor_profile)
    device_row = storage.load_device(device_id)
    with state.LOCK:
        state.ensure_entity(device_row)
    scheduler.add_device_job(device_row)
    storage.add_incident('info', name, storage.category_label(category), f"신규 장비 등록 완료 ({name})")
    has_credential = bool(community or v3_username or v3_auth_password or v3_priv_password)
    audit('REGISTER_DEVICE', target=device_id, details=f"{name} (SNMP 인증정보 포함)" if has_credential else name)
    resp = {'id': device_id}
    if token:
        lan_ip = storage.get_lan_ip()
        resp['token'] = token
        # Relative, not absolute-http -- the dashboard may now be loaded over
        # https://...:8443 via the Phase E Caddy proxy, and a browser blocks
        # (or silently drops) a download link that points at a plain-http
        # origin from an https page ("insecure download" blocking). A
        # relative URL resolves against whatever origin the browser is
        # actually on -- https:8443 through Caddy, or http:5057 direct --
        # and Caddy forwards /download/* to this same backend either way.
        resp['agentDownloadUrl'] = '/download/agent'
        resp['agentInstallerUrl'] = f'/download/installer/{token}'
        resp['agentConfigUrl'] = f'/download/config/{token}'
        # Unaffected by the above: this is the address the agent *process*
        # itself connects back to (a plain HTTP client, not a browser), so
        # it must stay the direct backend host:port, not a relative path.
        resp['agentCommand'] = f"InfraSightAgent.exe --server http://{lan_ip}:{PORT} --token {token} --install-startup"
    return 200, resp


@app.post('/api/devices')
@require_role('OPERATOR')
def api_register_device():
    body = request.get_json(force=True)
    status_code, resp = _register_device_core(
        body.get('category'), body.get('name'), body.get('mode'), body.get('ip'), body.get('fields') or {})
    return jsonify(resp), status_code


# --------------------------------------------- 네트워크 장비 엑셀 일괄 등록 --
MAX_BULK_IMPORT_ROWS = 100


@app.get('/download/network-bulk-template')
@require_role('OPERATOR')
def download_network_bulk_template():
    data, filename = network_bulk_import.build_template_xlsx()
    import io
    return send_file(io.BytesIO(data),
                      mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                      as_attachment=True, download_name=filename)


@app.post('/api/devices/bulk-import/network')
@require_role('OPERATOR')
def api_bulk_import_network_devices():
    """엑셀 파일 하나로 네트워크(NMS) 장비를 여러 대 한 번에 등록한다. 행
    하나당 _register_device_core를 한 번씩 그대로 호출하므로, 개별 등록과
    정확히 같은 검증/실측 연결 테스트(ping 또는 SNMP)를 거친다 -- 그래서
    장비가 많으면 응답이 느릴 수 있다 (행마다 최대 몇 초씩 실측하므로)."""
    f = request.files.get('file')
    if not f or not f.filename:
        return jsonify({'error': '엑셀 파일을 선택해주세요'}), 400
    try:
        rows = network_bulk_import.parse_xlsx(f.read())
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    if len(rows) > MAX_BULK_IMPORT_ROWS:
        return jsonify({'error': f'한 번에 최대 {MAX_BULK_IMPORT_ROWS}대까지 등록할 수 있습니다 (파일에 {len(rows)}행). 파일을 나눠서 다시 시도해주세요'}), 400

    results = []
    success_count = 0
    for row in rows:
        if row['parseError']:
            results.append({'rowNum': row['rowNum'], 'name': row['name'], 'ok': False, 'error': row['parseError']})
            continue
        fields = {'type': row['nettype'] or '기타'}
        if row['group']:
            fields['group'] = row['group']
        if row['mode'] == 'snmp':
            fields['community'] = row['community'] or 'public'
            fields['snmpPort'] = row['snmpPort'] or 161
            fields['snmpVersion'] = row['snmpVersion']
        status_code, resp = _register_device_core('net', row['name'], row['mode'], row['ip'], fields)
        ok = status_code == 200
        if ok:
            success_count += 1
        results.append({'rowNum': row['rowNum'], 'name': row['name'], 'ok': ok,
                         'error': None if ok else resp.get('error'), 'id': resp.get('id') if ok else None})
    audit('BULK_IMPORT_NETWORK_DEVICES', details=f'{success_count}/{len(rows)} 성공')
    return jsonify({'total': len(rows), 'successCount': success_count, 'results': results})


@app.get('/api/devices/export/network')
@require_role('ADMIN')
def api_export_network_devices():
    """등록된 네트워크 장비 전체를, 위 bulk-import 엔드포인트가 그대로 받아
    들일 수 있는 동일한 엑셀 양식으로 내보낸다 -- 이 PC에 등록된 네트워크
    장비들을 그대로 다른 PC의 InfraSight로 옮길 때 쓴다 (다운로드한 파일을
    편집 없이 그 PC의 "엑셀로 일괄 등록"에 바로 올리면 끝).

    ADMIN 전용인 이유: SNMP Community 문자열(사실상 비밀번호)이 평문으로
    담긴 파일을 만들어내는 기능이라, 일괄 등록(OPERATOR+)보다 더 민감하다.

    SNMPv3 장비와 Agent 장비는 내보내기에서 빠진다 -- 둘 다 이 엑셀 양식
    자체가 표현 못 하는 정보가 필요해서(v3는 사용자명/인증·암호화 프로토콜/
    비밀번호, Agent는 토큰 발급 + 해당 PC에서의 설치) 애초에 bulk-import가
    지원하지 않는 범위와 정확히 같다."""
    devices = [d for d in storage.load_devices() if d['category'] == 'net']
    rows = []
    skipped = 0
    for d in devices:
        fields = d.get('fields') or {}
        mode = d['mode']
        if mode not in network_bulk_import.SUPPORTED_MODES:
            skipped += 1  # Agent 모드 네트워크 장비는 등록 화면 자체가 안 만들지만, 혹시 몰라 방어적으로 건너뜀
            continue
        row = {'name': d['name'], 'ip': d['ip'] or '', 'type': fields.get('type'), 'group': fields.get('group'), 'mode': mode}
        if mode == 'snmp':
            snmp_version = fields.get('snmpVersion') or 'v2c'
            if snmp_version not in network_bulk_import.SUPPORTED_SNMP_VERSIONS:
                skipped += 1
                continue
            row['community'] = storage.get_credential(d['id'], 'snmp_community') or ''
            row['snmpPort'] = fields.get('snmpPort') or 161
            row['snmpVersion'] = snmp_version
        rows.append(row)
    data, filename = network_bulk_import.build_export_xlsx(rows)
    audit('EXPORT_NETWORK_DEVICES', details=f'{len(rows)}대 내보냄, {skipped}대 제외(SNMPv3)')
    import io
    resp = send_file(io.BytesIO(data),
                      mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                      as_attachment=True, download_name=filename)
    resp.headers['X-Export-Skipped-Count'] = str(skipped)
    return resp


@app.put('/api/devices/<device_id>')
@require_role('OPERATOR')
def api_update_device(device_id):
    device_row = storage.load_device(device_id)
    if not device_row or device_id == LOCAL_ID:
        return jsonify({'error': 'device not found'}), 404
    body = request.get_json(force=True)
    name = (body.get('name') or '').strip()
    ip = (body.get('ip') or '').strip() or None
    fields = body.get('fields') or {}
    mode = device_row['mode']  # category/mode are fixed at registration time -- not editable here
    if not name:
        return jsonify({'error': 'invalid payload'}), 400
    if not validation.is_safe_name(name):
        return jsonify({'error': '장비 이름에 사용할 수 없는 문자가 포함되어 있습니다 (특수문자 &|<>^%"\'` 등 제외, 80자 이하)'}), 400
    if mode in ('ping', 'snmp') and not ip:
        return jsonify({'error': 'ip required for this mode'}), 400
    if ip and not validation.is_valid_host(ip):
        return jsonify({'error': 'IP 주소 또는 호스트명 형식이 올바르지 않습니다'}), 400
    snmp_port = fields.get('snmpPort')
    if snmp_port not in (None, '') and not validation.is_valid_port(snmp_port):
        return jsonify({'error': 'snmpPort는 1~65535 사이의 숫자여야 합니다'}), 400
    group_field = (fields.get('group') or '').strip()
    if group_field:
        if len(group_field) > 60 or not validation.is_safe_name(group_field):
            return jsonify({'error': '그룹 이름에 사용할 수 없는 문자가 포함되어 있습니다 (60자 이하)'}), 400
        fields['group'] = group_field
    if 'tags' in fields:
        try:
            fields['tags'] = validation.validate_tags(fields['tags'])
        except ValueError as e:
            return jsonify({'error': str(e)}), 400
        if not fields['tags']:
            del fields['tags']
    old_thresholds = (device_row.get('fields') or {}).get('thresholds')
    if 'thresholds' in fields:
        try:
            fields['thresholds'] = validation.validate_thresholds(fields['thresholds'])
        except ValueError as e:
            return jsonify({'error': str(e)}), 400
        if not fields['thresholds']:
            del fields['thresholds']
    new_thresholds = fields.get('thresholds')
    for k, v in list(fields.items()):
        if isinstance(v, str) and len(v) > 200:
            fields[k] = v[:200]
    # Credential fields are never sent back to the client on load (see
    # api_agent_info / the register endpoint's own comments), so an edit
    # form always starts these blank. Only overwrite the stored secret when
    # the admin actually typed a new value here -- an empty submission means
    # "leave it as-is", not "erase it".
    community = fields.pop('community', None)
    v3_username = fields.pop('snmpv3Username', None)
    v3_auth_protocol = fields.pop('snmpv3AuthProtocol', None)
    v3_auth_password = fields.pop('snmpv3AuthPassword', None)
    v3_priv_protocol = fields.pop('snmpv3PrivProtocol', None)
    v3_priv_password = fields.pop('snmpv3PrivPassword', None)
    if mode == 'snmp' and (v3_username or v3_auth_protocol or v3_auth_password or v3_priv_protocol or v3_priv_password):
        v3_err = validation.validate_snmpv3_params(
            v3_username, v3_auth_protocol, v3_auth_password, v3_priv_protocol, v3_priv_password,
            require_username=False, partial=True)
        if v3_err:
            return jsonify({'error': v3_err}), 400
    conn = storage.get_db()
    conn.execute('UPDATE devices SET name=?, ip=?, fields=? WHERE id=?',
                 (name, ip, json.dumps(fields), device_id))
    conn.commit()
    conn.close()
    if new_thresholds != old_thresholds:
        storage.record_threshold_change('device', device_id, _current_username(), old_thresholds, new_thresholds)
        # 2-2 completion criterion: a changed threshold must affect alert
        # handling immediately, not just on this device's next "crossing" --
        # clearing the sustain/prev-incident trackers here means the very
        # next poll re-evaluates from a clean slate against the new values,
        # instead of still counting time accrued under the old threshold or
        # staying silent because the old thresholds already fired this
        # incident once.
        thresholds.clear_sustain_state(device_id)
    if community:
        storage.set_credential(device_id, 'snmp_community', community)
    if v3_username:
        storage.set_credential(device_id, 'snmpv3_username', v3_username)
    if v3_auth_protocol:
        storage.set_credential(device_id, 'snmpv3_auth_protocol', v3_auth_protocol)
    if v3_auth_password:
        storage.set_credential(device_id, 'snmpv3_auth_password', v3_auth_password)
    if v3_priv_protocol:
        storage.set_credential(device_id, 'snmpv3_priv_protocol', v3_priv_protocol)
    if v3_priv_password:
        storage.set_credential(device_id, 'snmpv3_priv_password', v3_priv_password)
    before_summary = {'name': device_row['name'], 'ip': device_row['ip'], **(device_row['fields'] or {})}
    after_summary = {'name': name, 'ip': ip, **fields}
    diff = _diff_str(before_summary, after_summary, set(before_summary) | set(after_summary))
    has_credential = bool(community or v3_username or v3_auth_password or v3_priv_password)
    detail_parts = [diff] if diff else []
    if has_credential:
        detail_parts.append('SNMP 인증정보 변경됨')
    audit('UPDATE_DEVICE', target=device_id, details='; '.join(detail_parts) or name)
    return jsonify({'ok': True, 'id': device_id})


@app.delete('/api/devices/<device_id>')
@require_role('OPERATOR')
def api_delete_device(device_id):
    if device_id == LOCAL_ID:
        return jsonify({'error': 'cannot delete local device'}), 400
    scheduler.remove_device_job(device_id)
    conn = storage.get_db()
    conn.execute('DELETE FROM devices WHERE id=?', (device_id,))
    conn.commit()
    conn.close()
    storage.delete_credentials(device_id)
    with state.LOCK:
        state.LIVE.pop(device_id, None)
        state.LAST_REPORT.pop(device_id, None)
    audit('DELETE_DEVICE', target=device_id)
    return jsonify({'ok': True})


@app.post('/api/devices/bulk-delete')
@require_role('ADMIN')
def api_bulk_delete_devices():
    # ADMIN-only on purpose, stricter than the single-device DELETE above
    # (OPERATOR+) -- deleting several devices in one click is much easier to
    # fat-finger than deleting one at a time via its own detail drawer, so
    # this one explicitly needs the higher bar.
    body = request.get_json(silent=True) or {}
    ids = body.get('ids')
    if not isinstance(ids, list) or not ids:
        return jsonify({'error': 'ids 배열이 필요합니다'}), 400
    # One shared connection/transaction for the whole batch, not one per
    # device as this originally did (including inside delete_credentials()
    # and audit()'s own write_audit() call -- 3 separate connect/commit/
    # close cycles per device). Each one briefly takes SQLite's single
    # writer lock, racing the live polling scheduler's own metric writes;
    # confirmed live that selecting enough devices at once made this slow
    # enough to actually exceed get_db()'s 10s lock-wait timeout and return
    # a raw 500 partway through. Batching into one transaction cuts that
    # 3x-per-device lock contention down to twice total for the real DB
    # writes (once for devices+credentials+audit rows, once implicitly via
    # the security file-trail calls below, which touch no DB at all).
    from applog import security_logger, safe_log_value
    username = _current_username()
    source_ip = request.remote_addr
    deleted, skipped = [], []
    conn = storage.get_db()
    try:
        for device_id in ids:
            if not isinstance(device_id, str):
                continue
            if device_id == LOCAL_ID:
                skipped.append(device_id)
                continue
            scheduler.remove_device_job(device_id)
            cur = conn.execute('DELETE FROM devices WHERE id=?', (device_id,))
            if cur.rowcount == 0:
                skipped.append(device_id)
                continue
            conn.execute('DELETE FROM credentials WHERE device_id=?', (device_id,))
            conn.execute(
                'INSERT INTO audit_log(username,action,target,ts,source_ip,details) VALUES (?,?,?,?,?,?)',
                (username, 'DELETE_DEVICE', device_id, int(time.time() * 1000), source_ip, None))
            with state.LOCK:
                state.LIVE.pop(device_id, None)
                state.LAST_REPORT.pop(device_id, None)
            deleted.append(device_id)
        summary = f"{len(deleted)}건 삭제, {len(skipped)}건 건너뜀"
        conn.execute(
            'INSERT INTO audit_log(username,action,target,ts,source_ip,details) VALUES (?,?,?,?,?,?)',
            (username, 'BULK_DELETE_DEVICES', None, int(time.time() * 1000), source_ip, summary))
        conn.commit()
    finally:
        conn.close()
    for device_id in deleted:
        security_logger.info('user=%s action=%s target=%s ip=%s details=%s',
                              safe_log_value(username), safe_log_value('DELETE_DEVICE'), safe_log_value(device_id),
                              safe_log_value(source_ip), safe_log_value(None))
    security_logger.info('user=%s action=%s target=%s ip=%s details=%s',
                          safe_log_value(username), safe_log_value('BULK_DELETE_DEVICES'), safe_log_value(None),
                          safe_log_value(source_ip), safe_log_value(summary))
    return jsonify({'ok': True, 'deletedCount': len(deleted), 'deletedIds': deleted, 'skippedIds': skipped})


# ------------------------------------------------------------- 2-1 groups --
@app.get('/api/groups')
@require_role('VIEWER')
def api_list_groups():
    """A group's membership/status isn't DB-static (status comes from
    state.LIVE, same as /api/state), so this is computed here each call
    rather than stored -- the device_groups table only holds the catalog
    (which names exist, their description), not any per-group rollup."""
    with state.LOCK:
        devices = storage.load_devices()
        serialized = [serialize_device(d) for d in devices]
    catalog = {g['name']: g for g in storage.load_device_groups()}
    by_name = defaultdict(list)
    for e in serialized:
        g = e.get('group')
        if g:
            by_name[g].append(e)
    conn = storage.get_db()
    out = []
    for name in sorted(set(catalog) | set(by_name)):
        members = by_name.get(name, [])
        status_counts = {'good': 0, 'warn': 0, 'crit': 0}
        for m in members:
            if m.get('status') in status_counts:
                status_counts[m['status']] += 1
        ids = [m['id'] for m in members]
        if ids:
            ph = ','.join('?' * len(ids))
            open_incidents = conn.execute(
                f"SELECT COUNT(*) c FROM incidents WHERE device_id IN ({ph}) AND status='open'", ids).fetchone()['c']
            total_incidents = conn.execute(
                f"SELECT COUNT(*) c FROM incidents WHERE device_id IN ({ph})", ids).fetchone()['c']
        else:
            open_incidents = total_incidents = 0
        meta = catalog.get(name)
        out.append({
            'name': name, 'description': meta['description'] if meta else None,
            'managed': name in catalog, 'deviceCount': len(members),
            'statusCounts': status_counts, 'openIncidents': open_incidents, 'totalIncidents': total_incidents,
            'thresholds': meta['thresholds'] if meta else None,
        })
    conn.close()
    return jsonify({'groups': out})


@app.post('/api/groups')
@require_role('OPERATOR')
def api_create_group():
    body = request.get_json(force=True)
    name = (body.get('name') or '').strip()
    description = (body.get('description') or '').strip() or None
    if not name or len(name) > 60:
        return jsonify({'error': '그룹 이름을 입력해주세요 (60자 이하)'}), 400
    if not validation.is_safe_name(name):
        return jsonify({'error': '그룹 이름에 사용할 수 없는 문자가 포함되어 있습니다'}), 400
    try:
        storage.create_device_group(name, description)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    audit('CREATE_GROUP', target=name)
    return jsonify({'ok': True})


@app.put('/api/groups/<string:name>')
@require_role('OPERATOR')
def api_update_group(name):
    body = request.get_json(force=True)
    new_name = (body.get('name') or '').strip() or None
    description = body.get('description')
    if new_name and new_name != name:
        if len(new_name) > 60 or not validation.is_safe_name(new_name):
            return jsonify({'error': '그룹 이름에 사용할 수 없는 문자가 포함되어 있습니다 (60자 이하)'}), 400
        try:
            moved = storage.rename_device_group(name, new_name)
        except ValueError as e:
            return jsonify({'error': str(e)}), 400
        if description is not None:
            storage.update_device_group_description(new_name, description.strip() or None)
        audit('UPDATE_GROUP', target=name, details=f'renamed to {new_name} ({moved}대 장비 함께 변경)')
        return jsonify({'ok': True, 'devicesRenamed': moved})
    if description is not None:
        storage.update_device_group_description(name, description.strip() or None)
    audit('UPDATE_GROUP', target=name, details='description updated')
    return jsonify({'ok': True, 'devicesRenamed': 0})


@app.delete('/api/groups/<string:name>')
@require_role('OPERATOR')
def api_delete_group(name):
    count = storage.count_devices_in_group(name)
    if count > 0:
        return jsonify({'error': f'이 그룹에 {count}대의 장비가 속해 있어 삭제할 수 없습니다. 먼저 장비들의 그룹을 변경해주세요.'}), 400
    storage.delete_device_group(name)
    audit('DELETE_GROUP', target=name)
    return jsonify({'ok': True})


# ---------------------------------------------------------- 2-2 thresholds --
@app.get('/api/thresholds/global')
@require_role('VIEWER')
def api_get_global_thresholds():
    return jsonify(thresholds.get_global_thresholds())


@app.put('/api/thresholds/global')
@require_role('OPERATOR')
def api_set_global_thresholds():
    body = request.get_json(force=True)
    try:
        cleaned = validation.validate_thresholds(body)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    old = thresholds.get_global_thresholds()
    thresholds.set_global_thresholds(cleaned)
    storage.record_threshold_change('global', 'global', _current_username(), old, thresholds.get_global_thresholds())
    # Global default changes every device that has no device/group override
    # for a given field, so there's no single device_id to target -- reset
    # every device's sustain window the same way api_update_device does for
    # one device, so the new default takes effect on the next poll instead
    # of continuing to count under the old one.
    for d in storage.load_devices():
        thresholds.clear_sustain_state(d['id'])
    audit('UPDATE_GLOBAL_THRESHOLDS')
    return jsonify({'ok': True})


@app.put('/api/groups/<string:name>/thresholds')
@require_role('OPERATOR')
def api_set_group_thresholds(name):
    group = storage.get_device_group(name)
    if not group:
        return jsonify({'error': '그룹을 찾을 수 없습니다'}), 404
    body = request.get_json(force=True)
    try:
        cleaned = validation.validate_thresholds(body)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    old = group.get('thresholds')
    storage.set_device_group_thresholds(name, cleaned or None)
    storage.record_threshold_change('group', name, _current_username(), old, cleaned or None)
    for d in storage.load_devices():
        if (d.get('fields') or {}).get('group') == name:
            thresholds.clear_sustain_state(d['id'])
    audit('UPDATE_GROUP_THRESHOLDS', target=name)
    return jsonify({'ok': True})


@app.get('/api/thresholds/history')
@require_role('VIEWER')
def api_threshold_history():
    scope = request.args.get('scope') or None
    scope_id = request.args.get('scopeId') or None
    limit = validation.clamp_int(request.args.get('limit'), 1, 200, 50)
    return jsonify({'history': storage.load_threshold_history(scope, scope_id, limit)})


# ---------------------------------------------------------- 2-3 maintenance windows --
@app.get('/api/maintenance/windows')
@require_role('VIEWER')
def api_list_maintenance_windows():
    now_dt = datetime.now()
    out = []
    for w in storage.load_maintenance_windows():
        target_ids = maintenance.resolve_target_device_ids(w)
        is_active, _, _ = maintenance.window_occurrence_bounds(w, now_dt) if w.get('enabled') else (False, None, None)
        out.append({**w, 'targetDeviceCount': len(target_ids), 'activeNow': is_active})
    return jsonify({'windows': out})


@app.post('/api/maintenance/windows')
@require_role('OPERATOR')
def api_create_maintenance_window():
    body = request.get_json(force=True)
    try:
        cleaned = validation.validate_maintenance_window(body)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    if cleaned['scope'] == 'device':
        if not storage.load_device(cleaned['scope_id']):
            return jsonify({'error': '대상 장비를 찾을 수 없습니다'}), 404
    else:
        if not storage.get_device_group(cleaned['scope_id']):
            return jsonify({'error': '대상 그룹을 찾을 수 없습니다'}), 404
    window_id = storage.create_maintenance_window(
        cleaned['scope'], cleaned['scope_id'], cleaned['kind'], cleaned['start_at'], cleaned['end_at'],
        cleaned['weekday'], cleaned['start_time'], cleaned['end_time'], cleaned['reason'], _current_username())
    audit('CREATE_MAINTENANCE_WINDOW', target=str(window_id), details=f"{cleaned['scope']}:{cleaned['scope_id']}")
    return jsonify({'ok': True, 'id': window_id})


@app.put('/api/maintenance/windows/<int:window_id>/enabled')
@require_role('OPERATOR')
def api_set_maintenance_window_enabled(window_id):
    window = storage.get_maintenance_window(window_id)
    if not window:
        return jsonify({'error': 'not found'}), 404
    body = request.get_json(force=True)
    enabled = bool(body.get('enabled'))
    storage.set_maintenance_window_enabled(window_id, enabled)
    if not enabled:
        # A disabled window must let go of any device it currently has in
        # maintenance -- otherwise that device would be stuck "점검 중"
        # forever, since tick() only ever looks at *enabled* windows to
        # decide when to turn a device back off.
        for d in storage.devices_owned_by_window(window_id):
            storage.set_maintenance(d['id'], False, window_id=None, started_by='scheduler')
    audit('SET_MAINTENANCE_WINDOW_ENABLED', target=str(window_id), details=f"enabled={enabled}")
    return jsonify({'ok': True})


@app.delete('/api/maintenance/windows/<int:window_id>')
@require_role('OPERATOR')
def api_delete_maintenance_window(window_id):
    for d in storage.devices_owned_by_window(window_id):
        storage.set_maintenance(d['id'], False, window_id=None, started_by='scheduler')
    storage.delete_maintenance_window(window_id)
    audit('DELETE_MAINTENANCE_WINDOW', target=str(window_id))
    return jsonify({'ok': True})


@app.get('/api/maintenance/log')
@require_role('VIEWER')
def api_maintenance_log():
    device_id = request.args.get('deviceId') or None
    limit = validation.clamp_int(request.args.get('limit'), 1, 200, 50)
    log = storage.load_maintenance_log(device_id, limit)
    device_names = {d['id']: d['name'] for d in storage.load_devices()}
    for row in log:
        row['deviceName'] = device_names.get(row['device_id'], row['device_id'])
    return jsonify({'log': log})


# ----------------------------------------------------------- 2-5 알림 에스컬레이션 --
@app.get('/api/escalation/settings')
@require_role('OPERATOR')
def api_get_escalation_settings():
    return jsonify(storage.get_escalation_settings_public())


@app.put('/api/escalation/settings')
@require_role('OPERATOR')
def api_set_escalation_settings():
    body = request.get_json(force=True)
    if body.get('minSeverity') not in (None, 'warn', 'crit'):
        return jsonify({'error': 'minSeverity는 warn 또는 crit이어야 합니다'}), 400
    storage.set_escalation_settings(bool(body.get('enabled', False)), body.get('minSeverity') or 'crit')
    audit('SET_ESCALATION_SETTINGS', details=f"enabled={bool(body.get('enabled', False))}")
    return jsonify({'ok': True})


@app.get('/api/escalation/tiers')
@require_role('VIEWER')
def api_list_escalation_tiers():
    return jsonify({'tiers': storage.load_escalation_tiers()})


@app.post('/api/escalation/tiers')
@require_role('OPERATOR')
def api_create_escalation_tier():
    body = request.get_json(force=True)
    try:
        name, email, timeout_minutes = validation.validate_escalation_tier(body)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    tier_id = storage.create_escalation_tier(name, email, timeout_minutes)
    audit('CREATE_ESCALATION_TIER', target=str(tier_id), details=f"{name} <{email}>")
    return jsonify({'ok': True, 'id': tier_id})


@app.put('/api/escalation/tiers/<int:tier_id>')
@require_role('OPERATOR')
def api_update_escalation_tier(tier_id):
    body = request.get_json(force=True)
    try:
        name, email, timeout_minutes = validation.validate_escalation_tier(body)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    if not storage.update_escalation_tier(tier_id, name, email, timeout_minutes, bool(body.get('enabled', True))):
        return jsonify({'error': 'not found'}), 404
    audit('UPDATE_ESCALATION_TIER', target=str(tier_id), details=f"{name} <{email}>")
    return jsonify({'ok': True})


@app.delete('/api/escalation/tiers/<int:tier_id>')
@require_role('OPERATOR')
def api_delete_escalation_tier(tier_id):
    storage.delete_escalation_tier(tier_id)
    audit('DELETE_ESCALATION_TIER', target=str(tier_id))
    return jsonify({'ok': True})


@app.get('/api/escalation/log')
@require_role('VIEWER')
def api_escalation_log():
    incident_id = request.args.get('incidentId')
    incident_id = int(incident_id) if incident_id else None
    limit = validation.clamp_int(request.args.get('limit'), 1, 200, 50)
    return jsonify({'log': storage.load_escalation_log(incident_id, limit)})


# ------------------------------------------------- 3-1 가동률/SLA 리포트 --
_SLA_MAX_RANGE_MS = 370 * 86400 * 1000  # a little over a year -- generous, but not "compute since epoch"


def _sla_range_params():
    """start/end are explicit epoch-ms query params (no implicit "since
    forever" default -- the ticket itself calls out that the measurement
    period must be stated), defaulting to the last 30 days when omitted.
    granularity is optional; its absence means "one number for the whole
    range" rather than a bucketed series."""
    now_ms = int(time.time() * 1000)
    end_ms = validation.clamp_int(request.args.get('end'), 0, now_ms + _SLA_MAX_RANGE_MS, now_ms)
    start_ms = validation.clamp_int(request.args.get('start'), 0, end_ms, end_ms - 30 * 86400 * 1000)
    if end_ms - start_ms > _SLA_MAX_RANGE_MS:
        start_ms = end_ms - _SLA_MAX_RANGE_MS
    granularity = request.args.get('granularity') or None
    if granularity not in (None, 'day', 'week', 'month'):
        granularity = None
    return start_ms, end_ms, granularity


@app.get('/api/sla/settings')
@require_role('VIEWER')
def api_get_sla_settings():
    return jsonify(storage.get_sla_settings_public())


@app.put('/api/sla/settings')
@require_role('OPERATOR')
def api_set_sla_settings():
    body = request.get_json(force=True)
    severities = body.get('downtimeSeverities')
    if not isinstance(severities, list) or not severities or any(s not in ('warn', 'crit') for s in severities):
        return jsonify({'error': 'downtimeSeverities는 warn/crit로만 구성된 목록이어야 합니다'}), 400
    storage.set_sla_settings(severities)
    audit('SET_SLA_SETTINGS', details=','.join(severities))
    return jsonify({'ok': True})


@app.get('/api/sla/device/<device_id>')
@require_role('VIEWER')
def api_sla_device(device_id):
    device_row = storage.load_device(device_id)
    if not device_row:
        return jsonify({'error': 'device not found'}), 404
    start_ms, end_ms, granularity = _sla_range_params()
    report = sla.device_uptime_report(device_row, start_ms, end_ms)
    if granularity:
        report['buckets'] = sla.bucketed_device_report(device_row, start_ms, end_ms, granularity)
    return jsonify(report)


@app.get('/api/sla/group/<string:name>')
@require_role('VIEWER')
def api_sla_group(name):
    members = storage.devices_in_group(name)
    if not members:
        return jsonify({'error': '해당 그룹에 속한 장비가 없습니다'}), 404
    start_ms, end_ms, granularity = _sla_range_params()
    report = sla.group_uptime_report(name, members, start_ms, end_ms)
    if granularity:
        report['buckets'] = [
            sla.group_uptime_report(name, members, b_start, b_end)
            for b_start, b_end in sla._bucket_bounds(start_ms, end_ms, granularity)
            if max(b_start, start_ms) < min(b_end, end_ms)
        ]
    return jsonify(report)


@app.get('/api/sla/overview')
@require_role('VIEWER')
def api_sla_overview():
    """One summary row per device, for the 가동률 리포트 화면's default
    landing table -- the per-device/per-group detail endpoints above are
    for drilling into one target with bucketed history."""
    start_ms, end_ms, _ = _sla_range_params()
    devices = storage.load_devices()
    rows = [sla.device_uptime_report(d, start_ms, end_ms) for d in devices]
    groups = sorted({(d.get('fields') or {}).get('group') for d in devices} - {None})
    # Named group_name, not g -- g is also the Flask request-context object
    # imported at the top of this file (used by the Bearer-token auth path
    # to stash g.api_token_row); shadowing it here would be harmless today
    # (nothing in this loop body touches flask.g) but a landmine for the
    # next edit that does.
    group_rows = [sla.group_uptime_report(group_name, storage.devices_in_group(group_name), start_ms, end_ms) for group_name in groups]
    return jsonify({'periodStart': start_ms, 'periodEnd': end_ms, 'devices': rows, 'groups': group_rows})


# ------------------------------------------------------- 3-2 보고서 내보내기 --
@app.get('/api/reports/export')
@require_role('VIEWER')
def api_export_report():
    report_type = request.args.get('type')
    fmt = request.args.get('format')
    if report_type not in ('incident', 'resource', 'network'):
        return jsonify({'error': 'type은 incident, resource, network 중 하나여야 합니다'}), 400
    if fmt not in ('pdf', 'excel'):
        return jsonify({'error': 'format은 pdf 또는 excel이어야 합니다'}), 400
    start_ms, end_ms, _ = _sla_range_params()
    device_id = (request.args.get('deviceId') or '').strip() or None
    group = (request.args.get('group') or '').strip() or None
    if device_id and not storage.load_device(device_id):
        return jsonify({'error': 'device not found'}), 404
    try:
        data, filename, mimetype = reports.build_report(report_type, fmt, start_ms, end_ms, device_id, group)
    except Exception as e:
        app_logger.exception('report export failed')
        return jsonify({'error': f'보고서 생성에 실패했습니다: {e}'}), 500
    audit('EXPORT_REPORT', details=f'{report_type}/{fmt}')
    import io
    return send_file(io.BytesIO(data), mimetype=mimetype, as_attachment=True, download_name=filename)


# ------------------------------------------------------- 3-3 정기 보고서 발송 --
def _validate_report_schedule_body(body):
    name = (body.get('name') or '').strip()
    if not name or len(name) > 100:
        raise ValueError('보고서 이름을 입력해주세요 (100자 이하)')
    frequency = body.get('frequency')
    if frequency not in ('weekly', 'monthly'):
        raise ValueError('발송 주기는 weekly 또는 monthly여야 합니다')
    report_type = body.get('reportType')
    if report_type not in ('incident', 'resource', 'network'):
        raise ValueError('보고서 종류가 올바르지 않습니다')
    fmt = body.get('format')
    if fmt not in ('pdf', 'excel'):
        raise ValueError('형식은 pdf 또는 excel이어야 합니다')
    recipients = body.get('recipients')
    if not isinstance(recipients, list) or not recipients:
        raise ValueError('발송 대상 이메일을 1개 이상 입력해주세요')
    recipients = [r.strip() for r in recipients if r.strip()]
    if not recipients or any(not validation.is_valid_email(r) for r in recipients):
        raise ValueError('발송 대상 이메일 형식이 올바르지 않습니다')
    device_id = (body.get('deviceId') or '').strip() or None
    group_name = (body.get('group') or '').strip() or None
    if device_id and not storage.load_device(device_id):
        raise ValueError('대상 장비를 찾을 수 없습니다')
    return name, frequency, report_type, fmt, device_id, group_name, recipients


@app.get('/api/reports/schedules')
@require_role('VIEWER')
def api_list_report_schedules():
    return jsonify({'schedules': storage.load_report_schedules()})


@app.post('/api/reports/schedules')
@require_role('OPERATOR')
def api_create_report_schedule():
    body = request.get_json(force=True)
    try:
        name, frequency, report_type, fmt, device_id, group_name, recipients = _validate_report_schedule_body(body)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    schedule_id = storage.create_report_schedule(name, frequency, report_type, fmt, device_id, group_name, recipients, _current_username())
    audit('CREATE_REPORT_SCHEDULE', target=str(schedule_id), details=f"{name} ({frequency}/{report_type})")
    return jsonify({'ok': True, 'id': schedule_id})


@app.put('/api/reports/schedules/<int:schedule_id>/enabled')
@require_role('OPERATOR')
def api_set_report_schedule_enabled(schedule_id):
    if not storage.get_report_schedule(schedule_id):
        return jsonify({'error': 'not found'}), 404
    body = request.get_json(force=True)
    storage.set_report_schedule_enabled(schedule_id, bool(body.get('enabled')))
    audit('SET_REPORT_SCHEDULE_ENABLED', target=str(schedule_id), details=f"enabled={bool(body.get('enabled'))}")
    return jsonify({'ok': True})


@app.delete('/api/reports/schedules/<int:schedule_id>')
@require_role('OPERATOR')
def api_delete_report_schedule(schedule_id):
    storage.delete_report_schedule(schedule_id)
    audit('DELETE_REPORT_SCHEDULE', target=str(schedule_id))
    return jsonify({'ok': True})


@app.post('/api/reports/schedules/<int:schedule_id>/test')
@require_role('OPERATOR')
def api_test_report_schedule(schedule_id):
    """지금 바로 1회 발송 -- run_due_schedules의 재시도 루프는 타지 않는
    단발성 시도(바로 성공/실패를 알고 싶은 수동 테스트 버튼의 목적에 맞게),
    다만 결과는 동일하게 발송 이력에 기록된다."""
    sched = storage.get_report_schedule(schedule_id)
    if not sched:
        return jsonify({'error': 'not found'}), 404
    now_ms = int(time.time() * 1000)
    smtp_cfg = storage.get_smtp_config()
    if not smtp_cfg:
        # Log this the same way run_due_schedules() logs its own "no SMTP"
        # case -- a delivery attempt that failed before it could even try
        # sending is still a delivery attempt an operator needs to see in
        # the history, not a toast that evaporates the moment this response
        # is dismissed.
        err_msg = 'SMTP 채널이 설정되어 있지 않거나 비활성화 상태입니다'
        storage.record_report_delivery(schedule_id, now_ms, 'failed', err_msg, 0)
        storage.update_report_schedule_last_run(schedule_id, now_ms, 'failed')
        return jsonify({'error': err_msg}), 400
    try:
        ok, err = report_delivery.send_schedule_now(sched, smtp_cfg)
    except Exception as e:
        ok, err = False, f"{type(e).__name__}: {e}"
    storage.record_report_delivery(schedule_id, now_ms, 'success' if ok else 'failed', None if ok else err, 1)
    storage.update_report_schedule_last_run(schedule_id, now_ms, 'success' if ok else 'failed')
    audit('TEST_REPORT_SCHEDULE', target=str(schedule_id), details='ok' if ok else f'failed: {err}')
    if not ok:
        return jsonify({'error': f'발송에 실패했습니다: {err}'}), 502
    return jsonify({'ok': True})


@app.get('/api/reports/delivery-log')
@require_role('VIEWER')
def api_report_delivery_log():
    schedule_id = request.args.get('scheduleId')
    schedule_id = int(schedule_id) if schedule_id else None
    limit = validation.clamp_int(request.args.get('limit'), 1, 200, 50)
    log = storage.load_report_delivery_log(schedule_id, limit)
    schedule_names = {s['id']: s['name'] for s in storage.load_report_schedules()}
    for row in log:
        row['scheduleName'] = schedule_names.get(row['schedule_id'], f"#{row['schedule_id']}")
    return jsonify({'log': log})


# -------------------------------------------- 3-4 외부 공개 상태 페이지 (관리) --
# 아래 /api/public-status/* 는 전부 OPERATOR+ 인증이 필요한 "관리" 라우트다
# (어떤 장비를 공개할지, 공지를 작성/해제하는 행위는 그 자체로 내부 정보를
# 다루는 민감한 작업이므로). 실제 외부에서 호출되는 공개 라우트는 이 섹션
# 아래의 /api/public/* 이며, 그쪽은 의도적으로 require_role이 전혀 없다 --
# collector/public_status.py 모듈 docstring에 "공개 정보와 내부 정보 분리"
# 정책 전체가 적혀 있다.
@app.get('/api/public-status/services')
@require_role('OPERATOR')
def api_list_public_services():
    services = storage.load_public_services()
    device_names = {d['id']: d['name'] for d in storage.load_devices()}
    for s in services:
        s['deviceName'] = device_names.get(s['device_id'], '(삭제된 장비)')
    return jsonify({'services': services})


@app.post('/api/public-status/services')
@require_role('OPERATOR')
def api_create_public_service():
    body = request.get_json(force=True)
    label = (body.get('label') or '').strip()
    device_id = (body.get('deviceId') or '').strip()
    description = (body.get('description') or '').strip() or None
    if not label or len(label) > 80:
        return jsonify({'error': '공개 표시 이름을 입력해주세요 (80자 이하, 장비명이 아닌 서비스명을 권장합니다)'}), 400
    if not storage.load_device(device_id):
        return jsonify({'error': '대상 장비를 찾을 수 없습니다'}), 404
    if description and len(description) > 300:
        return jsonify({'error': '설명은 300자 이하여야 합니다'}), 400
    service_id = storage.create_public_service(label, device_id, description)
    audit('CREATE_PUBLIC_SERVICE', target=str(service_id), details=label)
    return jsonify({'ok': True, 'id': service_id})


@app.put('/api/public-status/services/<int:service_id>')
@require_role('OPERATOR')
def api_update_public_service(service_id):
    if not storage.get_public_service(service_id):
        return jsonify({'error': 'not found'}), 404
    body = request.get_json(force=True)
    label = body.get('label')
    if label is not None:
        label = label.strip()
        if not label or len(label) > 80:
            return jsonify({'error': '공개 표시 이름을 입력해주세요 (80자 이하)'}), 400
    description = body.get('description')
    if description is not None:
        description = description.strip() or None
        if description and len(description) > 300:
            return jsonify({'error': '설명은 300자 이하여야 합니다'}), 400
    enabled = body.get('enabled')
    display_order = body.get('displayOrder')
    storage.update_public_service(service_id, label=label, description=description, enabled=enabled, display_order=display_order)
    audit('UPDATE_PUBLIC_SERVICE', target=str(service_id),
          details=f"enabled={enabled}" if enabled is not None else None)
    return jsonify({'ok': True})


@app.delete('/api/public-status/services/<int:service_id>')
@require_role('OPERATOR')
def api_delete_public_service(service_id):
    storage.delete_public_service(service_id)
    audit('DELETE_PUBLIC_SERVICE', target=str(service_id))
    return jsonify({'ok': True})


_PUBLIC_ANNOUNCEMENT_STATUSES = ('investigating', 'identified', 'monitoring', 'resolved')


@app.get('/api/public-status/announcements')
@require_role('OPERATOR')
def api_list_public_announcements():
    limit = validation.clamp_int(request.args.get('limit'), 1, 200, 50)
    return jsonify({'announcements': storage.load_public_announcements(limit=limit)})


@app.post('/api/public-status/announcements')
@require_role('OPERATOR')
def api_create_public_announcement():
    body = request.get_json(force=True)
    title = (body.get('title') or '').strip()
    bodytext = (body.get('body') or '').strip() or None
    status = body.get('status') or 'investigating'
    service_id = body.get('serviceId')
    if not title or len(title) > 150:
        return jsonify({'error': '공지 제목을 입력해주세요 (150자 이하)'}), 400
    if status not in _PUBLIC_ANNOUNCEMENT_STATUSES:
        return jsonify({'error': 'status가 올바르지 않습니다'}), 400
    if service_id is not None and not storage.get_public_service(service_id):
        return jsonify({'error': '대상 서비스를 찾을 수 없습니다'}), 404
    ann_id = storage.create_public_announcement(service_id, title, bodytext, status, _current_username())
    audit('CREATE_PUBLIC_ANNOUNCEMENT', target=str(ann_id), details=title)
    return jsonify({'ok': True, 'id': ann_id})


@app.put('/api/public-status/announcements/<int:ann_id>')
@require_role('OPERATOR')
def api_update_public_announcement(ann_id):
    body = request.get_json(force=True)
    status = body.get('status')
    if status is not None and status not in _PUBLIC_ANNOUNCEMENT_STATUSES:
        return jsonify({'error': 'status가 올바르지 않습니다'}), 400
    bodytext = body.get('body')
    if not storage.update_public_announcement(ann_id, body=bodytext, status=status):
        return jsonify({'error': 'not found'}), 404
    audit('UPDATE_PUBLIC_ANNOUNCEMENT', target=str(ann_id), details=f"status={status}" if status else None)
    return jsonify({'ok': True})


@app.delete('/api/public-status/announcements/<int:ann_id>')
@require_role('OPERATOR')
def api_delete_public_announcement(ann_id):
    storage.delete_public_announcement(ann_id)
    audit('DELETE_PUBLIC_ANNOUNCEMENT', target=str(ann_id))
    return jsonify({'ok': True})


# -------------------------------------------- 3-4 외부 공개 상태 페이지 (공개) --
# 의도적으로 require_role이 없다 -- 이 두 라우트와 /status 페이지 라우트는
# session을 전혀 읽지 않고, 항상 동일한 (누구나 볼 수 있는) 데이터만
# 반환한다. collector/public_status.py가 실제 필드 단위 분리를 담당한다.
@app.get('/api/public/status')
def api_public_status():
    if _public_rate_limited(request.remote_addr):
        return jsonify({'error': 'rate_limited'}), 429
    return jsonify({'services': public_status.public_services_view()})


@app.get('/api/public/announcements')
def api_public_announcements():
    if _public_rate_limited(request.remote_addr):
        return jsonify({'error': 'rate_limited'}), 429
    return jsonify({'announcements': public_status.public_announcements_view()})


@app.get('/status')
def public_status_page():
    resp = send_from_directory(BASE_DIR, 'status.html')
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return resp


@app.post('/api/agent/report')
def api_agent_report():
    body = request.get_json(force=True)
    token = body.get('token') or ''
    device_row = storage.find_device_by_token(token)
    if not device_row:
        return jsonify({'error': 'unknown token'}), 404
    with state.LOCK:
        entity = state.ensure_entity(device_row)
    # Bug fix: record_report acquires state.LOCK itself now (the code review
    # pass's finding #5 fix) to protect only its actual entity mutation, not
    # the slow bits around it -- calling it while *this* call site still held
    # the same lock around it deadlocked every single agent report (the lock
    # isn't reentrant, so the thread blocked on itself forever). This is
    # exactly scheduler.py's own _run_job pattern: hold the lock only for
    # ensure_entity, release it, then call into the collector unlocked.
    # request.remote_addr (not any client-supplied field) so a device can't
    # misreport its own address -- the real TCP peer, correctly resolved
    # through Caddy too via _TrustedProxyFix above.
    agent_collector.record_report(entity, device_row, body, request.remote_addr)
    metrics.record_entity_metrics(device_row['id'], entity)
    return jsonify({'ok': True})


@app.post('/api/incidents/<int:incident_id>/ack')
@require_role('OPERATOR')
def api_ack_incident(incident_id):
    body = request.get_json(silent=True) or {}
    acknowledged_by = (body.get('by') or '').strip() or _current_username()
    storage.ack_incident(incident_id, acknowledged_by)
    audit('ACK_INCIDENT', target=str(incident_id))
    return jsonify({'ok': True})


@app.put('/api/devices/<device_id>/maintenance')
@require_role('OPERATOR')
def api_set_maintenance(device_id):
    device_row = storage.load_device(device_id)
    if not device_row:
        return jsonify({'error': 'device not found'}), 404
    body = request.get_json(force=True)
    enabled = bool(body.get('enabled'))
    start = body.get('start')
    end = body.get('end')
    reason = (body.get('reason') or '').strip() or None
    storage.set_maintenance(device_id, enabled, start, end, reason, started_by=_current_username())
    audit('SET_MAINTENANCE', target=device_id, details=f"enabled={enabled}")
    return jsonify({'ok': True})


@app.get('/api/devices/<device_id>/metrics')
@require_role('VIEWER')
def api_device_metrics(device_id):
    metric = request.args.get('metric', 'cpu')
    granularity = request.args.get('granularity', 'raw')
    if granularity not in ('raw', '5m', '1h'):
        return jsonify({'error': 'granularity must be raw, 5m, or 1h'}), 400
    since_ms = request.args.get('since', type=int)
    limit = validation.clamp_int(request.args.get('limit', 500, type=int), 1, 5000, default=500)
    points = storage.load_metric_history(device_id, metric, granularity, since_ms, limit)
    return jsonify({'deviceId': device_id, 'metric': metric, 'granularity': granularity, 'points': points})


@app.put('/api/devices/<device_id>/vendor-profile')
@require_role('OPERATOR')
def api_set_vendor_profile(device_id):
    device_row = storage.load_device(device_id)
    if not device_row:
        return jsonify({'error': 'device not found'}), 404
    body = request.get_json(force=True)
    profile = body.get('profile') or 'generic'
    if profile not in ('generic', 'cisco', 'ups'):
        return jsonify({'error': 'unknown profile'}), 400
    storage.set_vendor_profile(device_id, profile)
    audit('SET_VENDOR_PROFILE', target=device_id, details=profile)
    return jsonify({'ok': True})


@app.post('/api/devices/<device_id>/token/reissue')
@require_role('OPERATOR')
def api_reissue_token(device_id):
    device_row = storage.load_device(device_id)
    if not device_row or device_row['mode'] != 'agent':
        return jsonify({'error': 'agent 모드 장비만 토큰을 재발급할 수 있습니다'}), 400
    new_token = secrets.token_hex(16)
    storage.set_device_token_hash(device_id, new_token)
    with state.LOCK:
        state.LAST_REPORT.pop(device_id, None)  # old token's freshness no longer applies
    audit('AGENT_TOKEN_REISSUE', target=device_id)
    lan_ip = storage.get_lan_ip()
    return jsonify({
        'token': new_token,
        # See the matching comment in api_register_device: relative so it
        # resolves against whatever origin (https:8443 via Caddy, or
        # http:5057 direct) the browser making this request is actually on.
        'agentInstallerUrl': f'/download/installer/{new_token}',
        'agentConfigUrl': f'/download/config/{new_token}',
        'agentCommand': f"InfraSightAgent.exe --server http://{lan_ip}:{PORT} --token {new_token} --install-startup",
    })


@app.post('/api/devices/<device_id>/token/revoke')
@require_role('OPERATOR')
def api_revoke_token(device_id):
    device_row = storage.load_device(device_id)
    if not device_row or device_row['mode'] != 'agent':
        return jsonify({'error': 'agent 모드 장비만 토큰을 폐기할 수 있습니다'}), 400
    storage.revoke_device_token(device_id)
    with state.LOCK:
        state.LAST_REPORT.pop(device_id, None)
    audit('AGENT_TOKEN_REVOKE', target=device_id)
    return jsonify({'ok': True})


@app.get('/api/topology/links')
@require_role('VIEWER')
def api_topology_links():
    # Phase 7 groundwork (directive section 31): LLDP-discovered links,
    # exposed for a future topology upgrade. The rendered map still uses the
    # existing hub-and-spoke layout untouched.
    return jsonify({'links': storage.load_device_links()})


# ------------------------------------------------------------------- 4-3 --
# NetFlow/sFlow traffic analysis. Read-only (VIEWER, like /api/state) --
# nothing here writes anything; collector/flow_listener.py's UDP threads and
# the 60s flush job in collector/scheduler.py are what populate the data
# these endpoints read.
_FLOW_RANGE_MS = {'1h': 3600_000, '6h': 6 * 3600_000, '24h': 24 * 3600_000, '7d': 7 * 24 * 3600_000}
# Coarser buckets for a longer range -- a 7-day chart at 1-minute resolution
# would be 10k points for no visual benefit over hourly.
_FLOW_RANGE_BUCKET_MS = {'1h': 60_000, '6h': 5 * 60_000, '24h': 15 * 60_000, '7d': 60 * 60_000}


def _flow_range_params():
    range_key = request.args.get('range') or '1h'
    if range_key not in _FLOW_RANGE_MS:
        range_key = '1h'
    since_ms = int(time.time() * 1000) - _FLOW_RANGE_MS[range_key]
    device_id = (request.args.get('deviceId') or '').strip() or None
    return since_ms, device_id, _FLOW_RANGE_BUCKET_MS[range_key]


@app.get('/api/flow/status')
@require_role('VIEWER')
def api_flow_status():
    return jsonify({'exporters': storage.load_flow_status(),
                     'netflowPort': storage.NETFLOW_PORT, 'sflowPort': storage.SFLOW_PORT})


@app.get('/api/flow/summary')
@require_role('VIEWER')
def api_flow_summary():
    since_ms, device_id, _ = _flow_range_params()
    return jsonify(storage.load_flow_summary(device_id, since_ms))


@app.get('/api/flow/timeseries')
@require_role('VIEWER')
def api_flow_timeseries():
    since_ms, device_id, bucket_ms = _flow_range_params()
    return jsonify({'points': storage.load_flow_timeseries(device_id, since_ms, bucket_ms)})


@app.get('/api/flow/protocols')
@require_role('VIEWER')
def api_flow_protocols():
    since_ms, device_id, _ = _flow_range_params()
    return jsonify({'protocols': storage.load_flow_protocols(device_id, since_ms)})


@app.get('/api/flow/top-talkers')
@require_role('VIEWER')
def api_flow_top_talkers():
    since_ms, device_id, _ = _flow_range_params()
    limit = validation.clamp_int(request.args.get('limit'), 1, 50, default=10)
    return jsonify({'pairs': storage.load_flow_top_pairs(device_id, since_ms, limit)})


@app.get('/api/settings/smtp')
@require_role('OPERATOR')
def api_get_smtp_settings():
    return jsonify(storage.get_smtp_config_public())


@app.put('/api/settings/smtp')
@require_role('OPERATOR')
def api_set_smtp_settings():
    body = request.get_json(force=True)
    host = (body.get('host') or '').strip()
    port = body.get('port')
    username = (body.get('username') or '').strip()
    alert_to = (body.get('alertTo') or '').strip() or username
    if not host or not port or not username:
        return jsonify({'error': 'host, port, username은 필수입니다'}), 400
    if not validation.is_valid_host(host):
        return jsonify({'error': 'host 형식이 올바르지 않습니다'}), 400
    if not validation.is_valid_port(port):
        return jsonify({'error': 'port는 1~65535 사이의 숫자여야 합니다'}), 400
    if not validation.is_valid_email(alert_to):
        return jsonify({'error': '수신 이메일 형식이 올바르지 않습니다'}), 400
    if body.get('minSeverity') not in (None, 'warn', 'crit'):
        return jsonify({'error': 'minSeverity는 warn 또는 crit이어야 합니다'}), 400
    storage.set_smtp_config(
        host=host, port=port, username=username, password=body.get('password') or None,
        use_tls=bool(body.get('useTls', True)), alert_to=alert_to,
        enabled=bool(body.get('enabled', True)), min_severity=body.get('minSeverity') or 'crit',
    )
    audit('SET_SMTP_SETTINGS', details=f"{username}@{host}:{port}")
    return jsonify({'ok': True})


@app.post('/api/settings/smtp/test')
@require_role('OPERATOR')
def api_test_smtp():
    cfg = storage.get_smtp_config()
    if not cfg:
        return jsonify({'error': 'SMTP 설정이 완료되지 않았거나 비활성화 상태입니다'}), 400
    from alerts.email_channel import EmailChannel
    channel = EmailChannel(cfg['host'], cfg['port'], cfg['username'], cfg['password'], cfg['use_tls'])
    ok, err = channel.send(cfg['alert_to'], '[InfraSight] 테스트 알림',
                            'InfraSight 알림 설정이 정상적으로 동작합니다.')
    # 1-2: the manual test button is a single attempt (no retry) -- a user
    # clicking "테스트 발송" wants an immediate pass/fail, not a silent 30s
    # wait while 3 attempts run. Still logged to the same history as the
    # real incident-alert path so "실패 상황의 로그 확인" covers both.
    storage.record_email_alert(int(time.time() * 1000), 'info', 'InfraSight', '테스트 알림 발송',
                                cfg['alert_to'], 'success' if ok else 'failed', None if ok else err, 1)
    # The raw smtplib/SSL error can echo back connection internals (and in
    # principle the account being used) -- keep it in the audit log for the
    # admin to look up server-side, not in the HTTP response body.
    audit('TEST_SMTP', details='ok' if ok else f'failed: {err}')
    if not ok:
        return jsonify({'error': 'SMTP 발송에 실패했습니다. 감사 로그에서 자세한 내용을 확인하세요.'}), 502
    return jsonify({'ok': True})


@app.get('/api/settings/smtp/log')
@require_role('OPERATOR')
def api_smtp_alert_log():
    """1-2: every email alert attempt (장애 알림 + 수동 테스트 발송), success
    and failure alike -- what "알림 성공·실패 로그 저장" means in the UI.
    `error` here is smtplib's own exception text (e.g. "535 Authentication
    failed"), never the password we sent -- same content already stored in
    the audit log for TEST_SMTP, just queryable per-attempt here."""
    return jsonify({'log': storage.load_email_alert_log(limit=100)})


# ---------------------------------------------------------- 2-4 알림 채널 --
def _webhook_settings_endpoints(prefix, channel_label, channel_cls_path):
    """Slack and Teams are configured/tested identically (one webhook URL +
    enabled + minSeverity) -- this registers the 3 routes for one prefix
    instead of writing the same handler twice."""

    def get_settings():
        return jsonify(storage.get_webhook_config_public(prefix))

    def set_settings():
        body = request.get_json(force=True)
        url = (body.get('url') or '').strip() or None
        if url and not validation.is_valid_webhook_url(url):
            return jsonify({'error': 'Webhook URL은 https:// 로 시작하는 올바른 주소여야 합니다'}), 400
        if not url and not storage.get_webhook_config_public(prefix)['urlSet']:
            return jsonify({'error': 'Webhook URL을 입력해주세요'}), 400
        if body.get('minSeverity') not in (None, 'warn', 'crit'):
            return jsonify({'error': 'minSeverity는 warn 또는 crit이어야 합니다'}), 400
        storage.set_webhook_config(prefix, url=url, enabled=bool(body.get('enabled', True)),
                                    min_severity=body.get('minSeverity') or 'crit')
        audit(f'SET_{prefix.upper()}_SETTINGS')
        return jsonify({'ok': True})

    def test_send():
        cfg = storage.get_webhook_config(prefix)
        if not cfg:
            return jsonify({'error': f'{channel_label} 설정이 완료되지 않았거나 비활성화 상태입니다'}), 400
        module_name, cls_name = channel_cls_path.rsplit('.', 1)
        import importlib
        channel_cls = getattr(importlib.import_module(module_name), cls_name)
        ok, err = channel_cls().send(cfg['url'], '[InfraSight] 테스트 알림',
                                      'InfraSight 알림 설정이 정상적으로 동작합니다.')
        audit(f'TEST_{prefix.upper()}', details='ok' if ok else f'failed: {err}')
        if not ok:
            return jsonify({'error': f'{channel_label} 발송에 실패했습니다. 감사 로그에서 자세한 내용을 확인하세요.'}), 502
        return jsonify({'ok': True})

    # Flask derives each endpoint's name from the view function's __name__ by
    # default -- since get_settings/set_settings/test_send are redefined
    # fresh (but identically named) on every call to this helper, an
    # explicit endpoint= per route is required or the second call (teams)
    # would collide with the first (slack) and Flask would refuse to start.
    app.get(f'/api/settings/{prefix}', endpoint=f'{prefix}_get_settings')(require_role('OPERATOR')(get_settings))
    app.put(f'/api/settings/{prefix}', endpoint=f'{prefix}_set_settings')(require_role('OPERATOR')(set_settings))
    app.post(f'/api/settings/{prefix}/test', endpoint=f'{prefix}_test_send')(require_role('OPERATOR')(test_send))


_webhook_settings_endpoints('slack', 'Slack', 'alerts.slack_channel.SlackChannel')
_webhook_settings_endpoints('teams', 'Teams', 'alerts.teams_channel.TeamsChannel')


@app.get('/api/settings/kakao')
@require_role('OPERATOR')
def api_get_kakao_settings():
    return jsonify(storage.get_kakao_config_public())


@app.put('/api/settings/kakao')
@require_role('OPERATOR')
def api_set_kakao_settings():
    body = request.get_json(force=True)
    rest_api_key = (body.get('restApiKey') or '').strip() or None
    client_secret = (body.get('clientSecret') or '').strip() or None
    if rest_api_key and len(rest_api_key) > 100:
        return jsonify({'error': 'REST API 키는 100자 이하여야 합니다'}), 400
    if client_secret and len(client_secret) > 100:
        return jsonify({'error': 'Client Secret은 100자 이하여야 합니다'}), 400
    if not rest_api_key and not storage.get_kakao_config_public()['restApiKeySet']:
        return jsonify({'error': 'REST API 키를 입력해주세요'}), 400
    if body.get('minSeverity') not in (None, 'warn', 'crit'):
        return jsonify({'error': 'minSeverity는 warn 또는 crit이어야 합니다'}), 400
    storage.set_kakao_config(bool(body.get('enabled', False)), rest_api_key, client_secret,
                              body.get('minSeverity') or 'crit')
    audit('SET_KAKAO_SETTINGS')
    return jsonify({'ok': True})


@app.get('/api/settings/kakao/redirect-uri')
@require_role('OPERATOR')
def api_kakao_redirect_uri():
    # The exact value the admin needs to register as a Redirect URI in the
    # Kakao Developers console -- computed from whatever host they're
    # currently viewing this settings page through (localhost vs. the LAN
    # IP give different values, and Kakao requires an exact match), rather
    # than guessed at or hardcoded.
    return jsonify({'redirectUri': request.url_root.rstrip('/') + '/api/kakao/callback'})


@app.get('/api/kakao/authorize')
@require_role('ADMIN')
def api_kakao_authorize():
    rest_api_key = storage.get_setting('kakao_rest_api_key')
    if not rest_api_key:
        return jsonify({'error': 'REST API 키를 먼저 저장해주세요'}), 400
    redirect_uri = request.url_root.rstrip('/') + '/api/kakao/callback'
    params = {
        'response_type': 'code',
        'client_id': rest_api_key,
        'redirect_uri': redirect_uri,
        'scope': 'talk_message',
    }
    return redirect(f'https://kauth.kakao.com/oauth/authorize?{urllib.parse.urlencode(params)}')


@app.get('/api/kakao/callback')
@require_role('ADMIN')
def api_kakao_callback():
    code = request.args.get('code')
    oauth_error = request.args.get('error')
    if oauth_error or not code:
        audit('KAKAO_OAUTH_CALLBACK', details=f"failed: {oauth_error or 'no code'}")
        return redirect('/?kakaoAuth=error')
    redirect_uri = request.url_root.rstrip('/') + '/api/kakao/callback'
    rest_api_key = storage.get_setting('kakao_rest_api_key')
    client_secret = storage.get_credential(storage.SMTP_SYSTEM_ID, 'kakao_client_secret')
    params = {
        'grant_type': 'authorization_code',
        'client_id': rest_api_key,
        'redirect_uri': redirect_uri,
        'code': code,
    }
    if client_secret:
        params['client_secret'] = client_secret
    try:
        req = urllib.request.Request(
            'https://kauth.kakao.com/oauth/token',
            data=urllib.parse.urlencode(params).encode('utf-8'),
            headers={'Content-Type': 'application/x-www-form-urlencoded'}, method='POST')
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode('utf-8'))
        storage.set_kakao_tokens(data['access_token'], data.get('refresh_token'), data.get('expires_in', 21599))
        audit('KAKAO_OAUTH_CALLBACK', details='ok')
        return redirect('/?kakaoAuth=success')
    except urllib.error.HTTPError as e:
        # The raw Kakao error body can include request details -- keep it in
        # the audit log for the admin to look up server-side, same pattern as
        # TEST_SMTP's smtplib error, not in the redirect URL.
        detail = e.read().decode('utf-8', 'replace')[:300]
        audit('KAKAO_OAUTH_CALLBACK', details=f"failed: HTTP {e.code}: {detail}")
        return redirect('/?kakaoAuth=error')
    except Exception as e:
        audit('KAKAO_OAUTH_CALLBACK', details=f"failed: {type(e).__name__}: {e}")
        return redirect('/?kakaoAuth=error')


@app.post('/api/settings/kakao/test')
@require_role('OPERATOR')
def api_test_kakao():
    cfg = storage.get_kakao_config()
    if not cfg:
        return jsonify({'error': '카카오 설정이 완료되지 않았거나 비활성화 상태이거나, 계정이 연결되지 않았습니다'}), 400
    from alerts.kakao_channel import KakaoChannel
    ok, err, new_tokens = KakaoChannel().send(cfg, '[InfraSight] 테스트 알림',
                                               'InfraSight 알림 설정이 정상적으로 동작합니다.')
    if new_tokens:
        storage.set_kakao_tokens(new_tokens['access_token'], new_tokens.get('refresh_token'), new_tokens['expires_in'])
    audit('TEST_KAKAO', details='ok' if ok else f'failed: {err}')
    if not ok:
        return jsonify({'error': '카카오톡 발송에 실패했습니다. 감사 로그에서 자세한 내용을 확인하세요.'}), 502
    return jsonify({'ok': True})


@app.post('/api/settings/kakao/disconnect')
@require_role('ADMIN')
def api_kakao_disconnect():
    storage.disconnect_kakao()
    audit('KAKAO_DISCONNECT')
    return jsonify({'ok': True})


@app.get('/api/settings/sms')
@require_role('OPERATOR')
def api_get_sms_settings():
    return jsonify(storage.get_sms_config_public())


@app.put('/api/settings/sms')
@require_role('OPERATOR')
def api_set_sms_settings():
    # SMS도 Kakao와 같은 이유로 구조만 제공한다: 실제 발송에는 유료 SMS 게이트웨이
    # 계정(API 키)과, 국내 기준 사전 등록된 발신번호가 필요하다.
    body = request.get_json(force=True)
    provider = (body.get('provider') or '').strip()
    sender_number = (body.get('senderNumber') or '').strip()
    if len(provider) > 60 or len(sender_number) > 20:
        return jsonify({'error': '입력값이 너무 깁니다'}), 400
    storage.set_sms_config(bool(body.get('enabled', False)), provider, sender_number, body.get('apiKey') or None)
    audit('SET_SMS_SETTINGS')
    return jsonify({'ok': True})


@app.get('/api/settings/kakaobiz')
@require_role('OPERATOR')
def api_get_kakaobiz_settings():
    return jsonify(storage.get_kakaobiz_config_public())


@app.put('/api/settings/kakaobiz')
@require_role('OPERATOR')
def api_set_kakaobiz_settings():
    body = request.get_json(force=True)
    api_key = (body.get('apiKey') or '').strip() or None
    api_secret = (body.get('apiSecret') or '').strip() or None
    pf_id = (body.get('pfId') or '').strip() or None
    template_id = (body.get('templateId') or '').strip() or None
    sender_number = (body.get('senderNumber') or '').strip() or None
    for label, val in (('API 키', api_key), ('API Secret', api_secret), ('발신 프로필 키(pfId)', pf_id),
                        ('템플릿 ID', template_id)):
        if val and len(val) > 100:
            return jsonify({'error': f'{label}는 100자 이하여야 합니다'}), 400
    if sender_number and len(sender_number) > 20:
        return jsonify({'error': '발신번호는 20자 이하여야 합니다'}), 400
    existing = storage.get_kakaobiz_config_public()
    if not api_key and not existing['apiKeySet']:
        return jsonify({'error': 'API 키를 입력해주세요'}), 400
    if not pf_id and not existing['pfId']:
        return jsonify({'error': '발신 프로필 키(pfId)를 입력해주세요'}), 400
    if not template_id and not existing['templateId']:
        return jsonify({'error': '템플릿 ID를 입력해주세요'}), 400
    if not sender_number and not existing['senderNumber']:
        return jsonify({'error': '발신번호를 입력해주세요'}), 400
    if body.get('minSeverity') not in (None, 'warn', 'crit'):
        return jsonify({'error': 'minSeverity는 warn 또는 crit이어야 합니다'}), 400
    storage.set_kakaobiz_config(bool(body.get('enabled', False)), api_key, api_secret, pf_id, template_id,
                                 sender_number, bool(body.get('smsFallback', False)), body.get('minSeverity') or 'crit')
    audit('SET_KAKAOBIZ_SETTINGS')
    return jsonify({'ok': True})


@app.post('/api/settings/kakaobiz/test')
@require_role('OPERATOR')
def api_test_kakaobiz():
    cfg = storage.get_kakaobiz_config()
    if not cfg:
        return jsonify({'error': '카카오 비즈니스 설정이 완료되지 않았거나 비활성화 상태이거나, 등록된 수신자가 없습니다'}), 400
    from alerts.kakao_biz_channel import KakaoBizChannel
    ok, err = KakaoBizChannel().send(cfg, '[InfraSight] 테스트 알림', 'InfraSight 알림 설정이 정상적으로 동작합니다.')
    audit('TEST_KAKAOBIZ', details='ok' if ok else f'failed: {err}')
    if not ok:
        return jsonify({'error': '알림톡 발송에 실패했습니다. 감사 로그에서 자세한 내용을 확인하세요.'}), 502
    return jsonify({'ok': True})


@app.get('/api/kakaobiz/recipients')
@require_role('VIEWER')
def api_list_kakaobiz_recipients():
    return jsonify({'recipients': storage.load_kakaobiz_recipients()})


@app.post('/api/kakaobiz/recipients')
@require_role('OPERATOR')
def api_create_kakaobiz_recipient():
    body = request.get_json(force=True)
    try:
        name, phone = validation.validate_kakaobiz_recipient(body)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    recipient_id = storage.create_kakaobiz_recipient(name, phone)
    audit('CREATE_KAKAOBIZ_RECIPIENT', target=str(recipient_id), details=f"{name} <{phone}>")
    return jsonify({'ok': True, 'id': recipient_id})


@app.put('/api/kakaobiz/recipients/<int:recipient_id>')
@require_role('OPERATOR')
def api_update_kakaobiz_recipient(recipient_id):
    body = request.get_json(force=True)
    try:
        name, phone = validation.validate_kakaobiz_recipient(body)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    if not storage.update_kakaobiz_recipient(recipient_id, name, phone, bool(body.get('enabled', True))):
        return jsonify({'error': 'not found'}), 404
    audit('UPDATE_KAKAOBIZ_RECIPIENT', target=str(recipient_id), details=f"{name} <{phone}>")
    return jsonify({'ok': True})


@app.delete('/api/kakaobiz/recipients/<int:recipient_id>')
@require_role('OPERATOR')
def api_delete_kakaobiz_recipient(recipient_id):
    storage.delete_kakaobiz_recipient(recipient_id)
    audit('DELETE_KAKAOBIZ_RECIPIENT', target=str(recipient_id))
    return jsonify({'ok': True})


@app.post('/api/system/backup')
@require_role('ADMIN')
def api_trigger_backup():
    backup_dir = os.path.join(BASE_DIR, 'backups')
    try:
        path = storage.backup_database(backup_dir, keep_days=storage.BACKUP_RETENTION_DAYS)
    except Exception as e:
        audit('BACKUP_FAILURE', details=str(e))
        return jsonify({'error': '백업에 실패했습니다. 감사 로그에서 자세한 내용을 확인하세요.'}), 500
    audit('MANUAL_BACKUP', target=os.path.basename(path))
    return jsonify({'ok': True, 'file': os.path.basename(path)})


@app.get('/')
def index():
    # No-cache: this file changes often during active development, and a
    # browser serving a stale cached copy after an edit looks identical to a
    # fix "not working" -- indistinguishable without opening devtools.
    resp = send_from_directory(BASE_DIR, 'index.html')
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp


def _agent_exe_path():
    return os.path.join(BASE_DIR, 'dist', 'InfraSightAgent.exe')


def _agent_exe_sha256():
    """Directive section 11: lets whoever's installing an agent cross-check
    the file they downloaded against what the server thinks it's serving,
    instead of just curl | run with no way to verify anything. Not a
    replacement for code signing -- there's no cert to sign with here -- but
    it's the realistic minimum for a self-hosted, unsigned .exe."""
    import hashlib
    exe_path = _agent_exe_path()
    if not os.path.exists(exe_path):
        return None
    h = hashlib.sha256()
    with open(exe_path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


@app.get('/api/agent/info')
def api_agent_info():
    exe_path = _agent_exe_path()
    exists = os.path.exists(exe_path)
    return jsonify({
        'available': exists,
        'version': storage.AGENT_VERSION,
        'sha256': _agent_exe_sha256() if exists else None,
        'sizeBytes': os.path.getsize(exe_path) if exists else None,
        'buildDate': time.strftime('%Y-%m-%d', time.gmtime(os.path.getmtime(exe_path))) if exists else None,
    })


@app.get('/download/agent')
def download_agent():
    if os.path.exists(_agent_exe_path()):
        return send_from_directory(os.path.join(BASE_DIR, 'dist'), 'InfraSightAgent.exe', as_attachment=True)
    return send_from_directory(BASE_DIR, 'agent.py', as_attachment=True)


# Keep the marker in sync with agent.py's EMBEDDED_CONFIG_MARKER. Appending
# bytes after the exe's own PE image doesn't corrupt it (Windows only reads
# up to where the executable's real sections end), so this single download
# is both a fully working InfraSightAgent.exe *and* carries this one device's
# server URL + token -- no separate .bat wrapper, no curl step, no typed
# command. agent.py looks for this marker in its own file on first run.
_AGENT_CONFIG_MARKER = b'\n===INFRASIGHT_CONFIG===\n'


@app.get('/download/installer/<token>')
def download_installer(token):
    device_row = storage.find_device_by_token(token)
    if not device_row:
        return jsonify({'error': 'invalid or expired token'}), 404
    exe_path = _agent_exe_path()
    if not os.path.exists(exe_path):
        return jsonify({'error': '에이전트 실행 파일이 서버에 없습니다. 관리자에게 문의하세요.'}), 500
    server_url = f"http://{storage.get_lan_ip()}:{PORT}"
    payload = json.dumps({'server': server_url, 'token': token}).encode('utf-8')
    with open(exe_path, 'rb') as f:
        exe_bytes = f.read()
    resp = Response(exe_bytes + _AGENT_CONFIG_MARKER + payload, mimetype='application/octet-stream')
    resp.headers['Content-Disposition'] = 'attachment; filename="InfraSightAgent.exe"'
    return resp


@app.get('/download/config/<token>')
def download_agent_config(token):
    """A tiny counterpart to /download/installer/<token> above, for the
    "download the reusable InfraSightAgent.exe once, never again" flow (see
    index.html's agent-command-box): the exe itself only needs grabbing a
    single time and can be copied PC to PC, but each new device still needs
    its own token somehow -- dropping this few-byte file next to that
    already-downloaded exe (same filename agent.py's read_sidecar_config()
    looks for) gets the same zero-typing, double-click-and-done result as
    the embedded installer, without re-downloading the ~8MB exe per device.
    No @require_role, same as /download/installer/<token>: this is meant to
    be opened directly on a different PC than the admin's own browser
    session, so the device token itself (not a login) is what gates it."""
    device_row = storage.find_device_by_token(token)
    if not device_row:
        return jsonify({'error': 'invalid or expired token'}), 404
    server_url = f"http://{storage.get_lan_ip()}:{PORT}"
    payload = json.dumps({'server': server_url, 'token': token})
    resp = Response(payload, mimetype='application/json')
    resp.headers['Content-Disposition'] = 'attachment; filename="InfraSightAgent.cfg"'
    return resp


@app.errorhandler(Exception)
def _handle_unexpected_error(e):
    """Security hardening Phase F/D: an unhandled exception previously meant
    whatever Flask's default error page shows (development server: a full
    traceback; here, running under waitress: a bare 500) -- and either way,
    nothing was ever recorded anywhere once the console window scrolled past
    it. This logs the real exception (with traceback) to logs/error.log and
    returns only a generic message to the client, consistent with the same
    "don't leak internals" fix already applied to the backup/SMTP-test
    endpoints in Phase C."""
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return e
    app_logger.error('Unhandled exception on %s %s: %s',
                      request.method, request.path, safe_log_value(e), exc_info=True)
    return jsonify({'error': '서버 오류가 발생했습니다'}), 500


def main():
    # Pulled out of the `if __name__ == '__main__':` block (one-click
    # installer pass) so installer.py's --serve mode can call this directly
    # after its own setup wizard, instead of duplicating backend startup.
    storage.init_db()
    scheduler.start()
    flow_listener.start()
    conn = storage.get_db()
    has_admin = conn.execute('SELECT 1 FROM users LIMIT 1').fetchone() is not None
    conn.close()
    if not has_admin:
        print("[경고] 로그인 계정이 없습니다. 아래 명령으로 관리자 계정을 먼저 만드세요:")
        print("  python -c \"import storage; storage.create_admin_if_missing('admin', '비밀번호')\"")
    startup_msg = f"InfraSight running at http://localhost:{PORT}  (LAN: http://{storage.get_lan_ip()}:{PORT})"
    print(startup_msg)
    app_logger.info(startup_msg)
    # trusted_proxy/trusted_proxy_headers: without these, waitress discards
    # every X-Forwarded-* header on every request before WSGI/_TrustedProxyFix
    # ever sees them (its own untrusted-proxy-spoofing guard, separate from
    # and in front of the one in _TrustedProxyFix above) -- confirmed live
    # building the Kakao OAuth redirect_uri, where request.scheme kept coming
    # back "http" even though Caddy (the only thing allowed to reach this
    # port un-firewalled) was both sending X-Forwarded-Proto correctly AND
    # the sole connection this trusts, by address, at the Flask layer. This
    # mirrors _TrustedProxyFix's own trust boundary (127.0.0.1, i.e. only
    # Caddy) one layer further out, at the WSGI server itself.
    serve(app, host='0.0.0.0', port=PORT, trusted_proxy='127.0.0.1',
          trusted_proxy_headers={'x-forwarded-for', 'x-forwarded-proto', 'x-forwarded-host'})


if __name__ == '__main__':
    main()
