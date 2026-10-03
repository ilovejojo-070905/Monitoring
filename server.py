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
import uuid
from collections import defaultdict, deque
from datetime import timedelta
from functools import wraps

from flask import Flask, Response, jsonify, request, send_from_directory, session
from waitress import serve
from werkzeug.middleware.proxy_fix import ProxyFix

import storage
import validation
from applog import app_logger, safe_log_value
from collector import state, scheduler, health, metrics
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
# Security hardening Phase B section 2/23: idle-timeout the session (Flask
# refreshes this on every request by default, so it's a *sliding* 30-minute
# window -- a dashboard tab left open and actively polling never idles out,
# but a closed/forgotten one does). SameSite=Lax stops the cookie being sent
# on cross-site POST/PUT/DELETE, which is most of what CSRF relies on; the
# explicit CSRF token below covers the rest.
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


def audit(action, target=None, details=None):
    storage.write_audit(session.get('user'), action, target, details, request.remote_addr)


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


def require_role(min_role='VIEWER'):
    """Replaces the old login_required for every protected route: checks the
    user is logged in, that their session hasn't been invalidated by a
    logout/password-change elsewhere (session_version), that their role meets
    the route's minimum, and -- for state-changing methods -- that a valid
    CSRF token was sent."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            username = session.get('user')
            if not username:
                return jsonify({'error': 'unauthorized'}), 401
            current_sv = storage.get_session_version(username)
            if current_sv is None or session.get('sv') != current_sv:
                session.clear()
                return jsonify({'error': 'session_expired'}), 401
            if storage.ROLE_RANK.get(session.get('role'), -1) < storage.ROLE_RANK.get(min_role, 0):
                audit('AUTHORIZATION_FAILURE', target=request.path, details=f"role={session.get('role')} needs {min_role}")
                return jsonify({'error': 'forbidden'}), 403
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
    if result['status'] != 'ok':
        storage.write_audit(username or None, 'LOGIN_FAILED', source_ip=ip)
        return jsonify({'error': '아이디 또는 비밀번호가 올바르지 않습니다'}), 401
    session.clear()  # session-fixation defense: never reuse whatever session existed pre-login
    csrf_token = secrets.token_hex(16)
    session['user'] = result['username']
    session['role'] = result['role']
    session['sv'] = result['session_version']
    session['csrf'] = csrf_token
    session.permanent = True
    storage.write_audit(result['username'], 'LOGIN', source_ip=ip)
    return jsonify({'ok': True, 'username': result['username'], 'role': result['role'], 'csrfToken': csrf_token,
                     'mustChangePassword': result.get('must_change_password', False)})


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
    if not storage.change_password(session['user'], current_password, new_password):
        return jsonify({'error': '현재 비밀번호가 올바르지 않습니다'}), 401
    audit('CHANGE_PASSWORD')
    session.clear()  # the password change already bumped session_version; drop our own copy too
    return jsonify({'ok': True})


@app.get('/api/users')
@require_role('ADMIN')
def api_list_users():
    return jsonify({'users': storage.list_users()})


@app.post('/api/users')
@require_role('ADMIN')
def api_create_user():
    body = request.get_json(force=True)
    username = (body.get('username') or '').strip()
    password = body.get('password') or ''
    role = (body.get('role') or 'VIEWER').upper()
    if not username or len(password) < 8:
        return jsonify({'error': '아이디와 8자 이상의 비밀번호가 필요합니다'}), 400
    if role not in storage.ROLES:
        return jsonify({'error': 'role은 ADMIN, OPERATOR, VIEWER 중 하나여야 합니다'}), 400
    try:
        storage.create_user(username, password, role)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    audit('CREATE_USER', target=username, details=role)
    return jsonify({'ok': True})


@app.delete('/api/users/<int:user_id>')
@require_role('ADMIN')
def api_delete_user(user_id):
    target = storage.get_user_by_id(user_id)
    if not target:
        return jsonify({'error': 'not found'}), 404
    if target['username'] == session.get('user'):
        return jsonify({'error': '자기 자신은 삭제할 수 없습니다'}), 400
    if target['role'] == 'ADMIN' and storage.count_admins() <= 1:
        return jsonify({'error': '마지막 관리자 계정은 삭제할 수 없습니다'}), 400
    storage.delete_user(user_id)
    audit('DELETE_USER', target=target['username'])
    return jsonify({'ok': True})


@app.put('/api/users/<int:user_id>')
@require_role('ADMIN')
def api_update_user(user_id):
    target = storage.get_user_by_id(user_id)
    if not target:
        return jsonify({'error': 'not found'}), 404
    body = request.get_json(force=True)
    role = (body.get('role') or '').upper() or None
    new_password = body.get('password') or ''
    if role and role not in storage.ROLES:
        return jsonify({'error': 'role은 ADMIN, OPERATOR, VIEWER 중 하나여야 합니다'}), 400
    if role and target['role'] == 'ADMIN' and role != 'ADMIN' and storage.count_admins() <= 1:
        return jsonify({'error': '마지막 관리자 계정의 권한은 변경할 수 없습니다'}), 400
    if new_password and len(new_password) < 8:
        return jsonify({'error': '새 비밀번호는 8자 이상이어야 합니다'}), 400
    if not role and not new_password:
        return jsonify({'error': '변경할 내용이 없습니다'}), 400
    storage.update_user(user_id, role=role, new_password=new_password or None)
    detail_parts = []
    if role and role != target['role']:
        detail_parts.append(f"role: {target['role']}->{role}")
    if new_password:
        detail_parts.append('password_reset')
    audit('UPDATE_USER', target=target['username'], details=', '.join(detail_parts) or None)
    return jsonify({'ok': True})


@app.post('/api/users/<int:user_id>/unlock')
@require_role('ADMIN')
def api_unlock_user(user_id):
    target = storage.get_user_by_id(user_id)
    if not target:
        return jsonify({'error': 'not found'}), 404
    storage.unlock_user(target['username'])
    audit('ACCOUNT_UNLOCKED', target=target['username'])
    return jsonify({'ok': True})


# ------------------------------------------------------------------ API --
def serialize_device(d):
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
    return base


@app.get('/api/state')
@require_role('VIEWER')
def api_state():
    with state.LOCK:
        devices = storage.load_devices()
        out = {'servers': [], 'dbs': [], 'nets': [], 'facs': []}
        key_map = {'server': 'servers', 'db': 'dbs', 'net': 'nets', 'fac': 'facs'}
        for d in devices:
            out[key_map[d['category']]].append(serialize_device(d))
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
@require_role('ADMIN')
def api_discovery_scan():
    body = request.get_json(force=True)
    range_text = (body.get('range') or '').strip()
    try:
        results = discovery.scan(range_text)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        app_logger.exception('network scan failed')
        return jsonify({'error': f'스캔 중 오류가 발생했습니다: {e}'}), 500
    existing_ips = {d['ip'] for d in storage.load_devices() if d.get('ip')}
    for r in results:
        r['alreadyRegistered'] = r['ip'] in existing_ips
    audit('NETWORK_SCAN', target=range_text, details=f'{len(results)}대 발견')
    return jsonify({'results': results})


@app.post('/api/devices/test-snmp')
@require_role('ADMIN')
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


@app.post('/api/devices')
@require_role('ADMIN')
def api_register_device():
    body = request.get_json(force=True)
    category = body.get('category')
    name = (body.get('name') or '').strip()
    mode = body.get('mode')
    ip = (body.get('ip') or '').strip() or None
    fields = body.get('fields') or {}
    if category not in ('server', 'db', 'net', 'fac') or mode not in ('agent', 'ping', 'snmp') or not name:
        return jsonify({'error': 'invalid payload'}), 400
    # Security hardening Phase C sections 12/18: name is used verbatim in a
    # per-device installer filename and title -- validating the character set
    # here is what actually prevents any downstream injection through it, not
    # escaping on the display side alone.
    if not validation.is_safe_name(name):
        return jsonify({'error': '장비 이름에 사용할 수 없는 문자가 포함되어 있습니다 (특수문자 &|<>^%"\'` 등 제외, 80자 이하)'}), 400
    if mode in ('ping', 'snmp') and not ip:
        return jsonify({'error': 'ip required for this mode'}), 400
    # Also closes the ping-argument-injection gap (collector/ping_collector.py
    # passes ip straight into a subprocess arg list; a leading '-' would
    # otherwise be read as a ping flag rather than a target).
    if ip and not validation.is_valid_host(ip):
        return jsonify({'error': 'IP 주소 또는 호스트명 형식이 올바르지 않습니다'}), 400
    if mode == 'snmp' and not SNMP_AVAILABLE:
        return jsonify({'error': 'SNMP 라이브러리(pysnmp)가 서버에 설치되어 있지 않습니다'}), 400
    port_field = fields.get('port')
    if port_field not in (None, '') and not validation.is_valid_port(port_field):
        return jsonify({'error': 'port는 1~65535 사이의 숫자여야 합니다'}), 400
    snmp_port = fields.get('snmpPort')
    if snmp_port not in (None, '') and not validation.is_valid_port(snmp_port):
        return jsonify({'error': 'snmpPort는 1~65535 사이의 숫자여야 합니다'}), 400
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
            return jsonify({'error': f'"{ip}"에 연결할 수 없습니다 ({attempts}회 중 {successes}회만 응답). IP 주소를 확인해주세요. 응답이 불안정해도 꼭 등록해야 한다면 SNMP나 Agent 방식을 이용해주세요.'}), 400
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
                return jsonify({'error': v3_err}), 400
        # Same reasoning as the ping check above: one lucky reply out of a
        # flaky device isn't good enough evidence to register on.
        ok, successes, attempts = snmp_collector.test_connection(
            ip, snmp_version, community or 'public', snmp_port_val, v3_username,
            v3_auth_protocol, v3_auth_password, v3_priv_protocol, v3_priv_password)
        if not ok:
            cred_hint = '사용자명/인증·개인정보 보호 정보' if snmp_version == 'v3' else 'Community 문자열'
            return jsonify({'error': f'"{ip}"에서 SNMP 응답을 받지 못했습니다 ({attempts}회 중 {successes}회만 응답). {cred_hint}/버전/포트를 확인해주세요. 응답이 없어도 꼭 등록해야 한다면 Ping이나 Agent 방식을 이용해주세요.'}), 400
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
        # Unaffected by the above: this is the address the agent *process*
        # itself connects back to (a plain HTTP client, not a browser), so
        # it must stay the direct backend host:port, not a relative path.
        resp['agentCommand'] = f"InfraSightAgent.exe --server http://{lan_ip}:{PORT} --token {token} --install-startup"
    return jsonify(resp)


@app.put('/api/devices/<device_id>')
@require_role('ADMIN')
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
@require_role('ADMIN')
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
    acknowledged_by = (body.get('by') or '').strip() or session.get('user')
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
    storage.set_maintenance(device_id, enabled, start, end, reason)
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
@require_role('ADMIN')
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
        'agentCommand': f"InfraSightAgent.exe --server http://{lan_ip}:{PORT} --token {new_token} --install-startup",
    })


@app.post('/api/devices/<device_id>/token/revoke')
@require_role('ADMIN')
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
@require_role('ADMIN')
def api_get_smtp_settings():
    return jsonify(storage.get_smtp_config_public())


@app.put('/api/settings/smtp')
@require_role('ADMIN')
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
@require_role('ADMIN')
def api_test_smtp():
    cfg = storage.get_smtp_config()
    if not cfg:
        return jsonify({'error': 'SMTP 설정이 완료되지 않았거나 비활성화 상태입니다'}), 400
    from alerts.email_channel import EmailChannel
    channel = EmailChannel(cfg['host'], cfg['port'], cfg['username'], cfg['password'], cfg['use_tls'])
    ok, err = channel.send(cfg['alert_to'], '[InfraSight] 테스트 알림',
                            'InfraSight 알림 설정이 정상적으로 동작합니다.')
    # The raw smtplib/SSL error can echo back connection internals (and in
    # principle the account being used) -- keep it in the audit log for the
    # admin to look up server-side, not in the HTTP response body.
    audit('TEST_SMTP', details='ok' if ok else f'failed: {err}')
    if not ok:
        return jsonify({'error': 'SMTP 발송에 실패했습니다. 감사 로그에서 자세한 내용을 확인하세요.'}), 502
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
    resp.headers['Content-Disposition'] = 'attachment; filename="InfraSight-Install.exe"'
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
    serve(app, host='0.0.0.0', port=PORT)


if __name__ == '__main__':
    main()
