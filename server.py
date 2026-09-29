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

import storage
import validation
from applog import app_logger, safe_log_value
from collector import state, scheduler, health, metrics
from collector import agent_collector
from collector.snmp_collector import SNMP_AVAILABLE

BASE_DIR = storage.BASE_DIR
PORT = storage.PORT
LOCAL_ID = storage.LOCAL_ID

app = Flask(__name__, static_folder=None)


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
# explicit CSRF token below covers the rest. Secure is left off deliberately
# -- there is no HTTPS reverse proxy in front of this deployment yet, and a
# Secure cookie simply never gets sent over plain HTTP, which would break
# login entirely. Revisit once Phase E (HTTPS) is in place.
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True
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
    dq = _login_attempts_by_ip[ip]
    while dq and now - dq[0] > IP_WINDOW_SEC:
        dq.popleft()
    if len(dq) >= IP_MAX_ATTEMPTS:
        return True
    dq.append(now)
    return False


def audit(action, target=None, details=None):
    storage.write_audit(session.get('user'), action, target, details, request.remote_addr)


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
    return jsonify({'ok': True, 'username': result['username'], 'role': result['role'], 'csrfToken': csrf_token})


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
    return jsonify({'username': session.get('user'), 'role': session.get('role'), 'csrfToken': session['csrf']})


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
    f = {k: v for k, v in d['fields'].items() if k not in ('community', 'snmpPort', 'snmpVersion')}
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
    return jsonify(out)


@app.get('/api/system/health')
@require_role('VIEWER')
def api_system_health():
    return jsonify(health.get_health())


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
    # Security hardening Phase C sections 12/18: name is embedded verbatim in
    # the generated installer .bat (title/echo lines) -- validating the
    # character set here is what actually prevents cmd.exe injection through
    # it, not escaping on the display side alone.
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
        resp['agentDownloadUrl'] = f"http://{lan_ip}:{PORT}/download/agent"
        resp['agentInstallerUrl'] = f"http://{lan_ip}:{PORT}/download/installer/{token}"
        resp['agentCommand'] = f"InfraSightAgent.exe --server http://{lan_ip}:{PORT} --token {token} --install-startup"
    return jsonify(resp)


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
        agent_collector.record_report(entity, device_row, body)
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
        'agentInstallerUrl': f"http://{lan_ip}:{PORT}/download/installer/{new_token}",
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
        path = storage.backup_database(backup_dir, keep=14)
    except Exception as e:
        audit('BACKUP_FAILURE', details=str(e))
        return jsonify({'error': '백업에 실패했습니다. 감사 로그에서 자세한 내용을 확인하세요.'}), 500
    audit('MANUAL_BACKUP', target=os.path.basename(path))
    return jsonify({'ok': True, 'file': os.path.basename(path)})


@app.get('/')
def index():
    return send_from_directory(BASE_DIR, 'index.html')


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
        'sha256': _agent_exe_sha256() if exists else None,
        'sizeBytes': os.path.getsize(exe_path) if exists else None,
        'buildDate': time.strftime('%Y-%m-%d', time.gmtime(os.path.getmtime(exe_path))) if exists else None,
    })


@app.get('/download/agent')
def download_agent():
    if os.path.exists(_agent_exe_path()):
        return send_from_directory(os.path.join(BASE_DIR, 'dist'), 'InfraSightAgent.exe', as_attachment=True)
    return send_from_directory(BASE_DIR, 'agent.py', as_attachment=True)


@app.get('/download/installer/<token>')
def download_installer(token):
    device_row = storage.find_device_by_token(token)
    if not device_row:
        return jsonify({'error': 'invalid or expired token'}), 404
    server_url = f"http://{storage.get_lan_ip()}:{PORT}"
    device_name = device_row['name']
    # Defense in depth on top of the registration-time check in
    # api_register_device: this name is about to be embedded verbatim into a
    # generated .bat (title/echo lines). A device registered before this
    # validation existed could still have an unsafe name sitting in the DB,
    # so re-check here rather than trusting the stored value.
    if not validation.is_safe_name(device_name):
        return jsonify({'error': '이 장비 이름에는 설치 스크립트에 안전하게 포함할 수 없는 문자가 있습니다. 장비를 다시 등록해주세요.'}), 400
    exe_hash = _agent_exe_sha256()
    # A single double-click: downloads the real agent exe, then runs it once
    # with the server+token already filled in (--install-startup also sets up
    # auto-start), so the person never has to type anything by hand.
    # chcp 65001 + a UTF-8 BOM keep the Korean text below from being misread
    # as the system ANSI codepage, which otherwise corrupts cmd's own parsing
    # of later lines (garbled multi-byte text can look like stray quotes/operators).
    lines = [
        '@echo off',
        'chcp 65001 >nul',
        f'title InfraSight Agent Install - {device_name}',
        'setlocal',
        'set INSTALL_DIR=%LOCALAPPDATA%\\InfraSightAgent',
        'if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%" >nul 2>&1',
        'echo.',
        f'echo InfraSight 에이전트를 설치합니다 ({device_name})...',
        'echo.',
        f'curl -L -o "%INSTALL_DIR%\\InfraSightAgent.exe" "{server_url}/download/agent"',
        'if not exist "%INSTALL_DIR%\\InfraSightAgent.exe" (',
        '  echo.',
        '  echo 다운로드에 실패했습니다. 인터넷 연결과 서버 주소를 확인해주세요.',
        '  pause',
        '  exit /b 1',
        ')',
    ] + ([f'echo 참고: 서버가 서명한 SHA-256 = {exe_hash}'] if exe_hash else []) + [
        'echo.',
        'echo 설정 중...',
        f'"%INSTALL_DIR%\\InfraSightAgent.exe" --server "{server_url}" --token "{token}" --install-startup --setup-only',
        'echo.',
        'echo 모니터링을 시작합니다...',
        'start "" /min "%INSTALL_DIR%\\InfraSightAgent.exe"',
        'echo.',
        'echo 설치가 완료되었습니다! 잠시 후 이 창은 자동으로 닫힙니다.',
        'ping -n 4 127.0.0.1 >nul',
        '',
    ]
    script = '﻿' + '\r\n'.join(lines)
    resp = Response(script, mimetype='text/plain; charset=utf-8')
    resp.headers['Content-Disposition'] = 'attachment; filename="InfraSight-Install.bat"'
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


if __name__ == '__main__':
    storage.init_db()
    scheduler.start()
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
