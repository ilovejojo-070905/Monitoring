"""
Shared DB/storage layer for InfraSight.

Pulled out of server.py so that both server.py (Flask routes) and the
collector/ package (scheduler + per-mode samplers) can read/write the
database without importing each other (avoids a circular import between
server.py and collector/*).
"""
import hashlib
import json
import os
import secrets
import socket
import sqlite3
import sys
import threading
import time

from werkzeug.security import generate_password_hash, check_password_hash

import secrets_crypto

# One-click installer pass: see applog.py's identical comment -- a frozen
# exe's __file__ is inside a throw-away temp extraction folder, so the DB
# (and everything else under BASE_DIR) would silently reset on every restart
# without this.
BASE_DIR = os.path.dirname(os.path.abspath(sys.executable)) if getattr(sys, 'frozen', False) else os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'infrasight.db')
# Overridable via env var (default unchanged: 5057) -- lets a second,
# isolated instance run side by side with the real one for testing, without
# needing a code change each time.
PORT = int(os.environ.get('INFRASIGHT_PORT', '5057'))
# 4-3: NetFlow/sFlow are push-based (the device sends to us), not polled --
# these are the UDP ports collector/flow_listener.py binds and listens on,
# the IANA-registered defaults for each. Overridable for the same reason
# PORT is (a second isolated instance for testing).
NETFLOW_PORT = int(os.environ.get('INFRASIGHT_NETFLOW_PORT', '2055'))
SFLOW_PORT = int(os.environ.get('INFRASIGHT_SFLOW_PORT', '6343'))
LOCAL_ID = 'local-pc'
IS_WINDOWS = os.name == 'nt'

# Additive columns introduced in the Phase 1 production-hardening pass.
# (name, SQL type/default) -- existing columns and data are never touched.
_NEW_DEVICE_COLUMNS = [
    ('polling_interval', 'REAL DEFAULT NULL'),
    ('timeout_sec', 'REAL DEFAULT NULL'),
    ('retry_count', 'INTEGER DEFAULT NULL'),
    ('monitoring_enabled', 'INTEGER DEFAULT 1'),
    ('consecutive_failures', 'INTEGER DEFAULT 0'),
    ('last_failure_reason', 'TEXT DEFAULT NULL'),
    ('last_success_at', 'INTEGER DEFAULT NULL'),
    # Device status management pass: last_success_at only ever records a WIN,
    # so there was no way to tell "never polled" from "polled once, ages ago"
    # (both showed NULL), and no timestamp at all for *when* the current
    # failure streak began. last_collected_at is touched on every attempt
    # (win or lose); last_failure_at only on a loss.
    ('last_collected_at', 'INTEGER DEFAULT NULL'),
    ('last_failure_at', 'INTEGER DEFAULT NULL'),
    # Agent management pass: what an agent-mode device's own process last
    # told us about itself, on every report -- separate from the fields
    # above (which are about whether we could reach/collect it at all).
    ('agent_version', 'TEXT DEFAULT NULL'),
    ('agent_os', 'TEXT DEFAULT NULL'),
    ('agent_started_at', 'INTEGER DEFAULT NULL'),
    # Captured server-side from the request's own peer address (via the
    # existing _TrustedProxyFix in server.py), never from a client-supplied
    # field -- an agent claiming its own IP can't be trusted the same way.
    ('agent_reported_ip', 'TEXT DEFAULT NULL'),
    ('agent_last_error', 'TEXT DEFAULT NULL'),
    # Phase 2: maintenance mode (directive section 15) -- polling keeps running
    # while a device is under maintenance, only add_incident() calls are skipped.
    ('maintenance_enabled', 'INTEGER DEFAULT 0'),
    ('maintenance_start', 'INTEGER DEFAULT NULL'),
    ('maintenance_end', 'INTEGER DEFAULT NULL'),
    ('maintenance_reason', 'TEXT DEFAULT NULL'),
    # 2-3: which maintenance_windows row (if any) is currently responsible
    # for this device's maintenance_enabled=1 -- NULL means either not in
    # maintenance, or in maintenance from the manual drawer toggle rather
    # than a schedule. Lets collector/maintenance.py's tick() tell "a window
    # put this device into maintenance, and should take it back out once the
    # window ends" apart from "an operator turned this on by hand, leave it
    # alone" without a separate ownership/priority system.
    ('maintenance_window_id', 'INTEGER DEFAULT NULL'),
    # Phase 7: SNMP vendor profile (directive section 18) -- 'generic' keeps
    # today's behavior (HOST-RESOURCES-MIB, falling back to Cisco OIDs), so
    # every already-registered SNMP device is unaffected until set otherwise.
    ('vendor_profile', "TEXT DEFAULT 'generic'"),
    # Security hardening Phase C section 10: the agent token is looked up by
    # its SHA-256 hash from here on, never by the plaintext column below --
    # see migrate_token_hashes().
    ('token_hash', 'TEXT DEFAULT NULL'),
]

# Phase 2: event engine columns (directive sections 10/11). Existing columns
# (ts/severity/source/category/message/status) are untouched, so any old row
# and any code that only reads those columns keeps working unmodified.
_NEW_INCIDENT_COLUMNS = [
    ('device_id', 'TEXT DEFAULT NULL'),
    ('event_type', 'TEXT DEFAULT NULL'),
    ('first_occurred_at', 'INTEGER DEFAULT NULL'),
    ('last_occurred_at', 'INTEGER DEFAULT NULL'),
    ('resolved_at', 'INTEGER DEFAULT NULL'),
    ('acknowledged_by', 'TEXT DEFAULT NULL'),
    ('acknowledged_at', 'INTEGER DEFAULT NULL'),
    ('occurrence_count', 'INTEGER DEFAULT 1'),
    # 2-3: true when this incident's row was written while the device was
    # under maintenance -- the row still exists either way (see
    # add_incident()'s docstring), this just lets the UI show a badge
    # instead of hiding it.
    ('during_maintenance', 'INTEGER DEFAULT 0'),
]

# Security hardening Phase B (sections 2/3/5/21-23): login lockout state and
# a per-user session_version used to make logout actually invalidate a
# signed-cookie session (Flask sessions have no server-side store by
# default, so "logout" alone can't revoke a copy of the cookie -- bumping
# this counter does, since every request compares the cookie's embedded
# value against the current one in the DB).
_NEW_USER_COLUMNS = [
    ('failed_attempts', 'INTEGER DEFAULT 0'),
    ('locked_until', 'INTEGER DEFAULT NULL'),
    ('session_version', 'INTEGER DEFAULT 0'),
    ('last_login_at', 'INTEGER DEFAULT NULL'),
    ('must_change_password', 'INTEGER DEFAULT 0'),
    # 1-4: account activation/deactivation -- distinct from the lockout
    # columns above (those are *automatic*, temporary, and self-clearing on
    # a correct password; this is a deliberate admin/operator action with no
    # time limit, for an account that shouldn't be able to log in at all
    # right now, e.g. someone who's left the team).
    ('is_active', 'INTEGER DEFAULT 1'),
    # 5-1 2FA: the TOTP secret itself is NOT a column here -- it's stored
    # encrypted in the existing `credentials` table (keyed 'user:<id>' /
    # 'totp_secret', same mechanism as SMTP/webhook secrets) since it needs
    # to come back in plaintext on every verify, unlike everything below
    # which only ever needs a yes/no or a timestamp.
    ('totp_enabled', 'INTEGER DEFAULT 0'),
    ('totp_enrolled_at', 'INTEGER DEFAULT NULL'),
    # Separate rate-limit counters from failed_attempts/locked_until above --
    # a correct password already proves *something*, so brute-forcing the
    # 6-digit TOTP step afterward is a distinct attack with its own budget
    # (1,000,000 possibilities per 30s window vs. an unbounded password
    # space) and deserves its own lockout clock rather than sharing one that
    # a successful password login already reset to 0.
    ('totp_failed_attempts', 'INTEGER DEFAULT 0'),
    ('totp_locked_until', 'INTEGER DEFAULT NULL'),
]

# 2-2: group-level default thresholds (JSON text, NULL = "no override --
# fall back to the global default"). device_groups itself was introduced in
# 2-1 this same session, but the additive-migration pattern is followed
# anyway for consistency with every other table here.
_NEW_GROUP_COLUMNS = [
    ('thresholds', 'TEXT DEFAULT NULL'),
]

ROLES = ('ADMIN', 'OPERATOR', 'VIEWER')
ROLE_RANK = {'VIEWER': 0, 'OPERATOR': 1, 'ADMIN': 2}
MAX_FAILED_ATTEMPTS = 5
LOCK_MINUTES = 10


def get_db():
    # Code review pass, finding #1: default timeout (5s) is the only thing
    # standing between concurrent writers and "database is locked" --
    # doubled here as defense in depth. The real fix for the dominant
    # write source (per-device metric writes, one connection per device
    # per poll tick) is collector/metrics.py's single background writer
    # thread -- this timeout is just margin for whatever lower-frequency
    # writes (device CRUD, incidents, audit) still open their own
    # connection and happen to land at the same instant. journal_mode=WAL,
    # set once on the file itself in init_db(), is what makes that fast
    # rather than concurrent (a persistent file property, not a
    # per-connection one, so it doesn't need repeating here).
    conn = sqlite3.connect(DB_PATH, timeout=15.0)
    conn.row_factory = sqlite3.Row
    return conn


def get_lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        return s.getsockname()[0]
    except Exception:
        return '127.0.0.1'
    finally:
        s.close()


def init_db():
    conn = get_db()
    # Code review pass, finding #1: journal_mode is a property of the DB file
    # itself (written into its header), so this one-time PRAGMA at startup is
    # all that's needed -- every future connection (from this process or a
    # restart) reads WAL mode back off the file automatically. Without it,
    # SQLite's default (rollback journal) blocks ALL readers for the
    # duration of any writer's transaction; WAL lets readers keep going
    # concurrently with a writer, which matters here because waitress's
    # request threads and the 10-worker device-polling pool are all hitting
    # this same file constantly.
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('''CREATE TABLE IF NOT EXISTS devices(
        id TEXT PRIMARY KEY,
        category TEXT NOT NULL,
        name TEXT NOT NULL,
        mode TEXT NOT NULL,
        ip TEXT,
        token TEXT,
        fields TEXT NOT NULL,
        created_at INTEGER NOT NULL
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS incidents(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER NOT NULL,
        severity TEXT NOT NULL,
        source TEXT NOT NULL,
        category TEXT NOT NULL,
        message TEXT NOT NULL,
        status TEXT NOT NULL
    )''')
    conn.commit()
    row = conn.execute('SELECT id FROM devices WHERE id=?', (LOCAL_ID,)).fetchone()
    if not row:
        conn.execute(
            'INSERT INTO devices(id,category,name,mode,ip,token,fields,created_at) VALUES (?,?,?,?,?,?,?,?)',
            (LOCAL_ID, 'server', socket.gethostname(), 'local', get_lan_ip(), None,
             json.dumps({'os': 'windows' if IS_WINDOWS else 'linux', 'role': '로컬 PC (실측)'}),
             int(time.time() * 1000)))
        conn.commit()
    conn.execute('''CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        created_at INTEGER NOT NULL
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS audit_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        action TEXT NOT NULL,
        target TEXT,
        ts INTEGER NOT NULL,
        source_ip TEXT,
        details TEXT
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS credentials(
        device_id TEXT NOT NULL,
        type TEXT NOT NULL,
        secret TEXT,
        PRIMARY KEY (device_id, type)
    )''')
    # Phase 4: global settings (directive sections 12/13/24) -- SMTP config
    # lives here except the password itself, which reuses the credentials
    # table above (device_id='__system__') so no plaintext secret sits
    # alongside ordinary config values.
    conn.execute('''CREATE TABLE IF NOT EXISTS settings(
        key TEXT PRIMARY KEY,
        value TEXT
    )''')
    # Phase 5: metrics retention (directive section 25). Raw samples are kept
    # only briefly; 5-minute and 1-hour rollups keep the history usable long
    # after the raw rows are purged. Without this, every hist[] chart (cpu/
    # mem/traffic/latency) loses all history on every server restart, since
    # today those arrays only ever live in the in-memory LIVE dict.
    conn.execute('''CREATE TABLE IF NOT EXISTS metrics_raw(
        device_id TEXT NOT NULL,
        metric TEXT NOT NULL,
        ts INTEGER NOT NULL,
        value REAL NOT NULL
    )''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_metrics_raw ON metrics_raw(device_id, metric, ts)')
    conn.execute('''CREATE TABLE IF NOT EXISTS metrics_5m(
        device_id TEXT NOT NULL,
        metric TEXT NOT NULL,
        bucket_ts INTEGER NOT NULL,
        avg_value REAL NOT NULL,
        min_value REAL NOT NULL,
        max_value REAL NOT NULL,
        sample_count INTEGER NOT NULL,
        PRIMARY KEY (device_id, metric, bucket_ts)
    )''')
    # Phase 7: topology groundwork (directive section 31 -- "prepare" LLDP/CDP,
    # keep the visual topology as-is for now). Links are discovered/stored
    # here; nothing reads this table into the rendered topology yet.
    conn.execute('''CREATE TABLE IF NOT EXISTS device_links(
        from_device_id TEXT NOT NULL,
        to_device_id TEXT NOT NULL,
        link_type TEXT NOT NULL,
        remote_port TEXT,
        discovered_at INTEGER NOT NULL,
        PRIMARY KEY (from_device_id, to_device_id, link_type)
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS metrics_1h(
        device_id TEXT NOT NULL,
        metric TEXT NOT NULL,
        bucket_ts INTEGER NOT NULL,
        avg_value REAL NOT NULL,
        min_value REAL NOT NULL,
        max_value REAL NOT NULL,
        sample_count INTEGER NOT NULL,
        PRIMARY KEY (device_id, metric, bucket_ts)
    )''')
    # 4-3: NetFlow/sFlow flow records, pre-aggregated into 1-minute buckets.
    # Unlike metrics_raw above, there is deliberately no raw per-flow table --
    # flow volume scales with actual network traffic (not a fixed poll rate),
    # so collector/flow_listener.py accumulates incoming records in memory
    # and flushes already-aggregated rows here once a minute. device_id is
    # the registered device whose IP matches the flow's exporter, or
    # 'unknown:<ip>' when no device is registered at that IP yet -- which is
    # itself useful (it's how you discover an exporter that hasn't been
    # registered).
    conn.execute('''CREATE TABLE IF NOT EXISTS flow_bandwidth_1m(
        device_id TEXT NOT NULL,
        bucket_ts INTEGER NOT NULL,
        bytes_total INTEGER NOT NULL,
        packets_total INTEGER NOT NULL,
        PRIMARY KEY (device_id, bucket_ts)
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS flow_protocol_1m(
        device_id TEXT NOT NULL,
        bucket_ts INTEGER NOT NULL,
        protocol TEXT NOT NULL,
        bytes_total INTEGER NOT NULL,
        packets_total INTEGER NOT NULL,
        PRIMARY KEY (device_id, bucket_ts, protocol)
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS flow_top_pairs_1m(
        device_id TEXT NOT NULL,
        bucket_ts INTEGER NOT NULL,
        src_ip TEXT NOT NULL,
        dst_ip TEXT NOT NULL,
        bytes_total INTEGER NOT NULL,
        packets_total INTEGER NOT NULL,
        PRIMARY KEY (device_id, bucket_ts, src_ip, dst_ip)
    )''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_flow_bandwidth_1m ON flow_bandwidth_1m(bucket_ts)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_flow_protocol_1m ON flow_protocol_1m(bucket_ts)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_flow_top_pairs_1m ON flow_top_pairs_1m(bucket_ts)')
    # 4-3: which exporters we've actually heard from -- the runtime answer to
    # "장비 지원 여부 확인" (does this device actually support NetFlow/sFlow
    # and is it configured to send here), independent of whether it's a
    # registered InfraSight device.
    conn.execute('''CREATE TABLE IF NOT EXISTS flow_exporters(
        exporter_ip TEXT PRIMARY KEY,
        protocol TEXT NOT NULL,
        first_seen_at INTEGER NOT NULL,
        last_seen_at INTEGER NOT NULL,
        record_count INTEGER NOT NULL DEFAULT 0
    )''')
    # 2-6: network discovery scan history -- a scan's results used to only
    # ever live in the HTTP response and vanish the moment it was read. This
    # persists what was scanned, when, by whom, and what was found (one row
    # per scan + one row per live host in that scan), so "탐지 이력" is an
    # actual log, not just whatever's still on screen from the last scan.
    conn.execute('''CREATE TABLE IF NOT EXISTS discovery_scans(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        range_text TEXT NOT NULL,
        requested_by TEXT,
        started_at INTEGER NOT NULL,
        finished_at INTEGER NOT NULL,
        host_count INTEGER NOT NULL,
        found_count INTEGER NOT NULL
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS discovery_scan_results(
        scan_id INTEGER NOT NULL,
        ip TEXT NOT NULL,
        hostname TEXT,
        latency_ms REAL,
        guessed_type TEXT,
        already_registered INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (scan_id, ip)
    )''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_discovery_scans_started ON discovery_scans(started_at)')
    # 2-1: a managed catalog of group names, separate from the free-text
    # `fields.group` string every device already carries (unchanged --
    # devices still just reference a group BY NAME, not a foreign key, to
    # avoid a bigger migration). This table is what makes "그룹" an actual
    # thing you create/rename/delete instead of just whatever string
    # someone typed into a device's 그룹 field -- see rename_device_group()
    # for how a rename propagates to every member device.
    conn.execute('''CREATE TABLE IF NOT EXISTS device_groups(
        name TEXT PRIMARY KEY,
        description TEXT,
        created_at INTEGER NOT NULL
    )''')
    # 2-2: every threshold change, at any of the 3 scopes (global/group/
    # device) -- "임계치 변경 이력을 저장한다". scope_id is NULL for global,
    # the group name for a group, or the device id for a device.
    conn.execute('''CREATE TABLE IF NOT EXISTS threshold_history(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scope TEXT NOT NULL,
        scope_id TEXT,
        changed_by TEXT,
        changed_at INTEGER NOT NULL,
        old_value TEXT,
        new_value TEXT
    )''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_threshold_history_scope ON threshold_history(scope, scope_id, changed_at)')
    # 2-3: schedule definitions ("일회성" -- start_at/end_at a single absolute
    # ms range, or "weekly" -- weekday 0=Mon..6=Sun + 'HH:MM' start/end time
    # recomputed every occurrence). scope_id is a device id or a group name
    # depending on scope, resolved to member devices at evaluation time the
    # same way device_groups membership is resolved everywhere else in this
    # app (by fields.group, not a stored roster).
    conn.execute('''CREATE TABLE IF NOT EXISTS maintenance_windows(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scope TEXT NOT NULL,
        scope_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        start_at INTEGER,
        end_at INTEGER,
        weekday INTEGER,
        start_time TEXT,
        end_time TEXT,
        reason TEXT,
        enabled INTEGER DEFAULT 1,
        created_by TEXT,
        created_at INTEGER NOT NULL
    )''')
    # 점검 이력: every time a device actually entered/left maintenance,
    # whether from a window (window_id set) or the manual drawer toggle
    # (window_id NULL) -- "점검 이력 기록". Separate from the incidents table,
    # which (since the 2-3 fix) keeps recording real failures throughout.
    conn.execute('''CREATE TABLE IF NOT EXISTS maintenance_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT NOT NULL,
        window_id INTEGER,
        reason TEXT,
        started_at INTEGER NOT NULL,
        ended_at INTEGER,
        started_by TEXT
    )''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_maintenance_log_device ON maintenance_log(device_id, started_at)')
    # 2-5: 알림 에스컬레이션. escalation_tiers is the configured contact chain
    # (1차/2차/3차...); escalation_state tracks, per OPEN incident, how far
    # through that chain it's gotten so a repeat scheduler tick never
    # re-notifies a tier that already got this exact incident ("동일 장애의
    # 반복 에스컬레이션 방지") and never notifies past the end of the list.
    # escalation_log is purely for visibility ("확인 여부 기록"-adjacent --
    # distinct from the incident's own acknowledged_by/acknowledged_at,
    # which is the real "담당자가 실제로 확인했다" signal this ticket cares
    # about; a logged notify here only proves an email was *sent*).
    conn.execute('''CREATE TABLE IF NOT EXISTS escalation_tiers(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tier_order INTEGER NOT NULL,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        timeout_minutes INTEGER NOT NULL,
        enabled INTEGER DEFAULT 1,
        created_at INTEGER NOT NULL
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS escalation_state(
        incident_id INTEGER PRIMARY KEY,
        current_tier INTEGER NOT NULL DEFAULT 0,
        last_notified_at INTEGER,
        completed INTEGER DEFAULT 0
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS escalation_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id INTEGER NOT NULL,
        tier_order INTEGER NOT NULL,
        contact_name TEXT,
        email TEXT,
        notified_at INTEGER NOT NULL,
        ok INTEGER NOT NULL,
        error TEXT
    )''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_escalation_log_incident ON escalation_log(incident_id, notified_at)')
    # Kakao Method B (비즈니스 알림톡) -- unlike Method A's "나에게 보내기"
    # (one OAuth-connected account, no recipient concept), AlimTalk sends to
    # other people, so it needs its own recipient list -- same shape as
    # escalation_tiers (name + contact + enabled) but keyed on a phone
    # number instead of an email, and with no ordering/timeout concept.
    conn.execute('''CREATE TABLE IF NOT EXISTS kakao_biz_recipients(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT NOT NULL,
        enabled INTEGER DEFAULT 1,
        created_at INTEGER NOT NULL
    )''')
    # 5-1: recovery codes, one-way hashed exactly like hash_token() below --
    # see generate_recovery_codes()'s docstring.
    conn.execute('''CREATE TABLE IF NOT EXISTS totp_recovery_codes(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        code_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        used_at INTEGER
    )''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_totp_recovery_user ON totp_recovery_codes(user_id)')
    # 5-2: per-user API tokens. token_hash is the only form of the token
    # ever stored (hash_token(), same pattern as devices.token_hash) -- the
    # plaintext is generated, returned once in the create response, and
    # never persisted or logged anywhere. `scope` is a role name
    # (VIEWER/OPERATOR) compared via the same ROLE_RANK table require_role()
    # already uses for sessions, so a token is rank-checked identically to
    # a session without needing a parallel permission system.
    conn.execute('''CREATE TABLE IF NOT EXISTS api_tokens(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        scope TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER,
        last_used_at INTEGER,
        revoked_at INTEGER
    )''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(user_id)')
    # Lightweight call log, deliberately separate from audit_log -- a busy
    # API integration could call this far more often than any human-driven
    # audit event, and api_run_retention() below caps it the same way
    # metrics_raw gets rolled up/purged rather than kept forever.
    conn.execute('''CREATE TABLE IF NOT EXISTS api_token_usage(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token_id INTEGER NOT NULL,
        method TEXT NOT NULL,
        path TEXT NOT NULL,
        status_code INTEGER,
        ts INTEGER NOT NULL,
        source_ip TEXT
    )''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_api_token_usage_token ON api_token_usage(token_id, ts)')
    # 3-3: 정기 보고서 자동 발송. recipients is a JSON list of email
    # addresses (a schedule can have more than one, unlike the single
    # alert_to of the incident-alert SMTP path) -- device_id/group_name
    # mirror reports.py's own filter params, NULL meaning "전체 장비" same
    # as there.
    conn.execute('''CREATE TABLE IF NOT EXISTS report_schedules(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        frequency TEXT NOT NULL,
        report_type TEXT NOT NULL,
        format TEXT NOT NULL,
        device_id TEXT,
        group_name TEXT,
        recipients TEXT NOT NULL,
        enabled INTEGER DEFAULT 1,
        created_at INTEGER NOT NULL,
        created_by TEXT,
        last_run_at INTEGER,
        last_run_status TEXT
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS report_delivery_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        schedule_id INTEGER NOT NULL,
        run_at INTEGER NOT NULL,
        status TEXT NOT NULL,
        error TEXT,
        attempts INTEGER NOT NULL
    )''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_report_delivery_schedule ON report_delivery_log(schedule_id, run_at)')
    # 1-2: 장애 알림 이메일 발송 이력 -- 성공/실패 둘 다 매 시도마다 기록한다
    # (report_delivery_log와 동일한 구조/목적, 대상이 정기 보고서가 아니라
    # 개별 장애 알림이라는 점만 다르다). "알림 성공·실패 로그 저장" 요구사항의
    # 저장소.
    conn.execute('''CREATE TABLE IF NOT EXISTS email_alert_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER NOT NULL,
        severity TEXT NOT NULL,
        source TEXT NOT NULL,
        message TEXT NOT NULL,
        recipient TEXT NOT NULL,
        status TEXT NOT NULL,
        error TEXT,
        attempts INTEGER NOT NULL
    )''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_email_alert_log_ts ON email_alert_log(ts)')
    # 3-4: 외부 공개 상태 페이지. `label`/`description` are the ONLY text an
    # admin writes for public consumption -- device_id is resolved
    # server-side to compute live status, but is NEVER itself serialized
    # into a public API response (see collector/public_status.py's module
    # docstring for the full "공개 정보와 내부 정보 분리" policy). Nothing
    # is public by default -- `enabled` starts at 0, an admin must
    # deliberately opt each service in.
    conn.execute('''CREATE TABLE IF NOT EXISTS public_services(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        label TEXT NOT NULL,
        device_id TEXT NOT NULL,
        description TEXT,
        enabled INTEGER DEFAULT 0,
        display_order INTEGER NOT NULL,
        created_at INTEGER NOT NULL
    )''')
    # 장애 공지/복구 공지: deliberately a SEPARATE, operator-authored channel
    # from the internal incidents table -- an internal incident message can
    # contain details (SNMP error text, IP-adjacent hints, device internals)
    # that must never reach the public page, so nothing here is ever
    # auto-generated from storage.add_incident()'s own rows. service_id
    # NULL means a site-wide announcement (not tied to one service).
    conn.execute('''CREATE TABLE IF NOT EXISTS public_announcements(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        service_id INTEGER,
        title TEXT NOT NULL,
        body TEXT,
        status TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        created_by TEXT,
        resolved_at INTEGER
    )''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_public_announcements_created ON public_announcements(created_at)')
    conn.commit()
    conn.close()
    migrate_db()
    migrate_snmp_credentials()
    migrate_credential_encryption()
    migrate_token_hashes()


def migrate_db():
    """Additive-only migration: adds Phase 1/2 columns if missing. Never drops
    or renames anything, so existing rows (real registered devices, real
    incident history) survive."""
    conn = get_db()
    existing_devices = {r['name'] for r in conn.execute('PRAGMA table_info(devices)').fetchall()}
    for col_name, col_def in _NEW_DEVICE_COLUMNS:
        if col_name not in existing_devices:
            conn.execute(f'ALTER TABLE devices ADD COLUMN {col_name} {col_def}')
    existing_incidents = {r['name'] for r in conn.execute('PRAGMA table_info(incidents)').fetchall()}
    for col_name, col_def in _NEW_INCIDENT_COLUMNS:
        if col_name not in existing_incidents:
            conn.execute(f'ALTER TABLE incidents ADD COLUMN {col_name} {col_def}')
    existing_users = {r['name'] for r in conn.execute('PRAGMA table_info(users)').fetchall()}
    for col_name, col_def in _NEW_USER_COLUMNS:
        if col_name not in existing_users:
            conn.execute(f'ALTER TABLE users ADD COLUMN {col_name} {col_def}')
    # 2-2: per-group default thresholds, additive onto the 2-1 device_groups
    # table the same way as everywhere else in this function.
    existing_groups = {r['name'] for r in conn.execute('PRAGMA table_info(device_groups)').fetchall()}
    for col_name, col_def in _NEW_GROUP_COLUMNS:
        if col_name not in existing_groups:
            conn.execute(f'ALTER TABLE device_groups ADD COLUMN {col_name} {col_def}')
    conn.commit()
    conn.close()


def load_devices():
    conn = get_db()
    rows = conn.execute('SELECT * FROM devices ORDER BY created_at ASC').fetchall()
    conn.close()
    return [dict(r, fields=json.loads(r['fields'])) for r in rows]


def load_device(device_id):
    conn = get_db()
    row = conn.execute('SELECT * FROM devices WHERE id=?', (device_id,)).fetchone()
    conn.close()
    return dict(row, fields=json.loads(row['fields'])) if row else None


# ------------------------------------------------------------- 2-1 groups --
def load_device_groups():
    conn = get_db()
    rows = conn.execute('SELECT name,description,created_at,thresholds FROM device_groups ORDER BY name').fetchall()
    conn.close()
    out = []
    for r in rows:
        d = dict(r)
        d['thresholds'] = json.loads(d['thresholds']) if d['thresholds'] else None
        out.append(d)
    return out


def get_device_group(name):
    conn = get_db()
    row = conn.execute('SELECT name,description,created_at,thresholds FROM device_groups WHERE name=?', (name,)).fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    d['thresholds'] = json.loads(d['thresholds']) if d['thresholds'] else None
    return d


def set_device_group_thresholds(name, thresholds):
    """thresholds: a dict (validated by the caller) or None to clear the
    group's override and fall back to the global default again."""
    conn = get_db()
    conn.execute('UPDATE device_groups SET thresholds=? WHERE name=?',
                 (json.dumps(thresholds) if thresholds else None, name))
    conn.commit()
    conn.close()


def record_threshold_change(scope, scope_id, changed_by, old_value, new_value):
    """old_value/new_value: dicts (or None) -- stored as JSON text so the
    history reads back as exactly what was in effect before/after, not just
    "something changed"."""
    conn = get_db()
    conn.execute(
        'INSERT INTO threshold_history(scope,scope_id,changed_by,changed_at,old_value,new_value) VALUES (?,?,?,?,?,?)',
        (scope, scope_id, changed_by, int(time.time() * 1000),
         json.dumps(old_value) if old_value else None, json.dumps(new_value) if new_value else None))
    conn.commit()
    conn.close()


def load_threshold_history(scope=None, scope_id=None, limit=50):
    conn = get_db()
    q = 'SELECT * FROM threshold_history'
    conds, params = [], []
    if scope:
        conds.append('scope=?'); params.append(scope)
    if scope_id is not None:
        conds.append('scope_id=?'); params.append(scope_id)
    if conds:
        q += ' WHERE ' + ' AND '.join(conds)
    q += ' ORDER BY changed_at DESC LIMIT ?'
    params.append(limit)
    rows = conn.execute(q, params).fetchall()
    conn.close()
    out = []
    for r in rows:
        d = dict(r)
        d['old_value'] = json.loads(d['old_value']) if d['old_value'] else None
        d['new_value'] = json.loads(d['new_value']) if d['new_value'] else None
        out.append(d)
    return out


def create_device_group(name, description):
    conn = get_db()
    if conn.execute('SELECT 1 FROM device_groups WHERE name=?', (name,)).fetchone():
        conn.close()
        raise ValueError('이미 같은 이름의 그룹이 있습니다')
    conn.execute('INSERT INTO device_groups(name,description,created_at) VALUES (?,?,?)',
                 (name, description, int(time.time() * 1000)))
    conn.commit()
    conn.close()


def update_device_group_description(name, description):
    conn = get_db()
    conn.execute('UPDATE device_groups SET description=? WHERE name=?', (description, name))
    conn.commit()
    conn.close()


def rename_device_group(old_name, new_name):
    """Renames the catalog row (if one exists -- an ad-hoc group inferred
    purely from devices' own fields.group strings, never formally created,
    has none) and rewrites fields.group on every device that currently
    references old_name, since that reference is by name, not id. Returns
    the number of devices updated."""
    conn = get_db()
    if conn.execute('SELECT 1 FROM device_groups WHERE name=?', (new_name,)).fetchone():
        conn.close()
        raise ValueError('이미 같은 이름의 그룹이 있습니다')
    if conn.execute('SELECT 1 FROM device_groups WHERE name=?', (old_name,)).fetchone():
        conn.execute('UPDATE device_groups SET name=? WHERE name=?', (new_name, old_name))
    rows = conn.execute('SELECT id, fields FROM devices').fetchall()
    updated = 0
    for r in rows:
        fields = json.loads(r['fields'])
        if fields.get('group') == old_name:
            fields['group'] = new_name
            conn.execute('UPDATE devices SET fields=? WHERE id=?', (json.dumps(fields), r['id']))
            updated += 1
    conn.commit()
    conn.close()
    return updated


def count_devices_in_group(name):
    conn = get_db()
    rows = conn.execute('SELECT fields FROM devices').fetchall()
    conn.close()
    return sum(1 for r in rows if json.loads(r['fields']).get('group') == name)


def devices_in_group(name):
    """Full device rows (not just a count) for every device currently
    carrying fields.group == name -- same dynamic-membership resolution
    every other group feature in this app uses (collector/maintenance.py's
    resolve_target_device_ids, the group-threshold lookup, etc.), pulled out
    here so 3-1's SLA reports don't need to re-implement the same filter."""
    return [d for d in load_devices() if (d.get('fields') or {}).get('group') == name]


def delete_device_group(name):
    conn = get_db()
    conn.execute('DELETE FROM device_groups WHERE name=?', (name,))
    conn.commit()
    conn.close()


def update_failure_state(device_id, consecutive_failures, last_failure_reason, last_success_at,
                          last_collected_at, last_failure_at):
    """Called once per collection attempt (win or lose) by every sampler
    (ping/snmp/agent/local) and by the scheduler's own except-block on an
    unexpected collector error. last_collected_at is always "now"; the
    other four fields are the caller's already-computed win/lose state for
    this attempt (last_success_at/last_failure_at are each left as their
    previous value on the *other* outcome -- callers pass the row's current
    value through unchanged rather than this function guessing)."""
    conn = get_db()
    conn.execute(
        'UPDATE devices SET consecutive_failures=?, last_failure_reason=?, last_success_at=?, '
        'last_collected_at=?, last_failure_at=? WHERE id=?',
        (consecutive_failures, last_failure_reason, last_success_at, last_collected_at, last_failure_at, device_id))
    conn.commit()
    conn.close()


def update_agent_info(device_id, version, os_info, started_at, reported_ip, last_error):
    """Persists what an agent-mode device's own process last told us about
    itself (called from agent_collector.record_report on every incoming
    report) -- separate from update_failure_state's reachability bookkeeping
    above, since these describe the agent *process*, not the poll outcome."""
    conn = get_db()
    conn.execute(
        'UPDATE devices SET agent_version=?, agent_os=?, agent_started_at=?, agent_reported_ip=?, agent_last_error=? '
        'WHERE id=?',
        (version, os_info, started_at, reported_ip, last_error, device_id))
    conn.commit()
    conn.close()


# Agent management pass: the version this server can currently hand out via
# /download/agent and /download/installer/<token> -- keep in sync with
# agent.py's own AGENT_VERSION constant when bumping it and rebuilding
# dist/InfraSightAgent.exe. Exposed through /api/agent/info so the frontend
# can flag a device whose agentVersion (reported live, see above) doesn't
# match -- the version-comparison groundwork an eventual auto-update feature
# would need, without this pass implementing any actual update mechanism.
AGENT_VERSION = '1.3.0'


# Mirrors agent_collector.ONLINE_WINDOW_SEC / WARN_WINDOW_SEC. Duplicated
# (rather than imported) because collector.agent_collector imports storage,
# so importing it back here would be circular.
_AGENT_ONLINE_WINDOW_SEC = 15
_AGENT_WARN_WINDOW_SEC = 60


def compute_collection_state(device_row, warn_at=1, crit_at=2):
    """Derives the 5-value collection-health status (정상/주의/장애/미수집/알 수
    없음) from persisted fields alone, so it's always consistent with what
    the device list/drawer show and never drifts out of sync with a
    separately-cached value.

      good ('정상')     - responding normally
      warn ('주의')     - a few consecutive misses; likely transient, not yet
                          declared down (this is the buffer the packet-loss
                          requirement asked for)
      crit ('장애')     - misses have persisted past the threshold
      nodata ('미수집') - monitoring is off, or it has never been polled yet
      unknown ('알 수 없음') - the collector itself errored (a bug, a library
                          crash, ...) rather than getting a clean
                          reachable/unreachable answer

    warn_at/crit_at are consecutive-failure-count thresholds for ping/snmp/
    local; agent mode instead reuses its own existing time-window constants
    (report freshness, not poll count) since it's push- not poll-based.
    """
    if not device_row.get('monitoring_enabled', 1):
        return 'nodata'
    reason = device_row.get('last_failure_reason') or ''
    failures = device_row.get('consecutive_failures') or 0
    if failures > 0 and reason.startswith('COLLECTOR_ERROR'):
        return 'unknown'
    if device_row.get('mode') == 'agent':
        last_success = device_row.get('last_success_at')
        if not last_success:
            return 'nodata'
        age_sec = (time.time() * 1000 - last_success) / 1000.0
        if age_sec <= _AGENT_ONLINE_WINDOW_SEC:
            return 'good'
        return 'crit' if age_sec > _AGENT_WARN_WINDOW_SEC else 'warn'
    if not device_row.get('last_collected_at'):
        return 'nodata'
    if failures <= 0:
        return 'good'
    return 'crit' if failures >= crit_at else 'warn' if failures >= warn_at else 'good'


def add_incident(severity, source, category, message, device_id=None, event_type=None, _no_alert=False, maintenance=False):
    """Records an event.

    Phase 2 upgrade: when device_id+event_type are given, this folds repeated
    occurrences of the *same* problem on the *same* device into one row
    (occurrence_count++, last_occurred_at refreshed) instead of spawning a new
    row every poll -- this is what section 10/11 of the directive calls
    "event dedup". A recovery ('info' severity) closes out any still-open row
    for that device_id+event_type (status -> 'resolved', resolved_at set) --
    this is the "Recovery" behavior for Phase 2: without it, a device that
    goes crit -> good never leaves the "미해결" (unresolved) count on the
    dashboard, which was confirmed as a real gap while planning this phase.

    Call sites that don't pass device_id/event_type (e.g. device registration)
    keep the exact old behavior: always a new row, status derived from
    severity alone.

    Phase 4: fires an email alert (if configured) exactly when this call
    creates a brand-new open incident or escalates an existing one's
    severity -- never on a mere occurrence_count bump, so a device stuck
    flapping at the same severity doesn't spam an inbox once per poll.
    _no_alert is only for the alert engine's own failure-notice message, to
    avoid alerting about "alert failed" in a loop if SMTP is broken.

    2-3 fix: maintenance used to mean every caller skipped this function
    entirely (`if not storage.in_maintenance(...): add_incident(...)`), which
    conflated "don't page anyone about this" with "this never happened" --
    a real failure during a maintenance window left literally no record
    anywhere, contradicting the ticket's own "점검 중 실제 장애 발생 시 이벤트
    기록 유지" requirement. Now every caller always calls this (passing
    maintenance=storage.in_maintenance(device_row) instead of guarding the
    call), and only the alert dispatch is skipped here -- the incident row
    itself, dedup, and occurrence counting all behave exactly as outside
    maintenance, just tagged during_maintenance=1 so the UI can tell the two
    apart without hiding either.
    """
    now = int(time.time() * 1000)
    is_new_or_escalated = False
    recovered_something = False
    conn = get_db()
    try:
        if device_id and event_type and severity != 'info':
            existing = conn.execute(
                "SELECT id, severity FROM incidents WHERE device_id=? AND event_type=? AND status='open' ORDER BY id DESC LIMIT 1",
                (device_id, event_type)).fetchone()
            if existing:
                is_new_or_escalated = existing['severity'] != severity
                conn.execute(
                    'UPDATE incidents SET severity=?, message=?, last_occurred_at=?, occurrence_count=occurrence_count+1, during_maintenance=? WHERE id=?',
                    (severity, message, now, 1 if maintenance else 0, existing['id']))
            else:
                is_new_or_escalated = True
                conn.execute(
                    'INSERT INTO incidents(ts,severity,source,category,message,status,device_id,event_type,'
                    'first_occurred_at,last_occurred_at,occurrence_count,during_maintenance) VALUES (?,?,?,?,?,?,?,?,?,?,1,?)',
                    (now, severity, source, category, message, 'open', device_id, event_type, now, now, 1 if maintenance else 0))
        else:
            status = 'resolved' if severity == 'info' else 'open'
            is_new_or_escalated = status == 'open'
            conn.execute(
                'INSERT INTO incidents(ts,severity,source,category,message,status,device_id,event_type,'
                'first_occurred_at,last_occurred_at,resolved_at,occurrence_count,during_maintenance) VALUES (?,?,?,?,?,?,?,?,?,?,?,1,?)',
                (now, severity, source, category, message, status, device_id, event_type,
                 now, now, now if status == 'resolved' else None, 1 if maintenance else 0))
            if device_id and event_type and severity == 'info':
                cur = conn.execute(
                    "UPDATE incidents SET status='resolved', resolved_at=? WHERE device_id=? AND event_type=? AND status='open'",
                    (now, device_id, event_type))
                # Only a *real* recovery -- this device/event actually had an
                # open incident that just got closed -- should notify, not
                # every 'info' call (device registration also goes through
                # this branch with no open incident to close).
                recovered_something = cur.rowcount > 0
        conn.commit()
    finally:
        conn.close()

    # Alert suppression (not detection) is what maintenance mode actually
    # means -- see the docstring above. The row above was written exactly as
    # it would be outside maintenance; only the page/email/webhook is held
    # back here.
    if is_new_or_escalated and not _no_alert and not maintenance:
        _dispatch_alert(severity, source, message)
    elif recovered_something and not _no_alert and not maintenance:
        _dispatch_alert(severity, source, message, force=True)


def ack_incident(incident_id, acknowledged_by=None):
    now = int(time.time() * 1000)
    conn = get_db()
    conn.execute(
        "UPDATE incidents SET status='ack', acknowledged_by=?, acknowledged_at=? WHERE id=? AND status='open'",
        (acknowledged_by, now, incident_id))
    conn.commit()
    conn.close()


# ------------------------------------------------------------------- 2-5 --
# 알림 에스컬레이션: configured contact tiers + per-incident progress through
# them. Notification delivery itself (collector/escalation.py's tick()) only
# ever uses the email channel -- see that module's docstring for why a named
# 담당자 maps naturally to a personal email address where Slack/Teams (team
# channels, not individuals) don't.

def get_escalation_settings_public():
    return {
        'enabled': get_setting('escalation_enabled') == '1',
        'minSeverity': get_setting('escalation_min_severity', 'crit'),
    }


def set_escalation_settings(enabled, min_severity):
    set_setting('escalation_enabled', '1' if enabled else '0')
    set_setting('escalation_min_severity', min_severity)


def create_escalation_tier(name, email, timeout_minutes):
    conn = get_db()
    row = conn.execute('SELECT COALESCE(MAX(tier_order),0)+1 AS n FROM escalation_tiers').fetchone()
    tier_order = row['n']
    now = int(time.time() * 1000)
    cur = conn.execute(
        'INSERT INTO escalation_tiers(tier_order,name,email,timeout_minutes,enabled,created_at) VALUES (?,?,?,?,1,?)',
        (tier_order, name, email, timeout_minutes, now))
    tier_id = cur.lastrowid
    conn.commit()
    conn.close()
    return tier_id


def load_escalation_tiers():
    conn = get_db()
    rows = conn.execute('SELECT * FROM escalation_tiers ORDER BY tier_order').fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_escalation_tier(tier_id, name=None, email=None, timeout_minutes=None, enabled=None):
    conn = get_db()
    row = conn.execute('SELECT * FROM escalation_tiers WHERE id=?', (tier_id,)).fetchone()
    if not row:
        conn.close()
        return False
    d = dict(row)
    conn.execute(
        'UPDATE escalation_tiers SET name=?, email=?, timeout_minutes=?, enabled=? WHERE id=?',
        (name if name is not None else d['name'], email if email is not None else d['email'],
         timeout_minutes if timeout_minutes is not None else d['timeout_minutes'],
         1 if enabled else 0 if enabled is not None else d['enabled'], tier_id))
    conn.commit()
    conn.close()
    return True


def delete_escalation_tier(tier_id):
    conn = get_db()
    conn.execute('DELETE FROM escalation_tiers WHERE id=?', (tier_id,))
    conn.commit()
    conn.close()


def load_open_incidents():
    conn = get_db()
    rows = conn.execute("SELECT * FROM incidents WHERE status='open'").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_escalation_state(incident_id):
    conn = get_db()
    row = conn.execute('SELECT * FROM escalation_state WHERE incident_id=?', (incident_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def upsert_escalation_state(incident_id, current_tier, last_notified_at, completed):
    conn = get_db()
    conn.execute(
        'INSERT INTO escalation_state(incident_id,current_tier,last_notified_at,completed) VALUES (?,?,?,?) '
        'ON CONFLICT(incident_id) DO UPDATE SET current_tier=excluded.current_tier, '
        'last_notified_at=excluded.last_notified_at, completed=excluded.completed',
        (incident_id, current_tier, last_notified_at, 1 if completed else 0))
    conn.commit()
    conn.close()


def record_escalation_notify(incident_id, tier_order, contact_name, email, ok, error):
    conn = get_db()
    conn.execute(
        'INSERT INTO escalation_log(incident_id,tier_order,contact_name,email,notified_at,ok,error) VALUES (?,?,?,?,?,?,?)',
        (incident_id, tier_order, contact_name, email, int(time.time() * 1000), 1 if ok else 0, error))
    conn.commit()
    conn.close()


def load_escalation_log(incident_id=None, limit=50):
    conn = get_db()
    q = 'SELECT * FROM escalation_log'
    params = []
    if incident_id is not None:
        q += ' WHERE incident_id=?'
        params.append(incident_id)
    q += ' ORDER BY notified_at DESC LIMIT ?'
    params.append(limit)
    rows = conn.execute(q, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def in_maintenance(device_row):
    """True if this device's incidents should go out tagged during_maintenance
    (and their alert held back) right now. Polling and incident *recording*
    are never skipped because of this -- see add_incident()'s docstring; this
    flag only ever reaches a suppression decision, never a detection one."""
    if not device_row.get('maintenance_enabled'):
        return False
    now = int(time.time() * 1000)
    start = device_row.get('maintenance_start')
    end = device_row.get('maintenance_end')
    if start and now < start:
        return False
    if end and now > end:
        return False
    return True


def set_maintenance(device_id, enabled, start=None, end=None, reason=None, window_id=None, started_by=None):
    """The single place devices.maintenance_* actually changes -- used both
    by the manual drawer toggle (window_id=None) and by collector/
    maintenance.py's scheduler tick (window_id=that window's id). Always
    clears maintenance_window_id on enabled=False (and on a manual
    enabled=True, since window_id=None there) so a device's current
    maintenance_window_id reliably answers "is a schedule, not a person,
    responsible for this right now" -- see the column's own comment above
    _NEW_DEVICE_COLUMNS for why that distinction exists.

    2-3: every call now also writes a maintenance_log row (enabled=True opens
    one, enabled=False closes the most recent still-open one for this
    device) -- "점검 이력 기록", covering manual toggles the same as scheduled
    windows rather than only the latter.
    """
    conn = get_db()
    conn.execute(
        'UPDATE devices SET maintenance_enabled=?, maintenance_start=?, maintenance_end=?, maintenance_reason=?, maintenance_window_id=? WHERE id=?',
        (1 if enabled else 0, start, end, reason, window_id, device_id))
    now = int(time.time() * 1000)
    if enabled:
        conn.execute(
            'INSERT INTO maintenance_log(device_id,window_id,reason,started_at,started_by) VALUES (?,?,?,?,?)',
            (device_id, window_id, reason, now, started_by))
    else:
        conn.execute(
            'UPDATE maintenance_log SET ended_at=? WHERE id=(SELECT id FROM maintenance_log WHERE device_id=? AND ended_at IS NULL ORDER BY id DESC LIMIT 1)',
            (now, device_id))
    conn.commit()
    conn.close()


def load_maintenance_log(device_id=None, limit=50):
    conn = get_db()
    q = 'SELECT * FROM maintenance_log'
    params = []
    if device_id:
        q += ' WHERE device_id=?'
        params.append(device_id)
    q += ' ORDER BY started_at DESC LIMIT ?'
    params.append(limit)
    rows = conn.execute(q, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def load_maintenance_log_range(device_id, start_ms, end_ms):
    """Every maintenance_log row for this device whose [started_at, ended_at)
    overlaps [start_ms, end_ms) -- unlike load_maintenance_log() above (a
    recent-history list for the UI, capped at 50 rows), this is for 3-1's
    uptime calculation, which needs a complete, date-range-scoped set
    regardless of how many maintenance periods happened. A still-open period
    (ended_at IS NULL) is treated as ongoing through end_ms for overlap
    purposes -- it hasn't ended yet, so it covers up to "now"/the report's
    own end, whichever the caller clips to."""
    conn = get_db()
    rows = conn.execute(
        'SELECT * FROM maintenance_log WHERE device_id=? AND started_at<? AND (ended_at IS NULL OR ended_at>?) '
        'ORDER BY started_at',
        (device_id, end_ms, start_ms)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def load_incidents_in_range(device_id, event_types, start_ms, end_ms):
    """Every incident row for this device whose [first_occurred_at,
    resolved_at) overlaps [start_ms, end_ms), restricted to event_types
    (e.g. ['REACHABILITY'] for downtime, ['COLLECTION_ERROR'] for collection
    gaps -- see collector/sla.py). A still-open incident (resolved_at IS
    NULL) is treated as ongoing through end_ms, same reasoning as the
    maintenance-log range query above."""
    conn = get_db()
    placeholders = ','.join('?' * len(event_types))
    rows = conn.execute(
        f'SELECT * FROM incidents WHERE device_id=? AND event_type IN ({placeholders}) '
        f'AND first_occurred_at IS NOT NULL AND first_occurred_at<? AND (resolved_at IS NULL OR resolved_at>?) '
        f'ORDER BY first_occurred_at',
        (device_id, *event_types, end_ms, start_ms)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_sla_settings_public():
    return {
        # Which REACHABILITY incident severities count as real downtime for
        # uptime% -- default both, since this app's reachability smoothing
        # (collector/state.py's evaluate_status) already only escalates to
        # 'warn' after a real consecutive-failure streak, not a single
        # blip, so a 'warn'-only reachability incident is still a
        # meaningful outage, not noise.
        'downtimeSeverities': (get_setting('sla_downtime_severities') or 'warn,crit').split(','),
    }


def set_sla_settings(downtime_severities):
    set_setting('sla_downtime_severities', ','.join(downtime_severities))


# ------------------------------------------------------------------- 2-3 --
# 점검창 자동화: schedule definitions that drive devices.maintenance_* above
# automatically (collector/maintenance.py's tick()), on top of the existing
# manual per-device toggle rather than replacing it.

def create_maintenance_window(scope, scope_id, kind, start_at, end_at, weekday, start_time, end_time, reason, created_by):
    conn = get_db()
    now = int(time.time() * 1000)
    cur = conn.execute(
        'INSERT INTO maintenance_windows(scope,scope_id,kind,start_at,end_at,weekday,start_time,end_time,reason,enabled,created_by,created_at) '
        'VALUES (?,?,?,?,?,?,?,?,?,1,?,?)',
        (scope, scope_id, kind, start_at, end_at, weekday, start_time, end_time, reason, created_by, now))
    window_id = cur.lastrowid
    conn.commit()
    conn.close()
    return window_id


def load_maintenance_windows():
    conn = get_db()
    rows = conn.execute('SELECT * FROM maintenance_windows ORDER BY created_at DESC').fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_maintenance_window(window_id):
    conn = get_db()
    row = conn.execute('SELECT * FROM maintenance_windows WHERE id=?', (window_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def set_maintenance_window_enabled(window_id, enabled):
    conn = get_db()
    conn.execute('UPDATE maintenance_windows SET enabled=? WHERE id=?', (1 if enabled else 0, window_id))
    conn.commit()
    conn.close()


def delete_maintenance_window(window_id):
    conn = get_db()
    conn.execute('DELETE FROM maintenance_windows WHERE id=?', (window_id,))
    conn.commit()
    conn.close()


def devices_owned_by_window(window_id):
    """Devices currently in maintenance because of this specific window --
    used when deleting/disabling a window so it doesn't leave a device stuck
    'in maintenance' forever with nothing left to ever turn it back off."""
    conn = get_db()
    rows = conn.execute('SELECT * FROM devices WHERE maintenance_window_id=?', (window_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def category_label(cat):
    return {'server': 'SMS', 'db': 'DBMS', 'net': 'NMS', 'fac': 'FMS'}.get(cat, cat)


# --------------------------------------------------------------- Phase 3 --
# Login (originally single-admin only; Security Hardening Phase B added
# ADMIN/OPERATOR/VIEWER roles, account lockout, and session_version), an
# audit trail for every authenticated action, and moving SNMP community
# strings out of devices.fields (a plain JSON blob) into a dedicated table.

def create_admin_if_missing(username, password, must_change_password=False):
    """Only ever creates the very first account. Never overwrites an existing
    password on restart -- if an admin already exists, this is a no-op, so a
    password the user has since changed is never silently reset back.

    must_change_password=True is what install.ps1 uses for the installer's
    admin/admin default: the account works immediately, but every login
    (and every restored session -- see server.py's /api/auth/me) is routed
    through a forced password-change screen until it's cleared, which
    change_password() does as soon as a new password is actually set."""
    conn = get_db()
    row = conn.execute('SELECT id FROM users LIMIT 1').fetchone()
    if row:
        conn.close()
        return False
    conn.execute(
        'INSERT INTO users(username,password_hash,role,created_at,must_change_password) VALUES (?,?,?,?,?)',
        (username, generate_password_hash(password, method='scrypt'), 'ADMIN', int(time.time() * 1000),
         1 if must_change_password else 0))
    conn.commit()
    conn.close()
    return True


_DUMMY_HASH = generate_password_hash('not-a-real-password-just-for-timing', method='scrypt')


def verify_login(username, password):
    """Returns {'status': 'ok', username, role, session_version} on success,
    or {'status': 'locked'|'invalid', ...}. Never raises on a bad/missing
    username -- a nonexistent account still runs a (dummy) hash check so the
    response time doesn't reveal which usernames exist."""
    conn = get_db()
    row = conn.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
    now = int(time.time() * 1000)
    if not row:
        check_password_hash(_DUMMY_HASH, password)
        conn.close()
        return {'status': 'invalid'}
    if not row['is_active']:
        conn.close()
        return {'status': 'disabled'}
    if row['locked_until'] and row['locked_until'] > now:
        conn.close()
        return {'status': 'locked', 'locked_until': row['locked_until']}
    if not check_password_hash(row['password_hash'], password):
        attempts = (row['failed_attempts'] or 0) + 1
        newly_locked = attempts >= MAX_FAILED_ATTEMPTS
        locked_until = now + LOCK_MINUTES * 60 * 1000 if newly_locked else None
        conn.execute(
            'UPDATE users SET failed_attempts=?, locked_until=? WHERE username=?',
            (0 if newly_locked else attempts, locked_until, username))
        conn.commit()
        conn.close()
        return {'status': 'locked' if newly_locked else 'invalid', 'locked_until': locked_until}
    conn.execute(
        'UPDATE users SET failed_attempts=0, locked_until=NULL, last_login_at=? WHERE username=?',
        (now, username))
    conn.commit()
    session_version = row['session_version'] or 0
    conn.close()
    return {'status': 'ok', 'user_id': row['id'], 'username': row['username'], 'role': row['role'],
            'session_version': session_version, 'must_change_password': bool(row['must_change_password']),
            'totp_enabled': bool(row['totp_enabled'])}


def get_session_version(username):
    conn = get_db()
    row = conn.execute('SELECT session_version FROM users WHERE username=?', (username,)).fetchone()
    conn.close()
    return row['session_version'] if row else None


def bump_session_version(username):
    """Invalidates every existing session cookie for this user (logout,
    password change) -- the next request bearing an old cookie will find its
    embedded session_version no longer matches and get treated as logged out."""
    conn = get_db()
    conn.execute('UPDATE users SET session_version=session_version+1 WHERE username=?', (username,))
    conn.commit()
    conn.close()


def change_password(username, current_password, new_password):
    conn = get_db()
    row = conn.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
    if not row or not check_password_hash(row['password_hash'], current_password):
        conn.close()
        return False
    conn.execute(
        'UPDATE users SET password_hash=?, session_version=session_version+1, must_change_password=0 WHERE username=?',
        (generate_password_hash(new_password, method='scrypt'), username))
    conn.commit()
    conn.close()
    return True


def get_must_change_password(username):
    if not username:
        return False
    conn = get_db()
    row = conn.execute('SELECT must_change_password FROM users WHERE username=?', (username,)).fetchone()
    conn.close()
    return bool(row['must_change_password']) if row else False


# ------------------------------------------------------------------- 5-1 --
# 2FA (TOTP). The secret itself lives in the `credentials` table (encrypted,
# keyed 'user:<id>'/'totp_secret' during enrollment, 'totp_secret_pending'
# while a QR has been shown but not yet confirmed with a code -- see
# server.py's enroll/confirm endpoints) rather than a users column, reusing
# the exact mechanism already used for SMTP/webhook secrets. Everything
# here is the bookkeeping around that: enabled flag, lockout, recovery
# codes.

TOTP_MAX_FAILED_ATTEMPTS = 5
TOTP_LOCK_MINUTES = 10


def get_user_totp_enabled(user_id):
    conn = get_db()
    row = conn.execute('SELECT totp_enabled FROM users WHERE id=?', (user_id,)).fetchone()
    conn.close()
    return bool(row['totp_enabled']) if row else False


def set_user_totp_enabled(user_id, enabled):
    conn = get_db()
    conn.execute(
        'UPDATE users SET totp_enabled=?, totp_enrolled_at=? WHERE id=?',
        (1 if enabled else 0, int(time.time() * 1000) if enabled else None, user_id))
    conn.commit()
    conn.close()


def totp_lockout_state(user_id):
    conn = get_db()
    row = conn.execute('SELECT totp_failed_attempts, totp_locked_until FROM users WHERE id=?', (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else {'totp_failed_attempts': 0, 'totp_locked_until': None}


def record_totp_failure(user_id):
    """Same shape as verify_login()'s password lockout -- separate counter,
    see _NEW_USER_COLUMNS' comment on why TOTP gets its own budget."""
    conn = get_db()
    row = conn.execute('SELECT totp_failed_attempts FROM users WHERE id=?', (user_id,)).fetchone()
    attempts = ((row['totp_failed_attempts'] or 0) if row else 0) + 1
    now = int(time.time() * 1000)
    newly_locked = attempts >= TOTP_MAX_FAILED_ATTEMPTS
    locked_until = now + TOTP_LOCK_MINUTES * 60 * 1000 if newly_locked else None
    conn.execute(
        'UPDATE users SET totp_failed_attempts=?, totp_locked_until=? WHERE id=?',
        (0 if newly_locked else attempts, locked_until, user_id))
    conn.commit()
    conn.close()
    return locked_until


def clear_totp_failures(user_id):
    conn = get_db()
    conn.execute('UPDATE users SET totp_failed_attempts=0, totp_locked_until=NULL WHERE id=?', (user_id,))
    conn.commit()
    conn.close()


def disable_totp(user_id):
    """Used by both self-service disable and an admin-initiated reset
    (server.py's /api/users/<id>/totp/reset) -- wipes the secret, every
    recovery code, and the enabled flag so the next enrollment starts
    completely clean rather than layering a new secret over stale state."""
    delete_credential(f'user:{user_id}', 'totp_secret')
    delete_credential(f'user:{user_id}', 'totp_secret_pending')
    conn = get_db()
    conn.execute('DELETE FROM totp_recovery_codes WHERE user_id=?', (user_id,))
    conn.execute(
        'UPDATE users SET totp_enabled=0, totp_enrolled_at=NULL, totp_failed_attempts=0, totp_locked_until=NULL WHERE id=?',
        (user_id,))
    conn.commit()
    conn.close()


def generate_recovery_codes(user_id, count=10):
    """Returns the PLAINTEXT codes (shown to the user exactly once, same
    policy as an API token) -- only their SHA-256 hash is stored, same
    one-way pattern as hash_token()/device agent tokens, since a recovery
    code is also full-entropy random with nothing for a slow KDF to protect.
    Replaces any existing unused codes outright (re-generating implies the
    old set should no longer work)."""
    conn = get_db()
    conn.execute('DELETE FROM totp_recovery_codes WHERE user_id=?', (user_id,))
    now = int(time.time() * 1000)
    codes = []
    for _ in range(count):
        # Grouped like XXXX-XXXX for readability when written down --
        # secrets.token_hex(5) is 10 hex chars, split 5/5.
        raw = secrets.token_hex(5).upper()
        code = f'{raw[:5]}-{raw[5:]}'
        codes.append(code)
        conn.execute(
            'INSERT INTO totp_recovery_codes(user_id,code_hash,created_at) VALUES (?,?,?)',
            (user_id, hash_token(code), now))
    conn.commit()
    conn.close()
    return codes


def count_unused_recovery_codes(user_id):
    conn = get_db()
    n = conn.execute('SELECT COUNT(*) c FROM totp_recovery_codes WHERE user_id=? AND used_at IS NULL', (user_id,)).fetchone()['c']
    conn.close()
    return n


def consume_recovery_code(user_id, code):
    """Atomically checks-and-burns a recovery code -- returns True exactly
    once per code. Matches by hash, same as an API token/device token, so
    the plaintext code is never compared or stored anywhere after this."""
    conn = get_db()
    code_hash = hash_token((code or '').strip().upper())
    row = conn.execute(
        'SELECT id FROM totp_recovery_codes WHERE user_id=? AND code_hash=? AND used_at IS NULL',
        (user_id, code_hash)).fetchone()
    if not row:
        conn.close()
        return False
    conn.execute('UPDATE totp_recovery_codes SET used_at=? WHERE id=?', (int(time.time() * 1000), row['id']))
    conn.commit()
    conn.close()
    return True


# ------------------------------------------------------------------- 5-2 --
# API tokens. See api_tokens' CREATE TABLE comment in init_db() for the
# storage shape/reasoning; these are the CRUD + verification functions.

def create_api_token(user_id, name, scope, expires_at):
    """Returns (token_id, plaintext_token) -- the plaintext is never stored
    or returned again after this call, same one-time-reveal contract as
    recovery codes and the original device-agent token."""
    token = secrets.token_urlsafe(32)
    conn = get_db()
    now = int(time.time() * 1000)
    cur = conn.execute(
        'INSERT INTO api_tokens(user_id,name,token_hash,scope,created_at,expires_at) VALUES (?,?,?,?,?,?)',
        (user_id, name, hash_token(token), scope, now, expires_at))
    token_id = cur.lastrowid
    conn.commit()
    conn.close()
    return token_id, token


def find_api_token(token):
    """Looks up a token by its hash for request authentication -- returns
    None for anything that doesn't verify (unknown, revoked, expired) so
    the caller (require_role()) doesn't have to re-derive those checks.
    Joins in the owning username/role for audit logging and for capping a
    token's scope at its owner's current role (a demoted user's
    already-issued OPERATOR token shouldn't silently keep OPERATOR access)."""
    conn = get_db()
    row = conn.execute(
        'SELECT api_tokens.*, users.username AS owner_username, users.role AS owner_role, users.is_active AS owner_active '
        'FROM api_tokens JOIN users ON users.id = api_tokens.user_id WHERE token_hash=?',
        (hash_token(token),)).fetchone()
    conn.close()
    if not row:
        return None
    row = dict(row)
    if row['revoked_at']:
        return None
    if row['expires_at'] and row['expires_at'] < int(time.time() * 1000):
        return None
    if not row['owner_active']:
        return None
    if ROLE_RANK.get(row['scope'], 0) > ROLE_RANK.get(row['owner_role'], 0):
        row['scope'] = row['owner_role']
    return row


def touch_api_token_last_used(token_id):
    conn = get_db()
    conn.execute('UPDATE api_tokens SET last_used_at=? WHERE id=?', (int(time.time() * 1000), token_id))
    conn.commit()
    conn.close()


def list_api_tokens(user_id=None):
    conn = get_db()
    q = ('SELECT api_tokens.id,api_tokens.user_id,api_tokens.name,api_tokens.scope,api_tokens.created_at,'
         'api_tokens.expires_at,api_tokens.last_used_at,api_tokens.revoked_at,users.username AS owner_username '
         'FROM api_tokens JOIN users ON users.id = api_tokens.user_id')
    params = []
    if user_id is not None:
        q += ' WHERE api_tokens.user_id=?'
        params.append(user_id)
    q += ' ORDER BY api_tokens.created_at DESC'
    rows = conn.execute(q, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_api_token(token_id):
    conn = get_db()
    row = conn.execute('SELECT * FROM api_tokens WHERE id=?', (token_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def revoke_api_token(token_id):
    conn = get_db()
    conn.execute('UPDATE api_tokens SET revoked_at=? WHERE id=? AND revoked_at IS NULL', (int(time.time() * 1000), token_id))
    conn.commit()
    conn.close()


def record_api_token_usage(token_id, method, path, status_code, source_ip):
    conn = get_db()
    conn.execute(
        'INSERT INTO api_token_usage(token_id,method,path,status_code,ts,source_ip) VALUES (?,?,?,?,?,?)',
        (token_id, method, path, status_code, int(time.time() * 1000), source_ip))
    conn.commit()
    conn.close()


def load_api_token_usage(token_id=None, limit=50):
    conn = get_db()
    q = 'SELECT * FROM api_token_usage'
    params = []
    if token_id is not None:
        q += ' WHERE token_id=?'
        params.append(token_id)
    q += ' ORDER BY ts DESC LIMIT ?'
    params.append(limit)
    rows = conn.execute(q, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


API_TOKEN_USAGE_RETENTION_DAYS = 30


def run_api_token_usage_retention():
    cutoff = int(time.time() * 1000) - API_TOKEN_USAGE_RETENTION_DAYS * 86400 * 1000
    conn = get_db()
    conn.execute('DELETE FROM api_token_usage WHERE ts < ?', (cutoff,))
    conn.commit()
    conn.close()


def create_user(username, password, role):
    if role not in ROLES:
        raise ValueError('invalid role')
    conn = get_db()
    if conn.execute('SELECT 1 FROM users WHERE username=?', (username,)).fetchone():
        conn.close()
        raise ValueError('username already exists')
    conn.execute(
        'INSERT INTO users(username,password_hash,role,created_at) VALUES (?,?,?,?)',
        (username, generate_password_hash(password, method='scrypt'), role, int(time.time() * 1000)))
    conn.commit()
    conn.close()


def list_users():
    conn = get_db()
    rows = conn.execute(
        'SELECT id,username,role,created_at,last_login_at,locked_until,is_active,totp_enabled FROM users ORDER BY id'
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def count_active_admins():
    conn = get_db()
    n = conn.execute("SELECT COUNT(*) c FROM users WHERE role='ADMIN' AND is_active=1").fetchone()['c']
    conn.close()
    return n


def set_user_active(user_id, active):
    """Deactivating bumps session_version, same reasoning as a role
    downgrade or forced password reset above -- an already-open session
    shouldn't be able to outlive the account being turned off."""
    conn = get_db()
    conn.execute('UPDATE users SET is_active=?, session_version=session_version+1 WHERE id=?',
                 (1 if active else 0, user_id))
    conn.commit()
    conn.close()


def get_user_by_id(user_id):
    conn = get_db()
    row = conn.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_username(username):
    conn = get_db()
    row = conn.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


def count_admins():
    conn = get_db()
    n = conn.execute("SELECT COUNT(*) c FROM users WHERE role='ADMIN'").fetchone()['c']
    conn.close()
    return n


def delete_user(user_id):
    conn = get_db()
    conn.execute('DELETE FROM users WHERE id=?', (user_id,))
    conn.commit()
    conn.close()


def update_user(user_id, role=None, new_password=None):
    """Admin-initiated edit of another account's role and/or password (the
    account's own self-service change_password() above is separate and
    still requires the current password). Bumps session_version on either
    change so a role downgrade or a forced password reset can't be
    outlived by a session someone's already holding."""
    conn = get_db()
    if role:
        conn.execute('UPDATE users SET role=?, session_version=session_version+1 WHERE id=?', (role, user_id))
    if new_password:
        conn.execute('UPDATE users SET password_hash=?, session_version=session_version+1 WHERE id=?',
                     (generate_password_hash(new_password, method='scrypt'), user_id))
    conn.commit()
    conn.close()


def unlock_user(username):
    conn = get_db()
    conn.execute('UPDATE users SET failed_attempts=0, locked_until=NULL WHERE username=?', (username,))
    conn.commit()
    conn.close()


def write_audit(username, action, target=None, details=None, source_ip=None):
    conn = get_db()
    conn.execute(
        'INSERT INTO audit_log(username,action,target,ts,source_ip,details) VALUES (?,?,?,?,?,?)',
        (username, action, target, int(time.time() * 1000), source_ip, details))
    conn.commit()
    conn.close()
    # Security hardening Phase F: a redundant file trail alongside the DB
    # row, so the security history survives even if infrasight.db itself is
    # ever unavailable/corrupted, and is greppable without a DB client. Local
    # import to keep applog.py dependency-free of storage (no cycle either
    # way) and to avoid paying import cost for callers that never audit.
    from applog import security_logger, safe_log_value
    security_logger.info(
        'user=%s action=%s target=%s ip=%s details=%s',
        safe_log_value(username), safe_log_value(action), safe_log_value(target),
        safe_log_value(source_ip), safe_log_value(details))


def get_credential(device_id, cred_type):
    """Transparently decrypts (directive section 9/31) -- every caller
    (snmp_collector, the SMTP alert dispatcher) just gets the plaintext back
    and never has to know the value is encrypted in the DB."""
    conn = get_db()
    row = conn.execute('SELECT secret FROM credentials WHERE device_id=? AND type=?', (device_id, cred_type)).fetchone()
    conn.close()
    if not row:
        return None
    return secrets_crypto.decrypt(row['secret'])


def set_credential(device_id, cred_type, secret):
    if secret is None:
        return
    conn = get_db()
    conn.execute(
        'INSERT INTO credentials(device_id,type,secret) VALUES (?,?,?) '
        'ON CONFLICT(device_id,type) DO UPDATE SET secret=excluded.secret',
        (device_id, cred_type, secrets_crypto.encrypt(secret)))
    conn.commit()
    conn.close()


def delete_credential(device_id, cred_type):
    """Single-key delete, unlike delete_credentials() (plural) which wipes
    every credential for a device_id -- needed for 5-1's enrollment flow to
    discard a pending/unused TOTP secret without touching anything else."""
    conn = get_db()
    conn.execute('DELETE FROM credentials WHERE device_id=? AND type=?', (device_id, cred_type))
    conn.commit()
    conn.close()


def migrate_credential_encryption():
    """One-time upgrade: encrypts any credential still sitting in the table
    as plaintext from before Phase C. Safe to run every startup -- a value
    that's already a valid Fernet token is left alone (is_encrypted), so this
    never double-encrypts."""
    conn = get_db()
    rows = conn.execute('SELECT device_id, type, secret FROM credentials').fetchall()
    for r in rows:
        if r['secret'] and not secrets_crypto.is_encrypted(r['secret']):
            conn.execute(
                'UPDATE credentials SET secret=? WHERE device_id=? AND type=?',
                (secrets_crypto.encrypt(r['secret']), r['device_id'], r['type']))
    conn.commit()
    conn.close()


def delete_credentials(device_id):
    conn = get_db()
    conn.execute('DELETE FROM credentials WHERE device_id=?', (device_id,))
    conn.commit()
    conn.close()


def migrate_snmp_credentials():
    """One-time move of any SNMP community string still sitting in a device's
    fields JSON into the credentials table, run on every startup (idempotent:
    devices without a 'community' field are untouched). Existing data is
    preserved, not deleted -- it's relocated, and get_credential() falls back
    to the pre-migration default ('public') exactly like the old fields.get()
    did, so snmp_collector's behavior for already-registered switches doesn't
    change."""
    conn = get_db()
    rows = conn.execute("SELECT id, fields FROM devices WHERE mode='snmp'").fetchall()
    for r in rows:
        fields = json.loads(r['fields'])
        if 'community' in fields:
            community = fields.pop('community')
            set_credential(r['id'], 'snmp_community', community)
            conn.execute('UPDATE devices SET fields=? WHERE id=?', (json.dumps(fields), r['id']))
    conn.commit()
    conn.close()


# --------------------------------------------------------------- Phase C --
# Agent token security (directive section 10): the token is looked up by its
# SHA-256 hash, never stored or matched as plaintext. A plain hash (not
# scrypt/bcrypt) is the right tool here -- unlike a user password, an agent
# token is already a full-entropy random value (uuid4().hex[:16] = 64 bits
# from secrets-grade randomness), so there's nothing for a slow KDF to
# protect against that a fast hash doesn't already: nobody can feasibly
# brute-force 64 random bits either way, and a fast hash keeps every agent's
# report (sent every few seconds by every agent) cheap to verify.

def hash_token(token):
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def find_device_by_token(token):
    conn = get_db()
    row = conn.execute('SELECT * FROM devices WHERE token_hash=?', (hash_token(token),)).fetchone()
    conn.close()
    return dict(row, fields=json.loads(row['fields'])) if row else None


def set_device_token_hash(device_id, token):
    conn = get_db()
    conn.execute('UPDATE devices SET token_hash=?, token=NULL WHERE id=?', (hash_token(token), device_id))
    conn.commit()
    conn.close()


def revoke_device_token(device_id):
    conn = get_db()
    conn.execute('UPDATE devices SET token_hash=NULL, token=NULL WHERE id=?', (device_id,))
    conn.commit()
    conn.close()


def migrate_token_hashes():
    """One-time upgrade: any device that still has a plaintext token (every
    device registered before Phase C) gets its hash computed and the
    plaintext cleared. Already-migrated devices (token IS NULL) are skipped,
    so this is safe to run on every startup. This doesn't affect any already
    -deployed InfraSightAgent.exe: the agent only ever SENDS its token, it
    never reads it back from the server, so nothing on the agent side needs
    to change."""
    conn = get_db()
    rows = conn.execute("SELECT id, token FROM devices WHERE token IS NOT NULL AND token != ''").fetchall()
    for r in rows:
        conn.execute('UPDATE devices SET token_hash=?, token=NULL WHERE id=?', (hash_token(r['token']), r['id']))
    conn.commit()
    conn.close()


# --------------------------------------------------------------- Phase 5 --
# Metrics retention/aggregation (directive section 25) and DB backup
# (section 26). Raw samples are cheap and short-lived; the 5m/1h rollups are
# what makes a chart still show real history a week or a year later.

RAW_RETENTION_MS = 3 * 24 * 3600 * 1000        # 3 days of raw per-poll samples
FIVE_MIN_RETENTION_MS = 90 * 24 * 3600 * 1000  # 90 days of 5-minute rollups
ONE_HOUR_RETENTION_MS = 365 * 24 * 3600 * 1000  # 1 year of hourly rollups

FIVE_MIN_MS = 5 * 60 * 1000
ONE_HOUR_MS = 60 * 60 * 1000


def record_metrics(rows):
    """rows: iterable of (device_id, metric, ts_ms, value). Batched into one
    transaction so a full poll tick (several metrics x several devices) is a
    single write instead of one commit per value."""
    rows = [r for r in rows if r[3] is not None]
    if not rows:
        return
    conn = get_db()
    conn.executemany('INSERT INTO metrics_raw(device_id,metric,ts,value) VALUES (?,?,?,?)', rows)
    conn.commit()
    conn.close()


def _aggregate_into(conn, table, bucket_ms):
    conn.execute(f'''
        INSERT INTO {table}(device_id, metric, bucket_ts, avg_value, min_value, max_value, sample_count)
        SELECT device_id, metric, (ts/{bucket_ms})*{bucket_ms} AS bucket_ts,
               AVG(value), MIN(value), MAX(value), COUNT(*)
        FROM metrics_raw
        GROUP BY device_id, metric, bucket_ts
        ON CONFLICT(device_id, metric, bucket_ts) DO UPDATE SET
            avg_value=excluded.avg_value, min_value=excluded.min_value,
            max_value=excluded.max_value, sample_count=excluded.sample_count
    ''')


# 4-3: NetFlow/sFlow flow buckets. 14 days at 1-minute resolution is enough
# for the "기간별 트래픽 그래프" range options (1h/6h/24h/7d) without the
# unbounded growth a raw per-flow table would risk under real traffic.
FLOW_RETENTION_MS = 14 * 24 * 3600 * 1000
FLOW_BUCKET_MS = 60 * 1000


def record_flow_bandwidth(rows):
    """rows: iterable of (device_id, bucket_ts, bytes_total, packets_total).
    Each bucket is flushed exactly once by collector/flow_listener.py (its
    in-memory buffer for a minute is cleared right after flushing it), so a
    plain overwrite-on-conflict is correct here -- this isn't meant to
    accumulate across repeated calls for the same bucket, unlike the
    exporter upsert below."""
    if not rows:
        return
    conn = get_db()
    conn.executemany('''
        INSERT INTO flow_bandwidth_1m(device_id, bucket_ts, bytes_total, packets_total)
        VALUES (?,?,?,?)
        ON CONFLICT(device_id, bucket_ts) DO UPDATE SET
            bytes_total=excluded.bytes_total, packets_total=excluded.packets_total
    ''', rows)
    conn.commit()
    conn.close()


def record_flow_protocols(rows):
    """rows: iterable of (device_id, bucket_ts, protocol, bytes_total, packets_total)."""
    if not rows:
        return
    conn = get_db()
    conn.executemany('''
        INSERT INTO flow_protocol_1m(device_id, bucket_ts, protocol, bytes_total, packets_total)
        VALUES (?,?,?,?,?)
        ON CONFLICT(device_id, bucket_ts, protocol) DO UPDATE SET
            bytes_total=excluded.bytes_total, packets_total=excluded.packets_total
    ''', rows)
    conn.commit()
    conn.close()


def record_flow_top_pairs(rows):
    """rows: iterable of (device_id, bucket_ts, src_ip, dst_ip, bytes_total, packets_total)."""
    if not rows:
        return
    conn = get_db()
    conn.executemany('''
        INSERT INTO flow_top_pairs_1m(device_id, bucket_ts, src_ip, dst_ip, bytes_total, packets_total)
        VALUES (?,?,?,?,?,?)
        ON CONFLICT(device_id, bucket_ts, src_ip, dst_ip) DO UPDATE SET
            bytes_total=excluded.bytes_total, packets_total=excluded.packets_total
    ''', rows)
    conn.commit()
    conn.close()


def record_flow_exporters(rows):
    """rows: iterable of (exporter_ip, protocol, last_seen_at, record_count).
    Batched once per flush cycle (not once per packet) by flow_listener.py --
    record_count accumulates (an exporter sends many packets over time);
    first_seen_at is set only on the row's first-ever insert, never touched
    again."""
    if not rows:
        return
    conn = get_db()
    conn.executemany('''
        INSERT INTO flow_exporters(exporter_ip, protocol, first_seen_at, last_seen_at, record_count)
        VALUES (?,?,?,?,?)
        ON CONFLICT(exporter_ip) DO UPDATE SET
            protocol=excluded.protocol, last_seen_at=excluded.last_seen_at,
            record_count=record_count+excluded.record_count
    ''', [(ip, proto, last_seen, last_seen, cnt) for ip, proto, last_seen, cnt in rows])
    conn.commit()
    conn.close()


def run_flow_retention():
    """Purges flow_*_1m rows (and exporters not heard from in a while) past
    FLOW_RETENTION_MS. Called from the same daily cron as
    run_metrics_retention() -- no separate schedule needed."""
    now = int(time.time() * 1000)
    cutoff = now - FLOW_RETENTION_MS
    conn = get_db()
    try:
        conn.execute('DELETE FROM flow_bandwidth_1m WHERE bucket_ts < ?', (cutoff,))
        conn.execute('DELETE FROM flow_protocol_1m WHERE bucket_ts < ?', (cutoff,))
        conn.execute('DELETE FROM flow_top_pairs_1m WHERE bucket_ts < ?', (cutoff,))
        conn.execute('DELETE FROM flow_exporters WHERE last_seen_at < ?', (cutoff,))
        conn.commit()
    finally:
        conn.close()


# 2-6: discovery scan history. 90 days is plenty for "did I already scan
# this range recently" context without keeping it forever.
DISCOVERY_SCAN_RETENTION_MS = 90 * 24 * 3600 * 1000


def save_discovery_scan(range_text, requested_by, started_at, finished_at, host_count, results):
    """results: the same list api_discovery_scan already builds for the HTTP
    response ({ip, hostname, latencyMs, guessedType, alreadyRegistered}) --
    persisted as-is rather than re-derived, so the history shows exactly
    what the user saw at the time. Returns the new scan's id."""
    conn = get_db()
    cur = conn.execute(
        'INSERT INTO discovery_scans(range_text,requested_by,started_at,finished_at,host_count,found_count) '
        'VALUES (?,?,?,?,?,?)',
        (range_text, requested_by, started_at, finished_at, host_count, len(results)))
    scan_id = cur.lastrowid
    if results:
        conn.executemany(
            'INSERT INTO discovery_scan_results(scan_id,ip,hostname,latency_ms,guessed_type,already_registered) '
            'VALUES (?,?,?,?,?,?)',
            [(scan_id, r['ip'], r.get('hostname'), r.get('latencyMs'), r.get('guessedType'),
              1 if r.get('alreadyRegistered') else 0) for r in results])
    conn.commit()
    conn.close()
    return scan_id


def load_discovery_scans(limit=20):
    conn = get_db()
    rows = conn.execute(
        'SELECT id,range_text,requested_by,started_at,finished_at,host_count,found_count '
        'FROM discovery_scans ORDER BY started_at DESC LIMIT ?', (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def load_discovery_scan_detail(scan_id):
    conn = get_db()
    scan = conn.execute('SELECT * FROM discovery_scans WHERE id=?', (scan_id,)).fetchone()
    if not scan:
        conn.close()
        return None
    results = conn.execute(
        'SELECT ip,hostname,latency_ms,guessed_type,already_registered FROM discovery_scan_results '
        'WHERE scan_id=? ORDER BY ip', (scan_id,)
    ).fetchall()
    conn.close()
    out = dict(scan)
    out['results'] = [dict(r) for r in results]
    return out


def run_discovery_retention():
    cutoff = int(time.time() * 1000) - DISCOVERY_SCAN_RETENTION_MS
    conn = get_db()
    try:
        old_ids = [r['id'] for r in conn.execute(
            'SELECT id FROM discovery_scans WHERE started_at < ?', (cutoff,)).fetchall()]
        if old_ids:
            placeholders = ','.join('?' * len(old_ids))
            conn.execute(f'DELETE FROM discovery_scan_results WHERE scan_id IN ({placeholders})', old_ids)
            conn.execute(f'DELETE FROM discovery_scans WHERE id IN ({placeholders})', old_ids)
            conn.commit()
    finally:
        conn.close()


def load_flow_status():
    """Every exporter ever heard from, each annotated with whichever
    registered device (any category) has a matching IP -- the runtime
    answer to "which of my devices actually support/are configured for
    NetFlow/sFlow", independent of whether it's even a registered device."""
    conn = get_db()
    rows = conn.execute('SELECT * FROM flow_exporters ORDER BY last_seen_at DESC').fetchall()
    conn.close()
    devices_by_ip = {d['ip']: d for d in load_devices() if d.get('ip')}
    out = []
    for r in rows:
        d = devices_by_ip.get(r['exporter_ip'])
        out.append({
            'exporterIp': r['exporter_ip'], 'protocol': r['protocol'],
            'firstSeenAt': r['first_seen_at'], 'lastSeenAt': r['last_seen_at'],
            'recordCount': r['record_count'],
            'deviceId': d['id'] if d else None, 'deviceName': d['name'] if d else None,
        })
    return out


def load_flow_summary(device_id, since_ms):
    conn = get_db()
    q = 'SELECT COALESCE(SUM(bytes_total),0) b, COALESCE(SUM(packets_total),0) p FROM flow_bandwidth_1m WHERE bucket_ts >= ?'
    params = [since_ms]
    if device_id:
        q += ' AND device_id=?'
        params.append(device_id)
    row = conn.execute(q, params).fetchone()
    conn.close()
    return {'bytesTotal': row['b'], 'packetsTotal': row['p']}


def load_flow_timeseries(device_id, since_ms, bucket_ms=FLOW_BUCKET_MS):
    """bucket_ms lets the caller pick a coarser resolution for a longer
    range (e.g. hourly buckets over 7 days) so the chart isn't handed
    thousands of 1-minute points."""
    conn = get_db()
    q = f'''SELECT (bucket_ts/{bucket_ms})*{bucket_ms} AS b, SUM(bytes_total) bytes, SUM(packets_total) packets
            FROM flow_bandwidth_1m WHERE bucket_ts >= ?'''
    params = [since_ms]
    if device_id:
        q += ' AND device_id=?'
        params.append(device_id)
    q += ' GROUP BY b ORDER BY b'
    rows = conn.execute(q, params).fetchall()
    conn.close()
    return [{'ts': r['b'], 'bytes': r['bytes'], 'packets': r['packets']} for r in rows]


def load_flow_protocols(device_id, since_ms):
    conn = get_db()
    q = 'SELECT protocol, SUM(bytes_total) bytes, SUM(packets_total) packets FROM flow_protocol_1m WHERE bucket_ts >= ?'
    params = [since_ms]
    if device_id:
        q += ' AND device_id=?'
        params.append(device_id)
    q += ' GROUP BY protocol ORDER BY bytes DESC'
    rows = conn.execute(q, params).fetchall()
    conn.close()
    return [{'protocol': r['protocol'], 'bytes': r['bytes'], 'packets': r['packets']} for r in rows]


def load_flow_top_pairs(device_id, since_ms, limit=10):
    conn = get_db()
    q = '''SELECT src_ip, dst_ip, SUM(bytes_total) bytes, SUM(packets_total) packets
           FROM flow_top_pairs_1m WHERE bucket_ts >= ?'''
    params = [since_ms]
    if device_id:
        q += ' AND device_id=?'
        params.append(device_id)
    q += ' GROUP BY src_ip, dst_ip ORDER BY bytes DESC LIMIT ?'
    params.append(limit)
    rows = conn.execute(q, params).fetchall()
    conn.close()
    return [{'srcIp': r['src_ip'], 'dstIp': r['dst_ip'], 'bytes': r['bytes'], 'packets': r['packets']} for r in rows]


def run_metrics_retention():
    """Rolls the currently-buffered raw samples up into the 5m/1h tables
    (idempotent -- re-aggregating an already-aggregated bucket just overwrites
    it with the same numbers), then purges anything past its tier's retention
    window. Intended to run once a day; safe to run more often too."""
    now = int(time.time() * 1000)
    conn = get_db()
    try:
        _aggregate_into(conn, 'metrics_5m', FIVE_MIN_MS)
        _aggregate_into(conn, 'metrics_1h', ONE_HOUR_MS)
        conn.execute('DELETE FROM metrics_raw WHERE ts < ?', (now - RAW_RETENTION_MS,))
        conn.execute('DELETE FROM metrics_5m WHERE bucket_ts < ?', (now - FIVE_MIN_RETENTION_MS,))
        conn.execute('DELETE FROM metrics_1h WHERE bucket_ts < ?', (now - ONE_HOUR_RETENTION_MS,))
        conn.commit()
    finally:
        conn.close()


# Code review pass, finding #3: metrics had a retention policy; incidents
# and audit_log never did, so both grow without bound for as long as the
# app runs. An *open* incident is still something someone needs to act on
# no matter how old it is, so only resolved/ack'd ones are ever purged here
# -- audit_log has no such "still needs attention" concept, so it's purged
# by age alone.
INCIDENT_RETENTION_DAYS = 90
AUDIT_LOG_RETENTION_DAYS = 365


def run_incident_retention():
    now = int(time.time() * 1000)
    incident_cutoff = now - INCIDENT_RETENTION_DAYS * 86400 * 1000
    audit_cutoff = now - AUDIT_LOG_RETENTION_DAYS * 86400 * 1000
    conn = get_db()
    try:
        conn.execute("DELETE FROM incidents WHERE status!='open' AND ts<?", (incident_cutoff,))
        conn.execute('DELETE FROM audit_log WHERE ts<?', (audit_cutoff,))
        conn.commit()
    finally:
        conn.close()


def load_metric_history(device_id, metric, granularity='raw', since_ms=None, limit=500):
    """granularity: 'raw' | '5m' | '1h'. Returns rows oldest-first as
    {ts, value} (raw) or {ts, avg, min, max} (rollups)."""
    conn = get_db()
    try:
        if granularity == 'raw':
            q = 'SELECT ts, value FROM metrics_raw WHERE device_id=? AND metric=?'
            params = [device_id, metric]
            if since_ms:
                q += ' AND ts >= ?'; params.append(since_ms)
            q += ' ORDER BY ts DESC LIMIT ?'; params.append(limit)
            rows = conn.execute(q, params).fetchall()
            return [{'ts': r['ts'], 'value': r['value']} for r in reversed(rows)]
        table = 'metrics_5m' if granularity == '5m' else 'metrics_1h'
        q = f'SELECT bucket_ts, avg_value, min_value, max_value FROM {table} WHERE device_id=? AND metric=?'
        params = [device_id, metric]
        if since_ms:
            q += ' AND bucket_ts >= ?'; params.append(since_ms)
        q += ' ORDER BY bucket_ts DESC LIMIT ?'; params.append(limit)
        rows = conn.execute(q, params).fetchall()
        return [{'ts': r['bucket_ts'], 'avg': r['avg_value'], 'min': r['min_value'], 'max': r['max_value']}
                for r in reversed(rows)]
    finally:
        conn.close()


def create_report_schedule(name, frequency, report_type, fmt, device_id, group_name, recipients, created_by):
    conn = get_db()
    now = int(time.time() * 1000)
    cur = conn.execute(
        'INSERT INTO report_schedules(name,frequency,report_type,format,device_id,group_name,recipients,enabled,created_at,created_by) '
        'VALUES (?,?,?,?,?,?,?,1,?,?)',
        (name, frequency, report_type, fmt, device_id, group_name, json.dumps(recipients), now, created_by))
    schedule_id = cur.lastrowid
    conn.commit()
    conn.close()
    return schedule_id


def load_report_schedules():
    conn = get_db()
    rows = conn.execute('SELECT * FROM report_schedules ORDER BY created_at DESC').fetchall()
    conn.close()
    out = []
    for r in rows:
        d = dict(r)
        d['recipients'] = json.loads(d['recipients'])
        out.append(d)
    return out


def get_report_schedule(schedule_id):
    conn = get_db()
    row = conn.execute('SELECT * FROM report_schedules WHERE id=?', (schedule_id,)).fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    d['recipients'] = json.loads(d['recipients'])
    return d


def set_report_schedule_enabled(schedule_id, enabled):
    conn = get_db()
    conn.execute('UPDATE report_schedules SET enabled=? WHERE id=?', (1 if enabled else 0, schedule_id))
    conn.commit()
    conn.close()


def delete_report_schedule(schedule_id):
    conn = get_db()
    conn.execute('DELETE FROM report_schedules WHERE id=?', (schedule_id,))
    conn.execute('DELETE FROM report_delivery_log WHERE schedule_id=?', (schedule_id,))
    conn.commit()
    conn.close()


def update_report_schedule_last_run(schedule_id, run_at, status):
    conn = get_db()
    conn.execute('UPDATE report_schedules SET last_run_at=?, last_run_status=? WHERE id=?', (run_at, status, schedule_id))
    conn.commit()
    conn.close()


def record_report_delivery(schedule_id, run_at, status, error, attempts):
    conn = get_db()
    conn.execute(
        'INSERT INTO report_delivery_log(schedule_id,run_at,status,error,attempts) VALUES (?,?,?,?,?)',
        (schedule_id, run_at, status, error, attempts))
    conn.commit()
    conn.close()


def record_email_alert(ts, severity, source, message, recipient, status, error, attempts):
    conn = get_db()
    conn.execute(
        'INSERT INTO email_alert_log(ts,severity,source,message,recipient,status,error,attempts) VALUES (?,?,?,?,?,?,?,?)',
        (ts, severity, source, message, recipient, status, error, attempts))
    conn.commit()
    conn.close()


def load_email_alert_log(limit=50):
    conn = get_db()
    rows = conn.execute('SELECT * FROM email_alert_log ORDER BY ts DESC LIMIT ?', (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def load_report_delivery_log(schedule_id=None, limit=50):
    conn = get_db()
    q = 'SELECT * FROM report_delivery_log'
    params = []
    if schedule_id is not None:
        q += ' WHERE schedule_id=?'
        params.append(schedule_id)
    q += ' ORDER BY run_at DESC LIMIT ?'
    params.append(limit)
    rows = conn.execute(q, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ------------------------------------------------------------------- 3-4 --
def create_public_service(label, device_id, description):
    conn = get_db()
    now = int(time.time() * 1000)
    max_order = conn.execute('SELECT COALESCE(MAX(display_order),0) m FROM public_services').fetchone()['m']
    cur = conn.execute(
        'INSERT INTO public_services(label,device_id,description,enabled,display_order,created_at) VALUES (?,?,?,0,?,?)',
        (label, device_id, description, max_order + 1, now))
    service_id = cur.lastrowid
    conn.commit()
    conn.close()
    return service_id


def load_public_services():
    """Full rows, device_id included -- for the AUTHENTICATED admin
    management screen only. The public-facing serialization that strips
    device_id/label-adjacent internals lives in collector/public_status.py,
    never here."""
    conn = get_db()
    rows = conn.execute('SELECT * FROM public_services ORDER BY display_order').fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_public_service(service_id):
    conn = get_db()
    row = conn.execute('SELECT * FROM public_services WHERE id=?', (service_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def update_public_service(service_id, label=None, description=None, enabled=None, display_order=None):
    conn = get_db()
    row = conn.execute('SELECT * FROM public_services WHERE id=?', (service_id,)).fetchone()
    if not row:
        conn.close()
        return False
    d = dict(row)
    conn.execute(
        'UPDATE public_services SET label=?, description=?, enabled=?, display_order=? WHERE id=?',
        (label if label is not None else d['label'],
         description if description is not None else d['description'],
         (1 if enabled else 0) if enabled is not None else d['enabled'],
         display_order if display_order is not None else d['display_order'],
         service_id))
    conn.commit()
    conn.close()
    return True


def delete_public_service(service_id):
    conn = get_db()
    conn.execute('DELETE FROM public_services WHERE id=?', (service_id,))
    conn.execute('UPDATE public_announcements SET service_id=NULL WHERE service_id=?', (service_id,))
    conn.commit()
    conn.close()


def create_public_announcement(service_id, title, body, status, created_by):
    conn = get_db()
    now = int(time.time() * 1000)
    cur = conn.execute(
        'INSERT INTO public_announcements(service_id,title,body,status,created_at,created_by) VALUES (?,?,?,?,?,?)',
        (service_id, title, body, status, now, created_by))
    ann_id = cur.lastrowid
    conn.commit()
    conn.close()
    return ann_id


def update_public_announcement(ann_id, body=None, status=None):
    """Appends the progress of an ongoing incident (조사 중 -> 확인됨 ->
    모니터링 중 -> 해결됨) on the SAME announcement row rather than creating
    a new one each time -- resolved_at is stamped the moment status is set
    to 'resolved', same one-way transition the internal incidents table
    uses for its own resolved_at."""
    conn = get_db()
    row = conn.execute('SELECT * FROM public_announcements WHERE id=?', (ann_id,)).fetchone()
    if not row:
        conn.close()
        return False
    d = dict(row)
    new_status = status if status is not None else d['status']
    resolved_at = d['resolved_at']
    if new_status == 'resolved' and not resolved_at:
        resolved_at = int(time.time() * 1000)
    conn.execute(
        'UPDATE public_announcements SET body=?, status=?, resolved_at=? WHERE id=?',
        (body if body is not None else d['body'], new_status, resolved_at, ann_id))
    conn.commit()
    conn.close()
    return True


def delete_public_announcement(ann_id):
    conn = get_db()
    conn.execute('DELETE FROM public_announcements WHERE id=?', (ann_id,))
    conn.commit()
    conn.close()


def load_public_announcements(service_id=None, limit=50):
    conn = get_db()
    q = 'SELECT * FROM public_announcements'
    params = []
    if service_id is not None:
        q += ' WHERE service_id=?'
        params.append(service_id)
    q += ' ORDER BY created_at DESC LIMIT ?'
    params.append(limit)
    rows = conn.execute(q, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def summarize_metric_range(device_id, metric, start_ms, end_ms):
    """One (avg, max, sampleCount) summary for a metric over [start_ms,
    end_ms) -- for 3-2's 자원 사용률 보고서, which wants "평균/최대 사용률
    for the period" per device, not a time series. Tries metrics_1h first
    (cheapest, and the only tier retention guarantees survives for an
    older/longer report range), falls back to metrics_5m, then metrics_raw,
    returning None only if genuinely no data exists at any tier -- a device
    registered mid-period, or one that's been offline the whole time, is
    exactly when that matters."""
    conn = get_db()
    try:
        for table, is_rollup in (('metrics_1h', True), ('metrics_5m', True), ('metrics_raw', False)):
            ts_col = 'bucket_ts' if is_rollup else 'ts'
            if is_rollup:
                row = conn.execute(
                    f'SELECT AVG(avg_value) a, MAX(max_value) m, SUM(sample_count) c FROM {table} '
                    f'WHERE device_id=? AND metric=? AND {ts_col}>=? AND {ts_col}<?',
                    (device_id, metric, start_ms, end_ms)).fetchone()
            else:
                row = conn.execute(
                    f'SELECT AVG(value) a, MAX(value) m, COUNT(*) c FROM {table} '
                    f'WHERE device_id=? AND metric=? AND {ts_col}>=? AND {ts_col}<?',
                    (device_id, metric, start_ms, end_ms)).fetchone()
            if row and row['c']:
                return {'avg': row['a'], 'max': row['m'], 'sampleCount': row['c']}
        return None
    finally:
        conn.close()


# Data backup pass: the single knob for "최근 N일간 백업 유지" -- both the
# daily scheduled job (collector/scheduler.py's _run_backup_job) and the
# manual "지금 백업" admin button (server.py's /api/system/backup) call
# backup_database with this instead of their own literal, so there's one
# place to change the retention window rather than two that could drift out
# of sync with each other.
#
# 2nd-dev-pass finding #5: this used to be BACKUP_RETENTION_COUNT=14, a
# "keep the latest 14 files" count -- which only equals "14 days" if backup
# runs exactly once a day. The manual "지금 백업" button shares this same
# cleanup, so a few manual backups taken between daily runs silently pushed
# older-but-still-recent daily backups out of the window early. Retention is
# now based on each file's actual age, matching what the comment (and the
# 2nd-dev-pass spec's "최근 30일 검토") always said it did.
BACKUP_RETENTION_DAYS = 30


def backup_database(backup_dir, keep_days=BACKUP_RETENTION_DAYS):
    """Uses sqlite3's own backup API (not a raw file copy) so a backup taken
    while the collector thread is mid-write is still a consistent snapshot.
    Deletes backup files older than `keep_days`, regardless of how many
    accumulated in that window (daily cron + any manual ones).

    Phase F addition: runs PRAGMA integrity_check on the freshly-written copy
    before trusting it. A backup that never gets restored until the day it's
    actually needed is the worst time to discover it was silently corrupt --
    a failed check here deletes that copy and raises, so the caller's normal
    failure path (BACKUP_FAILURE audit entry / incident) fires instead of a
    bad file quietly sitting in the rotation."""
    os.makedirs(backup_dir, exist_ok=True)
    stamp = time.strftime('%Y-%m-%d_%H%M%S')
    dest_path = os.path.join(backup_dir, f'infrasight_{stamp}.db')
    src = sqlite3.connect(DB_PATH)
    try:
        dest = sqlite3.connect(dest_path)
        try:
            src.backup(dest)
            result = dest.execute('PRAGMA integrity_check').fetchone()[0]
            if result != 'ok':
                raise sqlite3.DatabaseError(f'backup integrity_check failed: {result}')
        finally:
            dest.close()
    except Exception:
        if os.path.exists(dest_path):
            try:
                os.remove(dest_path)
            except OSError:
                pass
        raise
    finally:
        src.close()
    cutoff = time.time() - keep_days * 86400
    for f in os.listdir(backup_dir):
        if not (f.startswith('infrasight_') and f.endswith('.db')):
            continue
        path = os.path.join(backup_dir, f)
        try:
            if os.path.getmtime(path) < cutoff:
                os.remove(path)
        except OSError:
            pass
    return dest_path


# --------------------------------------------------------------- Phase 7 --
# SNMP vendor profile selection, SNMPv3 credentials, and LLDP-based topology
# link discovery (directive sections 18/19/31).

def set_vendor_profile(device_id, profile):
    conn = get_db()
    conn.execute('UPDATE devices SET vendor_profile=? WHERE id=?', (profile, device_id))
    conn.commit()
    conn.close()


def find_device_by_name_or_ip(name=None, ip=None, exclude_id=None):
    """Best-effort match for LLDP neighbor correlation: a neighbor is only
    ever linked to a device that is ALREADY registered in InfraSight -- this
    never invents a new device from LLDP data."""
    conn = get_db()
    try:
        if ip:
            row = conn.execute('SELECT id FROM devices WHERE ip=? AND id!=?', (ip, exclude_id or '')).fetchone()
            if row:
                return row['id']
        if name:
            row = conn.execute('SELECT id FROM devices WHERE lower(name)=lower(?) AND id!=?', (name, exclude_id or '')).fetchone()
            if row:
                return row['id']
        return None
    finally:
        conn.close()


def upsert_device_link(from_device_id, to_device_id, link_type, remote_port=None):
    conn = get_db()
    conn.execute(
        'INSERT INTO device_links(from_device_id,to_device_id,link_type,remote_port,discovered_at) VALUES (?,?,?,?,?) '
        'ON CONFLICT(from_device_id,to_device_id,link_type) DO UPDATE SET remote_port=excluded.remote_port, discovered_at=excluded.discovered_at',
        (from_device_id, to_device_id, link_type, remote_port, int(time.time() * 1000)))
    conn.commit()
    conn.close()


def load_device_links():
    conn = get_db()
    rows = conn.execute('SELECT * FROM device_links').fetchall()
    conn.close()
    return [dict(r) for r in rows]


# --------------------------------------------------------------- Phase 4 --
# Alert engine: email notifications on new/escalated incidents (directive
# sections 23/24). SMTP host/port/username/etc. live in `settings`; the
# password reuses the `credentials` table under a synthetic device_id, so it
# never sits in plaintext next to ordinary config values.

SMTP_SYSTEM_ID = '__system__'
_SEVERITY_RANK = {'good': 0, 'info': 0, 'warn': 1, 'crit': 2}


def get_setting(key, default=None):
    conn = get_db()
    row = conn.execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
    conn.close()
    return row['value'] if row else default


def set_setting(key, value):
    conn = get_db()
    conn.execute(
        'INSERT INTO settings(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
        (key, value))
    conn.commit()
    conn.close()


def get_smtp_config():
    """Returns the SMTP config dict (including the password) if fully
    configured and enabled, else None. Used internally by _dispatch_alert and
    by the manual test-send endpoint -- never returned to the frontend as-is
    (the API layer strips the password before responding)."""
    if get_setting('smtp_enabled') != '1':
        return None
    host = get_setting('smtp_host')
    port = get_setting('smtp_port')
    username = get_setting('smtp_username')
    alert_to = get_setting('smtp_alert_to')
    password = get_credential(SMTP_SYSTEM_ID, 'smtp_password')
    if not (host and port and username and password and alert_to):
        return None
    return {
        'host': host, 'port': int(port), 'username': username, 'password': password,
        'use_tls': get_setting('smtp_use_tls', '1') == '1',
        'alert_to': alert_to,
        'min_severity': get_setting('smtp_min_severity', 'crit'),
    }


def get_smtp_config_public():
    """Same fields, minus the password, for the settings API/UI."""
    return {
        'enabled': get_setting('smtp_enabled') == '1',
        'host': get_setting('smtp_host'),
        'port': get_setting('smtp_port'),
        'username': get_setting('smtp_username'),
        'useTls': get_setting('smtp_use_tls', '1') == '1',
        'alertTo': get_setting('smtp_alert_to'),
        'minSeverity': get_setting('smtp_min_severity', 'crit'),
        'passwordSet': bool(get_credential(SMTP_SYSTEM_ID, 'smtp_password')),
    }


def set_smtp_config(host, port, username, password=None, use_tls=True, alert_to=None, enabled=True, min_severity='crit'):
    set_setting('smtp_host', host)
    set_setting('smtp_port', str(port))
    set_setting('smtp_username', username)
    set_setting('smtp_use_tls', '1' if use_tls else '0')
    set_setting('smtp_alert_to', alert_to or username)
    set_setting('smtp_min_severity', min_severity)
    set_setting('smtp_enabled', '1' if enabled else '0')
    if password:  # blank password on an update means "keep the existing one"
        set_credential(SMTP_SYSTEM_ID, 'smtp_password', password)


# 2-4: Slack/Teams are both plain incoming-webhook POSTs -- one URL *is* the
# destination, unlike email's separate host/port/credentials vs. alert_to.
# Reuses the same settings+credentials split as SMTP (the URL is treated as
# a credential, same as the SMTP password, since a leaked webhook URL lets
# anyone post into that channel) under the same synthetic SMTP_SYSTEM_ID row
# -- one extra credential key per channel, not a new table.
def get_webhook_config(prefix):
    """prefix: 'slack' or 'teams'. Returns {url, min_severity} if enabled and
    a URL is set, else None -- same "fully configured or not used" contract
    as get_smtp_config()."""
    if get_setting(f'{prefix}_enabled') != '1':
        return None
    url = get_credential(SMTP_SYSTEM_ID, f'{prefix}_webhook_url')
    if not url:
        return None
    return {'url': url, 'min_severity': get_setting(f'{prefix}_min_severity', 'crit')}


def get_webhook_config_public(prefix):
    return {
        'enabled': get_setting(f'{prefix}_enabled') == '1',
        'minSeverity': get_setting(f'{prefix}_min_severity', 'crit'),
        'urlSet': bool(get_credential(SMTP_SYSTEM_ID, f'{prefix}_webhook_url')),
    }


def set_webhook_config(prefix, url=None, enabled=True, min_severity='crit'):
    set_setting(f'{prefix}_enabled', '1' if enabled else '0')
    set_setting(f'{prefix}_min_severity', min_severity)
    if url:  # blank on an update means "keep the existing one", same as the SMTP password
        set_credential(SMTP_SYSTEM_ID, f'{prefix}_webhook_url', url)


# 2-4 / Kakao Method A: "나에게 보내기" (self-message) via Kakao Login OAuth --
# see alerts/kakao_channel.py for why this is the one Kakao integration that
# IS wired into _dispatch_alert below, unlike real 알림톡 (sending to other
# people). An admin's own Kakao account authorizes once (an OAuth code
# exchanged for an access_token + refresh_token below); every alert after
# that is this module refreshing the access_token when it's stale and
# POSTing to Kakao's own "나에게 보내기" API. Only the account that did the
# OAuth consent receives anything -- there is no concept of "recipients"
# here, which is exactly the Method A/B distinction flagged to the user
# before this was built.
def get_kakao_config():
    """Returns the Kakao config dict (including tokens) if enabled and an
    account has completed the OAuth consent, else None. Same "fully
    configured or not used" contract as get_smtp_config()."""
    if get_setting('kakao_enabled') != '1':
        return None
    rest_api_key = get_setting('kakao_rest_api_key')
    refresh_token = get_credential(SMTP_SYSTEM_ID, 'kakao_refresh_token')
    if not (rest_api_key and refresh_token):
        return None
    return {
        'rest_api_key': rest_api_key,
        'client_secret': get_credential(SMTP_SYSTEM_ID, 'kakao_client_secret'),
        'access_token': get_credential(SMTP_SYSTEM_ID, 'kakao_access_token'),
        'refresh_token': refresh_token,
        'expires_at': int(get_setting('kakao_token_expires_at') or 0),
        'min_severity': get_setting('kakao_min_severity', 'crit'),
    }


def get_kakao_config_public():
    return {
        'enabled': get_setting('kakao_enabled') == '1',
        'minSeverity': get_setting('kakao_min_severity', 'crit'),
        'restApiKeySet': bool(get_setting('kakao_rest_api_key')),
        'clientSecretSet': bool(get_credential(SMTP_SYSTEM_ID, 'kakao_client_secret')),
        'connected': bool(get_credential(SMTP_SYSTEM_ID, 'kakao_refresh_token')),
    }


def set_kakao_config(enabled, rest_api_key=None, client_secret=None, min_severity='crit'):
    set_setting('kakao_enabled', '1' if enabled else '0')
    set_setting('kakao_min_severity', min_severity)
    if rest_api_key:  # blank on an update means "keep the existing one", same as the SMTP password
        set_setting('kakao_rest_api_key', rest_api_key)
    if client_secret:
        set_credential(SMTP_SYSTEM_ID, 'kakao_client_secret', client_secret)


def set_kakao_tokens(access_token, refresh_token, expires_in):
    """Called after the OAuth callback exchanges a code, and again whenever
    alerts/kakao_channel.py refreshes a stale access_token. refresh_token is
    None on a plain refresh when Kakao doesn't reissue one (it only does
    that occasionally) -- kept as-is in that case rather than overwritten
    with None, since set_credential() already no-ops on None but this makes
    the intent explicit at the call site."""
    set_credential(SMTP_SYSTEM_ID, 'kakao_access_token', access_token)
    if refresh_token:
        set_credential(SMTP_SYSTEM_ID, 'kakao_refresh_token', refresh_token)
    # 5-minute safety margin so a near-expiry token gets refreshed proactively
    # instead of failing mid-send and needing the channel's own retry-after-
    # refresh fallback (see alerts/kakao_channel.py).
    set_setting('kakao_token_expires_at', str(int(time.time()) + int(expires_in) - 300))


def disconnect_kakao():
    delete_credential(SMTP_SYSTEM_ID, 'kakao_access_token')
    delete_credential(SMTP_SYSTEM_ID, 'kakao_refresh_token')
    set_setting('kakao_token_expires_at', '0')


def get_sms_config_public():
    return {
        'enabled': get_setting('sms_enabled') == '1',
        'provider': get_setting('sms_provider') or '',
        'senderNumber': get_setting('sms_sender_number') or '',
        'apiKeySet': bool(get_credential(SMTP_SYSTEM_ID, 'sms_api_key')),
    }


def set_sms_config(enabled, provider, sender_number, api_key=None):
    set_setting('sms_enabled', '1' if enabled else '0')
    set_setting('sms_provider', (provider or '').strip())
    set_setting('sms_sender_number', (sender_number or '').strip())
    if api_key:
        set_credential(SMTP_SYSTEM_ID, 'sms_api_key', api_key)


# Kakao Method B (비즈니스 알림톡) via Solapi's AlimTalk API -- see
# alerts/kakao_biz_channel.py for the actual HTTP/HMAC call and for exactly
# what template text needs to be submitted to Kakao for approval (the
# #{제목}/#{내용}/#{시각} variable names are hardcoded on both sides: the
# approved template and this channel's send() call have to agree on them).
# Unlike Method A, this sends to a list of other people (kakao_biz_recipients
# below), which is the whole reason it costs money per message.
def get_kakaobiz_config():
    """Returns the config dict (including the API secret) if enabled, fully
    configured, and at least one recipient is enabled, else None. Same
    "fully configured or not used" contract as get_smtp_config()."""
    if get_setting('kakaobiz_enabled') != '1':
        return None
    api_key = get_setting('kakaobiz_api_key')
    api_secret = get_credential(SMTP_SYSTEM_ID, 'kakaobiz_api_secret')
    pf_id = get_setting('kakaobiz_pf_id')
    template_id = get_setting('kakaobiz_template_id')
    sender_number = get_setting('kakaobiz_sender_number')
    if not (api_key and api_secret and pf_id and template_id and sender_number):
        return None
    recipients = [r['phone'] for r in load_kakaobiz_recipients() if r['enabled']]
    if not recipients:
        return None
    return {
        'api_key': api_key, 'api_secret': api_secret, 'pf_id': pf_id, 'template_id': template_id,
        'sender_number': sender_number, 'sms_fallback': get_setting('kakaobiz_sms_fallback') == '1',
        'recipients': recipients, 'min_severity': get_setting('kakaobiz_min_severity', 'crit'),
    }


def get_kakaobiz_config_public():
    return {
        'enabled': get_setting('kakaobiz_enabled') == '1',
        'minSeverity': get_setting('kakaobiz_min_severity', 'crit'),
        'apiKeySet': bool(get_setting('kakaobiz_api_key')),
        'apiSecretSet': bool(get_credential(SMTP_SYSTEM_ID, 'kakaobiz_api_secret')),
        'pfId': get_setting('kakaobiz_pf_id') or '',
        'templateId': get_setting('kakaobiz_template_id') or '',
        'senderNumber': get_setting('kakaobiz_sender_number') or '',
        'smsFallback': get_setting('kakaobiz_sms_fallback') == '1',
    }


def set_kakaobiz_config(enabled, api_key=None, api_secret=None, pf_id=None, template_id=None,
                         sender_number=None, sms_fallback=False, min_severity='crit'):
    set_setting('kakaobiz_enabled', '1' if enabled else '0')
    set_setting('kakaobiz_min_severity', min_severity)
    set_setting('kakaobiz_sms_fallback', '1' if sms_fallback else '0')
    if api_key:  # blank on an update means "keep the existing one", same as the SMTP password
        set_setting('kakaobiz_api_key', api_key)
    if api_secret:
        set_credential(SMTP_SYSTEM_ID, 'kakaobiz_api_secret', api_secret)
    if pf_id:
        set_setting('kakaobiz_pf_id', pf_id)
    if template_id:
        set_setting('kakaobiz_template_id', template_id)
    if sender_number:
        set_setting('kakaobiz_sender_number', sender_number)


def create_kakaobiz_recipient(name, phone):
    conn = get_db()
    now = int(time.time() * 1000)
    cur = conn.execute(
        'INSERT INTO kakao_biz_recipients(name,phone,enabled,created_at) VALUES (?,?,1,?)',
        (name, phone, now))
    recipient_id = cur.lastrowid
    conn.commit()
    conn.close()
    return recipient_id


def load_kakaobiz_recipients():
    conn = get_db()
    rows = conn.execute('SELECT * FROM kakao_biz_recipients ORDER BY created_at').fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_kakaobiz_recipient(recipient_id, name=None, phone=None, enabled=None):
    conn = get_db()
    row = conn.execute('SELECT * FROM kakao_biz_recipients WHERE id=?', (recipient_id,)).fetchone()
    if not row:
        conn.close()
        return False
    d = dict(row)
    conn.execute(
        'UPDATE kakao_biz_recipients SET name=?, phone=?, enabled=? WHERE id=?',
        (name if name is not None else d['name'], phone if phone is not None else d['phone'],
         1 if enabled else 0 if enabled is not None else d['enabled'], recipient_id))
    conn.commit()
    conn.close()
    return True


def delete_kakaobiz_recipient(recipient_id):
    conn = get_db()
    conn.execute('DELETE FROM kakao_biz_recipients WHERE id=?', (recipient_id,))
    conn.commit()
    conn.close()


def _get_alert_channels():
    """Every currently-configured outbound alert channel. Each entry is
    (name, AlertChannel instance, destination, this channel's own min-severity
    floor). Adding a new one later is: write an alerts/<x>_channel.py
    implementing alerts.base.AlertChannel, add a get_<x>_config()/
    set_<x>_config() pair next to get_smtp_config() above for its settings,
    and append one line here -- _dispatch_alert itself never has to change.

    The web channel isn't listed here because it doesn't need dispatching:
    every incident is already a DB row the instant add_incident() writes it,
    and the dashboard's existing 2.2s poll (index.html's syncState) picks it
    up and raises a toast for anything new/escalated/recovered. This list is
    only for channels that need an explicit outbound push. SMS is
    intentionally absent -- see the comment above its settings functions.
    Kakao's destination is the whole config dict (not a single string like
    the others) because alerts/kakao_channel.py may need to refresh the
    access_token mid-send -- see _dispatch_one_channel's kakao branch for
    where the refreshed token gets persisted back."""
    channels = []
    smtp_cfg = get_smtp_config()
    if smtp_cfg:
        from alerts.email_channel import EmailChannel
        channel = EmailChannel(smtp_cfg['host'], smtp_cfg['port'], smtp_cfg['username'], smtp_cfg['password'], smtp_cfg['use_tls'])
        channels.append(('email', channel, smtp_cfg['alert_to'], smtp_cfg['min_severity']))
    slack_cfg = get_webhook_config('slack')
    if slack_cfg:
        from alerts.slack_channel import SlackChannel
        channels.append(('slack', SlackChannel(), slack_cfg['url'], slack_cfg['min_severity']))
    teams_cfg = get_webhook_config('teams')
    if teams_cfg:
        from alerts.teams_channel import TeamsChannel
        channels.append(('teams', TeamsChannel(), teams_cfg['url'], teams_cfg['min_severity']))
    kakao_cfg = get_kakao_config()
    if kakao_cfg:
        from alerts.kakao_channel import KakaoChannel
        channels.append(('kakao', KakaoChannel(), kakao_cfg, kakao_cfg['min_severity']))
    kakaobiz_cfg = get_kakaobiz_config()
    if kakaobiz_cfg:
        from alerts.kakao_biz_channel import KakaoBizChannel
        channels.append(('kakao_biz', KakaoBizChannel(), kakaobiz_cfg, kakaobiz_cfg['min_severity']))
    return channels


# 1-2: a transient SMTP hiccup (relay momentarily unreachable, timeout) is
# common enough that giving up after one try would under-deliver real
# incident alerts -- mirrors report_delivery.py's RETRY_ATTEMPTS=3 pattern.
# Slack/Teams aren't retried here: this ticket is specifically about email,
# and a webhook POST failing almost always means a bad/revoked URL (not a
# transient blip), where retrying 3x just delays the "발송 실패" incident
# for no benefit.
EMAIL_ALERT_RETRY_ATTEMPTS = 3


def _dispatch_one_channel(name, channel, destination, severity, source, message):
    subject = f"[InfraSight] {severity.upper()} - {source}"
    if name == 'email':
        ok, err, attempts = False, None, 0
        for attempts in range(1, EMAIL_ALERT_RETRY_ATTEMPTS + 1):
            ok, err = channel.send(destination, subject, message)
            if ok:
                break
        record_email_alert(int(time.time() * 1000), severity, source, message, destination,
                            'success' if ok else 'failed', None if ok else err, attempts)
        if not ok:
            add_incident('warn', 'InfraSight', 'SYSTEM',
                          f"{name} 알림 발송 실패 ({attempts}회 시도): {err}", _no_alert=True)
    elif name == 'kakao':
        ok, err, new_tokens = channel.send(destination, subject, message)
        if new_tokens:
            set_kakao_tokens(new_tokens['access_token'], new_tokens.get('refresh_token'), new_tokens['expires_in'])
        if not ok:
            add_incident('warn', 'InfraSight', 'SYSTEM', f"{name} 알림 발송 실패: {err}", _no_alert=True)
    else:
        ok, err = channel.send(destination, subject, message)
        if not ok:
            add_incident('warn', 'InfraSight', 'SYSTEM', f"{name} 알림 발송 실패: {err}", _no_alert=True)


def _dispatch_alert(severity, source, message, force=False):
    # Channels used to go out one at a time, in sequence -- email first (up
    # to 3 attempts, each a real SMTP connect+TLS+auth round trip over the
    # network), then Slack/Teams only once email's attempt(s) finished. A
    # slow or timing-out mail server didn't just delay the email itself, it
    # delayed every other channel behind it (and blocked the collector's
    # poll loop the whole time, since add_incident() calls this inline).
    # Firing each channel from its own thread means they all start at once,
    # so Slack/Teams land as soon as their own webhook POST completes
    # instead of waiting on email's.
    #
    # force=True is what add_incident() passes for a recovery ('info')
    # message that actually closed an open incident -- recovery is always
    # rank 0 (_SEVERITY_RANK), so without this it would never clear any
    # channel's min_severity floor (confirmed live: a device that had
    # alerted at crit went back to 'good' and nothing fired). The intent a
    # user asked for -- "tell me when it's back to normal too" -- isn't
    # "recovery is itself a crit-worthy event", so this bypasses the
    # severity floor specifically for recoveries rather than reclassifying
    # 'info' as something higher ranked (which would also start firing for
    # unrelated info-only calls like device registration).
    for name, channel, destination, min_severity in _get_alert_channels():
        if not force and _SEVERITY_RANK.get(severity, 0) < _SEVERITY_RANK.get(min_severity, 2):
            continue
        threading.Thread(target=_dispatch_one_channel, args=(name, channel, destination, severity, source, message),
                          daemon=True).start()
