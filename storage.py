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
    # doubled here as defense in depth. The real fix is journal_mode=WAL,
    # set once on the file itself in init_db() (a persistent file property,
    # not a per-connection one, so it doesn't need repeating here).
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
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
AGENT_VERSION = '1.1.0'


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


def add_incident(severity, source, category, message, device_id=None, event_type=None, _no_alert=False):
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
    """
    now = int(time.time() * 1000)
    is_new_or_escalated = False
    conn = get_db()
    try:
        if device_id and event_type and severity != 'info':
            existing = conn.execute(
                "SELECT id, severity FROM incidents WHERE device_id=? AND event_type=? AND status='open' ORDER BY id DESC LIMIT 1",
                (device_id, event_type)).fetchone()
            if existing:
                is_new_or_escalated = existing['severity'] != severity
                conn.execute(
                    'UPDATE incidents SET severity=?, message=?, last_occurred_at=?, occurrence_count=occurrence_count+1 WHERE id=?',
                    (severity, message, now, existing['id']))
            else:
                is_new_or_escalated = True
                conn.execute(
                    'INSERT INTO incidents(ts,severity,source,category,message,status,device_id,event_type,'
                    'first_occurred_at,last_occurred_at,occurrence_count) VALUES (?,?,?,?,?,?,?,?,?,?,1)',
                    (now, severity, source, category, message, 'open', device_id, event_type, now, now))
        else:
            status = 'resolved' if severity == 'info' else 'open'
            is_new_or_escalated = status == 'open'
            conn.execute(
                'INSERT INTO incidents(ts,severity,source,category,message,status,device_id,event_type,'
                'first_occurred_at,last_occurred_at,resolved_at,occurrence_count) VALUES (?,?,?,?,?,?,?,?,?,?,?,1)',
                (now, severity, source, category, message, status, device_id, event_type,
                 now, now, now if status == 'resolved' else None))
            if device_id and event_type and severity == 'info':
                conn.execute(
                    "UPDATE incidents SET status='resolved', resolved_at=? WHERE device_id=? AND event_type=? AND status='open'",
                    (now, device_id, event_type))
        conn.commit()
    finally:
        conn.close()

    if is_new_or_escalated and not _no_alert:
        _dispatch_alert(severity, source, message)


def ack_incident(incident_id, acknowledged_by=None):
    now = int(time.time() * 1000)
    conn = get_db()
    conn.execute(
        "UPDATE incidents SET status='ack', acknowledged_by=?, acknowledged_at=? WHERE id=? AND status='open'",
        (acknowledged_by, now, incident_id))
    conn.commit()
    conn.close()


def in_maintenance(device_row):
    """True if this device's poll results should be silenced from add_incident
    right now. Polling itself must NOT be skipped -- only event creation --
    so that recovery during a maintenance window is still observable once the
    window ends (directive section 15)."""
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


def set_maintenance(device_id, enabled, start=None, end=None, reason=None):
    conn = get_db()
    conn.execute(
        'UPDATE devices SET maintenance_enabled=?, maintenance_start=?, maintenance_end=?, maintenance_reason=? WHERE id=?',
        (1 if enabled else 0, start, end, reason, device_id))
    conn.commit()
    conn.close()


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
    return {'status': 'ok', 'username': row['username'], 'role': row['role'], 'session_version': session_version,
            'must_change_password': bool(row['must_change_password'])}


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
        'SELECT id,username,role,created_at,last_login_at,locked_until,is_active FROM users ORDER BY id'
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


def _get_alert_channels():
    """Every currently-configured outbound alert channel. Each entry is
    (name, AlertChannel instance, destination, this channel's own min-severity
    floor). Adding a new one later (Teams, Slack, ...) is: write an
    alerts/<x>_channel.py implementing alerts.base.AlertChannel, add a
    get_<x>_config()/set_<x>_config() pair next to get_smtp_config() above
    for its settings, and append one line here -- _dispatch_alert itself
    never has to change.

    The web channel isn't listed here because it doesn't need dispatching:
    every incident is already a DB row the instant add_incident() writes it,
    and the dashboard's existing 2.2s poll (index.html's syncState) picks it
    up and raises a toast for anything new/escalated/recovered. This list is
    only for channels that need an explicit outbound push."""
    channels = []
    smtp_cfg = get_smtp_config()
    if smtp_cfg:
        from alerts.email_channel import EmailChannel
        channel = EmailChannel(smtp_cfg['host'], smtp_cfg['port'], smtp_cfg['username'], smtp_cfg['password'], smtp_cfg['use_tls'])
        channels.append(('email', channel, smtp_cfg['alert_to'], smtp_cfg['min_severity']))
    return channels


def _dispatch_alert(severity, source, message):
    for name, channel, destination, min_severity in _get_alert_channels():
        if _SEVERITY_RANK.get(severity, 0) < _SEVERITY_RANK.get(min_severity, 2):
            continue
        subject = f"[InfraSight] {severity.upper()} - {source}"
        ok, err = channel.send(destination, subject, message)
        if not ok:
            add_incident('warn', 'InfraSight', 'SYSTEM', f"{name} 알림 발송 실패: {err}", _no_alert=True)
