"""Unit-level regression tests for internal logic that has no HTTP surface
to drive it through functional_tests.py/security_tests.py -- vendor OID
correlation, environment-sensor state mapping, topology/MAC table storage,
incident state-transition rules, and the agent's token-handling fix.

Unlike the other two test files, this one does NOT need a running server:
it imports storage.py/collector/*.py/agent.py directly and exercises them
in-process. Run it from the install directory (same place storage.py lives):

    python unit_tests.py

Why this file exists: the 2026-10 "다른 환경에서 PC에 프로그램 삭제하고..."
session fixed a long list of real bugs (H3C/Aruba-CX/classic-HP SNMP vendor
profiles, the entity_module_filter table-averaging-dilution fix, 3 env-
sensor state converters, LLDP multi-port/stale-link handling, the ack-vs-
recovery incident bug, agent-mode escalation, maintenance-vs-escalation
suppression, the alert retry queue, the agent.py token-in-argv exposure)
by verifying each one with a throwaway scratch script that was never
committed -- so none of it would be caught if someone broke it again later.
This file is those scripts, cleaned up and kept.

Safety contract (same spirit as functional_tests.py):
  - Every device/incident/escalation-tier row this creates is named/IDed
    with a "unittest_" prefix and deleted again at the end of its own test,
    even if that test's assertions fail (try/finally).
  - storage._dispatch_alert and alerts.email_channel.EmailChannel.send are
    monkeypatched for the duration of this run so nothing here can ever
    trigger a real email/Slack/Kakao send on whatever channels happen to be
    configured on this instance.
  - Never writes to a singleton setting your real environment depends on
    (escalation on/off, min severity) without saving and restoring it.
"""
import asyncio
import os
import sys
import tempfile
import time

import storage
storage.init_db()

from collector import snmp_collector as sc
from collector import snmp_profiles as sp
from collector import agent_collector as ac
from collector import escalation
from collector.state import LAST_REPORT
import agent

results = []


def check(name, condition, detail=''):
    results.append((name, 'PASS' if condition else 'FAIL', detail))
    print(f"[{'PASS' if condition else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not condition else ''))
    return condition


# Safety net for the whole run: no real outbound send, ever.
_dispatch_calls = []
storage._dispatch_alert = lambda *a, **kw: _dispatch_calls.append(a)
from alerts.email_channel import EmailChannel
EmailChannel.send = lambda self, *a, **kw: (True, None)


def run_async(coro):
    return asyncio.get_event_loop().run_until_complete(coro) if asyncio.get_event_loop().is_running() else asyncio.run(coro)


# ======================================================================
# A. MAC/VLAN collection (collector/snmp_collector.py)
# ======================================================================

def test_mac_from_oid_suffix():
    check('A1 _mac_from_oid_suffix decodes a normal index',
          sc._mac_from_oid_suffix('0.1.2.3.4.5') == '00:01:02:03:04:05')
    check('A2 _mac_from_oid_suffix handles max byte values',
          sc._mac_from_oid_suffix('255.255.255.255.255.255') == 'ff:ff:ff:ff:ff:ff')
    check('A3 _mac_from_oid_suffix rejects wrong length', sc._mac_from_oid_suffix('1.2.3') is None)
    check('A4 _mac_from_oid_suffix rejects out-of-range octet', sc._mac_from_oid_suffix('1.2.3.4.5.300') is None)


def test_collect_mac_vlan_table():
    fdb_port = {'0.1.2.3.4.5': 1, '0.1.2.3.4.6': 1, '0.1.2.3.4.7': 2, '0.1.2.3.4.8': 1, '0.1.2.3.4.9': 99}
    fdb_status = {'0.1.2.3.4.5': '3', '0.1.2.3.4.6': '3', '0.1.2.3.4.7': '3', '0.1.2.3.4.8': '4', '0.1.2.3.4.9': '3'}
    base_port_ifindex = {'1': 10001, '2': 10002}
    pvid = {'1': 10, '2': 20}
    if_descr = {'10001': 'GigabitEthernet0/1', '10002': 'GigabitEthernet0/2'}

    async def fake_walk(engine, ip, auth_data, port, oid, timeout):
        return {sc.OID_DOT1D_TP_FDB_PORT: fdb_port, sc.OID_DOT1D_TP_FDB_STATUS: fdb_status,
                sc.OID_DOT1D_BASE_PORT_IFINDEX: base_port_ifindex, sc.OID_DOT1Q_PVID: pvid}[oid]

    orig = sc._snmp_walk
    sc._snmp_walk = fake_walk
    try:
        entries = asyncio.run(sc._collect_mac_vlan_table(None, '0.0.0.0', None, 161, if_descr, timeout=1.0))
    finally:
        sc._snmp_walk = orig
    by_mac = {e['mac']: e for e in entries}
    check('A5 learned MACs correlated to ifName/VLAN', len(entries) == 4 and
          by_mac['00:01:02:03:04:05'] == {'mac': '00:01:02:03:04:05', 'ifIndex': '10001', 'ifName': 'GigabitEthernet0/1', 'vlanId': 10},
          str(entries))
    check('A6 self-status row excluded', '00:01:02:03:04:08' not in by_mac)
    orphan = by_mac.get('00:01:02:03:04:09')
    check('A7 bridge port with no ifIndex mapping handled safely (no crash)',
          orphan is not None and orphan['ifIndex'] is None and orphan['ifName'] == '' and orphan['vlanId'] is None)


def test_replace_mac_table():
    dev = 'unittest_mac_dev'
    conn = storage.get_db()
    conn.execute("DELETE FROM mac_table WHERE device_id=?", (dev,))
    conn.commit()
    conn.close()
    try:
        storage.replace_mac_table(dev, [
            {'mac': 'aa:bb:cc:dd:ee:01', 'ifIndex': '1', 'ifName': 'Gi0/1', 'vlanId': 10},
            {'mac': 'aa:bb:cc:dd:ee:02', 'ifIndex': '2', 'ifName': 'Gi0/2', 'vlanId': 20},
        ])
        check('A8 replace_mac_table initial write', len(storage.load_mac_table(dev)) == 2)
        storage.replace_mac_table(dev, [
            {'mac': 'aa:bb:cc:dd:ee:02', 'ifIndex': '2', 'ifName': 'Gi0/2', 'vlanId': 20},
            {'mac': 'aa:bb:cc:dd:ee:03', 'ifIndex': '3', 'ifName': 'Gi0/3', 'vlanId': 30},
        ])
        macs = {r['mac'] for r in storage.load_mac_table(dev)}
        check('A9 replace_mac_table drops aged-out MAC, keeps/adds the rest', macs == {'aa:bb:cc:dd:ee:02', 'aa:bb:cc:dd:ee:03'}, str(macs))
    finally:
        conn = storage.get_db()
        conn.execute("DELETE FROM mac_table WHERE device_id=?", (dev,))
        conn.commit()
        conn.close()


# ======================================================================
# B. Topology/LLDP (collector/lldp.py, storage.py device_links)
# ======================================================================

def test_top_level_module_indices():
    ent_class = {'74': 9, '75': 6, '77': 7, '78': 8, '79': 8}
    ent_contained = {'74': 11, '75': 12, '77': 14, '78': 15, '79': 16}
    top = sc._top_level_module_indices(ent_class, ent_contained)
    check('B1 top-level module found with no nesting', top == ['74'], str(top))

    # Real A5500 shape: 164 (SubCard0) nested inside 74 (Board) via a
    # container -- and values are ints, like real pysnmp objects, not str,
    # which is the exact type-mismatch bug this function had once already.
    ent_class2 = {'2': 3, '11': 5, '74': 9, '75': 6, '77': 7, '78': 8, '79': 8, '137': 5, '164': 9}
    ent_contained2 = {'11': 2, '74': 11, '75': 12, '77': 14, '78': 15, '79': 16, '137': 74, '164': 137}
    top2 = sc._top_level_module_indices(ent_class2, ent_contained2)
    check('B2 nested subcard correctly excluded (int-typed values)', top2 == ['74'], str(top2))


def test_replace_lldp_links():
    from_id = 'unittest_lldp_from'
    conn = storage.get_db()
    conn.execute("DELETE FROM device_links WHERE from_device_id=?", (from_id,))
    conn.commit()
    conn.close()
    try:
        storage.replace_lldp_links(from_id, [('neighbor_x', '1', 'Gi0/1'), ('neighbor_x', '2', 'Gi0/2')])
        conn = storage.get_db()
        rows = conn.execute("SELECT local_port FROM device_links WHERE from_device_id=? ORDER BY local_port", (from_id,)).fetchall()
        conn.close()
        check('B3 same neighbor on 2 local ports kept as 2 separate rows',
              [r['local_port'] for r in rows] == ['1', '2'], str(rows))

        storage.replace_lldp_links(from_id, [('neighbor_x', '2', 'Gi0/2'), ('neighbor_y', '3', 'Gi0/3')])
        conn = storage.get_db()
        rows2 = conn.execute("SELECT to_device_id, local_port FROM device_links WHERE from_device_id=?", (from_id,)).fetchall()
        conn.close()
        keys = {(r['to_device_id'], r['local_port']) for r in rows2}
        check('B4 disappeared neighbor (port 1) removed, survivor + new one correct',
              keys == {('neighbor_x', '2'), ('neighbor_y', '3')}, str(keys))
    finally:
        conn = storage.get_db()
        conn.execute("DELETE FROM device_links WHERE from_device_id=?", (from_id,))
        conn.commit()
        conn.close()


def test_device_delete_cleans_links():
    a, b = 'unittest_del_a', 'unittest_del_b'
    conn = storage.get_db()
    conn.execute("DELETE FROM device_links WHERE from_device_id IN (?,?) OR to_device_id IN (?,?)", (a, b, a, b))
    conn.execute("DELETE FROM devices WHERE id IN (?,?)", (a, b))
    now_ms = int(time.time() * 1000)
    conn.execute("INSERT INTO devices(id,category,name,mode,ip,fields,created_at) VALUES (?,'server','DelA','ping','127.0.0.50','{}',?)", (a, now_ms))
    conn.execute("INSERT INTO devices(id,category,name,mode,ip,fields,created_at) VALUES (?,'server','DelB','ping','127.0.0.51','{}',?)", (b, now_ms))
    conn.execute("INSERT INTO device_links(from_device_id,to_device_id,link_type,local_port,remote_port,discovered_at) VALUES (?,?,?,?,?,?)",
                 (a, b, 'lldp', '1', 'Gi0/1', now_ms))
    conn.commit()
    conn.close()
    try:
        # exactly what api_delete_device does
        conn = storage.get_db()
        conn.execute('DELETE FROM devices WHERE id=?', (a,))
        conn.execute('DELETE FROM credentials WHERE device_id=?', (a,))
        conn.execute('DELETE FROM device_links WHERE from_device_id=? OR to_device_id=?', (a, a))
        conn.commit()
        conn.close()
        conn = storage.get_db()
        remaining = conn.execute("SELECT COUNT(*) c FROM device_links WHERE from_device_id=? OR to_device_id=?", (a, a)).fetchone()['c']
        conn.close()
        check('B5 device delete cleans up its device_links rows', remaining == 0)
    finally:
        conn = storage.get_db()
        conn.execute("DELETE FROM device_links WHERE from_device_id IN (?,?) OR to_device_id IN (?,?)", (a, b, a, b))
        conn.execute("DELETE FROM devices WHERE id IN (?,?)", (a, b))
        conn.commit()
        conn.close()


# ======================================================================
# C. Environment-sensor state converters (collector/snmp_collector.py)
# ======================================================================

def test_hp_icfsensor_env():
    type_ref = {'1': '1.3.6.1.4.1.11.2.3.7.8.3.1', '2': '1.3.6.1.4.1.11.2.3.7.8.3.2'}
    status = {'1': 4, '2': 4}
    fan, supply = sc._hp_icfsensor_env(type_ref, status)
    check('C1 hp_icfsensor: good status maps to normal', fan == {'2': '1'} and supply == {'1': '1'}, str((fan, supply)))
    fan2, _ = sc._hp_icfsensor_env(type_ref, {'1': 4, '2': 2})
    check('C2 hp_icfsensor: unconfirmed status code never reads as normal', fan2 == {'2': '9'}, str(fan2))


def test_h3c_entity_env():
    ent_class = {'74': 9, '75': 6, '77': 7, '78': 8, '79': 8}
    temp_raw = {'74': 37, '75': 65535, '77': 65535, '78': 30, '79': 37}
    temp_threshold = {'74': 65535, '75': 65535, '77': 65535, '78': 67, '79': 77}
    oper_status = {'74': 3, '75': 3, '77': 3, '78': 1, '79': 1}
    phys_descr = {'74': 'MODULE LEVEL1', '75': 'PSU', '77': 'FAN', '78': 'Temp1', '79': 'Temp2'}
    t_descr, t_value, t_state, fan, supply = sc._h3c_entity_env(ent_class, temp_raw, temp_threshold, oper_status, phys_descr)
    check('C3 h3c: NA-sentinel (65535) rows excluded from temp', t_value == {'74': 37, '78': 30, '79': 37}, str(t_value))
    check('C4 h3c: no-threshold temp -> unknown, not a guess', t_state['74'] == '9')
    check('C5 h3c: under-threshold temp -> normal', t_state['78'] == '1' and t_state['79'] == '1')
    check('C6 h3c: fan/supply from oper status', fan == {'77': '1'} and supply == {'75': '1'}, str((fan, supply)))
    _, _, _, fan2, _ = sc._h3c_entity_env(ent_class, temp_raw, temp_threshold, dict(oper_status, **{'77': 4}), phys_descr)
    check('C7 h3c: dangerous(4) oper status -> critical, not normal', fan2 == {'77': '3'}, str(fan2))


def test_entity_sensor_env():
    sensor_type = {'7001': 8, '7101': 10, '7201': 6}
    sensor_scale = {'7001': 8, '7101': 9, '7201': 9}
    sensor_precision = {'7001': 0, '7101': 0, '7201': 0}
    sensor_value = {'7001': 25750, '7101': 0, '7201': 0}
    sensor_status = {'7001': 1, '7101': 1, '7201': 1}
    phys_name = {'7001': 'Temp', '7101': 'Fan', '7201': 'PSU'}
    t_descr, t_value, t_state, fan, supply = sc._entity_sensor_env(sensor_type, sensor_scale, sensor_precision, sensor_value, sensor_status, phys_name)
    check('C8 entity_sensor: milli-scale decode (25750 -> 25.8C)', t_value == {'7001': 25.8}, str(t_value))
    check('C9 entity_sensor: fan/supply from type, not class table', fan == {'7101': '1'} and supply == {'7201': '1'})
    _, _, _, _, supply2 = sc._entity_sensor_env(sensor_type, sensor_scale, sensor_precision, sensor_value, dict(sensor_status, **{'7201': 3}), phys_name)
    check('C10 entity_sensor: nonoperational(3) -> unknown, not normal', supply2 == {'7201': '9'}, str(supply2))


# ======================================================================
# D. Vendor OID profile resolution (collector/snmp_profiles.py)
# ======================================================================

def test_vendor_profile_resolution():
    cx = sp.resolve_profile(None, 'Aruba JL675A 6100 48G CL4 4SFP+ Swch PL.10.10.1090')
    check('D1 ArubaOS-CX sysDescr resolves to aruba-cx', cx['name'] == 'aruba-cx', cx['name'])
    classic = sp.resolve_profile(None, 'HP J9776A 2530-24G Switch, revision YA.16.06.0006 (Formerly ProCurve)')
    check('D2 classic ProCurve sysDescr resolves to hp (not aruba-cx)', classic['name'] == 'hp', classic['name'])
    comware = sp.resolve_profile(None, 'HP Comware Platform Software ... Hewlett-Packard Development Company, L.P.')
    check('D3 Comware sysDescr resolves to hp-comware (not hp)', comware['name'] == 'hp-comware', comware['name'])


def test_server_category_module_filter():
    cpu_table = {'1': 0, '2': 0, '74': 13, '164': 0}
    ent_class = {'2': 3, '11': 5, '74': 9, '75': 6, '77': 7, '78': 8, '79': 8, '137': 5, '164': 9}
    ent_contained = {'11': 2, '74': 11, '75': 12, '77': 14, '78': 15, '79': 16, '137': 74, '164': 137}

    async def fake_walk(engine, ip, auth_data, port, oid, timeout):
        return {sp.OID_H3C_CPU: cpu_table, sp.OID_ENT_PHYSICAL_CLASS: ent_class, sp.OID_ENT_PHYSICAL_CONTAINED_IN: ent_contained}.get(oid, {})

    async def fake_get(engine, ip, auth_data, port, oids, timeout):
        return ['h3c-server', 'HP Comware Platform Software ... Hewlett-Packard Development Company, L.P.', '1']

    orig_walk, orig_get = sc._snmp_walk, sc._snmp_get
    sc._snmp_walk, sc._snmp_get = fake_walk, fake_get
    try:
        result = asyncio.run(sc._snmp_poll('0.0.0.0', None, 161, 'server', timeout=1.0, vendor_profile='hp-comware', lldp_due=False, extended_due=False))
    finally:
        sc._snmp_walk, sc._snmp_get = orig_walk, orig_get
    check('D4 server category computes entModuleIdx via vendor profile', result.get('entModuleIdx') == ['74'], str(result.get('entModuleIdx')))
    module_idx = result.get('entModuleIdx') or []
    filtered = {k: v for k, v in result['loads'].items() if k in module_idx} or result['loads']
    vals = [int(v) for v in filtered.values() if str(v).lstrip('-').isdigit()]
    cpu = round(sum(vals) / len(vals), 1)
    check('D5 server category CPU average not diluted by zero rows', cpu == 13.0, str(cpu))


# ======================================================================
# E. Incident lifecycle (storage.py add_incident/ack_incident)
# ======================================================================

def test_ack_then_recovery():
    dev, event = 'unittest_ack_dev', 'TEST_EVENT'
    conn = storage.get_db()
    conn.execute("DELETE FROM incidents WHERE device_id=?", (dev,))
    conn.commit()
    conn.close()
    try:
        storage.add_incident('crit', 'TestDev', 'TEST', 'down', device_id=dev, event_type=event, _no_alert=True)
        conn = storage.get_db()
        row = conn.execute("SELECT * FROM incidents WHERE device_id=?", (dev,)).fetchone()
        conn.close()
        incident_id = row['id']
        storage.ack_incident(incident_id, acknowledged_by='tester')
        storage.add_incident('info', 'TestDev', 'TEST', 'recovered', device_id=dev, event_type=event, _no_alert=True)
        conn = storage.get_db()
        row2 = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        conn.close()
        check('E1 ack then real recovery -> resolved (not stuck at ack forever)',
              row2['status'] == 'resolved' and row2['resolved_at'] is not None, dict(row2))
    finally:
        conn = storage.get_db()
        conn.execute("DELETE FROM incidents WHERE device_id=?", (dev,))
        conn.commit()
        conn.close()


def test_ack_then_escalate_reopens():
    dev, event = 'unittest_ack_esc_dev', 'TEST_EVENT'
    conn = storage.get_db()
    conn.execute("DELETE FROM incidents WHERE device_id=?", (dev,))
    conn.commit()
    conn.close()
    try:
        storage.add_incident('warn', 'TestDev', 'TEST', 'degraded', device_id=dev, event_type=event, _no_alert=True)
        conn = storage.get_db()
        incident_id = conn.execute("SELECT id FROM incidents WHERE device_id=?", (dev,)).fetchone()['id']
        conn.close()
        storage.ack_incident(incident_id, acknowledged_by='tester')
        storage.add_incident('crit', 'TestDev', 'TEST', 'now critical', device_id=dev, event_type=event, _no_alert=True)
        conn = storage.get_db()
        row = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        conn.close()
        check('E2 ack then escalation re-opens the incident', row['status'] == 'open' and row['severity'] == 'crit', dict(row))
    finally:
        conn = storage.get_db()
        conn.execute("DELETE FROM incidents WHERE device_id=?", (dev,))
        conn.commit()
        conn.close()


def test_agent_mode_escalation():
    dev = 'unittest_agent_esc_dev'
    device_row = {'id': dev, 'name': 'TestAgent', 'category': 'server', 'consecutive_failures': 0}
    entity = {'status': 'good', 'online': True, 'reachable': True}
    conn = storage.get_db()
    conn.execute("DELETE FROM incidents WHERE device_id=?", (dev,))
    conn.commit()
    conn.close()
    del _dispatch_calls[:]
    try:
        now0 = time.time()
        LAST_REPORT[dev] = now0 - 20  # past ONLINE_WINDOW_SEC(15), under WARN_WINDOW_SEC(60)
        ac.check_freshness(entity, device_row)
        check('E3 agent offline 20s -> warn', entity['status'] == 'warn', entity['status'])
        before = len(_dispatch_calls)

        ac.check_freshness(entity, device_row)  # repeated warn tick -- must not re-fire
        check('E4 repeated warn tick does not re-dispatch', len(_dispatch_calls) == before)

        LAST_REPORT[dev] = now0 - 70  # past WARN_WINDOW_SEC(60) -- the actual bug
        ac.check_freshness(entity, device_row)
        check('E5 agent offline 70s -> crit escalation actually dispatches (bug fixed)',
              entity['status'] == 'crit' and len(_dispatch_calls) == before + 1)
    finally:
        LAST_REPORT.pop(dev, None)
        conn = storage.get_db()
        conn.execute("DELETE FROM incidents WHERE device_id=?", (dev,))
        conn.commit()
        conn.close()


# ======================================================================
# F. Maintenance window vs. escalation (collector/escalation.py, storage.py)
# ======================================================================

def test_maintenance_suppresses_and_renotifies():
    dev, event = 'unittest_mnt_dev', 'TEST_EVENT'
    conn = storage.get_db()
    conn.execute("DELETE FROM incidents WHERE device_id=?", (dev,))
    conn.execute("DELETE FROM devices WHERE id=?", (dev,))
    now_ms = int(time.time() * 1000)
    conn.execute("INSERT INTO devices(id,category,name,mode,ip,fields,created_at,maintenance_enabled,monitoring_enabled) "
                 "VALUES (?,'server','MaintTestDev','ping','127.0.0.52','{}',?,1,1)", (dev, now_ms))
    conn.commit()
    conn.close()
    del _dispatch_calls[:]
    orig_settings = storage.get_escalation_settings_public()
    tier_id = None
    try:
        storage.add_incident('crit', 'MaintTestDev', 'TEST', 'down during maintenance', device_id=dev, event_type=event, maintenance=True)
        check('F1 incident during maintenance: alert suppressed', len(_dispatch_calls) == 0, str(_dispatch_calls))
        conn = storage.get_db()
        row = conn.execute("SELECT * FROM incidents WHERE device_id=?", (dev,)).fetchone()
        conn.close()
        check('F2 incident during maintenance: tagged during_maintenance=1', row['during_maintenance'] == 1)

        storage.set_escalation_settings(True, 'warn')
        tier_id = storage.create_escalation_tier('1차', 'tier1@example.com', 1)
        escalation.tick()
        state = storage.get_escalation_state(row['id'])
        check('F3 escalation skips incident while device still in maintenance', state is None, str(state))

        storage.set_maintenance(dev, False, window_id=None, started_by='tester')
        check('F4 maintenance end re-dispatches the suppressed alert', len(_dispatch_calls) == 1, str(_dispatch_calls))
        conn = storage.get_db()
        row2 = conn.execute("SELECT during_maintenance FROM incidents WHERE id=?", (row['id'],)).fetchone()
        conn.close()
        check('F5 maintenance end clears during_maintenance flag', row2['during_maintenance'] == 0)

        escalation.tick()
        state2 = storage.get_escalation_state(row['id'])
        check('F6 escalation proceeds normally once maintenance is off', state2 is not None and state2['current_tier'] == 1, str(state2))
    finally:
        if tier_id is not None:
            storage.delete_escalation_tier(tier_id)
        storage.set_escalation_settings(orig_settings['enabled'], orig_settings['minSeverity'])
        conn = storage.get_db()
        conn.execute("DELETE FROM incidents WHERE device_id=?", (dev,))
        conn.execute("DELETE FROM devices WHERE id=?", (dev,))
        conn.commit()
        conn.close()


# ======================================================================
# G. Alert retry queue (storage.py pending_alert_retries, collector/alert_retry.py)
# ======================================================================

def test_alert_retry_queue():
    from collector import alert_retry
    source = 'UnittestRetrySrc'
    conn = storage.get_db()
    conn.execute("DELETE FROM pending_alert_retries WHERE source=?", (source,))
    conn.commit()
    conn.close()
    try:
        storage.enqueue_alert_retry('slack', 'crit', source, 'test message', 'simulated failure')
        conn = storage.get_db()
        row = conn.execute("SELECT * FROM pending_alert_retries WHERE source=?", (source,)).fetchone()
        conn.close()
        check('G1 enqueue_alert_retry writes a row not yet due', row is not None and row['attempts'] == 0)
        check('G2 not due before its backoff window elapses', row['id'] not in [r['id'] for r in storage.load_due_alert_retries()])

        # force it due, and make resolve_alert_channel report "not configured"
        # for this made-up channel name -- tick() should just drop the row
        conn = storage.get_db()
        conn.execute("UPDATE pending_alert_retries SET next_attempt_at=? WHERE id=?", (int(time.time() * 1000) - 1000, row['id']))
        conn.commit()
        conn.close()
        orig_resolve = storage.resolve_alert_channel
        storage.resolve_alert_channel = lambda name: None
        try:
            alert_retry.tick()
        finally:
            storage.resolve_alert_channel = orig_resolve
        conn = storage.get_db()
        gone = conn.execute("SELECT * FROM pending_alert_retries WHERE id=?", (row['id'],)).fetchone()
        conn.close()
        check('G3 unconfigured channel -> retry row dropped (nothing to retry against)', gone is None)
    finally:
        conn = storage.get_db()
        conn.execute("DELETE FROM pending_alert_retries WHERE source=?", (source,))
        conn.commit()
        conn.close()


# ======================================================================
# H. Agent token exposure fix (agent.py)
# ======================================================================

def test_agent_token_not_in_argv():
    test_appdata = tempfile.mkdtemp(prefix='infrasight_unittest_agent_')
    orig_appdata = os.environ.get('LOCALAPPDATA')
    orig_frozen = getattr(sys, 'frozen', None)
    orig_executable = sys.executable
    orig_popen = agent.subprocess.Popen
    orig_stop = agent._stop_other_running_instances
    popen_calls = []
    try:
        os.environ['LOCALAPPDATA'] = test_appdata
        sys.frozen = True
        sys.executable = os.path.join(test_appdata, 'Downloads', 'InfraSightAgent.exe')
        os.makedirs(os.path.dirname(sys.executable), exist_ok=True)
        with open(sys.executable, 'wb') as f:
            f.write(b'fake')
        agent.subprocess.Popen = lambda args, **kw: popen_calls.append(args)
        agent._stop_other_running_instances = lambda: None

        result = agent.relocate_and_relaunch_if_needed('http://192.168.1.50:5057', 'SECRET_TOKEN_ABC123')
        check('H1 relocate_and_relaunch_if_needed succeeds', result is True)
        check('H2 subprocess.Popen was called exactly once', len(popen_calls) == 1)
        joined = ' '.join(str(a) for a in (popen_calls[0] if popen_calls else []))
        check('H3 token never appears in the spawned process argv (exposure fixed)', 'SECRET_TOKEN_ABC123' not in joined, joined)
        check('H4 --token/--server flags no longer used at all', '--token' not in joined and '--server' not in joined, joined)
        saved = agent.load_config()
        check('H5 server/token instead written to the stable config file the child reads on its own',
              saved.get('server') == 'http://192.168.1.50:5057' and saved.get('token') == 'SECRET_TOKEN_ABC123', str(saved))
    finally:
        agent.subprocess.Popen = orig_popen
        agent._stop_other_running_instances = orig_stop
        sys.executable = orig_executable
        if orig_frozen is None:
            try:
                del sys.frozen
            except AttributeError:
                pass
        else:
            sys.frozen = orig_frozen
        if orig_appdata is None:
            os.environ.pop('LOCALAPPDATA', None)
        else:
            os.environ['LOCALAPPDATA'] = orig_appdata
        import shutil
        shutil.rmtree(test_appdata, ignore_errors=True)


def main():
    for fn in (
        test_mac_from_oid_suffix, test_collect_mac_vlan_table, test_replace_mac_table,
        test_top_level_module_indices, test_replace_lldp_links, test_device_delete_cleans_links,
        test_hp_icfsensor_env, test_h3c_entity_env, test_entity_sensor_env,
        test_vendor_profile_resolution, test_server_category_module_filter,
        test_ack_then_recovery, test_ack_then_escalate_reopens, test_agent_mode_escalation,
        test_maintenance_suppresses_and_renotifies, test_alert_retry_queue,
        test_agent_token_not_in_argv,
    ):
        try:
            fn()
        except Exception as e:
            check(fn.__name__, False, f'raised {type(e).__name__}: {e}')

    passed = sum(1 for _, s, _ in results if s == 'PASS')
    failed = sum(1 for _, s, _ in results if s == 'FAIL')
    print(f"\n=== {passed} passed, {failed} failed (of {len(results)}) ===")
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
