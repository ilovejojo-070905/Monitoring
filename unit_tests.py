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


def test_mib_standard_vs_vendor_separation():
    mib, is_std = sp.mib_info(sp.OID_HR_PROCESSOR_LOAD)
    check('D6 HOST-RESOURCES-MIB OID classified as standard', is_std is True, (mib, is_std))
    mib, is_std = sp.mib_info(sp.OID_CISCO_CPU_5MIN)
    check('D7 CISCO-PROCESS-MIB OID classified as vendor (not standard)', is_std is False, (mib, is_std))
    mib, is_std = sp.mib_info('1.3.6.1.9.9.9999.1')
    check('D8 unknown OID honestly reports UNKNOWN/None, not a guess', mib == 'UNKNOWN' and is_std is None, (mib, is_std))

    cisco_summary = sp.profile_mib_summary('cisco')
    check('D9 cisco profile summary has no standard OIDs (its cpu/mem are both vendor-only)',
          len(cisco_summary['standard']) == 0, cisco_summary)
    check('D10 cisco profile summary lists its vendor OIDs', len(cisco_summary['vendor']) == 3, cisco_summary)

    hp_summary = sp.profile_mib_summary('hp')
    check('D11 hp profile summary includes its HOST-RESOURCES-MIB fallback as standard',
          any(e['oid'] == sp.OID_HR_PROCESSOR_LOAD for e in hp_summary['standard']), hp_summary)
    check('D12 hp profile summary includes its STATISTICS-MIB OIDs as vendor',
          any(e['mib'].startswith('STATISTICS-MIB') for e in hp_summary['vendor']), hp_summary)


# ======================================================================
# J. 64-bit interface counters + traffic-rate validation
# (collector/snmp_collector.py compute_counter_delta / _snmp_poll / sample_snmp)
# ======================================================================

def test_compute_counter_delta():
    # 합성 데이터: 실제 10Gbps+ 링크나 재부팅 타이밍 없이도 순수 함수라
    # 바로 검증 가능. 실측 검증은 불가(32비트 카운터가 실제로 한 바퀴
    # 돌 만큼의 트래픽을 이 환경에서 만들어낼 방법이 없음) -- 합성으로만
    # 다룬다는 걸 이름/주석에 명시.
    d, note = sc.compute_counter_delta(2000, 1000, 32, 2.0, 1000)
    check('J1 normal increase -> ok, plain subtraction', d == 1000 and note == 'ok', (d, note))

    # 10Gbps 인터페이스가 60초간 안 걸렸다가 다시 걸림 -- 32비트가 그 사이
    # 한 바퀴 도는 데 필요한 속도(~0.57Gbps)가 링크 속도 대비 충분히
    # 현실적이라 랩어라운드로 판단해야 함.
    prev, curr = (1 << 32) - 1000, 2000
    d, note = sc.compute_counter_delta(curr, prev, 32, 60.0, 10_000)
    check('J2 32-bit wraparound plausible on a 10Gbps link after a 60s gap -> wrapped',
          note == 'wrapped' and d == (curr - prev + (1 << 32)), (d, note))

    # 1Gbps 인터페이스에서 2초 사이 32비트가 한 바퀴 돌려면 17Gbps가
    # 필요함 -- 그 링크로는 물리적으로 불가능하니 인터페이스 재생성/
    # 카운터 리셋으로 판단해야 함.
    d, note = sc.compute_counter_delta(500, 3_000_000_000, 32, 2.0, 1000)
    check('J3 implausible wraparound on a 1Gbps link -> treated as reset (not wrapped)',
          note == 'reset' and d == 500, (d, note))

    # 64비트는 실질적으로 절대 안 돌기 때문에 감소는 항상 reset으로.
    d, note = sc.compute_counter_delta(100, 10_000_000_000, 64, 2.0, 1000)
    check('J4 64-bit counter decrease -> reset (2**64 wraparound is never physically plausible)',
          note == 'reset' and d == 100, (d, note))

    # ifHighSpeed 대비로도 물리적으로 불가능한 수준이면 0으로 깎임(터무니
    # 없는 순간 속도를 화면에 보여주는 대신).
    d, note = sc.compute_counter_delta(10_000_000_000, 0, 64, 1.0, 10)
    check('J5 delta far beyond ifHighSpeed -> implausible, clamped to 0', note == 'implausible' and d == 0, (d, note))


def test_hc_counter_fallback_full_coverage():
    ifdescr = {'1': 'Gi0/1', '2': 'Gi0/2'}
    oper = {'1': '1', '2': '1'}
    in_hc = {'1': '123456789012345', '2': '234567890123456'}
    out_hc = {'1': '111111111111111', '2': '222222222222222'}

    async def fake_walk(engine, ip, auth_data, port, oid, timeout):
        return {
            sc.OID_IF_DESCR: ifdescr, sc.OID_IF_ALIAS: {}, sc.OID_IF_OPER_STATUS: oper,
            sc.OID_IF_HC_IN_OCTETS: in_hc, sc.OID_IF_HC_OUT_OCTETS: out_hc,
            sp.OID_HR_PROCESSOR_LOAD: {},
        }.get(oid, {})

    async def fake_get(engine, ip, auth_data, port, oids, timeout):
        return ['dev', 'generic sysDescr', '1'], None

    orig_walk, orig_get = sc._snmp_walk, sc._snmp_get
    sc._snmp_walk, sc._snmp_get = fake_walk, fake_get
    try:
        result = asyncio.run(sc._snmp_poll('0.0.0.0', None, 161, 'net', timeout=1.0, vendor_profile='generic', lldp_due=False, extended_due=False))
    finally:
        sc._snmp_walk, sc._snmp_get = orig_walk, orig_get
    check('J6 full HC coverage (every interface answers) -> 64-bit counters used',
          result.get('ifCounterBits') == 64, result.get('ifCounterBits'))
    check('J7 in_oct is the HC table when coverage is full', result['in_oct'] == in_hc, result['in_oct'])


def test_hc_counter_fallback_partial_coverage():
    ifdescr = {'1': 'Gi0/1', '2': 'Gi0/2'}
    oper = {'1': '1', '2': '1'}
    in_hc = {'1': '123456789012345'}  # 2개 중 1개만 -- 불완전한 HC 커버리지
    out_hc = {'1': '111111111111111'}
    in_32 = {'1': '1000', '2': '2000'}
    out_32 = {'1': '500', '2': '600'}

    async def fake_walk(engine, ip, auth_data, port, oid, timeout):
        return {
            sc.OID_IF_DESCR: ifdescr, sc.OID_IF_ALIAS: {}, sc.OID_IF_OPER_STATUS: oper,
            sc.OID_IF_HC_IN_OCTETS: in_hc, sc.OID_IF_HC_OUT_OCTETS: out_hc,
            sc.OID_IF_IN_OCTETS: in_32, sc.OID_IF_OUT_OCTETS: out_32,
            sp.OID_HR_PROCESSOR_LOAD: {},
        }.get(oid, {})

    async def fake_get(engine, ip, auth_data, port, oids, timeout):
        return ['dev', 'generic sysDescr', '1'], None

    orig_walk, orig_get = sc._snmp_walk, sc._snmp_get
    sc._snmp_walk, sc._snmp_get = fake_walk, fake_get
    try:
        result = asyncio.run(sc._snmp_poll('0.0.0.0', None, 161, 'net', timeout=1.0, vendor_profile='generic', lldp_due=False, extended_due=False))
    finally:
        sc._snmp_walk, sc._snmp_get = orig_walk, orig_get
    check('J8 partial HC coverage -> falls back to 32-bit for the whole device (no per-interface mixing)',
          result.get('ifCounterBits') == 32, result.get('ifCounterBits'))
    check('J9 in_oct is the 32-bit table when HC coverage is incomplete', result['in_oct'] == in_32, result['in_oct'])


def test_sample_snmp_flags_low_confidence_traffic():
    from collector.state import hist as _hist
    dev_id = 'unittest_snmp_traffic_dev'
    device_row = {
        'id': dev_id, 'ip': '0.0.0.0', 'name': 'UnitTest Traffic Device',
        'fields': {'snmpVersion': 'v2c', 'snmpPort': 161, 'community': 'public'},
        'category': 'net', 'mode': 'snmp', 'vendor_profile': 'generic',
        'timeout_sec': 1.0, 'consecutive_failures': 0,
    }
    entity = {'status': 'good', 'hist': {'latency': _hist(0)}}

    canned = {
        'reachable': True, 'latencyMs': 1.0,
        'sysName': 'dev', 'sysDescr': 'generic', 'sysUptimeTicks': '100',
        'oper': {'1': '1'}, 'ifDescr': {'1': 'Gi0/1'}, 'ifAlias': {},
        'ifCounterBits': 32,
        # 1Gbps로 명시 -- compute_counter_delta가 속도를 모를 때 쓰는
        # 기본값(10Gbps 가정)보다 훨씬 낮게 잡아서, 3틱의 카운터 급감이
        # "랩어라운드로도 말이 안 되는" 수준이 되게 함(아래 J13).
        'ifHighSpeed': {'1': '1000'},
    }

    async def fake_poll(*a, **kw):
        return dict(canned)

    orig_poll = sc._snmp_poll
    sc._snmp_poll = fake_poll
    try:
        # 1틱: 카운터 2,000,000바이트에서 시작 -- 아직 이전 샘플이 없어서
        # 속도 계산은 안 되고 _snmpIfacePrev만 쌓인다.
        canned['in_oct'] = {'1': '2000000'}
        canned['out_oct'] = {'1': '1000000'}
        sc.sample_snmp(entity, device_row)
        check('J10 first tick: no prior sample -> no trafficLowConfidence flag yet',
              'trafficLowConfidence' not in entity, entity.get('trafficLowConfidence'))

        # 2틱: 60초가 지났는데(기본 2초 틱의 30배) 카운터는 정상적으로
        # 증가만 함 -- 카운터 자체는 'ok'지만 측정 간격이 너무 길어서
        # lowConfidence가 떠야 한다(비정상 카운터 변화 검증 항목).
        entity['_snmpPrev']['t'] -= 60.0
        canned['in_oct'] = {'1': '2500000'}
        canned['out_oct'] = {'1': '1200000'}
        sc.sample_snmp(entity, device_row)
        check('J11 long measurement gap (60s) -> trafficLowConfidence true even though counters just increased normally',
              entity.get('trafficLowConfidence') is True, entity.get('trafficLowConfidence'))
        check('J12 per-interface lowConfidence flag also set for the same reason',
              entity['interfaces'][0]['trafficLowConfidence'] is True, entity['interfaces'][0])

        # 3틱: 정상 간격(2초)인데 카운터가 재생성급으로 뚝 떨어짐(32비트가
        # 2초 안에 다 돌 수 없는 1Gbps 링크) -- counterNote가 reset이라
        # lowConfidence가 떠야 한다.
        entity['_snmpPrev']['t'] -= 2.0  # 다음 호출에서 dt가 다시 (신뢰 가능한) 2초가 되게 보정
        canned['in_oct'] = {'1': '500'}
        canned['out_oct'] = {'1': '300'}
        sc.sample_snmp(entity, device_row)
        check('J13 counter reset detected -> trafficLowConfidence true, traffic not negative-clamped-to-zero silently',
              entity['interfaces'][0]['trafficLowConfidence'] is True, entity['interfaces'][0])
    finally:
        sc._snmp_poll = orig_poll
        conn = storage.get_db()
        conn.execute("DELETE FROM devices WHERE id=?", (dev_id,))
        conn.execute("DELETE FROM incidents WHERE device_id=?", (dev_id,))
        conn.commit()
        conn.close()


def test_server_category_module_filter():
    cpu_table = {'1': 0, '2': 0, '74': 13, '164': 0}
    ent_class = {'2': 3, '11': 5, '74': 9, '75': 6, '77': 7, '78': 8, '79': 8, '137': 5, '164': 9}
    ent_contained = {'11': 2, '74': 11, '75': 12, '77': 14, '78': 15, '79': 16, '137': 74, '164': 137}

    async def fake_walk(engine, ip, auth_data, port, oid, timeout):
        return {sp.OID_H3C_CPU: cpu_table, sp.OID_ENT_PHYSICAL_CLASS: ent_class, sp.OID_ENT_PHYSICAL_CONTAINED_IN: ent_contained}.get(oid, {})

    async def fake_get(engine, ip, auth_data, port, oids, timeout):
        return ['h3c-server', 'HP Comware Platform Software ... Hewlett-Packard Development Company, L.P.', '1'], None

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


# ======================================================================
# I. SNMP error classification (collector/snmp_collector.py classify_snmp_error)
# ======================================================================

def test_classify_snmp_error():
    # 합성 데이터 테스트: 실제 장비 없이도 pysnmp.proto.errind의 진짜 클래스
    # 인스턴스를 직접 만들어서(실측으로 이미 확인된 "문자열이 아니라 클래스
    # 인스턴스" 사실에 기반) classify_snmp_error가 제대로 분류하는지 검증.
    # 실측 검증(실제 타임아웃/인증실패 장비 대상)은 별도 -- 이 테스트는
    # 그 둘을 섞지 않는다.
    from pysnmp.proto import errind

    kind, _ = sc.classify_snmp_error(errind.RequestTimedOut('no response'))
    check('I1 RequestTimedOut classified as timeout', kind == 'timeout', kind)

    kind, _ = sc.classify_snmp_error(errind.UnknownCommunityName('bad community'))
    check('I2 UnknownCommunityName classified as auth', kind == 'auth', kind)

    kind, _ = sc.classify_snmp_error(errind.AuthenticationFailure('bad auth'))
    check('I3 AuthenticationFailure (SNMPv3) classified as auth', kind == 'auth', kind)

    kind, _ = sc.classify_snmp_error(errind.LoopTerminated('loop'))
    check('I4 unrecognized errind class falls back to transport_error (safe default)', kind == 'transport_error', kind)

    kind, _ = sc.classify_snmp_error(None, error_status=1)
    check('I5 errorStatus without errorIndication classified as protocol_error', kind == 'protocol_error', kind)

    kind, _ = sc.classify_snmp_error(None, error_status=None)
    check('I6 no error at all -> kind is None', kind is None, kind)

    check('I7 reason mapping: timeout -> SNMP_TIMEOUT (existing devices.last_failure_reason enum)',
          sc.SNMP_ERROR_KIND_TO_REASON.get('timeout') == 'SNMP_TIMEOUT')
    check('I8 reason mapping: auth -> SNMP_AUTH_ERROR (previously never produced)',
          sc.SNMP_ERROR_KIND_TO_REASON.get('auth') == 'SNMP_AUTH_ERROR')
    check('I9 unmapped kind falls back to SNMP_TIMEOUT via .get default',
          sc.SNMP_ERROR_KIND_TO_REASON.get('transport_error', 'SNMP_TIMEOUT') == 'SNMP_TIMEOUT')


def test_snmp_get_returns_tuple_on_unreachable():
    # 합성 데이터: 실제 네트워크 접근 없이 get_cmd 자체를 가짜로 바꿔서
    # _snmp_get이 (None, 'timeout') 형태의 튜플을 돌려주는지 확인.
    from pysnmp.proto import errind

    async def fake_get_cmd(*a, **kw):
        return errind.RequestTimedOut('no response'), 0, 0, []

    orig_get_cmd = sc.get_cmd
    sc.get_cmd = fake_get_cmd
    try:
        values, kind = asyncio.run(sc._snmp_get(None, '0.0.0.0', None, 161, ['1.3.6.1.2.1.1.5.0'], timeout=0.1, retries=0))
        check('I10 _snmp_get returns (None, "timeout") when get_cmd times out', values is None and kind == 'timeout', (values, kind))
    finally:
        sc.get_cmd = orig_get_cmd


def main():
    for fn in (
        test_mac_from_oid_suffix, test_collect_mac_vlan_table, test_replace_mac_table,
        test_top_level_module_indices, test_replace_lldp_links, test_device_delete_cleans_links,
        test_hp_icfsensor_env, test_h3c_entity_env, test_entity_sensor_env,
        test_vendor_profile_resolution, test_mib_standard_vs_vendor_separation, test_server_category_module_filter,
        test_compute_counter_delta, test_hc_counter_fallback_full_coverage, test_hc_counter_fallback_partial_coverage,
        test_sample_snmp_flags_low_confidence_traffic,
        test_ack_then_recovery, test_ack_then_escalate_reopens, test_agent_mode_escalation,
        test_maintenance_suppresses_and_renotifies, test_alert_retry_queue,
        test_agent_token_not_in_argv,
        test_classify_snmp_error, test_snmp_get_returns_tuple_on_unreachable,
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
