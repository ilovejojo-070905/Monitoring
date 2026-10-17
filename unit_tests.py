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
import concurrent.futures
import os
import shutil
import sqlite3
import sys
import tempfile
import time

import storage
storage.init_db()

from collector import snmp_collector as sc
from collector import snmp_profiles as sp
from collector import agent_collector as ac
from collector import escalation
from collector import sla
from collector.state import LAST_REPORT
from collector import sflow_parser, netflow_parser
import agent
import struct

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
        # OID_DOT1Q_TP_FDB_PORT는 일부러 빈 dict -- 이 합성 장비는 실측으로
        # 확인한 Cisco 2960S처럼 Q-BRIDGE-MIB 테이블에 응답 안 하는 경우를
        # 흉내내서, 기존 dot1dTpFdbTable+PVID 폴백 경로를 그대로 검증한다.
        return {sc.OID_DOT1D_TP_FDB_PORT: fdb_port, sc.OID_DOT1D_TP_FDB_STATUS: fdb_status,
                sc.OID_DOT1D_BASE_PORT_IFINDEX: base_port_ifindex, sc.OID_DOT1Q_PVID: pvid,
                sc.OID_DOT1Q_TP_FDB_PORT: {}}[oid]

    orig = sc._snmp_walk
    sc._snmp_walk = fake_walk
    try:
        entries = asyncio.run(sc._collect_mac_vlan_table(None, '0.0.0.0', None, 161, if_descr, timeout=1.0))
    finally:
        sc._snmp_walk = orig
    by_mac = {e['mac']: e for e in entries}
    check('A5 learned MACs correlated to ifName/VLAN (dot1d+PVID fallback path)', len(entries) == 4 and
          by_mac['00:01:02:03:04:05'] == {'mac': '00:01:02:03:04:05', 'ifIndex': '10001', 'ifName': 'GigabitEthernet0/1', 'vlanId': 10},
          str(entries))
    check('A6 self-status row excluded', '00:01:02:03:04:08' not in by_mac)
    orphan = by_mac.get('00:01:02:03:04:09')
    check('A7 bridge port with no ifIndex mapping handled safely (no crash)',
          orphan is not None and orphan['ifIndex'] is None and orphan['ifName'] == '' and orphan['vlanId'] is None)


def test_mac_vlan_from_dot1q_oid_suffix():
    vlan_id, mac = sc._mac_vlan_from_dot1q_oid_suffix('10.0.1.2.3.4.5')
    check('A8 dot1q suffix decodes vlan + mac correctly', vlan_id == 10 and mac == '00:01:02:03:04:05', (vlan_id, mac))
    vlan_id, mac = sc._mac_vlan_from_dot1q_oid_suffix('1.2.3')
    check('A9 dot1q suffix rejects wrong length', mac is None, (vlan_id, mac))
    vlan_id, mac = sc._mac_vlan_from_dot1q_oid_suffix('0.1.2.3.4.5.6')
    check('A10 dot1q suffix rejects vlan id 0 (not a valid VLAN)', mac is None, (vlan_id, mac))


def test_collect_mac_vlan_table_prefers_dot1q_when_available():
    # 신규 기능(2026-10-16, "MAC/VLAN 정보 확장") -- HPE/Aruba(classic)
    # 실장비에 직접 걸어서 확인한 대로, dot1qTpFdbTable이 응답하면(Cisco와
    # 달리 커뮤니티 컨텍스트 없이도 바로 보임) 그게 우선이고 PVID 근사치는
    # 전혀 안 쓰인다 -- 트렁크 포트에서도 정확한 VLAN을 돌려줘야 함.
    base_port_ifindex = {'1': 10001, '2': 10002}
    if_descr = {'10001': 'GigabitEthernet0/1', '10002': 'GigabitEthernet0/2'}
    # VLAN 999는 포트1의 PVID(가정상 10)와 다름 -- dot1q 경로를 썼다는 걸
    # 확실히 구분하기 위해 일부러 PVID와 다른 값으로 둠.
    dot1q_port = {'999.0.1.2.3.4.5': 1, '20.0.1.2.3.4.6': 2}
    dot1q_status = {'999.0.1.2.3.4.5': '3', '20.0.1.2.3.4.6': '3'}

    async def fake_walk(engine, ip, auth_data, port, oid, timeout):
        return {
            sc.OID_DOT1D_BASE_PORT_IFINDEX: base_port_ifindex,
            sc.OID_DOT1Q_TP_FDB_PORT: dot1q_port,
            sc.OID_DOT1Q_TP_FDB_STATUS: dot1q_status,
        }[oid]

    orig = sc._snmp_walk
    sc._snmp_walk = fake_walk
    try:
        entries = asyncio.run(sc._collect_mac_vlan_table(None, '0.0.0.0', None, 161, if_descr, timeout=1.0))
    finally:
        sc._snmp_walk = orig
    by_mac = {e['mac']: e for e in entries}
    check('A11 dot1q path used when it answers -- exact per-MAC VLAN, not a PVID guess',
          by_mac.get('00:01:02:03:04:05', {}).get('vlanId') == 999, by_mac)
    check('A12 second entry correlated to its own port/VLAN correctly',
          by_mac.get('00:01:02:03:04:06') == {'mac': '00:01:02:03:04:06', 'ifIndex': '10002', 'ifName': 'GigabitEthernet0/2', 'vlanId': 20},
          by_mac)


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


def test_lldp_bidirectional_confirmation():
    # 신규 기능(2026-10-16, "LLDP 양방향 확인 여부"): A가 포트1에서 B를,
    # B가 포트2에서 A를 봤다고 서로 맞교대로(local/remote 포트가 정확히
    # 뒤집힘) 보고하면 confirmed=True. C는 D를 봤다고 보고했지만 D는
    # InfraSight에 등록 안 돼 있거나 LLDP가 꺼져 있어 반대 방향 보고가
    # 전혀 없는 상황 -- confirmed=False여야 한다.
    a, b, c = 'unittest_lldp_a', 'unittest_lldp_b', 'unittest_lldp_c'
    conn = storage.get_db()
    for x in (a, b, c):
        conn.execute("DELETE FROM device_links WHERE from_device_id=? OR to_device_id=?", (x, x))
    conn.commit()
    conn.close()
    try:
        storage.replace_lldp_links(a, [(b, '1', '2')])   # A: 포트1에서 B를 봤고, B의 포트가 2라고 보고
        storage.replace_lldp_links(b, [(a, '2', '1')])   # B: 포트2에서 A를 봤고, A의 포트가 1이라고 보고 (맞교대)
        storage.replace_lldp_links(c, [('unittest_lldp_unregistered_d', '1', '1')])  # C만 보고, 반대쪽 없음
        links = {(l['from_device_id'], l['to_device_id']): l['confirmed'] for l in storage.load_device_links()
                 if l['from_device_id'] in (a, b, c)}
        check('B5 A->B confirmed (B reported the exact reverse)', links.get((a, b)) is True, links)
        check('B6 B->A confirmed (symmetric)', links.get((b, a)) is True, links)
        check('B7 C->unregistered-D NOT confirmed (no reverse report exists)',
              links.get((c, 'unittest_lldp_unregistered_d')) is False, links)
    finally:
        conn = storage.get_db()
        for x in (a, b, c):
            conn.execute("DELETE FROM device_links WHERE from_device_id=? OR to_device_id=?", (x, x))
        conn.commit()
        conn.close()


def test_lldp_walk_distinguishes_failure_from_confirmed_empty():
    # 신규 기능(2026-10-16, "오래된 링크와 수집 실패를 실제 단절과 구별"):
    # _snmp_walk(return_status=True)가 "끝까지 확인했는데 0개"와 "도중에
    # 에러로 끊김"을 구분하는지, 그리고 walk_lldp_neighbors가 그 신호를
    # 그대로 confirmed로 전달하는지 확인. 실제 장비의 LLDP를 그 자리에서
    # 끄거나 SNMP를 끊어서 재현할 방법이 없어 합성 데이터로만 검증.
    async def fake_walk_confirmed_empty(engine, ip, auth_data, port, oid, timeout, return_status=False):
        return ({}, True) if return_status else {}

    async def fake_walk_failed(engine, ip, auth_data, port, oid, timeout, return_status=False):
        return ({}, False) if return_status else {}

    from collector import lldp as lldp_mod
    orig = sc._snmp_walk
    try:
        sc._snmp_walk = fake_walk_confirmed_empty
        result = asyncio.run(lldp_mod.walk_lldp_neighbors(None, '0.0.0.0', None, 161))
        check('B8 confirmed-empty walk -> neighbors=[] AND confirmed=True (real "no neighbors" signal)',
              result == {'neighbors': [], 'confirmed': True}, result)

        sc._snmp_walk = fake_walk_failed
        result = asyncio.run(lldp_mod.walk_lldp_neighbors(None, '0.0.0.0', None, 161))
        check('B9 failed walk -> neighbors=[] AND confirmed=False (collection failure, not a real disconnect)',
              result == {'neighbors': [], 'confirmed': False}, result)
    finally:
        sc._snmp_walk = orig


def test_sample_snmp_lldp_gate_respects_confirmed_flag():
    # sample_snmp가 confirmed=False일 때 기존 링크를 절대 안 건드리고,
    # confirmed=True + neighbors=[]일 때는 진짜로 지우는지 끝까지 확인.
    from collector.state import hist as _hist
    dev_id = 'unittest_snmp_lldp_gate_dev'
    other_id = 'unittest_snmp_lldp_gate_other'
    conn = storage.get_db()
    conn.execute("DELETE FROM device_links WHERE from_device_id=?", (dev_id,))
    conn.commit()
    conn.close()
    storage.replace_lldp_links(dev_id, [(other_id, '1', 'Gi0/1')])  # 기존 링크 하나 심어둠

    device_row = {
        'id': dev_id, 'ip': '0.0.0.0', 'name': 'UnitTest LLDP Gate Device',
        'fields': {'snmpVersion': 'v2c', 'snmpPort': 161, 'community': 'public'},
        'category': 'net', 'mode': 'snmp', 'vendor_profile': 'generic',
        'timeout_sec': 1.0, 'consecutive_failures': 0,
    }
    entity = {'status': 'good', 'hist': {'latency': _hist(0)}}
    base_result = {
        'reachable': True, 'latencyMs': 1.0, 'sysName': 'dev', 'sysDescr': 'generic', 'sysUptimeTicks': '100',
        'oper': {}, 'ifDescr': {}, 'ifAlias': {}, 'in_oct': {}, 'out_oct': {}, 'ifCounterBits': 32,
    }

    async def fake_poll_failed(*a, **kw):
        return dict(base_result, lldp={'neighbors': [], 'confirmed': False})

    async def fake_poll_confirmed_empty(*a, **kw):
        return dict(base_result, lldp={'neighbors': [], 'confirmed': True})

    orig_poll = sc._snmp_poll
    try:
        sc._snmp_poll = fake_poll_failed
        sc.sample_snmp(entity, device_row)
        remaining = [l for l in storage.load_device_links() if l['from_device_id'] == dev_id]
        check('B10 collection-failure tick (confirmed=False) leaves the existing stale link untouched',
              len(remaining) == 1, remaining)

        sc._snmp_poll = fake_poll_confirmed_empty
        sc.sample_snmp(entity, device_row)
        remaining2 = [l for l in storage.load_device_links() if l['from_device_id'] == dev_id]
        check('B11 confirmed-empty tick (confirmed=True, 0 neighbors) actually clears the stale link',
              len(remaining2) == 0, remaining2)
    finally:
        sc._snmp_poll = orig_poll
        conn = storage.get_db()
        conn.execute("DELETE FROM device_links WHERE from_device_id=?", (dev_id,))
        conn.commit()
        conn.close()


def test_topology_layout_persistence():
    # 신규 기능(2026-10-16, "수동 토폴로지 배치 정보를 자동 갱신 중
    # 보존"): 위치가 이제 서버(settings 테이블)에도 저장되는지 -- 저장한
    # 그대로 읽히는지, 그리고 두 번째 저장이 첫 번째 것을 통째로 교체하는지
    # (saveTopoLayout이 매번 전체 레이아웃 dict를 보내는 것과 같은 방식).
    orig = storage.get_topology_layout()
    try:
        storage.set_topology_layout({'hub': {'x': 70, 'y': 280}, 'dev1': {'x': 120.5, 'y': 300}})
        loaded = storage.get_topology_layout()
        check('B12 topology layout round-trips through storage', loaded == {'hub': {'x': 70, 'y': 280}, 'dev1': {'x': 120.5, 'y': 300}}, loaded)

        storage.set_topology_layout({'dev2': {'x': 5, 'y': 6}})
        loaded2 = storage.get_topology_layout()
        check('B13 second save fully replaces the layout (not merged)', loaded2 == {'dev2': {'x': 5, 'y': 6}}, loaded2)
    finally:
        storage.set_topology_layout(orig)


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

        # 2틱: 60초 넘게 지났는데(기본 2초 틱의 30배) 카운터는 정상적으로
        # 증가만 함 -- 카운터 자체는 'ok'지만 측정 간격이 너무 길어서
        # lowConfidence가 떠야 한다(비정상 카운터 변화 검증 항목). 정확히
        # 60.0이 아니라 60.5를 빼는 이유: 두 time.time() 호출 사이 실제
        # 경과 시간이 OS 클럭 해상도 때문에 0으로 반올림될 수 있어서,
        # 정확히 60.0으로 빼면 dt가 경계값(== 60, "신뢰 가능" 쪽)에
        # 걸려 테스트가 간헐적으로 실패했었음(실측으로 확인).
        entity['_snmpPrev']['t'] -= 60.5
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

def test_related_network_failure_correlation():
    # 신규 기능(2026-10-17, "상위 네트워크 장비 장애와 하위 장비 장애의
    # 연관성을 분석할 수 있도록 한다"): 스위치(net)가 지금 연속 실패 중
    # 이고, 그 스위치와 device_links로 바로 연결된 서버가 REACHABILITY
    # 장애를 새로 발생시키면, 메시지에 그 스위치가 언급돼야 한다.
    # 연결 안 된(또는 연결됐지만 지금 멀쩡한) 스위치는 언급되면 안 된다.
    switch_down = 'unittest_corr_switch_down'
    switch_up = 'unittest_corr_switch_up'
    server = 'unittest_corr_server'
    conn = storage.get_db()
    for d in (switch_down, switch_up, server):
        conn.execute("DELETE FROM devices WHERE id=?", (d,))
    conn.execute("DELETE FROM device_links WHERE from_device_id=? OR to_device_id=?", (server, server))
    conn.execute("DELETE FROM incidents WHERE device_id=?", (server,))
    now_ms = int(time.time() * 1000)
    conn.execute("INSERT INTO devices(id,category,name,mode,ip,fields,created_at,consecutive_failures) "
                 "VALUES (?,'net','DownSwitch','ping','127.0.0.60','{}',?,5)", (switch_down, now_ms))
    conn.execute("INSERT INTO devices(id,category,name,mode,ip,fields,created_at,consecutive_failures) "
                 "VALUES (?,'net','UpSwitch','ping','127.0.0.61','{}',?,0)", (switch_up, now_ms))
    conn.execute("INSERT INTO devices(id,category,name,mode,ip,fields,created_at,consecutive_failures) "
                 "VALUES (?,'server','TestServer','ping','127.0.0.62','{}',?,0)", (server, now_ms))
    conn.commit()
    storage.replace_lldp_links(server, [(switch_down, '1', 'Gi0/1'), (switch_up, '2', 'Gi0/2')])
    conn.close()
    try:
        storage.add_incident('crit', 'TestServer', 'TEST', '응답 없음', device_id=server, event_type='REACHABILITY', _no_alert=True)
        conn = storage.get_db()
        row = conn.execute("SELECT * FROM incidents WHERE device_id=? ORDER BY id DESC LIMIT 1", (server,)).fetchone()
        conn.close()
        check('M1 new REACHABILITY incident message mentions the directly-linked, currently-failing network device',
              'DownSwitch' in row['message'], row['message'])
        check('M2 message does NOT mention the linked-but-healthy switch', 'UpSwitch' not in row['message'], row['message'])
    finally:
        conn = storage.get_db()
        for d in (switch_down, switch_up, server):
            conn.execute("DELETE FROM devices WHERE id=?", (d,))
        conn.execute("DELETE FROM device_links WHERE from_device_id=? OR to_device_id=?", (server, server))
        conn.execute("DELETE FROM incidents WHERE device_id=?", (server,))
        conn.commit()
        conn.close()


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


def test_escalation_tier_order_stable_across_enable_disable():
    # 버그 수정(2026-10-17, "에스컬레이션 중복 발송 및 담당자 변경 상황을
    # 검증한다"): escalation_state.current_tier가 "몇 번째로 알렸는지"
    # 순번 카운트였을 때는, 2차를 알린 뒤 비활성화하고 다시 활성화하면(담당자
    # 교체/이탈 후 복귀의 흔한 형태) 카운트와 활성 목록의 "위치"가 어긋나서
    # 3차를 또 알리는(중복 발송) 결과가 재현됐음. tier_order 값 자체를
    # 저장하도록 고친 뒤에는 어떤 순서로 켜고 꺼도 각 티어가 정확히 한 번만
    # 알림을 받아야 한다.
    dev = 'unittest_esc_order_dev'
    event = 'TEST_ESC_ORDER_EVENT'
    conn = storage.get_db()
    conn.execute("DELETE FROM incidents WHERE device_id=?", (dev,))
    conn.execute("DELETE FROM devices WHERE id=?", (dev,))
    now_ms = int(time.time() * 1000)
    conn.execute("INSERT INTO devices(id,category,name,mode,ip,fields,created_at,maintenance_enabled,monitoring_enabled) "
                 "VALUES (?,'server','EscOrderDev','ping','127.0.0.53','{}',?,0,1)", (dev, now_ms))
    conn.commit()
    conn.close()

    orig_settings = storage.get_escalation_settings_public()
    tier_ids = []
    incident_id = None
    try:
        storage.add_incident('crit', 'EscOrderDev', 'TEST', 'down', device_id=dev, event_type=event, _no_alert=True)
        conn = storage.get_db()
        row = conn.execute("SELECT id FROM incidents WHERE device_id=?", (dev,)).fetchone()
        conn.close()
        incident_id = row['id']

        storage.set_escalation_settings(True, 'warn')
        tier_ids.append(storage.create_escalation_tier('1차', 't1@example.com', 0))
        tier2_id = storage.create_escalation_tier('2차', 't2@example.com', 0)
        tier_ids.append(tier2_id)
        tier_ids.append(storage.create_escalation_tier('3차', 't3@example.com', 0))

        escalation.tick()  # 1차 알림

        storage.update_escalation_tier(tier2_id, enabled=False)  # 2차 담당자 이탈 흉내 -- 차례가 오기 전에 미리 꺼둠
        escalation.tick()  # 1차 timeout 지남, 2차는 지금 비활성 -> 3차로 바로 넘어가야 함

        storage.update_escalation_tier(tier2_id, enabled=True)  # 2차 복귀/재배치
        escalation.tick()  # 3차가 마지막이라 이미 완료 -> 아무도 또 알리면 안 됨

        conn = storage.get_db()
        counts = {r['tier_order']: r['c'] for r in conn.execute(
            "SELECT tier_order, COUNT(*) c FROM escalation_log WHERE incident_id=? GROUP BY tier_order", (incident_id,)).fetchall()}
        conn.close()
        check('L1 tier 1 notified exactly once', counts.get(1) == 1, counts)
        check('L2 tier 2 notified zero times (was disabled exactly when its turn came, never retroactively notified)',
              counts.get(2, 0) == 0, counts)
        check('L3 tier 3 notified exactly once -- NOT duplicated by tier 2 later being re-enabled', counts.get(3) == 1, counts)
        state = storage.get_escalation_state(incident_id)
        check('L4 escalation state correctly marks completed once the highest tier_order has been notified',
              state is not None and state['completed'] == 1, state)
    finally:
        for tid in tier_ids:
            storage.delete_escalation_tier(tid)
        storage.set_escalation_settings(orig_settings['enabled'], orig_settings['minSeverity'])
        conn = storage.get_db()
        if incident_id:
            conn.execute("DELETE FROM escalation_log WHERE incident_id=?", (incident_id,))
            conn.execute("DELETE FROM escalation_state WHERE incident_id=?", (incident_id,))
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


# ======================================================================
# K. NetFlow/sFlow version/direction/parse-error clarity
# (collector/netflow_parser.py / collector/sflow_parser.py / collector/flow_listener.py)
# ======================================================================

def _ip_bytes(s):
    return bytes(int(x) for x in s.split('.'))


def _build_sflow_v5_packet(expanded, in_if, out_if, sampling_rate=20):
    """실측 장비가 없어 합성 패킷으로만 검증(이 환경의 실제 네트워크 장비는
    NetFlow/sFlow 둘 다 미지원, flow_test_sender.py의 기존 주석과 같은
    제약). expanded=True면 sFlow v5 flow_sample_expanded(sample_type=3)
    포맷 -- input/output 각각 8바이트(format 4 + value 4)짜리 구조라서
    기존 코드가 건너뛰던 바이트 수(8)가 실제로는 16이어야 했던 자리."""
    eth = b'\x11\x22\x33\x44\x55\x66\xaa\xbb\xcc\xdd\xee\xff' + struct.pack('!H', 0x0800)
    ip_hdr = bytes([0x45, 0, 0, 40, 0, 0, 0, 0, 64, 17, 0, 0]) + _ip_bytes('10.1.1.1') + _ip_bytes('10.1.1.2')
    udp_hdr = struct.pack('!HH', 53124, 53) + b'\x00' * 16
    header = eth + ip_hdr + udp_hdr

    flow_record_data = struct.pack('!IIII', 1, 512, 0, len(header)) + header
    flow_record = struct.pack('!II', 1, len(flow_record_data)) + flow_record_data
    flow_record += b'\x00' * ((-len(flow_record_data)) % 4)

    if expanded:
        sample_type = 3
        sample_data = struct.pack('!III', 1, 1, 1)  # sequence_number, source_id_type, source_id_index
        sample_data += struct.pack('!III', sampling_rate, 0, 0)  # sampling_rate, sample_pool, drops
        sample_data += struct.pack('!II', 0, in_if)   # input: format(0=single ifIndex) + value
        sample_data += struct.pack('!II', 0, out_if)  # output: format + value
    else:
        sample_type = 1
        sample_data = struct.pack('!IIIIIII', 1, (1 << 24) | 1, sampling_rate, 0, 0, in_if, out_if)
    sample_data += struct.pack('!I', 1) + flow_record  # num_flow_records=1
    sample = struct.pack('!II', sample_type, len(sample_data)) + sample_data

    datagram = struct.pack('!II', 5, 1) + _ip_bytes('192.168.1.1') + struct.pack('!IIII', 0, 100, 999, 1)
    return datagram + sample


def test_sflow_classic_sample_captures_version_and_direction():
    data = _build_sflow_v5_packet(expanded=False, in_if=7, out_if=9)
    flows = sflow_parser.parse(data, '192.168.1.1', 123456)
    check('K1 classic sFlow sample parses to exactly one flow', len(flows) == 1, flows)
    f = flows[0]
    check('K2 version field present and correct', f.get('version') == 5, f)
    check('K3 input ifIndex captured (not discarded)', f.get('in_if') == 7, f)
    check('K4 output ifIndex captured (not discarded)', f.get('out_if') == 9, f)


def test_sflow_expanded_sample_offset_fixed():
    # 버그 수정(2026-10-16, "NetFlow/sFlow ... 인터페이스 방향을 명확히
    # 표시" 작업 중 발견): expanded 포맷(sample_type=3)의 input/output은
    # 각각 8바이트(format+value)인데, 기존 코드는 총 8바이트만 건너뛰어서
    # (16바이트가 맞음) 그다음 num_flow_records부터 전부 틀린 자리를
    # 읽었음 -- 이 환경의 실제 장비는 expanded 포맷을 안 써서(ifIndex가
    # 2^24를 안 넘음) 지금까지 아무도 못 봤던 경로. 합성 패킷으로 오프셋이
    # 맞는지 확인: 맞게 읽히면 flow 1개가 정상적으로 나오고 in/out ifIndex도
    # (format 필드가 아니라) 진짜 값과 일치해야 한다.
    data = _build_sflow_v5_packet(expanded=True, in_if=11, out_if=22)
    flows = sflow_parser.parse(data, '192.168.1.1', 123456)
    check('K5 expanded-format sample parses to exactly one flow (offset not corrupted)', len(flows) == 1, flows)
    f = flows[0] if flows else {}
    check('K6 expanded-format input ifIndex is the actual value, not the format discriminator', f.get('in_if') == 11, f)
    check('K7 expanded-format output ifIndex is the actual value, not the format discriminator', f.get('out_if') == 22, f)
    check('K8 expanded-format flow data itself still parses correctly past the fixed offset',
          f.get('src_ip') == '10.1.1.1' and f.get('dst_ip') == '10.1.1.2', f)


def test_netflow_v5_captures_version_and_direction():
    header = struct.pack('!HHIIIIBBH', 5, 1, 12345, int(time.time()), 0, 1, 0, 0, 0)
    record = struct.pack(
        '!IIIHHIIIIHHBBBBHHBBH',
        0x0A630005, 0xCB007109, 0, 3, 4,
        7, 4200, 0, 0, 51000, 443, 0, 0, 6, 0, 0, 0, 0, 0, 0,
    )
    flows = netflow_parser.parse(header + record, '192.168.1.1', 123456)
    check('K9 NetFlow v5 record parses to exactly one flow', len(flows) == 1, flows)
    f = flows[0]
    check('K10 version field present and correct', f.get('version') == 5, f)
    check('K11 input/output ifIndex captured (not discarded)', f.get('in_if') == 3 and f.get('out_if') == 4, f)


def test_flow_parse_error_tracking_and_status_merge():
    # 신규 기능(2026-10-16, "파싱 오류를 명확히 표시"): flow_listener.py가
    # 실패한 패킷을 로그에만 남기던 걸 집계까지 하는지, 그리고
    # storage.load_flow_status()가 "한 번도 성공 못 한" exporter도
    # (flow_exporters에 행이 없어도) parse-error 쪽만으로 보여주는지.
    from collector import flow_listener
    ip = '203.0.113.250'
    orig = flow_listener._parse_errors
    flow_listener._parse_errors = {}
    conn = storage.get_db()
    conn.execute("DELETE FROM flow_parse_errors WHERE exporter_ip=?", (ip,))
    conn.execute("DELETE FROM flow_exporters WHERE exporter_ip=?", (ip,))
    conn.commit()
    conn.close()
    try:
        flow_listener._record_parse_error(ip, 'netflow', 1000, 'not NetFlow v5 (version=9)')
        flow_listener._record_parse_error(ip, 'netflow', 1001, 'not NetFlow v5 (version=9)')
        check('K12 in-memory parse-error counter accumulates per (ip, protocol)',
              flow_listener._parse_errors[(ip, 'netflow')][1] == 2, flow_listener._parse_errors)

        storage.record_flow_parse_errors([(ip, proto, ts, cnt, msg) for (ip2, proto), (ts, cnt, msg) in flow_listener._parse_errors.items() if ip2 == ip])
        statuses = {(s['exporterIp'], s['protocol']): s for s in storage.load_flow_status()}
        row = statuses.get((ip, 'netflow'))
        check('K13 an exporter that only ever failed to parse still shows up in /api/flow/status',
              row is not None and row['recordCount'] == 0 and row['parseErrorCount'] == 2, row)
        check('K14 lastParseError carries the actual message, not just a count',
              row is not None and 'version=9' in (row['lastParseError'] or ''), row)
    finally:
        flow_listener._parse_errors = orig
        conn = storage.get_db()
        conn.execute("DELETE FROM flow_parse_errors WHERE exporter_ip=?", (ip,))
        conn.execute("DELETE FROM flow_exporters WHERE exporter_ip=?", (ip,))
        conn.commit()
        conn.close()


# ======================================================================
# Q. DB 동시접근/디스크실패/백업/SLA 신뢰성 (운영 DB 검토 7개)
# 안전 규칙: 이 섹션의 테스트는 절대 운영 DB(storage.DB_PATH가 가리키는
# 실제 파일)를 건드리지 않는다 -- 복사본을 만들어 storage.DB_PATH를
# 임시로 그 복사본으로 바꿔 돌리고, 끝나면 반드시 원래 경로로 복원한다.
# ======================================================================

def test_db_concurrent_writes_no_lock_errors():
    # 점검(2026-10-17, "DB 동시 접근과 트랜잭션 경합을 점검한다"): WAL
    # 모드 + 15초 busy timeout(storage.get_db())이 실제로 동시 쓰기
    # 경합을 버텨내는지, 운영 DB의 복사본에 대해 직접 부하를 걸어 확인.
    # 운영 DB는 절대 안 건드림(복사본만 사용).
    test_dir = tempfile.mkdtemp(prefix='infrasight_unittest_dbcopy_')
    test_db = os.path.join(test_dir, 'test.db')
    shutil.copy(storage.DB_PATH, test_db)
    orig_path = storage.DB_PATH
    storage.DB_PATH = test_db
    try:
        storage.init_db()  # WAL 모드가 이 복사본 파일에도 적용되도록
        errors = []

        def writer(i):
            try:
                storage.add_incident('info', f'ConcurrencyTest{i}', 'TEST', 'concurrent write test', _no_alert=True)
            except Exception as e:
                errors.append(e)

        with concurrent.futures.ThreadPoolExecutor(max_workers=25) as ex:
            list(ex.map(writer, range(80)))
        check('Q1 80 concurrent add_incident calls against WAL-mode DB produce zero "database is locked" errors',
              len(errors) == 0, errors[:3])
    finally:
        storage.DB_PATH = orig_path
        shutil.rmtree(test_dir, ignore_errors=True)


def test_metrics_aggregation_idempotent_on_rerun():
    # 점검(2026-10-17, "메트릭 집계 작업의 재실행 및 중복 집계 방지를
    # 확인한다"): storage.run_metrics_retention()이 같은 raw 데이터에
    # 대해 여러 번 돌아도 5분/1시간 집계 값이 바뀌지 않는지(평균을 또
    # 더해서 2배가 되는 식의 중복이 없는지) 확인. 운영 DB 복사본 사용.
    test_dir = tempfile.mkdtemp(prefix='infrasight_unittest_dbcopy_')
    test_db = os.path.join(test_dir, 'test.db')
    shutil.copy(storage.DB_PATH, test_db)
    orig_path = storage.DB_PATH
    storage.DB_PATH = test_db
    try:
        storage.init_db()
        dev = 'unittest_agg_dev'
        conn = storage.get_db()
        conn.execute("DELETE FROM metrics_raw WHERE device_id=?", (dev,))
        conn.execute("DELETE FROM metrics_5m WHERE device_id=?", (dev,))
        conn.commit()
        conn.close()
        bucket_start = (int(time.time() * 1000) // storage.FIVE_MIN_MS) * storage.FIVE_MIN_MS
        storage.record_metrics([(dev, 'cpu', bucket_start + 1000, 10.0), (dev, 'cpu', bucket_start + 2000, 20.0)])

        storage.run_metrics_retention()
        conn = storage.get_db()
        row1 = dict(conn.execute("SELECT avg_value, sample_count FROM metrics_5m WHERE device_id=? AND metric='cpu'", (dev,)).fetchone())
        conn.close()

        storage.run_metrics_retention()  # 재실행
        storage.run_metrics_retention()  # 한 번 더
        conn = storage.get_db()
        row2 = dict(conn.execute("SELECT avg_value, sample_count FROM metrics_5m WHERE device_id=? AND metric='cpu'", (dev,)).fetchone())
        conn.close()

        check('Q2 re-running aggregation 3x does not change avg_value (no double-counting)',
              row1['avg_value'] == row2['avg_value'] == 15.0, (row1, row2))
        check('Q3 re-running aggregation 3x does not inflate sample_count', row2['sample_count'] == 2, row2)
    finally:
        storage.DB_PATH = orig_path
        shutil.rmtree(test_dir, ignore_errors=True)


def test_scheduler_job_survives_disk_full_write_failure():
    # 점검(2026-10-17, "디스크 용량 부족과 DB 쓰기 실패 시 동작을
    # 확인한다"): 샘플러 자체가 디스크풀급 에러로 실패하고, 그 에러를
    # 기록하려는 bookkeeping(update_failure_state/add_incident)까지
    # 똑같이 실패하는 최악의 경우에도 scheduler._run_job이 예외를 밖으로
    # 던지지 않고(스케줄러 자체가 안 죽음) health에 기록되는지 확인.
    from collector import scheduler, health, ping_collector
    dev = 'unittest_diskfull_dev'
    conn = storage.get_db()
    conn.execute("DELETE FROM devices WHERE id=?", (dev,))
    now_ms = int(time.time() * 1000)
    conn.execute("INSERT INTO devices(id,category,name,mode,ip,fields,created_at,monitoring_enabled) "
                 "VALUES (?,'server','DiskFullDev','ping','127.0.0.70','{}',?,1)", (dev, now_ms))
    conn.commit()
    conn.close()

    orig_sample_ping = ping_collector.sample_ping
    orig_update_failure_state = storage.update_failure_state

    def fake_sample_ping(entity, device_row):
        raise sqlite3.OperationalError('database or disk image is full')

    def fake_update_failure_state(*a, **kw):
        raise sqlite3.OperationalError('database or disk image is full')

    ping_collector.sample_ping = fake_sample_ping
    storage.update_failure_state = fake_update_failure_state
    try:
        raised = False
        try:
            scheduler._run_job(dev)
        except Exception:
            raised = True
        check('Q4 scheduler job does not propagate an exception even when the error AND its own bookkeeping both fail',
              not raised, raised)
        health_now = health.get_health()
        check('Q5 the failure is still visible via health.get_health() (file+in-memory log survives even if DB writes fail)',
              health_now.get('collectorLastError') is not None and 'disk image is full' in health_now['collectorLastError']['message'],
              health_now.get('collectorLastError'))
    finally:
        ping_collector.sample_ping = orig_sample_ping
        storage.update_failure_state = orig_update_failure_state
        conn = storage.get_db()
        conn.execute("DELETE FROM devices WHERE id=?", (dev,))
        conn.commit()
        conn.close()


def test_backup_integrity_check_rejects_corrupt_file():
    # 점검(2026-10-17, "백업 파일의 무결성 확인... 검증한다"): 손상된
    # .db 파일을 "백업"으로 복원 시도하면 거부되는지(라이브 DB를 건드리기
    # 전에) 확인. 운영 DB는 안 건드림 -- 가짜 손상 파일만 사용.
    test_dir = tempfile.mkdtemp(prefix='infrasight_unittest_backup_')
    try:
        corrupt_path = os.path.join(test_dir, 'infrasight_corrupt.db')
        with open(corrupt_path, 'wb') as f:
            f.write(b'not a real sqlite database file' * 100)
        raised = False
        try:
            storage.restore_database(test_dir, 'infrasight_corrupt.db')
        except Exception:
            raised = True
        check('Q6 restoring a corrupt file is rejected before ever touching the live DB', raised, raised)
    finally:
        shutil.rmtree(test_dir, ignore_errors=True)


def test_backup_failure_triggers_incident_and_health_log():
    # 점검(2026-10-17, "백업 실패 여부를 감지하고 알림을 제공한다"):
    # collector/scheduler.py의 _run_backup_job이 백업 실패를 health
    # 로그 + incident(알림 경로)로 둘 다 남기는지 확인.
    from collector import scheduler, health
    orig_backup = storage.backup_database

    def fake_backup_database(*a, **kw):
        raise OSError('disk full (simulated)')

    storage.backup_database = fake_backup_database
    conn = storage.get_db()
    conn.execute("DELETE FROM incidents WHERE source='InfraSight' AND message LIKE 'DB 백업 실패%'")
    conn.commit()
    conn.close()
    try:
        scheduler._run_backup_job()
        health_now = health.get_health()
        check('Q7 backup failure is logged via health.get_health()',
              health_now.get('collectorLastError') is not None and 'disk full' in health_now['collectorLastError']['message'],
              health_now.get('collectorLastError'))
        conn = storage.get_db()
        row = conn.execute("SELECT * FROM incidents WHERE source='InfraSight' AND message LIKE 'DB 백업 실패%' ORDER BY id DESC LIMIT 1").fetchone()
        conn.close()
        check('Q8 backup failure also creates an incident (goes through the normal alert-dispatch path)',
              row is not None and row['status'] == 'open', dict(row) if row else None)
    finally:
        storage.backup_database = orig_backup
        conn = storage.get_db()
        conn.execute("DELETE FROM incidents WHERE source='InfraSight' AND message LIKE 'DB 백업 실패%'")
        conn.commit()
        conn.close()


def test_restore_verifies_separate_copy_before_touching_live_db():
    # 점검+버그 수정(2026-10-17, "백업 파일의 무결성 확인 및 별도 경로
    # 복원 절차를 검증한다"): restore_database가 운영 DB_PATH에 바로
    # 쓰기 전에 별도의 임시 경로로 먼저 복원해보고 그 결과까지
    # integrity_check하는지 확인. 이 테스트는 storage.DB_PATH를 테스트
    # 복사본으로 바꿔서 실행 -- "운영 DB"라는 게 이 테스트 안에서는 그
    # 복사본이므로, 실제 운영 파일은 여전히 안 건드림.
    test_dir = tempfile.mkdtemp(prefix='infrasight_unittest_restore_')
    test_db = os.path.join(test_dir, 'live.db')
    backup_dir = os.path.join(test_dir, 'backups')
    os.makedirs(backup_dir, exist_ok=True)
    shutil.copy(storage.DB_PATH, test_db)
    orig_path = storage.DB_PATH
    storage.DB_PATH = test_db
    try:
        storage.init_db()
        backup_path = storage.backup_database(backup_dir)
        backup_filename = os.path.basename(backup_path)

        safety_backup_path, warning = storage.restore_database(backup_dir, backup_filename)
        check('Q9 restore_database succeeds for a genuinely valid backup', os.path.isfile(test_db), test_db)
        check('Q10 restore_database still produces its pre-restore safety backup', os.path.isfile(safety_backup_path), safety_backup_path)
        tmp_leftover = test_db + '.restore_verify.tmp'
        check('Q11 the temporary separate-path verification copy is cleaned up afterward (not left behind)',
              not os.path.exists(tmp_leftover), tmp_leftover)
    finally:
        storage.DB_PATH = orig_path
        shutil.rmtree(test_dir, ignore_errors=True)


def test_sla_insufficient_data_distinguished_from_healthy():
    # 버그 수정(2026-10-17, "SLA 집계에서 데이터 누락과 정상 상태를
    # 구분한다"): 측정 시간이 전혀 없는 기간(전부 유지보수로 빠짐)이
    # "정상 100%"와 다르게 insufficientData=True로 구분되는지, 그리고
    # 실제로 측정된 시간이 있고 장애가 없는 기간은 insufficientData가
    # False인 진짜 100%로 나오는지 확인.
    dev = 'unittest_sla_gap_dev'
    conn = storage.get_db()
    conn.execute("DELETE FROM devices WHERE id=?", (dev,))
    conn.execute("DELETE FROM maintenance_log WHERE device_id=?", (dev,))
    conn.execute("DELETE FROM incidents WHERE device_id=?", (dev,))
    now_ms = int(time.time() * 1000)
    period_start = now_ms - 2 * 3600 * 1000
    period_end = now_ms
    conn.execute("INSERT INTO devices(id,category,name,mode,ip,fields,created_at) "
                 "VALUES (?,'server','SlaGapDev','ping','127.0.0.71','{}',?)", (dev, now_ms))
    conn.execute("INSERT INTO maintenance_log(device_id,started_at,ended_at,started_by,reason) VALUES (?,?,?,?,?)",
                 (dev, period_start, period_end, 'tester', 'unittest full-period maintenance'))
    conn.commit()
    conn.close()
    try:
        device_row = storage.load_device(dev)
        report = sla.device_uptime_report(device_row, period_start, period_end)
        check('Q12 a period that is entirely maintenance (zero measured time) is flagged insufficientData=True',
              report['insufficientData'] is True, report)
        check('Q13 insufficientData periods still report uptimePct=100.0 for backward compatibility (consumers must check the flag)',
              report['uptimePct'] == 100.0, report)

        conn = storage.get_db()
        conn.execute("DELETE FROM maintenance_log WHERE device_id=?", (dev,))
        conn.commit()
        conn.close()
        report2 = sla.device_uptime_report(device_row, period_start, period_end)
        check('Q14 a period with real measured time and no incidents is a genuine 100% (insufficientData=False)',
              report2['insufficientData'] is False and report2['uptimePct'] == 100.0, report2)
    finally:
        conn = storage.get_db()
        conn.execute("DELETE FROM devices WHERE id=?", (dev,))
        conn.execute("DELETE FROM maintenance_log WHERE device_id=?", (dev,))
        conn.execute("DELETE FROM incidents WHERE device_id=?", (dev,))
        conn.commit()
        conn.close()


def main():
    for fn in (
        test_mac_from_oid_suffix, test_collect_mac_vlan_table,
        test_mac_vlan_from_dot1q_oid_suffix, test_collect_mac_vlan_table_prefers_dot1q_when_available,
        test_replace_mac_table,
        test_top_level_module_indices, test_replace_lldp_links,
        test_lldp_bidirectional_confirmation, test_lldp_walk_distinguishes_failure_from_confirmed_empty,
        test_sample_snmp_lldp_gate_respects_confirmed_flag, test_topology_layout_persistence,
        test_device_delete_cleans_links,
        test_hp_icfsensor_env, test_h3c_entity_env, test_entity_sensor_env,
        test_vendor_profile_resolution, test_mib_standard_vs_vendor_separation, test_server_category_module_filter,
        test_compute_counter_delta, test_hc_counter_fallback_full_coverage, test_hc_counter_fallback_partial_coverage,
        test_sample_snmp_flags_low_confidence_traffic,
        test_related_network_failure_correlation,
        test_ack_then_recovery, test_ack_then_escalate_reopens, test_agent_mode_escalation,
        test_maintenance_suppresses_and_renotifies, test_escalation_tier_order_stable_across_enable_disable,
        test_alert_retry_queue,
        test_agent_token_not_in_argv,
        test_classify_snmp_error, test_snmp_get_returns_tuple_on_unreachable,
        test_sflow_classic_sample_captures_version_and_direction, test_sflow_expanded_sample_offset_fixed,
        test_netflow_v5_captures_version_and_direction, test_flow_parse_error_tracking_and_status_merge,
        test_db_concurrent_writes_no_lock_errors, test_metrics_aggregation_idempotent_on_rerun,
        test_scheduler_job_survives_disk_full_write_failure, test_backup_integrity_check_rejects_corrupt_file,
        test_backup_failure_triggers_incident_and_health_log, test_restore_verifies_separate_copy_before_touching_live_db,
        test_sla_insufficient_data_distinguished_from_healthy,
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
