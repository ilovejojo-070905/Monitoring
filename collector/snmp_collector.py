"""SNMP sampler. Logic moved from server.py's SNMP section (OIDs, _snmp_get/
_snmp_walk/_snmp_poll, sample_snmp) unchanged, except:
  - per-device timeout_sec (falls back to the old hardcoded 1.5s)
  - reachability status now comes from collector.state.evaluate_status()
    (consecutive-failure smoothing) instead of an immediate 'crit' on the
    first failed poll -- same false-positive fix as ping_collector
  - Phase 7: CPU/memory OID selection goes through snmp_profiles.resolve_profile()
    instead of a hardcoded Cisco fallback, SNMPv3 (UsmUserData) is supported
    alongside v1/v2c CommunityData, and 'net' devices get a best-effort LLDP
    neighbor walk for future topology use.
All per-interface CPU/memory parsing (0-5 in the Phase 1 analysis) is
otherwise untouched: interface hist arrays, uptime parsing.
"""
import asyncio
import time

import storage
from collector import state, thresholds
from collector.state import hist, push_cap, evaluate_status
from collector import snmp_profiles
from collector import lldp

try:
    from pysnmp.hlapi.v3arch.asyncio import (
        SnmpEngine, CommunityData, UsmUserData, UdpTransportTarget, ContextData,
        ObjectType, ObjectIdentity, get_cmd, bulk_walk_cmd,
        usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol,
        usmDESPrivProtocol, usmAesCfb128Protocol, usmNoAuthProtocol, usmNoPrivProtocol,
    )
    SNMP_AVAILABLE = True
except Exception:
    SNMP_AVAILABLE = False

OID_SYS_NAME = '1.3.6.1.2.1.1.5.0'
OID_SYS_DESCR = '1.3.6.1.2.1.1.1.0'
OID_SYS_UPTIME = '1.3.6.1.2.1.1.3.0'
OID_IF_DESCR = '1.3.6.1.2.1.2.2.1.2'
OID_IF_OPER_STATUS = '1.3.6.1.2.1.2.2.1.8'
OID_IF_IN_OCTETS = '1.3.6.1.2.1.2.2.1.10'
OID_IF_OUT_OCTETS = '1.3.6.1.2.1.2.2.1.16'
OID_UPS_BATTERY_CAPACITY = '1.3.6.1.2.1.33.1.2.4.0'

DEFAULT_TIMEOUT_SEC = 1.5

AUTH_PROTOCOLS = {'MD5': usmHMACMD5AuthProtocol, 'SHA': usmHMACSHAAuthProtocol, None: usmNoAuthProtocol} if SNMP_AVAILABLE else {}
PRIV_PROTOCOLS = {'DES': usmDESPrivProtocol, 'AES': usmAesCfb128Protocol, None: usmNoPrivProtocol} if SNMP_AVAILABLE else {}


def _mp_model(version):
    return 0 if version == 'v1' else 1


def build_auth_data_raw(version, community, v3_username='', v3_auth_protocol=None,
                         v3_auth_password=None, v3_priv_protocol=None, v3_priv_password=None):
    """Same as build_auth_data below, but takes the v3 secrets directly
    instead of loading them from the credentials table -- needed at
    registration time, before a device_id (and so a credentials row) exists
    to look them up by."""
    if version != 'v3':
        return CommunityData(community, mpModel=_mp_model(version))
    return UsmUserData(
        v3_username or '',
        authKey=v3_auth_password or None,
        privKey=v3_priv_password or None,
        authProtocol=AUTH_PROTOCOLS.get(v3_auth_protocol, usmNoAuthProtocol),
        privProtocol=PRIV_PROTOCOLS.get(v3_priv_protocol, usmNoPrivProtocol),
    )


def build_auth_data(device_id, version, community):
    """Returns a pysnmp authData object: CommunityData for v1/v2c (unchanged
    from before Phase 7), or UsmUserData for v3. v3 secrets live in the
    credentials table (Phase 3 pattern), never in devices.fields."""
    if version != 'v3':
        return build_auth_data_raw(version, community)
    username = storage.get_credential(device_id, 'snmpv3_username') or ''
    auth_protocol_name = storage.get_credential(device_id, 'snmpv3_auth_protocol')
    auth_password = storage.get_credential(device_id, 'snmpv3_auth_password')
    priv_protocol_name = storage.get_credential(device_id, 'snmpv3_priv_protocol')
    priv_password = storage.get_credential(device_id, 'snmpv3_priv_password')
    return build_auth_data_raw(version, community, username, auth_protocol_name,
                                auth_password, priv_protocol_name, priv_password)


def check_reachable(ip, auth_data, port, timeout=1.5):
    """Lightweight one-shot SNMP GET (just sysName) for registration-time
    validation -- doesn't do any of sample_snmp's per-category polling."""
    try:
        result = snmp_run(_snmp_get(SnmpEngine(), ip, auth_data, port, [OID_SYS_NAME], timeout=timeout))
        return result is not None
    except Exception:
        return False


def test_connection(ip, version, community, port, v3_username=None, v3_auth_protocol=None,
                     v3_auth_password=None, v3_priv_protocol=None, v3_priv_password=None,
                     attempts=3, needed=2, timeout=1.5):
    """Majority-vote reachability probe (a single flaky reply isn't enough
    evidence either way) shared by two callers: the registration/update
    endpoints, which gate persistence on it, and the standalone
    /api/devices/test-snmp endpoint, which lets the registration UI show a
    pass/fail result before the user commits to registering. Returns
    (ok, successes, attempts) -- the counts are surfaced in the UI/error
    message, not just a bare bool, so "1 of 3 answered" reads differently
    from "0 of 3"."""
    auth_data = build_auth_data_raw(version, community, v3_username, v3_auth_protocol,
                                     v3_auth_password, v3_priv_protocol, v3_priv_password)
    successes = sum(1 for _ in range(attempts) if check_reachable(ip, auth_data, port, timeout=timeout))
    return successes >= needed, successes, attempts


async def _snmp_get(engine, ip, auth_data, port, oids, timeout=1.5):
    target = await UdpTransportTarget.create((ip, int(port)), timeout=timeout, retries=0)
    var_binds = [ObjectType(ObjectIdentity(oid)) for oid in oids]
    errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
        engine, auth_data, target, ContextData(), *var_binds)
    if errorIndication or errorStatus:
        return None
    values = []
    for vb in varBinds:
        v = str(vb[1])
        values.append(None if 'No Such' in v else v)
    return values


async def _snmp_walk(engine, ip, auth_data, port, base_oid, timeout=1.5, max_rows=256):
    target = await UdpTransportTarget.create((ip, int(port)), timeout=timeout, retries=0)
    out = {}
    count = 0
    async for (errorIndication, errorStatus, errorIndex, varBinds) in bulk_walk_cmd(
            engine, auth_data, target, ContextData(),
            0, 20, ObjectType(ObjectIdentity(base_oid)), lexicographicMode=False):
        if errorIndication or errorStatus:
            break
        for vb in varBinds:
            oid_str = str(vb[0])
            if not oid_str.startswith(base_oid + '.'):
                return out
            out[oid_str[len(base_oid) + 1:]] = vb[1]
        count += 1
        if count > max_rows:
            break
    return out


async def _snmp_poll(ip, auth_data, port, category, timeout, vendor_profile, lldp_due):
    """One SNMP session (one engine, one event loop) per device per poll."""
    engine = SnmpEngine()
    result = {'reachable': False, 'latencyMs': None}
    start = time.time()
    basics = await _snmp_get(engine, ip, auth_data, port, [OID_SYS_NAME, OID_SYS_DESCR, OID_SYS_UPTIME], timeout=timeout)
    result['latencyMs'] = round((time.time() - start) * 1000, 1)
    if basics is None:
        return result
    result['reachable'] = True
    result['sysName'], result['sysDescr'], result['sysUptimeTicks'] = basics[0], basics[1], basics[2]
    profile = snmp_profiles.resolve_profile(vendor_profile, result['sysDescr'])
    if category == 'net':
        result['ifDescr'] = await _snmp_walk(engine, ip, auth_data, port, OID_IF_DESCR, timeout=timeout)
        result['oper'] = await _snmp_walk(engine, ip, auth_data, port, OID_IF_OPER_STATUS, timeout=timeout)
        result['in_oct'] = await _snmp_walk(engine, ip, auth_data, port, OID_IF_IN_OCTETS, timeout=timeout)
        result['out_oct'] = await _snmp_walk(engine, ip, auth_data, port, OID_IF_OUT_OCTETS, timeout=timeout)
        loads = {}
        if profile['cpu_oid']:
            loads = await _snmp_walk(engine, ip, auth_data, port, profile['cpu_oid'], timeout=timeout)
        if not loads and profile.get('cpu_fallback_oid'):
            loads = await _snmp_walk(engine, ip, auth_data, port, profile['cpu_fallback_oid'], timeout=timeout)
        result['loads'] = loads
        if profile.get('mem_used_oid'):
            result['memUsed'] = await _snmp_walk(engine, ip, auth_data, port, profile['mem_used_oid'], timeout=timeout)
        if profile.get('mem_free_oid'):
            result['memFree'] = await _snmp_walk(engine, ip, auth_data, port, profile['mem_free_oid'], timeout=timeout)
        if lldp_due:
            result['lldp'] = await lldp.walk_lldp_neighbors(engine, ip, auth_data, port, timeout=timeout)
    elif category in ('server', 'db'):
        profile_srv = snmp_profiles.resolve_profile(vendor_profile, result['sysDescr'])
        cpu_oid = profile_srv['cpu_oid'] or snmp_profiles.OID_HR_PROCESSOR_LOAD
        result['loads'] = await _snmp_walk(engine, ip, auth_data, port, cpu_oid, timeout=timeout)
    elif category == 'fac':
        result['batt'] = await _snmp_get(engine, ip, auth_data, port, [OID_UPS_BATTERY_CAPACITY], timeout=timeout)
    return result


def snmp_run(coro):
    return asyncio.run(coro)


def sample_snmp(entity, device_row):
    ip = device_row['ip']
    fields = device_row['fields']
    device_id = device_row['id']
    # Phase 3: the community string lives in the credentials table now, not in
    # this fields JSON blob -- fields.get('community') is kept as a fallback
    # only for a device polled in the brief window before migrate_snmp_
    # credentials() has run once at startup.
    community = storage.get_credential(device_id, 'snmp_community') or fields.get('community') or 'public'
    version = fields.get('snmpVersion') or 'v2c'
    port = fields.get('snmpPort') or 161
    category = device_row['category']
    timeout_s = device_row.get('timeout_sec') or DEFAULT_TIMEOUT_SEC
    vendor_profile = device_row.get('vendor_profile')
    # Code review pass, finding #5: these dict reads/writes are the part
    # that's actually shared with /api/state's concurrent reads -- the SNMP
    # exchange a few lines down is the slow part and deliberately stays
    # unlocked (each device's own worker thread is the whole point of the
    # pool). Scoped to the flat, easy-to-verify mutation points in this
    # function rather than the large nested per-interface stats block
    # further down, where the risk of a reindentation mistake outweighs
    # protecting data that's already read-mostly and rarely raced.
    with state.LOCK:
        prev_status = entity.get('status', 'good')
        entity['mode'] = 'snmp'
        entity['online'] = True

    prev_failures = device_row.get('consecutive_failures') or 0

    if not SNMP_AVAILABLE:
        with state.LOCK:
            entity.update(reachable=False, status='crit', latencyMs=None)
        return

    now = time.time()
    lldp_due = category == 'net' and (now - (entity.get('_lldpLastRun') or 0)) >= lldp.LLDP_INTERVAL_SEC
    if lldp_due:
        entity['_lldpLastRun'] = now

    try:
        auth_data = build_auth_data(device_id, version, community)
        result = snmp_run(_snmp_poll(ip, auth_data, port, category, timeout=timeout_s, vendor_profile=vendor_profile, lldp_due=lldp_due))
    except Exception:
        result = {'reachable': False, 'latencyMs': None}

    if result.get('lldp'):
        try:
            lldp.apply_discovered_links(device_id, result['lldp'])
        except Exception:
            pass

    with state.LOCK:
        entity['reachable'] = result['reachable']
        entity['latencyMs'] = result.get('latencyMs')
        push_cap(entity['hist']['latency'], entity['latencyMs'] if entity['latencyMs'] is not None else 0)

    failures = 0 if result['reachable'] else prev_failures + 1
    status = evaluate_status(failures) if not result['reachable'] else 'good'
    now_ms = int(time.time() * 1000)
    storage.update_failure_state(
        device_row['id'], failures,
        None if result['reachable'] else 'SNMP_TIMEOUT',
        now_ms if result['reachable'] else device_row.get('last_success_at'),
        now_ms,
        device_row.get('last_failure_at') if result['reachable'] else now_ms)

    if not result['reachable']:
        with state.LOCK:
            entity['status'] = status
        if prev_status == 'good' and status != 'good' and not storage.in_maintenance(device_row):
            storage.add_incident(status, device_row['name'], storage.category_label(category),
                                  f"{device_row['name']} SNMP 응답 없음 (커뮤니티/버전을 확인하세요, 연속 {failures}회)",
                                  device_id=device_row['id'], event_type='REACHABILITY')
        return

    with state.LOCK:
        entity['status'] = 'good'
        entity['sysName'] = result.get('sysName')
        entity['sysDescr'] = result.get('sysDescr')
        try:
            ticks = result.get('sysUptimeTicks')
            if ticks is not None:
                entity['uptime'] = round(int(ticks) / 100 / 86400, 2)
        except Exception:
            pass
    if prev_status != 'good' and not storage.in_maintenance(device_row):
        storage.add_incident('info', device_row['name'], storage.category_label(category),
                              f"{device_row['name']} SNMP 응답 정상 복구",
                              device_id=device_row['id'], event_type='REACHABILITY')

    if category == 'net' and 'oper' in result:
        try:
            oper, in_oct, out_oct = result['oper'], result['in_oct'], result['out_oct']
            total_in = sum(int(v) for v in in_oct.values())
            total_out = sum(int(v) for v in out_oct.values())
            entity['portsUp'] = sum(1 for v in oper.values() if str(v) == '1')
            entity['portsTotal'] = len(oper)
            now = time.time()
            prev = entity.get('_snmpPrev')
            prev_ifaces = entity.get('_snmpIfacePrev') or {}
            entity.setdefault('hist', {}).setdefault('traffic', hist(0))
            iface_rates = {}
            if prev:
                dt = max(now - prev['t'], 1)
                in_mbps = max((total_in - prev['in']) * 8 / dt / 1_000_000, 0)
                out_mbps = max((total_out - prev['out']) * 8 / dt / 1_000_000, 0)
                entity['trafficIn'] = round(in_mbps, 2)
                entity['trafficOut'] = round(out_mbps, 2)
                push_cap(entity['hist']['traffic'], round(in_mbps + out_mbps, 2))
                for idx, v in in_oct.items():
                    if idx in prev_ifaces:
                        d_in = max(int(v) - prev_ifaces[idx].get('in', 0), 0)
                        d_out = max(int(out_oct.get(idx, 0)) - prev_ifaces[idx].get('out', 0), 0)
                        iface_rates[idx] = {
                            'inMbps': round(d_in * 8 / dt / 1_000_000, 3),
                            'outMbps': round(d_out * 8 / dt / 1_000_000, 3),
                        }
            entity['_snmpPrev'] = {'in': total_in, 'out': total_out, 't': now}
            entity['_snmpIfacePrev'] = {idx: {'in': int(v), 'out': int(out_oct.get(idx, 0))} for idx, v in in_oct.items()}

            ifdescr = result.get('ifDescr') or {}
            iface_hist = entity.setdefault('_ifaceHist', {})
            ifaces = []
            for idx, name in ifdescr.items():
                rate = iface_rates.get(idx, {'inMbps': 0.0, 'outMbps': 0.0})
                iface_hist.setdefault(idx, hist(0))
                push_cap(iface_hist[idx], round(rate['inMbps'] + rate['outMbps'], 3))
                ifaces.append({
                    'idx': idx, 'name': str(name),
                    'status': 'up' if str(oper.get(idx, '2')) == '1' else 'down',
                    'inMbps': rate['inMbps'], 'outMbps': rate['outMbps'],
                    'hist': list(iface_hist[idx]),
                })
            ifaces.sort(key=lambda x: int(x['idx']) if x['idx'].isdigit() else 0)
            entity['interfaces'] = ifaces[:64]
        except Exception:
            pass
        try:
            vals = [int(v) for v in result.get('loads', {}).values() if str(v).lstrip('-').isdigit()]
            if vals:
                cpu = round(sum(vals) / len(vals), 1)
                entity['cpu'] = cpu
                entity.setdefault('hist', {}).setdefault('cpu', hist(0))
                push_cap(entity['hist']['cpu'], cpu)
        except Exception:
            pass
        try:
            mem_used = result.get('memUsed') or {}
            mem_free = result.get('memFree') or {}
            used_total = sum(int(v) for v in mem_used.values())
            free_total = sum(int(v) for v in mem_free.values())
            if used_total + free_total > 0:
                mem_pct = round(used_total / (used_total + free_total) * 100, 1)
                entity['mem'] = mem_pct
                entity.setdefault('hist', {}).setdefault('mem', hist(0))
                push_cap(entity['hist']['mem'], mem_pct)
        except Exception:
            pass
    elif category in ('server', 'db') and 'loads' in result:
        try:
            vals = [int(v) for v in result['loads'].values() if str(v).lstrip('-').isdigit()]
            if vals:
                cpu = round(sum(vals) / len(vals), 1)
                entity['cpu'] = cpu
                entity.setdefault('hist', {}).setdefault('cpu', hist(0))
                push_cap(entity['hist']['cpu'], cpu)
        except Exception:
            pass
    elif category == 'fac' and result.get('batt'):
        try:
            batt = result['batt']
            if batt and batt[0] is not None:
                entity['battPct'] = float(batt[0])
        except Exception:
            pass

    # 2-2: resource-threshold evaluation -- until now SNMP-polled devices
    # (switches/routers/SNMP-mode servers/DBs) only ever got a status/
    # incident from reachability, never from the CPU/mem a poll actually
    # read (that's the "biggest gap" the 2-2 audit found). category=='fac'
    # battery has its own separate UI threshold untouched by this ticket,
    # and no category here exposes a disk OID, so disk stays None
    # (evaluate_resource already treats None as "can't be over threshold").
    cpu_val = entity.get('cpu') if category in ('net', 'server', 'db') else None
    mem_val = entity.get('mem') if category == 'net' else None
    if cpu_val is not None or mem_val is not None:
        device_thresholds = thresholds.resolve_thresholds(device_row)
        resource_status, incident_event = thresholds.evaluate_resource(
            device_row['id'], cpu_val, mem_val, None, device_thresholds)
        with state.LOCK:
            entity['status'] = thresholds.worse(entity['status'], resource_status)
        if incident_event and not storage.in_maintenance(device_row):
            kind, new_status = incident_event
            if kind == 'escalate':
                storage.add_incident(new_status, device_row['name'], storage.category_label(category),
                                      f"리소스 사용률 {'임계치 초과' if new_status == 'crit' else '주의 구간 진입'} (CPU {cpu_val or 0:.0f}% / MEM {mem_val or 0:.0f}%)",
                                      device_id=device_row['id'], event_type='RESOURCE')
            else:
                storage.add_incident('info', device_row['name'], storage.category_label(category),
                                      f"{device_row['name']} 리소스 사용률 정상 범위로 복구",
                                      device_id=device_row['id'], event_type='RESOURCE')
