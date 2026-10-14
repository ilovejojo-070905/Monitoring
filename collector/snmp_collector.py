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
# ifXTable's ifAlias, NOT ifTable's ifDescr above -- ifDescr is the interface's
# own fixed technical name ("GigabitEthernet0/1", what's already shown as the
# interface row's name), ifAlias is the free-text description an admin can
# set per-port ("3층 스위치 업링크" etc.), which is what "interface
# description" means in day-to-day network-engineering usage. Most switches
# leave this blank unless someone's deliberately documented their ports, so
# it's normal for this to come back empty for many/most interfaces.
OID_IF_ALIAS = '1.3.6.1.2.1.31.1.1.1.18'
OID_IF_OPER_STATUS = '1.3.6.1.2.1.2.2.1.8'
OID_IF_ADMIN_STATUS = '1.3.6.1.2.1.2.2.1.7'
OID_IF_IN_OCTETS = '1.3.6.1.2.1.2.2.1.10'
OID_IF_OUT_OCTETS = '1.3.6.1.2.1.2.2.1.16'
OID_IF_IN_ERRORS = '1.3.6.1.2.1.2.2.1.14'
OID_IF_OUT_ERRORS = '1.3.6.1.2.1.2.2.1.20'
OID_IF_IN_DISCARDS = '1.3.6.1.2.1.2.2.1.13'
OID_IF_OUT_DISCARDS = '1.3.6.1.2.1.2.2.1.19'
# ifXTable's ifHighSpeed, already in Mbps (32-bit, but wide enough for any
# link speed likely to show up here) -- used as the utilization-% denominator.
# ifSpeed (ifTable, bps) saturates at 4.3Gbps on gigabit+ links so it's not used.
OID_IF_HIGH_SPEED = '1.3.6.1.2.1.31.1.1.1.15'
OID_UPS_BATTERY_CAPACITY = '1.3.6.1.2.1.33.1.2.4.0'

# HOST-RESOURCES-MIB hrStorageTable -- generic (non-Cisco-specific) memory
# fallback. The 'generic' SNMP profile only tries Cisco OIDs for memory
# today (snmp_profiles.py), so any non-Cisco device silently gets no memory
# reading at all. This walks the storage table and picks out the one row
# whose hrStorageType is hrStorageRam -- supported by any device implementing
# the standard MIB, not just Cisco.
OID_HR_STORAGE_TYPE = '1.3.6.1.2.1.25.2.3.1.2'
OID_HR_STORAGE_SIZE = '1.3.6.1.2.1.25.2.3.1.5'
OID_HR_STORAGE_USED = '1.3.6.1.2.1.25.2.3.1.6'
OID_HR_STORAGE_ALLOC_UNITS = '1.3.6.1.2.1.25.2.3.1.4'
HR_STORAGE_TYPE_RAM = '1.3.6.1.2.1.25.2.1.2'

# ENTITY-MIB chassis info -- simplified scope: just entPhysicalTable index 1
# (the chassis entry itself on most devices), not the full entity tree. One
# cheap extra GET per poll, tried for every category/vendor since it's a
# standard MIB.
OID_ENT_PHYSICAL_DESCR = '1.3.6.1.2.1.47.1.1.1.1.2.1'
OID_ENT_PHYSICAL_MODEL_NAME = '1.3.6.1.2.1.47.1.1.1.1.13.1'
OID_ENT_PHYSICAL_SERIAL_NUM = '1.3.6.1.2.1.47.1.1.1.1.11.1'
# Same entPhysicalDescr/Name columns as above, but as walkable table
# prefixes (no fixed ".1" chassis-only index) -- used by the env-sensor
# handlers below to label a sensor row by whichever physical entity it
# belongs to, not just the chassis.
OID_ENT_PHYSICAL_DESCR_TABLE = '1.3.6.1.2.1.47.1.1.1.1.2'
OID_ENT_PHYSICAL_NAME_TABLE = '1.3.6.1.2.1.47.1.1.1.1.7'

# The 4-3-추가 items below (error/discard counters, admin status, link speed,
# generic hrStorage memory, ENTITY-MIB, ENVMON) roughly doubled the number of
# SNMP round trips the 'net' category makes every poll tick. Verified live:
# polling the real 36-interface Catalyst 2960S at the default 2s tick with
# all of them enabled every tick made the switch itself stop answering SNMP
# (and even ICMP) within about two minutes -- its management-plane CPU
# couldn't keep up with ~15+ requests every 2 seconds, sustained. None of
# these fields need 2-second freshness (errors/discards/util move slowly;
# hardware model and environmental sensors barely change at all), so they're
# walked on this slower cadence instead -- same pattern as LLDP_INTERVAL_SEC.
EXTENDED_POLL_INTERVAL_SEC = 20

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


async def _snmp_poll(ip, auth_data, port, category, timeout, vendor_profile, lldp_due, extended_due):
    """One SNMP session (one engine, one event loop) per device per poll.

    extended_due gates the slow-changing / purely informational items (error
    counters, admin status, link speed, hrStorage memory fallback, ENTITY-MIB,
    ENVMON) so a busy 'net' device isn't hit with ~2x the SNMP round trips on
    every single 2-second tick -- see EXTENDED_POLL_INTERVAL_SEC above."""
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
        result['ifAlias'] = await _snmp_walk(engine, ip, auth_data, port, OID_IF_ALIAS, timeout=timeout)
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
        if profile.get('mem_pct_oid'):
            # Already a 0-100 percentage per entity (Juniper jnxOperatingBuffer,
            # H3C/Comware hh3cEntityExtMemUsage) -- averaged directly below,
            # not run through the used/(used+free)*100 byte-count formula.
            result['memPct'] = await _snmp_walk(engine, ip, auth_data, port, profile['mem_pct_oid'], timeout=timeout)
        if extended_due:
            result['adminStatus'] = await _snmp_walk(engine, ip, auth_data, port, OID_IF_ADMIN_STATUS, timeout=timeout)
            result['inErrors'] = await _snmp_walk(engine, ip, auth_data, port, OID_IF_IN_ERRORS, timeout=timeout)
            result['outErrors'] = await _snmp_walk(engine, ip, auth_data, port, OID_IF_OUT_ERRORS, timeout=timeout)
            result['inDiscards'] = await _snmp_walk(engine, ip, auth_data, port, OID_IF_IN_DISCARDS, timeout=timeout)
            result['outDiscards'] = await _snmp_walk(engine, ip, auth_data, port, OID_IF_OUT_DISCARDS, timeout=timeout)
            result['ifHighSpeed'] = await _snmp_walk(engine, ip, auth_data, port, OID_IF_HIGH_SPEED, timeout=timeout)
            if not result.get('memUsed') and not result.get('memFree') and not result.get('memPct'):
                hr_type = await _snmp_walk(engine, ip, auth_data, port, OID_HR_STORAGE_TYPE, timeout=timeout)
                ram_idx = next((idx for idx, v in hr_type.items() if str(v).lstrip('.') == HR_STORAGE_TYPE_RAM), None)
                if ram_idx is not None:
                    hr_size = await _snmp_walk(engine, ip, auth_data, port, OID_HR_STORAGE_SIZE, timeout=timeout)
                    hr_used = await _snmp_walk(engine, ip, auth_data, port, OID_HR_STORAGE_USED, timeout=timeout)
                    hr_units = await _snmp_walk(engine, ip, auth_data, port, OID_HR_STORAGE_ALLOC_UNITS, timeout=timeout)
                    result['hrMemSize'] = hr_size.get(ram_idx)
                    result['hrMemUsed'] = hr_used.get(ram_idx)
                    result['hrMemUnits'] = hr_units.get(ram_idx)
            ent_class = None
            if profile.get('entity_module_filter'):
                ent_class = await _snmp_walk(engine, ip, auth_data, port, snmp_profiles.OID_ENT_PHYSICAL_CLASS, timeout=timeout)
                ent_contained = await _snmp_walk(engine, ip, auth_data, port, snmp_profiles.OID_ENT_PHYSICAL_CONTAINED_IN, timeout=timeout)
                result['entModuleIdx'] = _top_level_module_indices(ent_class, ent_contained)
            env_mib = profile.get('env_mib')
            if env_mib == 'cisco_envmon':
                result['envTempDescr'] = await _snmp_walk(engine, ip, auth_data, port, snmp_profiles.OID_CISCO_ENVMON_TEMP_DESCR, timeout=timeout)
                result['envTempValue'] = await _snmp_walk(engine, ip, auth_data, port, snmp_profiles.OID_CISCO_ENVMON_TEMP_VALUE, timeout=timeout)
                result['envTempState'] = await _snmp_walk(engine, ip, auth_data, port, snmp_profiles.OID_CISCO_ENVMON_TEMP_STATE, timeout=timeout)
                result['envFanState'] = await _snmp_walk(engine, ip, auth_data, port, snmp_profiles.OID_CISCO_ENVMON_FAN_STATE, timeout=timeout)
                result['envSupplyState'] = await _snmp_walk(engine, ip, auth_data, port, snmp_profiles.OID_CISCO_ENVMON_SUPPLY_STATE, timeout=timeout)
            elif env_mib == 'juniper_opertable':
                # Same jnxOperatingTable already walked for CPU above, just
                # with the descr/state/temp columns this time -- one mixed
                # table needs classifying into temp/fan/supply buckets
                # (_juniper_env_from_opertable), unlike Cisco's 3 separate
                # ready-made tables.
                oper_descr = await _snmp_walk(engine, ip, auth_data, port, snmp_profiles.OID_JUNIPER_OPER_DESCR, timeout=timeout)
                oper_state = await _snmp_walk(engine, ip, auth_data, port, snmp_profiles.OID_JUNIPER_OPER_STATE, timeout=timeout)
                oper_temp = await _snmp_walk(engine, ip, auth_data, port, snmp_profiles.OID_JUNIPER_OPER_TEMP, timeout=timeout)
                (result['envTempDescr'], result['envTempValue'], result['envTempState'],
                 result['envFanState'], result['envSupplyState']) = _juniper_env_from_opertable(oper_descr, oper_state, oper_temp)
            elif env_mib == 'hp_icfsensor':
                sensor_type_ref = await _snmp_walk(engine, ip, auth_data, port, snmp_profiles.OID_HP_ICF_SENSOR_TYPE_REF, timeout=timeout)
                sensor_status = await _snmp_walk(engine, ip, auth_data, port, snmp_profiles.OID_HP_ICF_SENSOR_STATUS, timeout=timeout)
                result['envFanState'], result['envSupplyState'] = _hp_icfsensor_env(sensor_type_ref, sensor_status)
            elif env_mib == 'h3c_entity_ext':
                if ent_class is None:
                    ent_class = await _snmp_walk(engine, ip, auth_data, port, snmp_profiles.OID_ENT_PHYSICAL_CLASS, timeout=timeout)
                temp_raw = await _snmp_walk(engine, ip, auth_data, port, snmp_profiles.OID_H3C_TEMPERATURE, timeout=timeout)
                temp_threshold = await _snmp_walk(engine, ip, auth_data, port, snmp_profiles.OID_H3C_TEMPERATURE_THRESHOLD, timeout=timeout)
                oper_status = await _snmp_walk(engine, ip, auth_data, port, snmp_profiles.OID_H3C_OPER_STATUS, timeout=timeout)
                phys_descr = await _snmp_walk(engine, ip, auth_data, port, OID_ENT_PHYSICAL_DESCR_TABLE, timeout=timeout)
                (result['envTempDescr'], result['envTempValue'], result['envTempState'],
                 result['envFanState'], result['envSupplyState']) = _h3c_entity_env(ent_class, temp_raw, temp_threshold, oper_status, phys_descr)
            elif env_mib == 'entity_sensor':
                sensor_type = await _snmp_walk(engine, ip, auth_data, port, snmp_profiles.OID_ENT_PHY_SENSOR_TYPE, timeout=timeout)
                sensor_scale = await _snmp_walk(engine, ip, auth_data, port, snmp_profiles.OID_ENT_PHY_SENSOR_SCALE, timeout=timeout)
                sensor_precision = await _snmp_walk(engine, ip, auth_data, port, snmp_profiles.OID_ENT_PHY_SENSOR_PRECISION, timeout=timeout)
                sensor_value = await _snmp_walk(engine, ip, auth_data, port, snmp_profiles.OID_ENT_PHY_SENSOR_VALUE, timeout=timeout)
                sensor_status = await _snmp_walk(engine, ip, auth_data, port, snmp_profiles.OID_ENT_PHY_SENSOR_OPER_STATUS, timeout=timeout)
                phys_name = await _snmp_walk(engine, ip, auth_data, port, OID_ENT_PHYSICAL_NAME_TABLE, timeout=timeout)
                (result['envTempDescr'], result['envTempValue'], result['envTempState'],
                 result['envFanState'], result['envSupplyState']) = _entity_sensor_env(
                    sensor_type, sensor_scale, sensor_precision, sensor_value, sensor_status, phys_name)
            try:
                ent = await _snmp_get(engine, ip, auth_data, port,
                                       [OID_ENT_PHYSICAL_DESCR, OID_ENT_PHYSICAL_MODEL_NAME, OID_ENT_PHYSICAL_SERIAL_NUM],
                                       timeout=timeout)
                if ent:
                    result['entDescr'], result['entModel'], result['entSerial'] = ent[0], ent[1], ent[2]
            except Exception:
                pass
        if lldp_due:
            result['lldp'] = await lldp.walk_lldp_neighbors(engine, ip, auth_data, port, timeout=timeout)
    elif category in ('server', 'db'):
        profile_srv = snmp_profiles.resolve_profile(vendor_profile, result['sysDescr'])
        cpu_oid = profile_srv['cpu_oid'] or snmp_profiles.OID_HR_PROCESSOR_LOAD
        result['loads'] = await _snmp_walk(engine, ip, auth_data, port, cpu_oid, timeout=timeout)
        if extended_due:
            try:
                ent = await _snmp_get(engine, ip, auth_data, port,
                                       [OID_ENT_PHYSICAL_DESCR, OID_ENT_PHYSICAL_MODEL_NAME, OID_ENT_PHYSICAL_SERIAL_NUM],
                                       timeout=timeout)
                if ent:
                    result['entDescr'], result['entModel'], result['entSerial'] = ent[0], ent[1], ent[2]
            except Exception:
                pass
    elif category == 'fac':
        result['batt'] = await _snmp_get(engine, ip, auth_data, port, [OID_UPS_BATTERY_CAPACITY], timeout=timeout)
    return result


def snmp_run(coro):
    return asyncio.run(coro)


def _safe_int(v):
    try:
        return int(v)
    except Exception:
        return None


def _top_level_module_indices(ent_class, ent_contained_in):
    """entPhysicalTable 전체에서 class==module(9)인 행 중, containedIn 체인을
    타고 올라갔을 때 그 위에 또 다른 module(9)이 없는 것만 고른다 (= 최상위
    보드만, 보드 안에 또 들어있는 서브카드는 제외). H3C 전용: hh3cEntityExt
    CpuUsage/MemUsage가 포트/전원/팬/센서 등 이 테이블의 모든 행에 대해
    값을 노출하면서(해당 없는 행은 0), 그중 실제로 CPU/메모리를 갖는
    행이 어떤 것인지는 class/containedIn으로만 구분할 수 있기 때문
    (OID_H3C_* 주석 참고)."""
    # ent_class/ent_contained_in come straight from _snmp_walk: string keys
    # (the OID suffix), but raw pysnmp value objects, not strings. A value
    # used as the NEXT lookup key (the parent index) has to be str()'d first,
    # or the dict lookup against ent_class's string keys silently misses --
    # which is exactly what happened here before this fix (confirmed live:
    # every ancestor lookup failed, so 'nested' never tripped and a subcard
    # that's actually inside the board got kept as if it were top-level too).
    top_level = []
    for idx, cls in ent_class.items():
        if str(cls) != snmp_profiles.ENT_PHYSICAL_CLASS_MODULE:
            continue
        ancestor = str(ent_contained_in.get(idx, ''))
        seen = set()
        nested = False
        while ancestor and ancestor != '0' and ancestor not in seen:
            seen.add(ancestor)
            if str(ent_class.get(ancestor, '')) == snmp_profiles.ENT_PHYSICAL_CLASS_MODULE:
                nested = True
                break
            ancestor = str(ent_contained_in.get(ancestor, ''))
        if not nested:
            top_level.append(idx)
    return top_level


_ENVMON_STATE_LABEL = {'1': 'normal', '2': 'warning', '3': 'critical', '4': 'shutdown', '5': 'notPresent'}


def _juniper_env_from_opertable(oper_descr, oper_state, oper_temp):
    """Turns JUNIPER-MIB's one mixed jnxOperatingTable (one row per
    component -- Routing Engine/FPC/PIC/fan/PSU all together, not separate
    per-sensor-type tables like Cisco's ENVMON) into the same
    {envTempDescr, envTempValue, envTempState, envFanState, envSupplyState}
    shape every profile's extraction produces, so the entity['envTemps'/
    'envFans'/'envSupplies'] builder further down in sample_snmp stays
    vendor-agnostic and untouched. Rows are classified by the
    component-class digit at the start of each row's table index (see
    snmp_profiles.JUNIPER_CLASS_*); jnxOperatingState's own enum is remapped
    into Cisco ENVMON's '1'..'5' vocabulary, but only the confirmed-normal
    codes map to '1' -- everything else becomes '9' (not a real ENVMON
    code, so _ENVMON_STATE_LABEL.get(...) falls through to 'unknown')
    rather than guessing a severity it isn't confident about (see
    snmp_profiles.JUNIPER_STATE_NORMAL_CODES for the full reasoning)."""
    def remap_state(raw):
        return '1' if str(raw) in snmp_profiles.JUNIPER_STATE_NORMAL_CODES else '9'

    env_temp_descr, env_temp_value, env_temp_state = {}, {}, {}
    for idx, val in oper_temp.items():
        temp_val = _safe_int(val)
        if not temp_val:  # 0/unparseable -- this row isn't a real temperature reading
            continue
        env_temp_descr[idx] = oper_descr.get(idx)
        env_temp_value[idx] = temp_val
        env_temp_state[idx] = remap_state(oper_state.get(idx))

    env_fan_state = {idx: remap_state(v) for idx, v in oper_state.items()
                      if idx.split('.')[0] == snmp_profiles.JUNIPER_CLASS_FAN}
    env_supply_state = {idx: remap_state(v) for idx, v in oper_state.items()
                         if idx.split('.')[0] == snmp_profiles.JUNIPER_CLASS_POWER_SUPPLY}
    return env_temp_descr, env_temp_value, env_temp_state, env_fan_state, env_supply_state


def _hp_icfsensor_env(sensor_type_ref, sensor_status):
    """hpicfSensorTable (HP-ICF-CHASSIS), classic ProCurve/ProVision --
    confirmed live against a real 2530/J9776A (fan + power rows only, no
    temperature row on that model; see the OID_HP_ICF_* comment in
    snmp_profiles.py). The type-ref column's value is the full OID of the
    icfSensors sub-node it belongs to, so fan/power is told apart by that
    OID's own suffix, not a short enum. Only the confirmed good(4) status
    maps to '1' -- any other code (including ones this project hasn't
    seen on a real faulted sensor) falls to '9', same unmapped-sentinel
    convention _juniper_env_from_opertable uses above."""
    fan_state, supply_state = {}, {}
    for idx, type_ref in sensor_type_ref.items():
        type_ref_s = str(type_ref)
        code = '1' if str(sensor_status.get(idx, '')) == snmp_profiles.HP_ICF_SENSOR_STATUS_GOOD else '9'
        if type_ref_s.endswith(snmp_profiles.HP_ICF_SENSOR_TYPE_FAN_SUFFIX):
            fan_state[idx] = code
        elif type_ref_s.endswith(snmp_profiles.HP_ICF_SENSOR_TYPE_POWER_SUFFIX):
            supply_state[idx] = code
    return fan_state, supply_state


def _h3c_entity_env(ent_class, temp_raw, temp_threshold, oper_status, phys_descr):
    """hh3cEntityExtStateTable, H3C/Comware -- confirmed live against a
    real A5500. temp_raw/temp_threshold both use 65535 as an explicit
    "not applicable" sentinel for every non-sensor row (ports, containers,
    PSU, fan...) -- filtered out here, not averaged/diluted the way CPU/mem
    briefly were before the module-filter fix above. A temp row with no
    threshold (also 65535) still gets its value shown, just with state
    '9' (unknown) since there's nothing confirmed to compare it against.
    Fan/supply status comes from a *different* column (hh3cEntityExtOper
    Status) that also carries values for ports etc, so it's filtered by
    entPhysicalClass instead; only enabled(3)/dangerous(4) are trusted
    (per H3C's own MIB doc), everything else (notSupported/disabled, or
    anything unexpected) falls to '9'."""
    NA = snmp_profiles.H3C_NA_VALUE
    temp_descr, temp_value, temp_state = {}, {}, {}
    for idx, raw in temp_raw.items():
        if str(raw) == NA:
            continue
        temp_descr[idx] = phys_descr.get(idx)
        temp_value[idx] = raw
        thresh = str(temp_threshold.get(idx, NA))
        if thresh == NA:
            temp_state[idx] = '9'
        else:
            try:
                temp_state[idx] = '3' if int(str(raw)) >= int(thresh) else '1'
            except Exception:
                temp_state[idx] = '9'

    def remap_oper(raw):
        s = str(raw)
        if s == snmp_profiles.H3C_OPER_STATUS_ENABLED:
            return '1'
        if s == snmp_profiles.H3C_OPER_STATUS_DANGEROUS:
            return '3'
        return '9'

    fan_state, supply_state = {}, {}
    for idx, cls in ent_class.items():
        cls_s = str(cls)
        if cls_s == snmp_profiles.ENT_PHYSICAL_CLASS_FAN:
            fan_state[idx] = remap_oper(oper_status.get(idx))
        elif cls_s == snmp_profiles.ENT_PHYSICAL_CLASS_POWER_SUPPLY:
            supply_state[idx] = remap_oper(oper_status.get(idx))
    return temp_descr, temp_value, temp_state, fan_state, supply_state


def _entity_sensor_env(sensor_type, sensor_scale, sensor_precision, sensor_value, sensor_status, phys_name):
    """Standard ENTITY-SENSOR-MIB (RFC 3433), currently only enabled for
    ArubaOS-CX -- confirmed live against a real 6100/JL675A. entPhySensorType
    tells temp(celsius)/fan(rpm)/supply(watts) apart directly, no class-table
    correlation needed (unlike H3C above). Value decode (raw * 10^(scale
    exponent - precision)) is the RFC's own formula, cross-checked against
    one real reading rather than taken on faith -- see the
    OID_ENT_PHY_SENSOR_* comment in snmp_profiles.py. Only ok(1) maps to
    '1'; unavailable(2)/nonoperational(3) both fall to '9' (unknown) rather
    than being told apart, since this project hasn't seen a real
    nonoperational sensor to confirm that split against."""
    temp_descr, temp_value, temp_state = {}, {}, {}
    fan_state, supply_state = {}, {}
    for idx, t in sensor_type.items():
        t_s = str(t)
        code = '1' if str(sensor_status.get(idx, '')) == snmp_profiles.ENT_SENSOR_STATUS_OK else '9'
        if t_s == snmp_profiles.ENT_SENSOR_TYPE_CELSIUS:
            try:
                raw = int(str(sensor_value.get(idx)))
                scale_exp = snmp_profiles.ENT_SENSOR_SCALE_EXPONENT.get(str(sensor_scale.get(idx)), 0)
                precision = _safe_int(sensor_precision.get(idx)) or 0
                temp_value[idx] = round(raw * (10 ** (scale_exp - precision)), 1)
                temp_descr[idx] = phys_name.get(idx)
                temp_state[idx] = code
            except Exception:
                pass
        elif t_s == snmp_profiles.ENT_SENSOR_TYPE_RPM:
            fan_state[idx] = code
        elif t_s == snmp_profiles.ENT_SENSOR_TYPE_WATTS:
            supply_state[idx] = code
    return temp_descr, temp_value, temp_state, fan_state, supply_state


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
    extended_due = (now - (entity.get('_extendedLastRun') or 0)) >= EXTENDED_POLL_INTERVAL_SEC
    if extended_due:
        entity['_extendedLastRun'] = now

    try:
        auth_data = build_auth_data(device_id, version, community)
        result = snmp_run(_snmp_poll(ip, auth_data, port, category, timeout=timeout_s, vendor_profile=vendor_profile, lldp_due=lldp_due, extended_due=extended_due))
    except Exception:
        result = {'reachable': False, 'latencyMs': None}

    if result.get('lldp'):
        try:
            lldp.apply_discovered_links(device_id, result['lldp'])
        except Exception:
            pass

    # Extended (slow-cadence) fields only arrive in `result` on ticks where
    # extended_due was true -- cached here so every other tick keeps
    # rendering the last known values instead of them flickering to empty.
    ext_cache = entity.setdefault('_extCache', {})
    for _k in ('adminStatus', 'inErrors', 'outErrors', 'inDiscards', 'outDiscards', 'ifHighSpeed',
               'hrMemSize', 'hrMemUsed', 'hrMemUnits', 'entDescr', 'entModel', 'entSerial',
               'envTempDescr', 'envTempValue', 'envTempState', 'envFanState', 'envSupplyState',
               'entModuleIdx'):
        if _k in result:
            ext_cache[_k] = result[_k]

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
        # Bug found live (2026-10-09): this used to fire only on the very
        # first good->bad transition (prev_status == 'good'). evaluate_status
        # escalates warn->crit after just 2 consecutive failures, but once
        # prev_status was already 'warn' that condition never fires again --
        # the incident row (and every alert channel, Kakao included) stayed
        # stuck at the original 'warn' severity for the rest of the outage,
        # even though the dashboard correctly showed 'crit'. Matches
        # ping_collector.py's rank-comparison, which already handled this
        # correctly: fire add_incident() on ANY upward severity move, not
        # just the first one -- add_incident()'s own dedup/escalation logic
        # (storage.py) takes it from there.
        rank = {'good': 0, 'warn': 1, 'crit': 2}
        if rank.get(status, 0) > rank.get(prev_status, 0):
            storage.add_incident(status, device_row['name'], storage.category_label(category),
                                  f"{device_row['name']} SNMP 응답 없음 (커뮤니티/버전을 확인하세요, 연속 {failures}회)",
                                  device_id=device_row['id'], event_type='REACHABILITY', maintenance=storage.in_maintenance(device_row))
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
    if prev_status != 'good':
        storage.add_incident('info', device_row['name'], storage.category_label(category),
                              f"{device_row['name']} SNMP 응답 정상 복구",
                              device_id=device_row['id'], event_type='REACHABILITY', maintenance=storage.in_maintenance(device_row))

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
            ifalias = result.get('ifAlias') or {}
            admin = ext_cache.get('adminStatus') or {}
            in_err = ext_cache.get('inErrors') or {}
            out_err = ext_cache.get('outErrors') or {}
            in_disc = ext_cache.get('inDiscards') or {}
            out_disc = ext_cache.get('outDiscards') or {}
            high_speed = ext_cache.get('ifHighSpeed') or {}
            iface_hist = entity.setdefault('_ifaceHist', {})
            ifaces = []
            for idx, name in ifdescr.items():
                rate = iface_rates.get(idx, {'inMbps': 0.0, 'outMbps': 0.0})
                iface_hist.setdefault(idx, hist(0))
                push_cap(iface_hist[idx], round(rate['inMbps'] + rate['outMbps'], 3))
                speed_mbps = _safe_int(high_speed.get(idx))
                util_in = round(rate['inMbps'] / speed_mbps * 100, 1) if speed_mbps else None
                util_out = round(rate['outMbps'] / speed_mbps * 100, 1) if speed_mbps else None
                raw_alias = str(ifalias.get(idx) or '').strip()
                # H3C/Comware switches (HP A5500 등) 자체 SNMP 에이전트가
                # 관리자가 설명을 하나도 안 입력해도 ifAlias에 "<ifDescr>
                # Interface" 형태의 기본값을 자동으로 채워 넣는다 (실제
                # 장비로 확인함 -- CLI에는 아무 description도 없는데 SNMP는
                # 빈 문자열이 아니라 이 placeholder를 돌려줌). 그대로
                # 보여주면 "이름 · 이름 Interface"처럼 이름이 그냥 중복돼
                # 보이므로, 이 정확한 패턴만 "설명 없음"으로 취급한다 --
                # 실제로 사람이 "GigabitEthernet1/0/2 Interface"라고 의미
                # 있는 설명을 적을 일은 없다고 봐도 되는 수준으로 구체적인
                # 패턴이라 다른 벤더의 진짜 설명을 잘못 지울 위험은 없음.
                description = '' if raw_alias.lower() == f'{name} interface'.lower() else raw_alias
                ifaces.append({
                    'idx': idx, 'name': str(name),
                    'description': description,
                    'status': 'up' if str(oper.get(idx, '2')) == '1' else 'down',
                    'adminStatus': 'up' if str(admin.get(idx, '1')) == '1' else 'down',
                    'inMbps': rate['inMbps'], 'outMbps': rate['outMbps'],
                    'speedMbps': speed_mbps,
                    'utilInPct': util_in, 'utilOutPct': util_out,
                    'inErrors': _safe_int(in_err.get(idx)),
                    'outErrors': _safe_int(out_err.get(idx)),
                    'inDiscards': _safe_int(in_disc.get(idx)),
                    'outDiscards': _safe_int(out_disc.get(idx)),
                    'hist': list(iface_hist[idx]),
                })
            ifaces.sort(key=lambda x: int(x['idx']) if x['idx'].isdigit() else 0)
            entity['interfaces'] = ifaces[:64]
        except Exception:
            pass
        try:
            loads = result.get('loads') or {}
            # entModuleIdx (H3C/Comware only, see OID_H3C_* / _top_level_module_
            # indices) narrows this table down to the row(s) that actually carry
            # a CPU -- without it, averaging in the port/PSU/fan/sensor rows
            # (which all report 0 for this OID) silently crushes the real
            # reading toward 0. Every other vendor never sets entModuleIdx, so
            # this is a no-op for them.
            module_idx = ext_cache.get('entModuleIdx')
            if module_idx:
                loads = {k: v for k, v in loads.items() if k in module_idx} or loads
            vals = [int(v) for v in loads.values() if str(v).lstrip('-').isdigit()]
            if vals:
                cpu = round(sum(vals) / len(vals), 1)
                entity['cpu'] = cpu
                entity.setdefault('hist', {}).setdefault('cpu', hist(0))
                push_cap(entity['hist']['cpu'], cpu)
        except Exception:
            pass
        try:
            mem_pct_direct = result.get('memPct') or {}
            module_idx = ext_cache.get('entModuleIdx')
            if module_idx:
                mem_pct_direct = {k: v for k, v in mem_pct_direct.items() if k in module_idx} or mem_pct_direct
            mem_used = result.get('memUsed') or {}
            mem_free = result.get('memFree') or {}
            used_total = sum(int(v) for v in mem_used.values())
            free_total = sum(int(v) for v in mem_free.values())
            mem_pct = None
            pct_vals = [int(v) for v in mem_pct_direct.values() if str(v).lstrip('-').isdigit()]
            if pct_vals:
                mem_pct = round(sum(pct_vals) / len(pct_vals), 1)
            elif used_total + free_total > 0:
                mem_pct = round(used_total / (used_total + free_total) * 100, 1)
            elif ext_cache.get('hrMemSize') and ext_cache.get('hrMemUsed'):
                units = _safe_int(ext_cache.get('hrMemUnits')) or 1
                size_bytes = int(ext_cache['hrMemSize']) * units
                used_bytes = int(ext_cache['hrMemUsed']) * units
                if size_bytes > 0:
                    mem_pct = round(used_bytes / size_bytes * 100, 1)
            if mem_pct is not None:
                entity['mem'] = mem_pct
                entity.setdefault('hist', {}).setdefault('mem', hist(0))
                push_cap(entity['hist']['mem'], mem_pct)
        except Exception:
            pass
        try:
            if ext_cache.get('envTempValue') or ext_cache.get('envFanState') or ext_cache.get('envSupplyState'):
                temp_descr = ext_cache.get('envTempDescr') or {}
                temp_value = ext_cache.get('envTempValue') or {}
                temp_state = ext_cache.get('envTempState') or {}
                fan_state = ext_cache.get('envFanState') or {}
                supply_state = ext_cache.get('envSupplyState') or {}
                entity['envTemps'] = [{
                    'description': str(temp_descr.get(idx) or '').strip(),
                    'valueC': _safe_int(val),
                    'state': _ENVMON_STATE_LABEL.get(str(temp_state.get(idx, '')), 'unknown'),
                } for idx, val in temp_value.items()]
                entity['envFans'] = [_ENVMON_STATE_LABEL.get(str(v), 'unknown') for v in fan_state.values()]
                entity['envSupplies'] = [_ENVMON_STATE_LABEL.get(str(v), 'unknown') for v in supply_state.values()]
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

    if ext_cache.get('entModel') or ext_cache.get('entSerial') or ext_cache.get('entDescr'):
        entity['hwModel'] = (ext_cache.get('entModel') or '').strip() or None
        entity['hwSerial'] = (ext_cache.get('entSerial') or '').strip() or None
        entity['hwDescr'] = (ext_cache.get('entDescr') or '').strip() or None

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
        if incident_event:
            kind, new_status = incident_event
            maint = storage.in_maintenance(device_row)
            if kind == 'escalate':
                storage.add_incident(new_status, device_row['name'], storage.category_label(category),
                                      f"리소스 사용률 {'임계치 초과' if new_status == 'crit' else '주의 구간 진입'} (CPU {cpu_val or 0:.0f}% / MEM {mem_val or 0:.0f}%)",
                                      device_id=device_row['id'], event_type='RESOURCE', maintenance=maint)
            else:
                storage.add_incident('info', device_row['name'], storage.category_label(category),
                                      f"{device_row['name']} 리소스 사용률 정상 범위로 복구",
                                      device_id=device_row['id'], event_type='RESOURCE', maintenance=maint)
