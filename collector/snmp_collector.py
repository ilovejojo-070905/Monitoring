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

# 신규 기능(2026-10-16, "SNMPv3 인증 실패/타임아웃/미지원 OID 구분"): pysnmp가
# errorIndication으로 돌려주는 값은 그냥 문자열이 아니라 pysnmp.proto.errind의
# 실제 클래스 인스턴스라서(실측으로 확인: RequestTimedOut 등), 그 클래스
# 이름으로 분류하면 메시지 문자열을 추측해서 매칭하는 것보다 훨씬 안정적이다.
# 이전엔 errorIndication/errorStatus를 전부 하나로 묶어 그냥 None/실패로만
# 처리했음 -- "장비가 꺼져있다"와 "SNMP 커뮤니티 문자열이 틀렸다"가 화면에
# 똑같이 보이던 문제. 전체 열거는 지원 안 함(인증과도, 타임아웃과도 무관한
# 그 외 전송/프로토콜 오류 전부)로 떨어지게 하는 안전한 기본값 -- 몰라서
# 틀리게 "인증 실패"라고 하느니 "그 외 오류"가 안전하다는, 이 프로젝트가
# 환경센서 상태 변환에서 이미 쓰던 것과 같은 정책.
SNMP_ERROR_TIMEOUT_CLASSES = frozenset({'RequestTimedOut', 'EmptyResponse'})
SNMP_ERROR_AUTH_CLASSES = frozenset({
    'UnknownCommunityName', 'NoEncryption', 'EncryptionError', 'DecryptionError',
    'NoAuthentication', 'AuthenticationError', 'AuthenticationFailure',
    'UnsupportedAuthProtocol', 'UnsupportedPrivProtocol', 'UnknownSecurityName',
    'UnsupportedSecurityModel', 'UnsupportedSecurityLevel', 'NotInTimeWindow',
    'UnknownUserName', 'WrongDigest', 'UnknownEngineID', 'EngineIDMismatch',
})


def classify_snmp_error(error_indication, error_status=None):
    """(kind, detail) -- kind is one of 'timeout'/'auth'/'transport_error'/
    'protocol_error'/None (no error). 미지원 OID 자체는 여기서 분류하지
    않는다: 그건 요청 전체가 아니라 varbind 하나가 noSuchObject/noSuchInstance
    로 응답한 것이라(errorIndication/errorStatus 둘 다 없는 정상 응답 안에서
    생기는 일), 이미 _snmp_get/_snmp_walk이 그 값을 None으로 바꿔서 호출한
    쪽은 "그 OID만 없음"과 "요청 자체가 실패함(이 함수가 다루는 것)"을
    이미 구분할 수 있다."""
    if error_indication is not None:
        name = type(error_indication).__name__
        if name in SNMP_ERROR_TIMEOUT_CLASSES:
            return 'timeout', str(error_indication)
        if name in SNMP_ERROR_AUTH_CLASSES:
            return 'auth', str(error_indication)
        return 'transport_error', str(error_indication)
    if error_status:
        return 'protocol_error', str(error_status)
    return None, None

# devices.last_failure_reason은 설계 당시(개발지시서 v2, 7/8항)부터
# PING_TIMEOUT/SNMP_TIMEOUT/SNMP_AUTH_ERROR/AGENT_OFFLINE/COLLECTOR_ERROR
# 5종 열거값으로 문서화돼 있었지만, SNMP_AUTH_ERROR는 지금까지 실제로 쓰인
# 적이 없었다(sample_snmp가 reachable=False면 항상 'SNMP_TIMEOUT'을 그대로
# 박아넣었음) -- classify_snmp_error의 분류를 그 기존 열거값에 맞춰 매핑.
# transport_error/protocol_error는 기존 5종에 없는 범주라 'SNMP_TIMEOUT'으로
# 떨어뜨림(완전히 새 열거값을 추가해 last_failure_reason 소비자쪽을 다 같이
# 바꾸는 대신, 이미 있는 "응답을 못 받음" 의미에 가장 가까운 값 재사용).
SNMP_ERROR_KIND_TO_REASON = {
    'timeout': 'SNMP_TIMEOUT',
    'auth': 'SNMP_AUTH_ERROR',
}

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
# 신규 기능(2026-10-16, "64비트 인터페이스 카운터 우선 사용"): ifInOctets/
# ifOutOctets(위 OID_IF_IN_OCTETS/OID_IF_OUT_OCTETS)는 32비트라 3.4Gbps를
# 넘는 링크에서는 poll 주기(기본 2초) 안에도 카운터가 한 바퀴 돌 수 있다.
# ifXTable의 64비트 카운터(ifHCInOctets/ifHCOutOctets)를 걸어서, 있으면
# 그걸 우선 쓰고 없으면(옛 장비/저속 인터페이스는 RFC 2863 권고상 64비트
# 테이블에 행이 없을 수 있음) 32비트로 자동 폴백 -- 인터페이스 단위로
# 섞여도 되게 설계(한 장비 안에서도 포트별로 있고 없고가 다를 수 있음).
OID_IF_HC_IN_OCTETS = '1.3.6.1.2.1.31.1.1.1.6'
OID_IF_HC_OUT_OCTETS = '1.3.6.1.2.1.31.1.1.1.10'
# 측정 간격이 이보다 길면(장애/재시작 등으로 한동안 못 걸렀다가 다시 걸린
# 경우) 그 구간 평균 Mbps는 "최선의 추정치"일 뿐 순간값과는 거리가 멀다 --
# 틀렸다고 숨기는 대신 lowConfidence로 표시해서 화면에서 구분 가능하게.
# 기본 tick이 2초(EXTENDED_POLL_INTERVAL_SEC 주석 참고)인 것 대비 30배.
TRAFFIC_RATE_MAX_RELIABLE_DT_SEC = 60

# MAC 주소/VLAN 수집 (신규 기능, 2026-10-16) -- 표준 BRIDGE-MIB/Q-BRIDGE-MIB
# (벤더 전용 아님). dot1dTpFdbTable은 MAC별로 안 뜨고 "브리지 포트 번호"로만
# 어디서 봤는지 알려줘서(VLAN 정보 없음), dot1dBasePortIfIndex로 그 브리지
# 포트를 실제 ifIndex로, dot1qPvid로 그 포트의 기본(access) VLAN으로 각각
# 상관시켜야 한다. 트렁크 포트처럼 VLAN이 여러 개인 포트는 PVID 하나로만
# 표시되는 근사치.
OID_DOT1D_TP_FDB_PORT = '1.3.6.1.2.1.17.4.3.1.2'
OID_DOT1D_TP_FDB_STATUS = '1.3.6.1.2.1.17.4.3.1.3'
OID_DOT1D_BASE_PORT_IFINDEX = '1.3.6.1.2.1.17.1.4.1.2'
OID_DOT1Q_PVID = '1.3.6.1.2.1.17.7.1.4.5.1.1'
DOT1D_FDB_STATUS_LEARNED = '3'
MAC_VLAN_INTERVAL_SEC = 300  # LLDP_INTERVAL_SEC와 같은 주기 -- MAC 테이블도 2초마다 걸을 필요 없음

# 확장(2026-10-16, "MAC/VLAN 정보 확장"): 위 PVID 근사치는 트렁크 포트에서
# 틀릴 수 있다는 걸 알고도 쓰던 것 -- Q-BRIDGE-MIB의 dot1qTpFdbTable은 그
# 문제가 원천적으로 없다(인덱스 자체가 "<vlanId>.<MAC 6개 옥텟>"이라 VLAN이
# 추측이 아니라 그 MAC이 실제로 학습된 테이블 안에 이미 들어있음). 예전엔
# "벤더 구현 편차가 커서 신뢰도가 낮다"는 이유로 범위에서 뺐었는데, 이번에
# 이 프로젝트가 실제로 등록해 쓰는 4개 실장비에 직접 걸어서 확인한 결과:
# HPE/Aruba(classic) 2대는 별도 VLAN 컨텍스트 없이 바로 응답(기존
# dot1dTpFdbTable과 행 수까지 정확히 일치), Cisco 2960S 1대는 0행으로
# 빈 응답(Cisco는 SNMP community에 "@<vlanId>" 접미사로 VLAN 컨텍스트를
# 넣어야 그 VLAN의 dot1qTpFdbTable을 보여주는 알려진 제약 -- 이 프로젝트가
# 쓰는 community 문자열 하나로는 애초에 전체를 못 봄). 그래서 "존재하면
# 그걸 쓰고, 비어 있으면(Cisco처럼) 기존 PVID 근사 방식으로 자동 폴백" --
# 기존 반환 형태({mac,ifIndex,ifName,vlanId})는 그대로라 호환성 깨짐 없음,
# Cisco처럼 폴백하는 장비는 이전과 완전히 같게 동작.
OID_DOT1Q_TP_FDB_PORT = '1.3.6.1.2.1.17.7.1.2.2.1.2'
OID_DOT1Q_TP_FDB_STATUS = '1.3.6.1.2.1.17.7.1.2.2.1.3'

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


def compute_counter_delta(curr, prev, bits, dt_sec, high_speed_mbps=None):
    """신규 기능(2026-10-16, "카운터 초기화·오버플로·인터페이스 재생성 처리").

    두 폴링 시점 사이 인터페이스 카운터(ifInOctets/ifHCInOctets 등)의
    증가량(바이트)을 계산. curr >= prev면 평범한 증가라 바로 뺄셈
    ('ok'). curr < prev면 두 가지 중 하나인데 카운터 값만 봐서는 원천적으로
    구분 불가능:
      1) 카운터가 2**bits에서 한 바퀴 돌았다 (overflow/wraparound)
      2) 인터페이스가 재생성됐거나 장비가 재부팅돼 카운터가 0 근처부터
         다시 시작했다 (reset)
    구분 기준: (1)이 맞으려면 dt_sec 동안 그 비트폭 카운터가 실제로 한
    바퀴 돌 만큼의 속도가 나와야 한다 -- 그 요구 속도가 이 인터페이스의
    ifHighSpeed(모르면 10Gbps로 가정) 대비 비정상적으로(4배 넘게) 높으면
    물리적으로 불가능하다고 보고 (2)로 판단한다. 틀리게 "랩어라운드"라고
    단정해서 트래픽이 터무니없이 튀어 보이는 것보다, reset 쪽으로 판단해서
    "이번 구간은 curr 바이트만큼 새로 쌓인 것"으로 보수적으로 처리하는
    게 더 안전한 기본값.

    반환: (delta_bytes, note) -- note는 'ok'/'wrapped'/'reset'/'implausible'.
    'implausible'은 계산된 delta가 ifHighSpeed 대비로도 물리적으로
    불가능한 수준일 때(링크 속도의 4배 초과) -- 그런 경우 화면에 터무니없는
    순간 속도를 보여주는 대신 0으로 깎아서 돌려준다. 호출부는 note가
    'ok'가 아니면 그 구간을 lowConfidence로 표시해야 한다."""
    dt_sec = max(dt_sec, 0.001)
    wrap_span = 1 << bits
    if curr >= prev:
        delta, note = curr - prev, 'ok'
    else:
        wrapped_delta = (curr - prev) + wrap_span
        wrap_required_bps = wrap_span * 8 / dt_sec
        plausible_cap_bps = max((high_speed_mbps or 10_000) * 1_000_000 * 4, 1)
        if wrap_required_bps <= plausible_cap_bps:
            delta, note = wrapped_delta, 'wrapped'
        else:
            delta, note = curr, 'reset'
    if high_speed_mbps:
        max_bytes = high_speed_mbps * 1_000_000 * dt_sec / 8 * 4
        if delta > max_bytes:
            return 0, 'implausible'
    return delta, note


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
    validation -- doesn't do any of sample_snmp's per-category polling.
    retries=0 explicitly: test_connection() below already calls this up to
    `attempts` times as its own majority-vote retry, so _snmp_get's own
    default retry would multiply the worst-case wait on top of that (see
    _snmp_get's own comment) -- a real, measured regression on registration/
    test-snmp response time, not a hypothetical one."""
    try:
        values, _kind = snmp_run(_snmp_get(SnmpEngine(), ip, auth_data, port, [OID_SYS_NAME], timeout=timeout, retries=0))
        return values is not None
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


async def _snmp_get(engine, ip, auth_data, port, oids, timeout=1.5, retries=1):
    # 버그 수정(2026-10-16): retries=0이면 UDP 패킷 하나만 손실돼도(흔한
    # 일시적 현상, 꼭 장비가 실제로 다운돼야 생기는 게 아님) 이 호출 전체가
    # 그 자리에서 바로 실패했음 -- 기본값을 1회 재시도로 바꿔 그런 일시적
    # 손실을 흡수함. 대가: 진짜로 응답이 없는 장비는 이 호출 하나가 실패를
    # 확정하기까지 최대 timeout의 2배가 걸림 -- 보통의 poll tick 안에서는
    # 받아들일 만한 수준(기존 timeout_s 기본값 1.5초 기준 최대 3초)이고,
    # evaluate_status()가 이미 여러 틱에 걸친 연속 실패를 요구하므로 반응성
    # 자체가 느려지는 건 아님.
    #
    # 다만 check_reachable()/test_connection()처럼 호출 하나가 이미 여러
    # 번(다수결) 시도하는 경로에서는 그 attempts 횟수에 이 재시도가 또
    # 곱해져서(예: 3번의 다수결 시도 각각이 최대 timeout의 2배) 등록
    # API 응답이 눈에 띄게 느려지는 실제 회귀가 있었음(실측: 보안
    # 테스트 스위트가 자신의 HTTP 클라이언트 타임아웃에 걸려 제대로
    # 정리도 못 하고 죽는 것까지 확인) -- 그런 호출부는 retries=0을
    # 명시로 넘겨서 이 재시도가 중복으로 곱해지지 않게 한다.
    target = await UdpTransportTarget.create((ip, int(port)), timeout=timeout, retries=retries)
    var_binds = [ObjectType(ObjectIdentity(oid)) for oid in oids]
    errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
        engine, auth_data, target, ContextData(), *var_binds)
    if errorIndication or errorStatus:
        kind, _detail = classify_snmp_error(errorIndication, errorStatus)
        return None, kind
    values = []
    for vb in varBinds:
        v = str(vb[1])
        values.append(None if 'No Such' in v else v)
    return values, None


async def _snmp_walk(engine, ip, auth_data, port, base_oid, timeout=1.5, max_rows=256, retries=1, return_status=False):
    # 위 _snmp_get과 같은 이유로 기본값 retries=0 -> 1.
    #
    # return_status(2026-10-16, "오래된 링크와 수집 실패를 실제 단절과
    # 구별"): 기본값 False면 이전과 완전히 동일하게 dict만 돌려준다 --
    # 이미 30곳 넘게 이 함수를 쓰는 기존 호출부를 전부 건드리지 않기
    # 위한 선택. True로 호출하면 (dict, confirmed) 튜플을 돌려주는데,
    # confirmed=False는 "도중에 진짜 SNMP 에러로 끊겨서 이 dict가
    # 불완전/신뢰 불가"라는 뜻이고(빈 dict든 일부만 찼든 마찬가지),
    # confirmed=True는 "이 테이블을 끝까지 확인했고 이 dict가 전체
    # 결과"라는 뜻 -- 특히 confirmed=True + 빈 dict는 "그 OID 아래
    # 항목이 실제로 0개임을 확인함"이라, lldp.py가 이걸로 "장비가 LLDP
    # 이웃이 하나도 없다고 확인 응답함"과 "이번 폴링이 그냥 실패함"을
    # 구분해서 전자일 때만 끊어진 링크를 지운다(replace_lldp_links).
    target = await UdpTransportTarget.create((ip, int(port)), timeout=timeout, retries=retries)
    out = {}
    count = 0
    confirmed = True
    async for (errorIndication, errorStatus, errorIndex, varBinds) in bulk_walk_cmd(
            engine, auth_data, target, ContextData(),
            0, 20, ObjectType(ObjectIdentity(base_oid)), lexicographicMode=False):
        if errorIndication or errorStatus:
            confirmed = False
            break
        for vb in varBinds:
            oid_str = str(vb[0])
            if not oid_str.startswith(base_oid + '.'):
                return (out, True) if return_status else out
            out[oid_str[len(base_oid) + 1:]] = vb[1]
        count += 1
        if count > max_rows:
            break
    return (out, confirmed) if return_status else out


async def _snmp_poll(ip, auth_data, port, category, timeout, vendor_profile, lldp_due, extended_due):
    """One SNMP session (one engine, one event loop) per device per poll.

    extended_due gates the slow-changing / purely informational items (error
    counters, admin status, link speed, hrStorage memory fallback, ENTITY-MIB,
    ENVMON) so a busy 'net' device isn't hit with ~2x the SNMP round trips on
    every single 2-second tick -- see EXTENDED_POLL_INTERVAL_SEC above."""
    engine = SnmpEngine()
    result = {'reachable': False, 'latencyMs': None}
    start = time.time()
    basics, err_kind = await _snmp_get(engine, ip, auth_data, port, [OID_SYS_NAME, OID_SYS_DESCR, OID_SYS_UPTIME], timeout=timeout)
    result['latencyMs'] = round((time.time() - start) * 1000, 1)
    if basics is None:
        result['failureReason'] = SNMP_ERROR_KIND_TO_REASON.get(err_kind, 'SNMP_TIMEOUT')
        return result
    result['reachable'] = True
    result['sysName'], result['sysDescr'], result['sysUptimeTicks'] = basics[0], basics[1], basics[2]
    profile = snmp_profiles.resolve_profile(vendor_profile, result['sysDescr'])
    if category == 'net':
        result['ifDescr'] = await _snmp_walk(engine, ip, auth_data, port, OID_IF_DESCR, timeout=timeout)
        result['ifAlias'] = await _snmp_walk(engine, ip, auth_data, port, OID_IF_ALIAS, timeout=timeout)
        result['oper'] = await _snmp_walk(engine, ip, auth_data, port, OID_IF_OPER_STATUS, timeout=timeout)
        # 64비트 카운터(ifHCIn/OutOctets) 우선 사용, 모든 인터페이스를
        # 못 덮으면(옛 장비, 또는 RFC 2863상 느린 인터페이스는 HC 생략
        # 가능) 32비트 테이블로 그 틱 전체를 통째로 폴백 -- 인터페이스별로
        # 섞어 쓰지 않는 이유: 한쪽만 HC가 비어 있는 상태를 섞으면 그
        # 인터페이스는 매 틱 0바이트로 보일 위험이 있어서, "전부 64비트
        # 아니면 전부 32비트" 중 더 안전한 쪽(실제로 전부 커버하는 쪽)을
        # 고른다. ifDescr는 바로 위에서 이미 걸었으니 추가 라운드트립 없이
        # "몇 개 인터페이스가 있는지"의 기준으로 재사용.
        in_hc = await _snmp_walk(engine, ip, auth_data, port, OID_IF_HC_IN_OCTETS, timeout=timeout)
        out_hc = await _snmp_walk(engine, ip, auth_data, port, OID_IF_HC_OUT_OCTETS, timeout=timeout)
        iface_count = len(result['ifDescr'])
        if iface_count and len(in_hc) >= iface_count and len(out_hc) >= iface_count:
            result['in_oct'], result['out_oct'], result['ifCounterBits'] = in_hc, out_hc, 64
        else:
            result['in_oct'] = await _snmp_walk(engine, ip, auth_data, port, OID_IF_IN_OCTETS, timeout=timeout)
            result['out_oct'] = await _snmp_walk(engine, ip, auth_data, port, OID_IF_OUT_OCTETS, timeout=timeout)
            result['ifCounterBits'] = 32
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
                ent, _ent_err = await _snmp_get(engine, ip, auth_data, port,
                                       [OID_ENT_PHYSICAL_DESCR, OID_ENT_PHYSICAL_MODEL_NAME, OID_ENT_PHYSICAL_SERIAL_NUM],
                                       timeout=timeout)
                if ent:
                    result['entDescr'], result['entModel'], result['entSerial'] = ent[0], ent[1], ent[2]
            except Exception:
                pass
        if lldp_due:
            result['lldp'] = await lldp.walk_lldp_neighbors(engine, ip, auth_data, port, timeout=timeout)
            # MAC/VLAN도 LLDP와 같은 느린 주기로 -- 둘 다 "초 단위로 신선할
            # 필요 없는" 정보고, 바쁜 스위치의 MAC 테이블은 수백~수천 행일
            # 수 있어 매 2초 틱마다 걷는 건 이 파일 위쪽의 EXTENDED_POLL_
            # INTERVAL_SEC 주석이 실측으로 겪은 "management-plane 과부하"와
            # 같은 위험이 있음.
            try:
                result['macTable'] = await _collect_mac_vlan_table(
                    engine, ip, auth_data, port, result.get('ifDescr') or {}, timeout=timeout)
            except Exception:
                pass
    elif category in ('server', 'db'):
        profile_srv = snmp_profiles.resolve_profile(vendor_profile, result['sysDescr'])
        cpu_oid = profile_srv['cpu_oid'] or snmp_profiles.OID_HR_PROCESSOR_LOAD
        result['loads'] = await _snmp_walk(engine, ip, auth_data, port, cpu_oid, timeout=timeout)
        # 버그 수정(2026-10-16): 'net' 카테고리에서 H3C/Comware 테이블 평균
        # 희석 버그를 고치며 넣은 entity_module_filter(entModuleIdx)가
        # 'server'/'db' 카테고리엔 전혀 연결돼 있지 않았음 -- 같은
        # hp-comware 프로필이 (이례적이지만) 'server'/'db'로 등록된
        # 장비에 쓰이면 그 똑같은 버그가 그대로 재발할 수 있었음. 'net'
        # 쪽과 동일한 로직을 그대로 연결.
        if profile_srv.get('entity_module_filter'):
            ent_class = await _snmp_walk(engine, ip, auth_data, port, snmp_profiles.OID_ENT_PHYSICAL_CLASS, timeout=timeout)
            ent_contained = await _snmp_walk(engine, ip, auth_data, port, snmp_profiles.OID_ENT_PHYSICAL_CONTAINED_IN, timeout=timeout)
            result['entModuleIdx'] = _top_level_module_indices(ent_class, ent_contained)
        if extended_due:
            try:
                ent, _ent_err = await _snmp_get(engine, ip, auth_data, port,
                                       [OID_ENT_PHYSICAL_DESCR, OID_ENT_PHYSICAL_MODEL_NAME, OID_ENT_PHYSICAL_SERIAL_NUM],
                                       timeout=timeout)
                if ent:
                    result['entDescr'], result['entModel'], result['entSerial'] = ent[0], ent[1], ent[2]
            except Exception:
                pass
    elif category == 'fac':
        result['batt'], _batt_err = await _snmp_get(engine, ip, auth_data, port, [OID_UPS_BATTERY_CAPACITY], timeout=timeout)
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


def _mac_from_oid_suffix(suffix):
    """dot1dTpFdbTable's index IS the MAC address, one decimal octet per OID
    component ('0.1.2.3.4.5' -> 00:01:02:03:04:05) -- no separate "address"
    column to read, the table index already is one."""
    try:
        parts = [int(p) for p in suffix.split('.')]
        if len(parts) != 6 or any(p < 0 or p > 255 for p in parts):
            return None
        return ':'.join(f'{p:02x}' for p in parts)
    except Exception:
        return None


def _mac_vlan_from_dot1q_oid_suffix(suffix):
    """dot1qTpFdbTable's index is '<vlanId>.<MAC 6 octets>' -- unlike
    dot1dTpFdbTable, the VLAN this MAC was actually learned on is already
    part of the index itself, not something to approximate from a port's
    PVID. Returns (vlan_id, mac) or (None, None)."""
    try:
        parts = [int(p) for p in suffix.split('.')]
        if len(parts) != 7:
            return None, None
        vlan_id, octets = parts[0], parts[1:]
        if vlan_id < 1 or any(o < 0 or o > 255 for o in octets):
            return None, None
        return vlan_id, ':'.join(f'{o:02x}' for o in octets)
    except Exception:
        return None, None


async def _collect_mac_vlan_table(engine, ip, auth_data, port, if_descr, timeout):
    """BRIDGE-MIB/Q-BRIDGE-MIB MAC/VLAN table. Returns a list of
    {mac, ifIndex, ifName, vlanId}, one row per MAC currently in the switch's
    forwarding table (status=learned(3) only -- self/mgmt/other rows are the
    switch's own ports/static entries, not something plugged into the
    network).

    dot1qTpFdbTable(VLAN-정확) 우선 시도, 응답 없으면(실측으로 확인된 Cisco의
    community@vlan 제약 등) dot1dTpFdbTable+PVID 근사치로 폴백 -- 위
    OID_DOT1Q_TP_FDB_PORT 주석 참고."""
    base_port_ifindex = await _snmp_walk(engine, ip, auth_data, port, OID_DOT1D_BASE_PORT_IFINDEX, timeout=timeout)

    dot1q_port = await _snmp_walk(engine, ip, auth_data, port, OID_DOT1Q_TP_FDB_PORT, timeout=timeout)
    if dot1q_port:
        dot1q_status = await _snmp_walk(engine, ip, auth_data, port, OID_DOT1Q_TP_FDB_STATUS, timeout=timeout)
        entries = []
        for suffix, bridge_port in dot1q_port.items():
            if str(dot1q_status.get(suffix, '')) != DOT1D_FDB_STATUS_LEARNED:
                continue
            vlan_id, mac = _mac_vlan_from_dot1q_oid_suffix(suffix)
            if not mac:
                continue
            bridge_port_s = str(bridge_port)
            if_index = base_port_ifindex.get(bridge_port_s)
            if_index_s = str(if_index) if if_index is not None else None
            entries.append({
                'mac': mac,
                'ifIndex': if_index_s,
                'ifName': str(if_descr.get(if_index_s) or '') if if_index_s else '',
                'vlanId': vlan_id,
            })
        return entries

    fdb_port = await _snmp_walk(engine, ip, auth_data, port, OID_DOT1D_TP_FDB_PORT, timeout=timeout)
    fdb_status = await _snmp_walk(engine, ip, auth_data, port, OID_DOT1D_TP_FDB_STATUS, timeout=timeout)
    if not fdb_port:
        return []
    pvid = await _snmp_walk(engine, ip, auth_data, port, OID_DOT1Q_PVID, timeout=timeout)
    entries = []
    for mac_suffix, bridge_port in fdb_port.items():
        if str(fdb_status.get(mac_suffix, '')) != DOT1D_FDB_STATUS_LEARNED:
            continue
        mac = _mac_from_oid_suffix(mac_suffix)
        if not mac:
            continue
        bridge_port_s = str(bridge_port)
        if_index = base_port_ifindex.get(bridge_port_s)
        if_index_s = str(if_index) if if_index is not None else None
        entries.append({
            'mac': mac,
            'ifIndex': if_index_s,
            'ifName': str(if_descr.get(if_index_s) or '') if if_index_s else '',
            'vlanId': _safe_int(pvid.get(bridge_port_s)),
        })
    return entries


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

    # 신규 기능(2026-10-16, "오래된 링크와 수집 실패를 실제 단절과 구별"):
    # result['lldp']는 이제 {'neighbors': [...], 'confirmed': bool} 형태.
    # confirmed=False(이번 폴링에서 LLDP 테이블을 못 받음)면 기존 링크를
    # 그대로 두고 아무것도 안 한다 -- 모르는 걸 "끊어졌다"고 지우지
    # 않는다는 안전 정책(이전엔 neighbors가 비어 있으면 confirmed 여부와
    # 상관없이 똑같이 건너뛰어서, 장비가 "이웃 0개"라고 확실히 응답한
    # 경우조차 끊어진 링크가 영원히 안 지워졌음).
    lldp_result = result.get('lldp')
    if lldp_result is not None and lldp_result.get('confirmed'):
        try:
            lldp.apply_discovered_links(device_id, lldp_result.get('neighbors') or [])
        except Exception:
            pass
    if 'macTable' in result:
        try:
            storage.replace_mac_table(device_id, result['macTable'])
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
        None if result['reachable'] else result.get('failureReason', 'SNMP_TIMEOUT'),
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
            bits = result.get('ifCounterBits', 32)
            entity['portsUp'] = sum(1 for v in oper.values() if str(v) == '1')
            entity['portsTotal'] = len(oper)
            now = time.time()
            prev = entity.get('_snmpPrev')
            prev_ifaces = entity.get('_snmpIfacePrev') or {}
            entity.setdefault('hist', {}).setdefault('traffic', hist(0))
            iface_rates = {}
            # 신규 기능(2026-10-16, "측정 간격·비정상 카운터 변화 검증" +
            # "64비트 카운터/오버플로/재생성 처리"): 전체 합계를 먼저 구하고
            # 그 합계의 증감만 보던 이전 방식은 카운터 오버플로/재생성을
            # 아예 구분하지 못하고 max(.., 0)으로 음수를 그냥 0으로 뭉갰다 --
            # 인터페이스 하나가 재부팅으로 카운터가 리셋되면 "이번 틱 트래픽
            # 0"으로 보였을 것. 이제 인터페이스별로 compute_counter_delta를
            # 돌려 랩어라운드/리셋을 구분하고, 그 델타들을 합쳐서 장비 전체
            # 합계를 만든다(합계를 먼저 내고 델타를 구하는 게 아니라).
            if prev:
                dt = max(now - prev['t'], 1)
                dt_reliable = dt <= TRAFFIC_RATE_MAX_RELIABLE_DT_SEC
                high_speed_early = ext_cache.get('ifHighSpeed') or {}
                total_in_delta = total_out_delta = 0
                for idx, v in in_oct.items():
                    prevp = prev_ifaces.get(idx)
                    # 지난 틱과 카운터 비트폭이 다르면(예: 장비가 막 재시작돼
                    # 이번 틱부터 64비트 HC 테이블에 응답하기 시작함) 두 값을
                    # 직접 비교할 수 없다 -- 이번 틱은 델타를 안 내고 다음
                    # 틱부터 새 비트폭 기준으로 다시 쌓는다.
                    if not prevp or prevp.get('bits') != bits:
                        continue
                    speed_mbps = _safe_int(high_speed_early.get(idx))
                    d_in, note_in = compute_counter_delta(int(v), prevp.get('in', 0), bits, dt, speed_mbps)
                    d_out, note_out = compute_counter_delta(int(out_oct.get(idx, 0)), prevp.get('out', 0), bits, dt, speed_mbps)
                    iface_rates[idx] = {
                        'inMbps': round(d_in * 8 / dt / 1_000_000, 3),
                        'outMbps': round(d_out * 8 / dt / 1_000_000, 3),
                        'lowConfidence': (not dt_reliable) or note_in != 'ok' or note_out != 'ok',
                    }
                    total_in_delta += d_in
                    total_out_delta += d_out
                in_mbps = round(total_in_delta * 8 / dt / 1_000_000, 2)
                out_mbps = round(total_out_delta * 8 / dt / 1_000_000, 2)
                entity['trafficIn'] = in_mbps
                entity['trafficOut'] = out_mbps
                # 측정 간격 자체가 너무 길면(장애/재시작 후 한참 지나 다시
                # 걸린 경우) 그 구간 평균은 "최선의 추정치"일 뿐이라 숨기지
                # 않고 플래그로 표시 -- 화면/API 소비자가 "신뢰도 낮음"으로
                # 구분할 수 있게.
                entity['trafficLowConfidence'] = not dt_reliable
                push_cap(entity['hist']['traffic'], round(in_mbps + out_mbps, 2))
            entity['_snmpPrev'] = {'t': now}
            entity['_snmpIfacePrev'] = {idx: {'in': int(v), 'out': int(out_oct.get(idx, 0)), 'bits': bits} for idx, v in in_oct.items()}

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
                rate = iface_rates.get(idx, {'inMbps': 0.0, 'outMbps': 0.0, 'lowConfidence': False})
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
                    'trafficLowConfidence': rate.get('lowConfidence', False),
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
            loads = result['loads'] or {}
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
