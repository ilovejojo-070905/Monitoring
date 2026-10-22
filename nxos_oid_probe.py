"""Cisco Nexus(NX-OS) SNMP OID 실측 진단 스크립트 — Nexus 전용
snmp_profiles.py 프로필을 추가하기 전, 실제 NX-OS 장비가 어느 OID로
CPU/메모리/환경센서를 응답하는지 확인하는 읽기 전용 도구.

이 프로젝트의 확고한 원칙("실제 장비에서 검증하지 않은 OID를 검증
완료로 표시하지 않는다")에 따라, 아래 OID들은 전부 "후보"일 뿐
확정이 아니다 — Catalyst(IOS)와 Nexus(NX-OS)는 같은 Cisco라도
enterprise OID 트리/인덱싱이 다른 경우가 흔하다고 알려져 있고(이미
이 프로젝트가 HP/H3C/ArubaOS-CX에서 "sysDescr에 같은 제조사 이름이
있어도 실제 칩/OS가 다르면 OID도 다르다"를 실측으로 거듭 확인한
것과 같은 종류의 문제), NX-OS 버전/플랫폼별로도 지원 MIB가 갈릴 수
있다.

실행:
    INFRASIGHT_TEST_SNMP_COMMUNITY='...' python nxos_oid_probe.py <IP>
    (SNMPv3면 INFRASIGHT_TEST_SNMP_V3_USER 등 추가 env var 필요 -- 아래 참고)

이 스크립트는 collector/snmp_collector.py의 _snmp_get/_snmp_walk와
완전히 동일한 pysnmp 호출 패턴(동일 라이브러리, 동일 timeout/retries
관례)을 그대로 재사용한다 -- 실제 수집기가 쓰는 것과 다른 경로로
테스트해서 "스크립트에선 되는데 실제 수집기에선 안 된다" 같은 괴리가
생기지 않게 하기 위함.
"""
import asyncio
import os
import sys

try:
    from pysnmp.hlapi.v3arch.asyncio import (
        SnmpEngine, CommunityData, UsmUserData, UdpTransportTarget, ContextData,
        ObjectType, ObjectIdentity, get_cmd, bulk_walk_cmd,
        usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol,
        usmDESPrivProtocol, usmAesCfb128Protocol, usmNoAuthProtocol, usmNoPrivProtocol,
    )
except Exception as e:
    print(f'pysnmp를 가져올 수 없습니다: {e}\npip install pysnmp 로 설치해주세요.')
    sys.exit(1)

AUTH_PROTOCOLS = {'MD5': usmHMACMD5AuthProtocol, 'SHA': usmHMACSHAAuthProtocol, None: usmNoAuthProtocol}
PRIV_PROTOCOLS = {'DES': usmDESPrivProtocol, 'AES': usmAesCfb128Protocol, None: usmNoPrivProtocol}

# 후보 OID -- 전부 "미검증, 실측 필요". 출처는 Cisco 공개 MIB 문서 기준
# 일반 지식이며, 이 프로젝트의 다른 모든 벤더 프로필처럼 실제 장비
# 응답으로만 확정한다.
CANDIDATES = {
    'CPU': [
        ('HOST-RESOURCES-MIB hrProcessorLoad (표준, generic 프로필이 이미 씀)', '1.3.6.1.2.1.25.3.3.1.2', 'walk'),
        ('CISCO-PROCESS-MIB cpmCPUTotal5min (기존 cisco 프로필, IOS 기준)', '1.3.6.1.4.1.9.9.109.1.1.1.1.7', 'walk'),
        ('CISCO-PROCESS-MIB cpmCPUTotal5minRev (NX-OS 문서에서 자주 언급됨)', '1.3.6.1.4.1.9.9.109.1.1.1.1.8', 'walk'),
        ('CISCO-SYSTEM-EXT-MIB cseSysCPUUtilization (NX-OS 전용으로 알려짐)', '1.3.6.1.4.1.9.9.305.1.1.1.0', 'get'),
    ],
    'MEM': [
        ('CISCO-MEMORY-POOL-MIB ciscoMemoryPoolUsed (기존 cisco 프로필, IOS 기준)', '1.3.6.1.4.1.9.9.48.1.1.1.5', 'walk'),
        ('CISCO-MEMORY-POOL-MIB ciscoMemoryPoolFree (기존 cisco 프로필, IOS 기준)', '1.3.6.1.4.1.9.9.48.1.1.1.6', 'walk'),
        ('CISCO-SYSTEM-EXT-MIB cseSysMemoryUtilization (NX-OS 전용으로 알려짐)', '1.3.6.1.4.1.9.9.305.1.1.2.0', 'get'),
        ('CISCO-ENHANCED-MEMPOOL-MIB cempMemPoolUsed', '1.3.6.1.4.1.9.9.221.1.1.1.1.7', 'walk'),
        ('CISCO-ENHANCED-MEMPOOL-MIB cempMemPoolFree', '1.3.6.1.4.1.9.9.221.1.1.1.1.8', 'walk'),
        ('CISCO-ENHANCED-MEMPOOL-MIB cempMemPoolHCUsed (64비트)', '1.3.6.1.4.1.9.9.221.1.1.1.1.18', 'walk'),
        ('CISCO-ENHANCED-MEMPOOL-MIB cempMemPoolHCFree (64비트)', '1.3.6.1.4.1.9.9.221.1.1.1.1.20', 'walk'),
    ],
    'ENV': [
        ('CISCO-ENVMON-MIB ciscoEnvMonTemperatureStatusValue (기존 cisco 프로필, IOS 기준 -- 1차 실측 응답 없음)', '1.3.6.1.4.1.9.9.13.1.3.1.3', 'walk'),
        ('CISCO-ENVMON-MIB ciscoEnvMonFanStatusValue (기존 cisco 프로필, IOS 기준 -- 1차 실측 응답 없음)', '1.3.6.1.4.1.9.9.13.1.4.1.3', 'walk'),
        ('표준 ENTITY-SENSOR-MIB entPhySensorValue (aruba-cx 프로필이 이미 씀, 표준 MIB -- 1차 실측 응답 없음)', '1.3.6.1.2.1.99.1.1.1.4', 'walk'),
        # 2차 실측(2026-10-22, env_mib 비워둔 뒤 사용자가 "환경센서 안 보임" 재확인
        # 요청) -- 1차에서 안 쓴 다른 MIB 트리로 재시도.
        ('[2차] CISCO-ENTITY-FRU-CONTROL-MIB cefcFanTrayStatus (팬 트레이 상태)', '1.3.6.1.4.1.9.9.117.1.4.1.1.1', 'walk'),
        ('[2차] CISCO-ENTITY-FRU-CONTROL-MIB cefcFRUPowerOperStatus (전원 공급 상태)', '1.3.6.1.4.1.9.9.117.1.1.2.1.2', 'walk'),
        ('[2차] CISCO-ENTITY-FRU-CONTROL-MIB cefcModuleStatus (모듈 상태)', '1.3.6.1.4.1.9.9.117.1.2.1.1.2', 'walk'),
        # 진단용: entSensorValue가 빈 이유가 "센서 미지원"인지 "ENTITY-MIB
        # 테이블 자체가 이 장비에서 비어있음"인지 구분하기 위해 entPhysicalTable
        # 자체에 행이 있는지부터 확인 (표준 MIB, 응답 있으면 테이블은 존재함).
        ('[진단] 표준 ENTITY-MIB entPhysicalDescr (entPhysicalTable에 행이 있는지 확인용)', '1.3.6.1.2.1.47.1.1.1.1.2', 'walk'),
    ],
    'MAC/VLAN': [
        ('표준 Q-BRIDGE-MIB dot1qTpFdbPort (VLAN 정확, 일부 Cisco는 community@vlan 필요)', '1.3.6.1.2.1.17.7.1.2.2.1.2', 'walk'),
        ('표준 BRIDGE-MIB dot1dTpFdbPort (VLAN 근사치 폴백)', '1.3.6.1.2.1.17.4.3.1.2', 'walk'),
    ],
}


def build_auth_data():
    community = os.environ.get('INFRASIGHT_TEST_SNMP_COMMUNITY')
    if community:
        return CommunityData(community, mpModel=1)  # v2c
    v3_user = os.environ.get('INFRASIGHT_TEST_SNMP_V3_USER')
    if v3_user:
        auth_proto = AUTH_PROTOCOLS.get(os.environ.get('INFRASIGHT_TEST_SNMP_V3_AUTH_PROTO'))
        priv_proto = PRIV_PROTOCOLS.get(os.environ.get('INFRASIGHT_TEST_SNMP_V3_PRIV_PROTO'))
        return UsmUserData(
            v3_user,
            authKey=os.environ.get('INFRASIGHT_TEST_SNMP_V3_AUTH_PASS') or None,
            privKey=os.environ.get('INFRASIGHT_TEST_SNMP_V3_PRIV_PASS') or None,
            authProtocol=auth_proto, privProtocol=priv_proto,
        )
    print('INFRASIGHT_TEST_SNMP_COMMUNITY(v2c) 또는 INFRASIGHT_TEST_SNMP_V3_USER(v3) 환경변수가 필요합니다.')
    sys.exit(1)


async def probe_get(engine, auth_data, target, oid):
    var_binds = [ObjectType(ObjectIdentity(oid))]
    errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
        engine, auth_data, target, ContextData(), *var_binds)
    if errorIndication or errorStatus:
        return None, f'{errorIndication or errorStatus}'
    vals = [str(vb[1]) for vb in varBinds if 'No Such' not in str(vb[1])]
    return (vals or None), None


async def probe_walk(engine, auth_data, target, base_oid, max_rows=10):
    out = {}
    try:
        async for (errorIndication, errorStatus, errorIndex, varBinds) in bulk_walk_cmd(
                engine, auth_data, target, ContextData(),
                0, 10, ObjectType(ObjectIdentity(base_oid)), lexicographicMode=False):
            if errorIndication or errorStatus:
                return (out or None), f'{errorIndication or errorStatus}'
            for vb in varBinds:
                oid_str = str(vb[0])
                if not oid_str.startswith(base_oid + '.'):
                    return (out or None), None
                out[oid_str[len(base_oid) + 1:]] = str(vb[1])
            if len(out) >= max_rows:
                break
    except Exception as e:
        return (out or None), str(e)
    return (out or None), None


async def main():
    if len(sys.argv) < 2:
        print('사용법: python nxos_oid_probe.py <장비 IP> [포트(기본 161)]')
        sys.exit(1)
    ip = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 161
    auth_data = build_auth_data()
    engine = SnmpEngine()
    target = await UdpTransportTarget.create((ip, port), timeout=2.0, retries=1)

    # 먼저 sysDescr로 이 장비가 진짜 NX-OS인지, 지금 resolve_profile()이
    # 뭘로 잡을지부터 실측 확인.
    print(f'=== {ip}:{port} SNMP 진단 ===\n')
    sys_descr_vals, err = await probe_get(engine, auth_data, target, '1.3.6.1.2.1.1.1.0')
    sys_descr = sys_descr_vals[0] if sys_descr_vals else None
    print(f'sysDescr: {sys_descr!r}' if sys_descr else f'sysDescr 조회 실패: {err}')
    if sys_descr:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from collector import snmp_profiles
        current = snmp_profiles.resolve_profile(None, sys_descr)
        print(f'현재 코드 기준 자동 감지 프로필: {current["name"]} '
              f'({"NX-OS 전용 프로필 추가 전이라 이 장비도 일반 cisco(IOS) 프로필로 묶임" if current["name"] == "cisco" else ""})')
    print()

    for group, items in CANDIDATES.items():
        print(f'--- {group} ---')
        for label, oid, kind in items:
            if kind == 'get':
                vals, err = await probe_get(engine, auth_data, target, oid)
            else:
                vals, err = await probe_walk(engine, auth_data, target, oid)
            if vals:
                sample = list(vals.items())[:3] if isinstance(vals, dict) else vals[:3]
                print(f'  [응답 있음] {label}\n      OID {oid} -> {sample}')
            else:
                print(f'  [응답 없음] {label}\n      OID {oid} -> {err}')
        print()

    print('위에서 "[응답 있음]"으로 나온 항목들이 실제로 쓸 수 있는 후보입니다.')
    print('CPU/MEM은 숫자가 상식적인 범위(0~100 또는 실제 CLI 수치와 비슷)인지,')
    print('display cpu/show system resources 같은 CLI 명령 결과와 직접 대조해주세요.')


if __name__ == '__main__':
    asyncio.run(main())
