"""등록된 SNMP 장비별 수집 진단 (읽기 전용) -- ops/collect-diagnostics.ps1이 호출.

사용자 요청("다른 장소에서 신규 사이트 설치하고 Aruba 5412 등록했는데 cpu/메모리/
환경센서가 보이질 않아"): 현장 PC에 원격 접속하지 않고도 원인을 볼 수 있게, 진단
zip에 장비마다 아래를 남긴다.
  - sysDescr와 자동 인식된 벤더 프로필(수동 지정값 포함)
  - 그 프로필로 실제 수집기(_snmp_poll)를 한 번 돌린 결과: CPU/메모리/환경센서가
    무엇으로 왔는지(빈 값이면 왜 화면에 안 나오는지 바로 보임), 걸린 시간
  - 모든 벤더 프로필의 CPU/메모리 OID를 하나씩 걸어 본 결과 -- "어느 프로필이면
    값이 나오는지"(= 인식 규칙을 어떻게 고치면 되는지)
  - 환경센서 후보 테이블(HP hpicfSensor / 표준 ENTITY-SENSOR / Cisco ENVMON) 행 수
SNMP 커뮤니티/v3 비밀번호는 절대 출력하지 않는다. 장비에는 수집기와 같은 등록
설정으로 GET/WALK만 한다(설정 변경 없음).

사용: python snmp_probe.py <InfraSight 설치 폴더>
"""
import asyncio
import os
import sys
import time

# 진단 파일에 그대로 저장되므로 콘솔 코드페이지(cp949)와 무관하게 UTF-8로 출력.
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

install_dir = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
os.chdir(install_dir)
sys.path.insert(0, install_dir)

import storage  # noqa: E402
from collector import snmp_collector as sc, snmp_profiles as sp  # noqa: E402

try:
    from pysnmp.hlapi.asyncio import SnmpEngine  # noqa: E402
except Exception as e:  # pragma: no cover
    print(f'pysnmp를 불러오지 못했습니다: {e}')
    sys.exit(0)

PER_DEVICE_TIMEOUT_SEC = 90


def short(v, n=8):
    """dict/값을 짧게 -- 행이 많으면 앞 n개 + 총 개수."""
    if v is None:
        return 'None'
    if isinstance(v, dict):
        items = list(v.items())
        body = ', '.join(f'{k}={(x.prettyPrint() if hasattr(x, "prettyPrint") else x)}'[:60] for k, x in items[:n])
        more = f' ...(총 {len(items)}개)' if len(items) > n else ''
        return '{' + body + more + '}' if items else '{} (응답 없음)'
    return str(v.prettyPrint() if hasattr(v, 'prettyPrint') else v)[:200]


async def walk_count(eng, ip, auth, port, oid):
    try:
        r = await sc._snmp_walk(eng, ip, auth, port, oid, timeout=2.0, max_rows=64)
        return r
    except Exception as e:
        return f'오류 {e}'


async def probe(dev):
    fields = dev.get('fields') or {}
    version = fields.get('snmpVersion', 'v2c')
    port = int(fields.get('snmpPort') or 161)
    community = storage.get_credential(dev['id'], 'snmp_community')
    auth = sc.build_auth_data(dev['id'], version, community)
    out = []
    t0 = time.time()
    r = await sc._snmp_poll(dev['ip'], auth, port, dev.get('category') or 'net', 2.0,
                            dev.get('vendor_profile'), False, True)
    out.append(f"  실제 수집기 1회 실행: {time.time() - t0:.1f}초, 응답={r.get('reachable')} 실패사유={r.get('failureReason')}")
    descr = r.get('sysDescr')
    out.append(f'  sysDescr: {descr}')
    out.append(f"  벤더 프로필: 저장값={dev.get('vendor_profile')!r} -> 자동 인식={sp.resolve_profile_name(dev.get('vendor_profile'), descr)}")
    if not r.get('reachable'):
        return out
    out.append(f"  인터페이스 수: {len(r.get('ifDescr') or {})}, 카운터 {r.get('ifCounterBits')}비트")
    for k in ('loads', 'memUsed', 'memFree', 'memPct', 'hrMemSize', 'hrMemUsed', 'entModel',
              'envTempDescr', 'envTempValue', 'envTempState', 'envFanState', 'envSupplyState'):
        if k in r:
            out.append(f'  {k}: {short(r.get(k))}')

    eng = SnmpEngine()
    out.append('  [프로필별 CPU/메모리 OID 응답] -- 값이 나오는 프로필이 이 장비에 맞는 것')
    seen = set()
    for name, prof in sp.PROFILES.items():
        for key in ('cpu_oid', 'cpu_fallback_oid', 'mem_used_oid', 'mem_free_oid', 'mem_pct_oid'):
            oid = prof.get(key)
            if not oid or oid in seen:
                continue
            seen.add(oid)
            res = await walk_count(eng, dev['ip'], auth, port, oid)
            if isinstance(res, dict) and res:
                out.append(f'    {name}.{key} {oid}: {short(res, 4)}')
    if len(out) and not out[-1].startswith('    '):
        out.append('    (어느 프로필의 CPU/메모리 OID에도 응답 없음 -- SNMP view 제한이거나 미지원 MIB)')

    out.append('  [환경센서 후보 테이블]')
    for label, oid in (('HP hpicfSensor 종류', sp.OID_HP_ICF_SENSOR_TYPE_REF),
                       ('HP hpicfSensor 상태', sp.OID_HP_ICF_SENSOR_STATUS),
                       ('HP hpicfSensor 이름', sp.OID_HP_ICF_SENSOR_DESCR),
                       ('ENTITY-SENSOR 종류', sp.OID_ENT_PHY_SENSOR_TYPE),
                       ('Cisco ENVMON 온도', sp.OID_CISCO_ENVMON_TEMP_DESCR)):
        res = await walk_count(eng, dev['ip'], auth, port, oid)
        out.append(f'    {label}: {short(res, 10)}')
    return out


def main():
    devices = [d for d in storage.load_devices() if d.get('mode') == 'snmp']
    if not devices:
        print('SNMP로 등록된 장비가 없습니다.')
        return
    for d in devices:
        print(f"\n### {d['name']} ({d['ip']}, 분류={d.get('category')}, 수집={'켜짐' if d.get('monitoring_enabled') != 0 else '꺼짐'})")
        try:
            lines = asyncio.run(asyncio.wait_for(probe(d), PER_DEVICE_TIMEOUT_SEC))
        except asyncio.TimeoutError:
            lines = [f'  {PER_DEVICE_TIMEOUT_SEC}초 안에 끝나지 않아 중단(장비 응답이 매우 느림)']
        except Exception as e:
            lines = [f'  진단 중 오류: {type(e).__name__}: {e}']
        print('\n'.join(lines), flush=True)


if __name__ == '__main__':
    main()
