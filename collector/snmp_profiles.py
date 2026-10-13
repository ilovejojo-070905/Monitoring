"""SNMP vendor OID profiles (directive section 18).

Before Phase 7 the Cisco-specific CPU/memory OIDs were a hardcoded fallback
inside sample_snmp: try the standard HOST-RESOURCES-MIB OID, and if that
comes back empty, try the Cisco OID instead. That worked (it's how the real
Cisco switch registered in this project gets its CPU/memory today) but adding
a second vendor meant editing sample_snmp's control flow directly. This module
promotes that fallback into a lookup table instead: a new vendor is a new
dict entry, not a new branch in the poller.
"""

OID_HR_PROCESSOR_LOAD = '1.3.6.1.2.1.25.3.3.1.2'
OID_UPS_BATTERY_CAPACITY = '1.3.6.1.2.1.33.1.2.4.0'
OID_CISCO_CPU_5MIN = '1.3.6.1.4.1.9.9.109.1.1.1.1.7'
OID_CISCO_MEM_USED = '1.3.6.1.4.1.9.9.48.1.1.1.5'
OID_CISCO_MEM_FREE = '1.3.6.1.4.1.9.9.48.1.1.1.6'

# HP/Aruba (classic ProCurve/ProVision switches), STATISTICS-MIB --
# hpSwitchCpuStat / hpGlobalMemAllocBytes / hpGlobalMemFreeBytes. These are
# TABLE columns like the Cisco ones above (not single scalar leaves), so
# they're walked the same way -- that also sidesteps the single biggest
# real-world headache with these OIDs: the final instance suffix (.0, .1,
# .9.1, ...) genuinely varies by model/firmware (confirmed against several
# independent HPE community threads while adding this), so walking the
# column prefix picks up whatever instance that specific device actually
# exposes instead of guessing one fixed suffix that only some models have.
# Caveat this project can't fully resolve without a real HP/Aruba device to
# test against: newer Aruba CX-series switches (2930F/6100/6300...) often
# don't expose this STATISTICS-MIB branch at all and use HOST-RESOURCES-MIB
# instead -- cpu_fallback_oid below covers that case the same way 'generic'
# already does for non-Cisco gear.
OID_HP_CPU = '1.3.6.1.4.1.11.2.14.11.5.1.9.6.1'
OID_HP_MEM_USED = '1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.5'
OID_HP_MEM_FREE = '1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.6'

# Juniper JUNIPER-MIB jnxOperatingTable -- one row per physical/logical
# component (Routing Engine, each FPC, each PIC, fan trays, PSUs...), not
# one row per device, so walking the whole column and averaging (same
# averaging snmp_collector.py already does for every profile's 'loads')
# mixes the Routing Engine's real CPU load in with mostly-irrelevant
# component rows -- a reasonable, directionally-useful approximation (the
# same simplification this project already accepts for Cisco, which
# usually only has one CPU row so it's rarely visible there), not a precise
# "RE-only" reading. Isolating just the Routing Engine row would need
# correlating against jnxOperatingDescr (column 5), which is the same class
# of table-correlation work the module docstring above already calls out
# as out of scope for this single-OID-per-vendor model.
OID_JUNIPER_CPU = '1.3.6.1.4.1.2636.3.1.13.1.8'
OID_JUNIPER_MEM_BUFFER = '1.3.6.1.4.1.2636.3.1.13.1.11'

# HP A-series/5500 등 Comware 펌웨어(H3C OEM) 장비는 'hp' 프로필(classic
# ProCurve/ProVision, enterprise-11 트리)과 완전히 다른 칩/트리를 쓴다 --
# sysDescr엔 "Hewlett-Packard"가 들어있어 'hp'로 오인식되지만 실제로는
# H3C의 HH3C-ENTITY-EXT-MIB(enterprise-25506)를 쓰는 별도 제품 계열이라
# enterprise-11 OID엔 아무것도 응답하지 않는다 (CPU/메모리 둘 다 안 보이는
# 실제 증상으로 확인됨). hh3cEntityExtCpuUsage/MemUsage는 물리 엔티티별
# 행을 갖는 테이블이지만, 둘 다 이미 0-100 "퍼센트" 값이다 (Cisco/HP처럼
# used/free 바이트 쌍이 아님) -- 그래서 mem_used_oid에 넣지 않고 아래
# PROFILES에 새로 추가한 mem_pct_oid 필드로 받는다 (Juniper의
# jnxOperatingBuffer를 mem_used_oid에 잘못 넣으면 공식이 늘 100%로
# 깨지는 문제를 피하려고 그때 미구현으로 남겨뒀던 것과 같은 함정 --
# 이번엔 "쓰지 않기"가 아니라 "퍼센트 전용 필드로 제대로 받기"로 해결).
OID_H3C_CPU = '1.3.6.1.4.1.25506.2.6.1.1.1.1.6'
OID_H3C_MEM_PCT = '1.3.6.1.4.1.25506.2.6.1.1.1.1.8'

# CISCO-ENVMON-MIB (중간 난이도 항목: 온도/팬/전원 상태) -- Cisco 전용, 'generic'
# 프로필에서는 조회하지 않는다. 세 상태 OID 모두 같은 enum을 쓴다
# (1=normal, 2=warning, 3=critical, 4=shutdown, 5=notPresent). 이 5단계가
# InfraSight 전체(여기·snmp_collector.py·index.html)가 공유하는 "표준
# 환경센서 상태 어휘"다 -- 다른 벤더를 추가할 때도 그 벤더의 원래 enum을
# 그대로 노출하지 않고 반드시 이 5단계로 변환해서 맞춰야 한다 (아래 Juniper
# 항목 참고).
OID_CISCO_ENVMON_TEMP_DESCR = '1.3.6.1.4.1.9.9.13.1.3.1.2'
OID_CISCO_ENVMON_TEMP_VALUE = '1.3.6.1.4.1.9.9.13.1.3.1.3'
OID_CISCO_ENVMON_TEMP_STATE = '1.3.6.1.4.1.9.9.13.1.3.1.6'
OID_CISCO_ENVMON_FAN_STATE = '1.3.6.1.4.1.9.9.13.1.4.1.3'
OID_CISCO_ENVMON_SUPPLY_STATE = '1.3.6.1.4.1.9.9.13.1.5.1.3'

# Juniper 환경센서: 별도 MIB가 아니라 CPU에 이미 쓰고 있는 그 jnxOperatingTable
# 그대로 재사용한다 (장비당 한 행이 아니라 부품 하나당 한 행 -- Routing
# Engine/FPC/PIC/팬/전원 전부 같은 테이블에 섞여 있음). Cisco처럼 온도/팬/
# 전원이 각자 별도 테이블로 안 나뉘어 있어서, 행을 구분하려면 테이블
# 인덱스의 첫 번째 숫자(부품 종류 코드)로 걸러야 한다 -- 여러 출처에서
# 공통으로 확인된 값: 2=전원, 4=팬, 7=FPC, 8=PIC, 9=Routing Engine.
# (snmp_collector.py가 이 구분 로직을 실제로 수행한다 -- 여기는 OID만.)
OID_JUNIPER_OPER_DESCR = '1.3.6.1.4.1.2636.3.1.13.1.5'
OID_JUNIPER_OPER_STATE = '1.3.6.1.4.1.2636.3.1.13.1.6'
OID_JUNIPER_OPER_TEMP = '1.3.6.1.4.1.2636.3.1.13.1.7'
JUNIPER_CLASS_POWER_SUPPLY = '2'
JUNIPER_CLASS_FAN = '4'

# jnxOperatingState는 Cisco ENVMON과 전혀 다른 enum이라(부품의 "가동 상태"지
# "정상/주의/위험" 같은 등급이 아님), 코드 숫자를 그대로 넘기면 완전히 다른
# 뜻인 Cisco 쪽 '2'(warning)·'3'(critical) 라벨로 잘못 해석된다. 조사로
# 확실히 확인된 값만 "정상"(Cisco 쪽 '1')으로 변환하고, 나머지(= 확신 없는
# 값들)는 전부 "알수없음"으로 떨어지게 한다 -- 틀릴 바엔 "모른다"가 "고장난
# 걸 정상이라고 표시"보다 훨씬 안전하다는 판단.
JUNIPER_STATE_NORMAL_CODES = ('2', '5')  # running(2) / running at full speed(5)

PROFILES = {
    # 'generic' preserves the exact pre-Phase-7 behavior: try the standard
    # OID first, fall back to the Cisco OID if the device doesn't answer it.
    # A device that answers neither (most non-Cisco gear) falls through to
    # the HOST-RESOURCES-MIB hrStorage walk in snmp_collector.py instead --
    # that one needs table correlation (type+size+used per row) so it can't
    # be expressed as a single OID string here.
    'generic': {
        'name': 'generic',
        'cpu_oid': OID_HR_PROCESSOR_LOAD,
        'cpu_fallback_oid': OID_CISCO_CPU_5MIN,
        'mem_used_oid': OID_CISCO_MEM_USED,
        'mem_free_oid': OID_CISCO_MEM_FREE,
    },
    'cisco': {
        'name': 'cisco',
        'cpu_oid': OID_CISCO_CPU_5MIN,
        'cpu_fallback_oid': None,
        'mem_used_oid': OID_CISCO_MEM_USED,
        'mem_free_oid': OID_CISCO_MEM_FREE,
        # env_mib: which environment-sensor (온도/팬/전원) parser
        # snmp_collector.py should use, if any -- None/absent means "this
        # vendor's env sensor OIDs aren't reliable enough to guess at" (see
        # the hp/dell/juniper entries below for why that's the honest answer
        # for some of them, not just an oversight).
        'env_mib': 'cisco_envmon',
    },
    'ups': {
        'name': 'ups',
        'cpu_oid': None,
        'cpu_fallback_oid': None,
        'mem_used_oid': None,
        'mem_free_oid': None,
    },
    'hp': {
        'name': 'hp',
        'cpu_oid': OID_HP_CPU,
        # Falls back to the standard MIB (not a second vendor OID, unlike
        # 'generic' falling back to Cisco's) -- newer Aruba CX switches
        # commonly answer HOST-RESOURCES-MIB instead of the classic
        # STATISTICS-MIB branch above (see the OID_HP_* comment).
        'cpu_fallback_oid': OID_HR_PROCESSOR_LOAD,
        'mem_used_oid': OID_HP_MEM_USED,
        'mem_free_oid': OID_HP_MEM_FREE,
        # No env_mib: HP-ICF-CHASSIS does have a sensor table
        # (hpicfSensorDescr/hpicfSensorStatus under icfSensors), but while
        # researching it the only operational-status value multiple sources
        # agreed on was good(4) -- one monitoring tool's own state table
        # listed 2 as "Bad" while its own lookup elsewhere listed 3 as
        # "Bad" for the same column, and the exact column OIDs beneath
        # icfSensors weren't confirmed precisely enough to commit here with
        # the same confidence as the CPU/mem OIDs above. Shipping a sensor
        # reading that's silently backwards (reports a failed fan as
        # "normal") is worse than showing nothing, so this is left
        # unimplemented rather than guessed.
        'env_mib': None,
    },
    # Dell/Dell EMC Networking's own CPU/memory OIDs turned out to not be
    # usable here: every PowerConnect/PowerSwitch product line keeps them
    # under a different final suffix (62xx vs M-series vs 34xx/54xx all
    # differ), with no single column prefix that generalizes the way
    # Cisco's/HP's do -- committing one specific model's OID as "the Dell
    # OID" would silently return nothing for every other Dell line. Modern
    # Dell EMC Networking OS9/OS10 gear answers standard HOST-RESOURCES-MIB
    # reliably, so this profile is deliberately just that (same OID as
    # 'generic's primary path, no vendor-specific fallback or memory OID --
    # memory falls through to the HR-MIB hrStorage walk in
    # snmp_collector.py, same as 'generic' does for any non-Cisco device).
    # It exists as its own named entry (rather than just leaving Dell gear
    # on 'generic') purely so it's selectable/inspectable by name.
    'dell': {
        'name': 'dell',
        'cpu_oid': OID_HR_PROCESSOR_LOAD,
        'cpu_fallback_oid': None,
        'mem_used_oid': None,
        'mem_free_oid': None,
        # No env_mib, same reasoning as the CPU/mem decision above: Dell's
        # temp/fan/power OIDs are split across at least 3 unrelated MIB
        # trees depending on product generation (62xx/M-series vs
        # 54xx/34xx vs the tree N-able's own checks use), with no common
        # prefix and no standard-MIB equivalent to fall back on the way
        # HOST-RESOURCES-MIB covers CPU/memory -- there's no safe default
        # here, only "guess which Dell you have."
        'env_mib': None,
    },
    'juniper': {
        'name': 'juniper',
        'cpu_oid': OID_JUNIPER_CPU,
        'cpu_fallback_oid': OID_HR_PROCESSOR_LOAD,
        # jnxOperatingBuffer is already a buffer-pool utilization
        # *percentage* (Gauge32, 0-100), not a used/free byte count like
        # mem_used_oid/mem_free_oid expect -- wiring it into mem_used_oid
        # with no mem_free_oid would make free_total always 0, so
        # snmp_collector.py's used/(used+free)*100 formula would always
        # collapse to exactly 100% (confirmed by reading the actual formula
        # before shipping this, not assumed). mem_pct_oid (added for the
        # H3C/Comware profile below, which has the same percentage-not-
        # bytes shape) is the correct home for it instead -- snmp_collector.py
        # averages mem_pct_oid's walked values directly, no used/free math.
        'mem_used_oid': None,
        'mem_free_oid': None,
        'mem_pct_oid': OID_JUNIPER_MEM_BUFFER,
        'env_mib': 'juniper_opertable',
    },
    # HP A-series switches running Comware (H3C OEM firmware) -- see the
    # OID_H3C_* comment above for why this can't share the 'hp' profile
    # despite sysDescr containing "Hewlett-Packard" (confirmed from a real
    # device: "HP Comware Platform Software ... HP A5500-24G-4SFP HI Switch
    # ... Hewlett-Packard Development Company, L.P." -- CPU/memory both
    # blank under 'hp' because enterprise-11 OIDs don't exist on this chip).
    'hp-comware': {
        'name': 'hp-comware',
        'cpu_oid': OID_H3C_CPU,
        'cpu_fallback_oid': OID_HR_PROCESSOR_LOAD,
        'mem_used_oid': None,
        'mem_free_oid': None,
        'mem_pct_oid': OID_H3C_MEM_PCT,
        # No env_mib: scope here is CPU/memory only (the actual reported
        # symptom) -- Comware does have its own entity-sensor MIB
        # (hh3cEntityExtTemperature, under the same enterprise-25506 tree)
        # but it wasn't researched/verified as part of this fix, so it's
        # left unimplemented rather than guessed, same policy as hp/dell's
        # env_mib above.
        'env_mib': None,
    },
}


def resolve_profile(vendor_profile, sys_descr):
    """An explicit vendor_profile (set on the device) always wins. Otherwise,
    'generic' auto-upgrades to a specific vendor when sysDescr announces it --
    this is exactly the auto-detection that was implicit in the old
    fallback-based code for Cisco, extended here to the vendors added
    alongside hp/dell/juniper above, same single-substring-check style.
    'hp' itself is deliberately NOT one of the keywords (too short/common a
    substring to safely match against arbitrary sysDescr text) -- HP/Aruba
    gear is matched by its actual product line names instead.
    'comware' is checked BEFORE the hewlett-packard/hpe keywords below: a
    real Comware device's sysDescr contains BOTH ("HP Comware Platform
    Software ... Hewlett-Packard Development Company, L.P."), and
    'hp-comware' is the one that actually has working OIDs for it (see the
    OID_H3C_* comment above) -- checking order here matters, not just
    which keywords exist."""
    if vendor_profile and vendor_profile != 'generic':
        return PROFILES.get(vendor_profile, PROFILES['generic'])
    if sys_descr:
        descr = sys_descr.lower()
        if 'cisco' in descr:
            return PROFILES['cisco']
        if 'comware' in descr:
            return PROFILES['hp-comware']
        if 'procurve' in descr or 'aruba' in descr or 'hewlett-packard' in descr or 'hpe' in descr:
            return PROFILES['hp']
        if 'dell' in descr or 'powerconnect' in descr:
            return PROFILES['dell']
        if 'juniper' in descr or 'junos' in descr:
            return PROFILES['juniper']
    return PROFILES['generic']
