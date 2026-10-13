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
#
# column .5 자리 bug found live (실제 HP 2530-24G/J9776A에 붙여서 확인,
# 2026-10-13): 메모리가 63%에 고정된 채 안 변한다는 제보로 테이블 행 전체
# (.1~.7)를 직접 walk해서 확인함. .5는 "Total Used Memory"가 아니라 CLI의
# "System Total Memory"와 정확히 일치하는 총 메모리 크기였고(둘 다
# 67108864), 실제 할당량(used)은 그 다음 컬럼 .7에 있었음 (.6=free,
# .7=used, .6+.7=.5가 정확히 들어맞는 것도 직접 확인). 기존 .5를 그대로
# mem_used_oid에 넣으면 공식이 total/(total+free)*100이 되어 총 메모리가
# 안 변하는 한 결과도 거의 안 변하는, 63% 근처에 "고정된 것처럼 보이는"
# 틀린 값이 나왔던 것 -- Juniper/H3C 때와 같은 "테이블에서 엉뚱한 행/열을
# 고른 탓에 숫자가 그럴듯해 보이지만 실제로는 틀린" 종류의 버그.
OID_HP_CPU = '1.3.6.1.4.1.11.2.14.11.5.1.9.6.1'
OID_HP_MEM_USED = '1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.7'
OID_HP_MEM_FREE = '1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.6'

# ArubaOS-CX (6100/6200/6300/... -- a completely different, Linux-based OS
# from the classic ArubaOS-Switch/ProVision line above, not a newer firmware
# of the same thing) doesn't answer the STATISTICS-MIB OIDs above at all, so
# 'hp' silently falls back to generic HOST-RESOURCES-MIB (cpu_fallback_oid,
# and the hrStorage walk in snmp_collector.py for memory). CPU via
# hrProcessorLoad turned out fine (community-confirmed, matches this
# project's own live test against a real 6100/JL675A). Memory did not:
# hrStorageTable's "Physical memory" used/size on this Linux-based device
# counts OS page cache/buffers as "used" the way `free`'s naive total-free
# does, landing at 34% while the switch's own `show system resource-
# utilization` says 26% -- the same cache-vs-available gap every Linux box
# has, not a wrong-OID bug like HP/H3C's were, and not reliably reversible
# from the generic cache/buffer rows alone (tried subtracting them off
# live: overshoots past zero, because this agent's "Cached"/"Shared" rows
# don't decompose "Physical memory"'s used value by simple arithmetic).
# arubaWiredSystemInfoMemory (ARUBAWIRED-SYSTEMINFO-MIB / renamed
# HPE_ANW-SYSTEMINFO-MIB, confirmed via HPE/Aruba community threads) is
# Aruba's own already-computed percentage for this -- walked and confirmed
# live against the same 6100: returns exactly 26, matching the CLI exactly.
# One row per subsystem (index is a string like "management_module/1/1",
# matching the module names `show environment` already uses) -- this
# project's one real CX device only has that single row, so averaging the
# walk (same pattern as every other profile's mem_pct_oid) is correct here;
# untested on a stacked/modular CX chassis that might expose more rows.
OID_ARUBA_CX_MEM_PCT = '1.3.6.1.4.1.47196.4.1.1.3.22.1.0.1.1.4'

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
#
# 그런데 실제 장비(HP A5500)에 붙여서 확인해보니 (display cpu-usage/display
# memory의 실측값: CPU 13%, 메모리 15%와 비교) CPU/메모리가 그보다 훨씬 낮게
# (0.2~0.3%) 떴다 -- 이 테이블이 CPU/메모리를 가진 보드뿐 아니라 전원/팬/
# 온도센서/포트 등 entPhysicalTable의 모든 행에 대해 똑같이 이 컬럼을
# 노출하면서, 해당 안 되는 행은 전부 0으로 채워놓기 때문 (실측: 40행 중
# 진짜 값이 있는 건 "Board"(entPhysicalClass=module) 행 1개뿐, 나머지
# 39개는 전부 0 -- 그대로 평균 내면 실제 값이 40분의 1 가까이로 희석됨).
# Juniper 쪽에서 이미 "구성요소 여러 개를 평균 내면 섞인다"는 걸 알고도
# 받아들인 단순화(허용 범위의 부정확함)와는 질적으로 다른 문제 -- 몇 배가
# 아니라 자릿수가 바뀌는 수준이라 그냥 받아들일 수 없었음. 그래서 H3C만은
# ENTITY-MIB(entPhysicalClass/entPhysicalContainedIn, 표준 MIB -- H3C
# 전용이 아님)로 "module(9)이면서 그 위 조상 중에 또 다른 module(9)이 없는"
# 행만 골라서(= 최상위 보드만, SubCard 같은 module 안에 또 들어있는
# module은 제외) 평균 내도록 함 -- 이미 이 코드베이스에 있는 HR-MIB
# 폴백(hrStorageType을 먼저 walk해서 RAM 행만 골라 쓰는 패턴, 위쪽
# OID_HR_STORAGE_* 주석 참고)과 같은 종류의 "분류 컬럼을 먼저 봐서 맞는
# 행만 쓰기" 방식이라 이 모듈의 "테이블 상관관계는 범위 밖" 원칙을 깨는
# 게 아니라 이미 있는 그 예외를 한 번 더 쓰는 것.
OID_H3C_CPU = '1.3.6.1.4.1.25506.2.6.1.1.1.1.6'
OID_H3C_MEM_PCT = '1.3.6.1.4.1.25506.2.6.1.1.1.1.8'
OID_ENT_PHYSICAL_CLASS = '1.3.6.1.2.1.47.1.1.1.1.5'
OID_ENT_PHYSICAL_CONTAINED_IN = '1.3.6.1.2.1.47.1.1.1.1.4'
ENT_PHYSICAL_CLASS_MODULE = '9'

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
    # ArubaOS-CX (6100/6200/6300/... -- see the OID_ARUBA_CX_MEM_PCT comment
    # above). CPU reuses the plain HOST-RESOURCES-MIB OID directly as
    # cpu_oid (not as a 'hp' cpu_fallback_oid) since this device never
    # answers the STATISTICS-MIB branch at all -- no point trying it first.
    'aruba-cx': {
        'name': 'aruba-cx',
        'cpu_oid': OID_HR_PROCESSOR_LOAD,
        'cpu_fallback_oid': None,
        'mem_used_oid': None,
        'mem_free_oid': None,
        'mem_pct_oid': OID_ARUBA_CX_MEM_PCT,
        # No env_mib: ArubaOS-CX's `show environment` output (confirmed live)
        # implies ENTITY-SENSOR-MIB or another Aruba-specific table, but that
        # wasn't researched as part of this fix -- scope here was CPU/memory
        # only, same as the hp-comware profile's env_mib decision.
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
        # hh3cEntityExtCpuUsage/MemUsage cover every entPhysicalTable row
        # (ports/PSU/fans/sensors included, all reporting 0), not just the
        # CPU-bearing board -- see the OID_H3C_* comment above. This tells
        # snmp_collector.py to filter cpu_oid/mem_pct_oid's walked rows down
        # to just the top-level module(s) via ENTITY-MIB classification
        # before averaging, instead of averaging the whole table.
        'entity_module_filter': True,
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
    which keywords exist.
    'aruba' + no 'procurve' is checked BEFORE the procurve/aruba/hewlett-
    packard/hpe line below: every real ArubaOS-Switch (classic) sysDescr
    seen so far carries a fixed "(Formerly ProCurve)" marketing string
    (confirmed live on a 2530/J9776A), while ArubaOS-CX (a different,
    Linux-based OS with no ProCurve heritage) never does (confirmed live
    on a 6100/JL675A) -- so 'procurve' present or absent is what actually
    tells the two apart, not just the word 'aruba' alone (both say it)."""
    if vendor_profile and vendor_profile != 'generic':
        return PROFILES.get(vendor_profile, PROFILES['generic'])
    if sys_descr:
        descr = sys_descr.lower()
        if 'cisco' in descr:
            return PROFILES['cisco']
        if 'comware' in descr:
            return PROFILES['hp-comware']
        if 'aruba' in descr and 'procurve' not in descr:
            return PROFILES['aruba-cx']
        if 'procurve' in descr or 'aruba' in descr or 'hewlett-packard' in descr or 'hpe' in descr:
            return PROFILES['hp']
        if 'dell' in descr or 'powerconnect' in descr:
            return PROFILES['dell']
        if 'juniper' in descr or 'junos' in descr:
            return PROFILES['juniper']
    return PROFILES['generic']
