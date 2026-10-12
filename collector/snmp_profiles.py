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

# CISCO-ENVMON-MIB (중간 난이도 항목: 온도/팬/전원 상태) -- Cisco 전용, 'generic'
# 프로필에서는 조회하지 않는다. 세 상태 OID 모두 같은 enum을 쓴다
# (1=normal, 2=warning, 3=critical, 4=shutdown, 5=notPresent).
OID_CISCO_ENVMON_TEMP_DESCR = '1.3.6.1.4.1.9.9.13.1.3.1.2'
OID_CISCO_ENVMON_TEMP_VALUE = '1.3.6.1.4.1.9.9.13.1.3.1.3'
OID_CISCO_ENVMON_TEMP_STATE = '1.3.6.1.4.1.9.9.13.1.3.1.6'
OID_CISCO_ENVMON_FAN_STATE = '1.3.6.1.4.1.9.9.13.1.4.1.3'
OID_CISCO_ENVMON_SUPPLY_STATE = '1.3.6.1.4.1.9.9.13.1.5.1.3'

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
    },
    'juniper': {
        'name': 'juniper',
        'cpu_oid': OID_JUNIPER_CPU,
        'cpu_fallback_oid': OID_HR_PROCESSOR_LOAD,
        # jnxOperatingBuffer (OID_JUNIPER_MEM_BUFFER, defined above) looks
        # like it belongs here but deliberately isn't used: it's already a
        # buffer-pool utilization *percentage* (Gauge32, 0-100), not a
        # used/free byte count like every other profile's mem OIDs expect.
        # snmp_collector.py computes mem% as
        # used/(used+free)*100 -- wiring a percentage into mem_used_oid
        # with no mem_free_oid would make free_total always 0, so that
        # formula would always collapse to exactly 100%, not "imprecise"
        # but flatly wrong (confirmed by reading the actual formula before
        # shipping this, not assumed). Leaving both unset here falls
        # through to the HR-MIB hrStorage walk instead (same safe path
        # 'generic'/'dell' use) -- correct, if JUNOS answers it, rather
        # than confidently wrong.
        'mem_used_oid': None,
        'mem_free_oid': None,
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
    gear is matched by its actual product line names instead."""
    if vendor_profile and vendor_profile != 'generic':
        return PROFILES.get(vendor_profile, PROFILES['generic'])
    if sys_descr:
        descr = sys_descr.lower()
        if 'cisco' in descr:
            return PROFILES['cisco']
        if 'procurve' in descr or 'aruba' in descr or 'hewlett-packard' in descr or 'hpe' in descr:
            return PROFILES['hp']
        if 'dell' in descr or 'powerconnect' in descr:
            return PROFILES['dell']
        if 'juniper' in descr or 'junos' in descr:
            return PROFILES['juniper']
    return PROFILES['generic']
