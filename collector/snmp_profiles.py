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
}


def resolve_profile(vendor_profile, sys_descr):
    """An explicit vendor_profile (set on the device) always wins. Otherwise,
    'generic' auto-upgrades to 'cisco' when sysDescr announces it -- this is
    exactly the auto-detection that was implicit in the old fallback-based
    code, just made explicit and inspectable."""
    if vendor_profile and vendor_profile != 'generic':
        return PROFILES.get(vendor_profile, PROFILES['generic'])
    if sys_descr and 'cisco' in sys_descr.lower():
        return PROFILES['cisco']
    return PROFILES['generic']
