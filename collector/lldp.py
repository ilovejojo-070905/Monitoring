"""Phase 7: best-effort LLDP neighbor discovery for 'net' category SNMP
devices, feeding storage.device_links (directive section 31 -- "prepare"
LLDP/CDP without changing the rendered topology yet).

This only ever links two devices InfraSight ALREADY has registered: a
neighbor's advertised sysName is looked up against existing devices, and if
nothing matches, nothing is stored. It never invents a new device/node from
LLDP data.
"""

OID_LLDP_REM_SYS_NAME = '1.0.8802.1.1.2.1.4.1.1.9'
OID_LLDP_REM_PORT_ID = '1.0.8802.1.1.2.1.4.1.1.7'

LLDP_INTERVAL_SEC = 300  # neighbor tables change rarely; no need to walk every poll


async def walk_lldp_neighbors(engine, ip, auth_data, port, timeout=1.5):
    from collector.snmp_collector import _snmp_walk  # local import: avoids a circular import at module load
    sys_names = await _snmp_walk(engine, ip, auth_data, port, OID_LLDP_REM_SYS_NAME, timeout=timeout)
    port_ids = await _snmp_walk(engine, ip, auth_data, port, OID_LLDP_REM_PORT_ID, timeout=timeout)
    neighbors = []
    for key, name in sys_names.items():
        name_str = str(name).strip()
        if name_str:
            neighbors.append({'sysName': name_str, 'portId': str(port_ids.get(key, ''))})
    return neighbors


def apply_discovered_links(device_id, neighbors):
    import storage
    for n in neighbors:
        matched_id = storage.find_device_by_name_or_ip(name=n['sysName'], exclude_id=device_id)
        if matched_id:
            storage.upsert_device_link(device_id, matched_id, 'lldp', remote_port=n.get('portId'))
