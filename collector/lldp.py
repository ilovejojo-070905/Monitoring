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
    sys_names, names_ok = await _snmp_walk(engine, ip, auth_data, port, OID_LLDP_REM_SYS_NAME, timeout=timeout, return_status=True)
    port_ids, ports_ok = await _snmp_walk(engine, ip, auth_data, port, OID_LLDP_REM_PORT_ID, timeout=timeout, return_status=True)
    neighbors = []
    for key, name in sys_names.items():
        name_str = str(name).strip()
        if name_str:
            # lldpRemTable's own index is "<lldpRemTimeMark>.<lldpRemLocalPortNum>.
            # <lldpRemIndex>" -- the local port this specific neighbor was seen
            # on is already right there in the walk's own key, no extra OID
            # needed. Used (storage.replace_lldp_links) so the same neighbor
            # showing up on two different local ports keeps two separate link
            # rows instead of one overwriting the other.
            key_parts = key.split('.')
            local_port = key_parts[1] if len(key_parts) >= 2 else ''
            neighbors.append({'sysName': name_str, 'portId': str(port_ids.get(key, '')), 'localPort': local_port})
    # 신규 기능(2026-10-16, "오래된 링크와 수집 실패를 실제 단절과 구별"):
    # confirmed=True + neighbors=[] 는 "이 장비가 LLDP 이웃이 하나도 없다고
    # 확인 응답함"(진짜 단절일 수 있음 -- apply_discovered_links가 기존
    # 링크를 지워도 됨), confirmed=False는 "이번 폴링에서 그 테이블을 못
    # 받았음"(장비 상태를 알 수 없으니 기존 링크를 그대로 둬야 함). 둘 다
    # neighbors가 똑같이 []였던 이전 방식은 이 둘을 구분할 방법이 아예
    # 없었음.
    return {'neighbors': neighbors, 'confirmed': names_ok and ports_ok}


def apply_discovered_links(device_id, neighbors):
    import storage
    current_links = []
    for n in neighbors:
        matched_id = storage.find_device_by_name_or_ip(name=n['sysName'], exclude_id=device_id)
        if matched_id:
            current_links.append((matched_id, n.get('localPort') or '', n.get('portId')))
    storage.replace_lldp_links(device_id, current_links)
